"""Dados públicos de um domínio ou IP para a consulta à IA: registros DNS e registro (RDAP).

Só roda quando o usuário clica em **Perguntar à IA**, junto com a consulta:

- **DNS** (pelo resolvedor do próprio add-on, o mesmo DNS que a casa usa; nenhum destino novo):
  IPs, cadeia de CNAME, servidores de nome, existência de MX, SPF e DMARC. Se o
  AdGuard/Pi-hole bloquear o domínio (``0.0.0.0`` ou NXDOMAIN), isso é dito, para a IA não concluir
  que o domínio não existe. Feito em Python (dnspython): nada de rodar ``dig`` com texto vindo de fora.
- **RDAP** (o "whois" moderno dos registros): data de registro, expiração, registrador e status do
  domínio; para um IP, a rede e a organização dona. O servidor certo vem da lista oficial da IANA
  (``data.iana.org/rdap``), guardada por uma semana. Sai só o domínio registrado (ou o IP), o mesmo
  dado que já vai para a IA.

O TTL não vai: o resolvedor da casa devolve o tempo que *falta* no cache dele (pode ser 0 para um
domínio comum), o que faria a IA ver um "TTL baixíssimo" onde não há.

Os textos de registros TXT não são enviados (só se existe SPF/DMARC): além de inúteis para a análise,
poderiam carregar instruções para a IA.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from .net import EgressDeniedError, HttpError, SafeHttpClient

_LOGGER = logging.getLogger(__name__)

IANA_HOST = "data.iana.org"
BOOTSTRAP = {"dns": "https://data.iana.org/rdap/dns.json", "ipv4": "https://data.iana.org/rdap/ipv4.json",
             "ipv6": "https://data.iana.org/rdap/ipv6.json"}
BOOTSTRAP_TTL = 7 * 24 * 3600
DNS_TIMEOUT = 4.0
RDAP_TIMEOUT = 15.0
_MAX_ADDRESSES = 6
_MAX_NAMES = 4
_BLOCKED_ADDRESSES = {"0.0.0.0", "::", "127.0.0.1", "::1"}


# --- DNS ----------------------------------------------------------------------------------


def _resolver() -> Any | None:
    try:
        import dns.asyncresolver
        import dns.resolver
    except ImportError:  # pragma: no cover - dependência do add-on
        return None
    try:
        resolver = dns.asyncresolver.Resolver()
    except dns.resolver.NoResolverConfiguration:
        return None
    resolver.lifetime = DNS_TIMEOUT
    return resolver


async def _records(resolver: Any, name: str, rtype: str) -> tuple[list[str], int | None, str | None]:
    """(valores, menor TTL, erro: "nxdomain"|"sem_resposta"|"falha"|None)."""
    import dns.exception
    import dns.resolver

    try:
        answer = await resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return [], None, "nxdomain"
    except dns.resolver.NoAnswer:
        return [], None, "sem_resposta"
    except (dns.exception.DNSException, OSError):
        return [], None, "falha"
    values = [r.to_text().rstrip(".") for r in answer]
    return values, answer.rrset.ttl if answer.rrset is not None else None, None


async def _cname_chain(resolver: Any, name: str) -> list[str]:
    import dns.exception
    import dns.rdatatype

    try:
        answer = await resolver.resolve(name, "A", raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError):
        return []
    targets = []
    for rrset in answer.response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            targets += [r.target.to_text().rstrip(".") for r in rrset]
    return targets[:_MAX_NAMES]


async def _zone_of(resolver: Any, name: str) -> tuple[str, list[str]]:
    """Zona (o domínio que tem NS) e os servidores de nome, subindo no máximo três níveis."""
    labels = name.split(".")
    for i in range(min(3, len(labels) - 1)):
        candidate = ".".join(labels[i:])
        values, _, error = await _records(resolver, candidate, "NS")
        if values:
            return candidate, sorted(values)[:_MAX_NAMES]
        if error == "falha":
            break
    return ".".join(labels[-2:]), []


async def dns_facts(host: str) -> dict[str, Any] | None:
    """Registros DNS públicos de ``host`` (domínio) ou o nome reverso (IP). None sem resolvedor."""
    resolver = _resolver()
    if resolver is None:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        import dns.reversename

        names, _, error = await _records(resolver, dns.reversename.from_address(str(ip)).to_text(), "PTR")
        return {"reverso": names[:_MAX_NAMES], "erro": error}
    (a, _, err_a), (aaaa, _, _), cnames = await asyncio.gather(
        _records(resolver, host, "A"), _records(resolver, host, "AAAA"), _cname_chain(resolver, host))
    zone, ns = await _zone_of(resolver, host)
    (mx, _, _), (txt, _, _), (dmarc, _, _) = await asyncio.gather(
        _records(resolver, zone, "MX"), _records(resolver, zone, "TXT"), _records(resolver, f"_dmarc.{zone}", "TXT"))
    addresses = (a + aaaa)[:_MAX_ADDRESSES]
    blocked = err_a == "nxdomain" or (bool(addresses) and all(x in _BLOCKED_ADDRESSES for x in addresses))
    return {
        "enderecos": addresses, "cname": cnames,
        "zona": zone, "servidores_de_nome": ns,
        "tem_mx": bool(mx), "tem_spf": any("v=spf1" in t.lower() for t in txt),
        "tem_dmarc": any("v=dmarc1" in t.lower() for t in dmarc),
        "bloqueado_ou_inexistente": blocked, "nxdomain": err_a == "nxdomain",
    }


# --- RDAP ---------------------------------------------------------------------------------


async def _bootstrap(http: SafeHttpClient, kind: str, cache_dir: Path | None) -> dict[str, Any]:
    path = cache_dir / f"rdap-{kind}.json" if cache_dir else None
    if path is not None:
        try:
            if time.time() - path.stat().st_mtime < BOOTSTRAP_TTL:
                return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    data = await http.get_json(BOOTSTRAP[kind])
    if not isinstance(data, dict):
        return {}
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            pass
    return data


def _services(bootstrap: dict[str, Any]) -> list[tuple[list[str], list[str]]]:
    out = []
    for item in bootstrap.get("services") or []:
        if isinstance(item, list) and len(item) == 2 and isinstance(item[0], list) and isinstance(item[1], list):
            out.append(([str(k).lower() for k in item[0]], [str(u) for u in item[1] if str(u).startswith("https://")]))
    return out


def _all_hosts(services: list[tuple[list[str], list[str]]]) -> frozenset[str]:
    return frozenset((urlsplit(u).hostname or "").lower() for _, urls in services for u in urls) - {""}


def _base_for_domain(services: list[tuple[list[str], list[str]]], domain: str) -> str | None:
    best, best_len = None, 0
    for keys, urls in services:
        for key in keys:
            if urls and (domain == key or domain.endswith("." + key)) and len(key) > best_len:
                best, best_len = urls[0], len(key)
    return best


def _base_for_ip(services: list[tuple[list[str], list[str]]], ip: ipaddress._BaseAddress) -> str | None:
    best, best_prefix = None, -1
    for keys, urls in services:
        for key in keys:
            try:
                net = ipaddress.ip_network(key, strict=False)
            except ValueError:
                continue
            if urls and ip.version == net.version and ip in net and net.prefixlen > best_prefix:
                best, best_prefix = urls[0], net.prefixlen
    return best


def _vcard_name(entity: dict[str, Any]) -> str | None:
    card = entity.get("vcardArray")
    if isinstance(card, list) and len(card) == 2 and isinstance(card[1], list):
        for field in card[1]:
            if isinstance(field, list) and len(field) >= 4 and field[0] == "fn" and str(field[3]).strip():
                return str(field[3]).strip()[:120]
    return None


def _entity(data: dict[str, Any], role: str) -> str | None:
    for entity in data.get("entities") or []:
        if isinstance(entity, dict) and role in (entity.get("roles") or []):
            return _vcard_name(entity) or (str(entity.get("handle"))[:80] if entity.get("handle") else None)
    return None


def _events(data: dict[str, Any]) -> dict[str, str]:
    out = {}
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") and event.get("eventDate"):
            out[str(event["eventAction"])] = str(event["eventDate"])[:25]
    return out


def _age_days(date: str | None, now: datetime | None = None) -> int | None:
    if not date:
        return None
    try:
        when = datetime.fromisoformat(date)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0, ((now or datetime.now(UTC)) - when).days)


async def rdap_facts(host: str, cache_dir: Path | None = None,
                     session: aiohttp.ClientSession | None = None) -> dict[str, Any] | None:
    """Registro do domínio (data, registrador, status) ou do IP (rede, organização). None se não houver."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    kind = "dns" if ip is None else f"ipv{ip.version}"
    iana = SafeHttpClient(allowed_hosts=frozenset({IANA_HOST}), timeout=RDAP_TIMEOUT, session=session)
    try:
        services = _services(await _bootstrap(iana, kind, cache_dir))
    finally:
        await iana.close()
    if not services:
        return None
    base = _base_for_ip(services, ip) if ip is not None else _base_for_domain(services, host)
    if base is None:
        return None
    # Só os servidores RDAP da lista da IANA (inclusive nos redirecionamentos entre registros).
    http = SafeHttpClient(allowed_hosts=_all_hosts(services), timeout=RDAP_TIMEOUT, session=session)
    headers = {"Accept": "application/rdap+json"}
    base = base if base.endswith("/") else base + "/"
    try:
        if ip is not None:
            data = await http.get_json(f"{base}ip/{ip}", headers)
            return {"tipo": "ip", "rede": str(data.get("name") or "")[:80] or None,
                    "pais": str(data.get("country") or "")[:8] or None,
                    "organizacao": _entity(data, "registrant") or _entity(data, "administrative"),
                    "faixa": (f"{data.get('startAddress')} - {data.get('endAddress')}"
                              if data.get("startAddress") else None)}
        labels = host.split(".")
        for size in (2, 3):  # domínio registrado: exemplo.com, ou exemplo.com.br
            if size > len(labels):
                break
            name = ".".join(labels[-size:])
            try:
                data = await http.get_json(f"{base}domain/{name}", headers)
            except HttpError as err:
                if err.status in (400, 404):
                    continue
                raise
            events = _events(data)
            created = events.get("registration")
            return {"tipo": "dominio", "dominio": name, "registrado_em": created, "idade_dias": _age_days(created),
                    "expira_em": events.get("expiration"), "atualizado_em": events.get("last changed"),
                    "registrador": _entity(data, "registrar"),
                    "status": [str(s)[:40] for s in (data.get("status") or [])][:6]}
        return None
    finally:
        await http.close()


async def collect(host: str, cache_dir: Path | None = None,
                  session: aiohttp.ClientSession | None = None) -> dict[str, Any]:
    """DNS e RDAP de ``host``. Falhas viram ausência do dado (a consulta à IA segue sem ele)."""

    async def safe(coro: Any, label: str) -> Any:
        try:
            return await coro
        except (HttpError, EgressDeniedError, aiohttp.ClientError, TimeoutError, ValueError, OSError) as err:
            _LOGGER.info("Dados de %s para a IA indisponíveis (%s): %s", host, label, type(err).__name__)
            return None

    dns_data, rdap_data = await asyncio.gather(safe(dns_facts(host), "DNS"),
                                               safe(rdap_facts(host, cache_dir, session), "RDAP"))
    return {k: v for k, v in (("dns", dns_data), ("rdap", rdap_data)) if v}


# --- Texto para a pessoa ------------------------------------------------------------------


def summary(facts: dict[str, Any], lang: str) -> list[str]:
    """Linhas curtas com os dados coletados, no idioma da interface."""
    en = lang == "en"
    lines: list[str] = []
    rdap, dns_data = facts.get("rdap") or {}, facts.get("dns") or {}
    if rdap.get("tipo") == "dominio":
        if rdap.get("registrado_em"):
            days = rdap.get("idade_dias")
            date = str(rdap["registrado_em"])[:10]
            lines.append(f"Registered on {date} ({days} days ago)" if en else f"Registrado em {date} (há {days} dias)")
        if rdap.get("registrador"):
            lines.append(("Registrar: " if en else "Registrador: ") + rdap["registrador"])
        if rdap.get("status"):
            lines.append("Status: " + ", ".join(rdap["status"]))
    elif rdap.get("tipo") == "ip":
        owner = " · ".join(str(x) for x in (rdap.get("organizacao"), rdap.get("rede"), rdap.get("pais")) if x)
        if owner:
            lines.append(("Network owner: " if en else "Dono da rede: ") + owner)
    if "reverso" in dns_data:
        names = dns_data.get("reverso") or []
        lines.append(("Reverse name: " if en else "Nome reverso: ") + (", ".join(names) or ("none" if en else "nenhum")))
    elif dns_data:
        if dns_data.get("bloqueado_ou_inexistente"):
            lines.append("Blocked by your DNS or does not exist" if en
                         else "Bloqueado pelo seu DNS ou não existe")
        elif dns_data.get("enderecos"):
            lines.append(("Addresses: " if en else "Endereços: ") + ", ".join(dns_data["enderecos"]))
        if dns_data.get("cname"):
            lines.append("CNAME: " + " → ".join(dns_data["cname"]))
        if dns_data.get("servidores_de_nome"):
            lines.append(("Name servers: " if en else "Servidores de nome: ") + ", ".join(dns_data["servidores_de_nome"]))
        mail = [("MX", dns_data.get("tem_mx")), ("SPF", dns_data.get("tem_spf")), ("DMARC", dns_data.get("tem_dmarc"))]
        lines.append("E-mail: " + ", ".join(
            f"{name} {'yes' if ok else 'no'}" if en else f"{name} {'sim' if ok else 'não'}" for name, ok in mail))
    return lines
