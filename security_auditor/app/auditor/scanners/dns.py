"""Fase 3: domínios consultados pelo host do HA, via AdGuard Home e/ou Pi-hole.

IMPORTANTE: o DNS de todos os add-ons e integrações passa pelo DNS do
Supervisor (hassio_dns), que encaminha para o seu servidor. Para o AdGuard ou
Pi-hole, todas as consultas vêm do mesmo cliente (o host do HA, ou
172.30.32.3 quando o AdGuard roda como add-on no próprio HA). Por isso NÃO é
possível saber qual add-on ou integração fez cada consulta.

Com os dois configurados, as consultas são somadas (cada domínio mostra em qual
servidor apareceu). Cada servidor tem o seu próprio cliente HTTP, que só fala com
o host da sua URL; credenciais nunca vão para outro lugar e são mascaradas nos logs.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import aiohttp

from ..config import DnsServer
from ..masking import shannon_entropy
from ..models import ComponentType, Finding, Severity
from ..net import EgressDeniedError, HttpError, SafeHttpClient
from .base import ScanContext

_LOGGER = logging.getLogger(__name__)

WINDOW = timedelta(hours=24)
MAX_PER_CLIENT = 20_000
PAGE = 500
HASSIO_DNS_IP = "172.30.32.3"
TOP_DOMAINS = 150

AVISO = (
    "Atenção: o DNS de todos os add-ons e integrações passa pelo Home Assistant, então o servidor DNS "
    "vê todas as consultas vindas do mesmo cliente. Não é possível saber qual add-on ou integração "
    "consultou cada domínio."
)

# Serviços usados para exfiltração, túneis reversos e hospedagem de payloads.
_SUSPICIOUS = re.compile(
    r"(^|\.)(pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|termbin\.com|ix\.io|transfer\.sh|"
    r"ngrok(-free)?\.(io|app|dev)|ngrok\.com|webhook\.site|requestbin\.\w+|pipedream\.net|"
    r"interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator\.net|serveo\.net|loca\.lt|"
    r"localtunnel\.me|anonfiles\.com|file\.io|[^.]+\.onion)$"
)
# Pools de mineração de criptomoedas (cryptojacking).
_MINING = re.compile(
    r"(^|\.)(minexmr\.com|nanopool\.org|2miners\.com|supportxmr\.com|moneroocean\.stream|f2pool\.com|"
    r"hashvault\.pro|herominers\.com|unmineable\.com|nicehash\.com|xmrpool\.eu|c3pool\.com|"
    r"ethermine\.org|miningpoolhub\.com|viabtc\.com|antpool\.com|kryptex\.network)$"
    r"|(^|\.)(xmr|monero|pool|stratum)[.-][^.]*(pool|mine|mining)"
)
# Domínios cujo uso de subdomínios aleatórios é normal (CDNs, nuvem, Nabu Casa).
_RANDOM_OK = re.compile(
    r"(^|\.)(amazonaws\.com|cloudfront\.net|akamai(edge|hd)?\.net|edgekey\.net|azureedge\.net|"
    r"azurewebsites\.net|windows\.net|googleusercontent\.com|googleapis\.com|gvt[12]\.com|"
    r"fastly\.net|cloudflare\.(com|net)|githubusercontent\.com|nabu\.casa|ui\.nabu\.casa|"
    r"tuya(us|eu|cn|in)?\.com|amazonalexa\.com|duckdns\.org|1e100\.net|apple\.com|icloud\.com)$"
)
_LOCAL = re.compile(r"(\.in-addr\.arpa|\.ip6\.arpa|\.local|\.lan|\.home\.arpa|\.internal|\.localdomain)$")
_SECOND_LEVEL = frozenset({"com", "co", "net", "org", "gov", "edu", "ac", "or", "ne"})


@dataclass
class DnsQuery:
    ts: datetime
    domain: str
    client: str
    blocked: bool
    server: str = ""


@dataclass
class DomainStats:
    domain: str
    count: int = 0
    blocked: int = 0
    first: datetime | None = None
    last: datetime | None = None
    new: bool = False
    servers: set[str] = field(default_factory=set)

    def add(self, q: DnsQuery) -> None:
        self.count += 1
        if q.server:
            self.servers.add(q.server)
        self.blocked += int(q.blocked)
        self.first = q.ts if self.first is None or q.ts < self.first else self.first
        self.last = q.ts if self.last is None or q.ts > self.last else self.last


class DnsProviderError(Exception):
    """Falha de configuração, credenciais ou resposta do servidor DNS (mensagem em português)."""


def normalize(domain: str) -> str | None:
    d = domain.strip().lower().rstrip(".")
    if not d or "." not in d or _LOCAL.search(d):
        return None
    return d


def base_domain(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def looks_random(domain: str) -> bool:
    """Rótulo longo e de alta entropia, típico de DGA ou de túnel por DNS."""
    if _RANDOM_OK.search(domain):
        return False
    labels = domain.split(".")[:-1]
    for label in labels:
        if len(label) >= 20 and shannon_entropy(label) >= 3.8 and re.search(r"\d", label) and re.search(r"[a-z]", label):
            return True
    return False


# --- Provedores ---------------------------------------------------------------------


_FRACTION = re.compile(r"(\.\d{6})\d+")


def _parse_rfc3339(value: str) -> datetime:
    """Datas do AdGuard têm nanossegundos; o Python aceita até microssegundos."""
    dt = datetime.fromisoformat(_FRACTION.sub(r"\1", value.replace("Z", "+00:00")))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


_ADGUARD_BLOCKED = frozenset(
    {"FilteredBlackList", "FilteredSafeBrowsing", "FilteredParental", "FilteredBlockedService"}
)


class AdGuardHome:
    def __init__(self, http: SafeHttpClient, base_url: str, username: str | None, password: str | None) -> None:
        self._http = http
        self._base = base_url.rstrip("/")
        token = base64.b64encode(f"{username}:{password or ''}".encode()).decode() if username else None
        self._headers = {"Authorization": f"Basic {token}"} if token else {}

    async def queries(self, client: str, since: datetime, limit: int = MAX_PER_CLIENT) -> list[DnsQuery]:
        out: list[DnsQuery] = []
        older_than = ""
        while len(out) < limit:
            params = {"limit": str(PAGE), "search": client}
            if older_than:
                params["older_than"] = older_than
            try:
                data = await self._http.get_json(f"{self._base}/control/querylog", headers=self._headers, params=params)
            except HttpError as err:
                if err.status in (401, 403):
                    raise DnsProviderError("o AdGuard Home recusou o usuário/senha") from err
                raise
            entries = data.get("data") or []
            for e in entries:
                ts = _parse_rfc3339(str(e.get("time")))
                if ts < since:
                    return out
                if str(e.get("client", "")) != client:
                    continue  # "search" também casa com o texto do domínio
                name = (e.get("question") or {}).get("name", "")
                out.append(DnsQuery(ts, str(name), client, str(e.get("reason", "")) in _ADGUARD_BLOCKED))
            older_than = str(data.get("oldest") or "")
            if not entries or not older_than:
                break
        return out

    async def close(self) -> None:
        return None


_PIHOLE_BLOCKED = frozenset({
    "GRAVITY", "GRAVITY_CNAME", "DENYLIST", "DENYLIST_CNAME", "REGEX", "REGEX_CNAME", "EXTERNAL_BLOCKED_IP",
    "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "EXTERNAL_BLOCKED_EDE15", "SPECIAL_DOMAIN",
})


class PiHole6:
    """API do Pi-hole v6 (/api). A sessão é encerrada ao final (logout)."""

    def __init__(self, http: SafeHttpClient, base_url: str, password: str | None) -> None:
        self._http = http
        self._base = base_url.rstrip("/")
        self._password = password or ""
        self._sid: str | None = None
        self._logged_in = False

    async def _login(self) -> None:
        if self._logged_in:
            return
        try:
            data = await self._http.post_json(f"{self._base}/api/auth", {"password": self._password})
        except HttpError as err:
            if err.status in (400, 401, 403):
                raise DnsProviderError("o Pi-hole recusou a senha (use a senha de app do Pi-hole v6)") from err
            if err.status == 404:
                raise DnsProviderError("API /api não encontrada: só o Pi-hole v6 é suportado") from err
            raise
        session = (data or {}).get("session") or {}
        if not session.get("valid"):
            raise DnsProviderError("o Pi-hole não abriu a sessão (senha incorreta?)")
        self._sid = session.get("sid")
        self._logged_in = True

    def _headers(self) -> dict[str, str]:
        return {"X-FTL-SID": self._sid} if self._sid else {}

    async def queries(self, client: str, since: datetime, limit: int = MAX_PER_CLIENT) -> list[DnsQuery]:
        await self._login()
        out: list[DnsQuery] = []
        start = 0
        cursor: str | None = None
        now = datetime.now(UTC)
        while len(out) < limit:
            params = {
                "from": str(int(since.timestamp())), "until": str(int(now.timestamp())),
                "length": str(PAGE), "start": str(start), "client_ip": client,
            }
            if cursor:
                params["cursor"] = cursor
            data = await self._http.get_json(f"{self._base}/api/queries", headers=self._headers(), params=params)
            items = data.get("queries") or []
            for q in items:
                ip = str((q.get("client") or {}).get("ip", ""))
                if ip != client:
                    continue
                out.append(DnsQuery(
                    datetime.fromtimestamp(float(q.get("time", 0)), UTC), str(q.get("domain", "")), ip,
                    str(q.get("status", "")) in _PIHOLE_BLOCKED,
                ))
            if len(items) < PAGE:
                break
            start += PAGE
            cursor = str(data["cursor"]) if data.get("cursor") is not None else cursor
        return out

    async def close(self) -> None:
        if self._sid:
            try:
                await self._http.delete(f"{self._base}/api/auth", headers=self._headers())
            except Exception:  # noqa: BLE001 - logout é cortesia; nunca falha a varredura
                _LOGGER.debug("Logout do Pi-hole falhou")
            self._sid = None


# --- Análise ------------------------------------------------------------------------


def aggregate(queries: Iterable[DnsQuery], known: set[str]) -> dict[str, DomainStats]:
    stats: dict[str, DomainStats] = {}
    for q in queries:
        d = normalize(q.domain)
        if d is None:
            continue
        s = stats.get(d)
        if s is None:
            s = stats[d] = DomainStats(d, new=bool(known) and d not in known)
        s.add(q)
    return stats


def analyze(stats: dict[str, DomainStats], first_run: bool) -> list[Finding]:
    findings: list[Finding] = []

    def finding(rule: str, sev: Severity, title: str, why: str, todo: str, snippet: str,
                category: str, key: str = "") -> None:
        findings.append(Finding(
            component="dns", component_type=ComponentType.NETWORK, category=category,
            rule_id=f"auditor.dns.{rule}", severity=sev, title=title,
            explanation=f"{why} {AVISO}", recommendation=todo, snippet=snippet, source="dns",
            extra={"fingerprint_key": key},
        ))

    def line(s: DomainStats) -> str:
        last = s.last.astimezone().strftime("%d/%m %H:%M") if s.last else "?"
        extra = f", {s.blocked} bloqueada(s)" if s.blocked else ""
        return f"{s.domain}: {s.count} consulta(s){extra}, última {last}"

    for s in sorted(stats.values(), key=lambda s: s.domain):
        if _SUSPICIOUS.search(s.domain):
            finding("destino-suspeito", Severity.HIGH, f"Consulta a serviço suspeito: {s.domain}",
                    "O host do HA consultou um serviço usado com frequência para exfiltração de dados, "
                    "túneis reversos ou hospedagem de payloads.",
                    "Procure esse domínio no código das integrações e add-ons (os achados de análise "
                    "estática ajudam) e nos logs; pare o componente responsável se não houver explicação.",
                    line(s), "destino_suspeito", s.domain)
        elif _MINING.search(s.domain):
            finding("mineracao", Severity.HIGH, f"Consulta a pool de mineração: {s.domain}",
                    "Contato com pool de mineração de criptomoedas é o sinal típico de cryptojacking: alguém "
                    "usando o processador da sua máquina para minerar.",
                    "Veja nas estatísticas qual add-on está com CPU alta e investigue-o.",
                    line(s), "mineracao", s.domain)

    random_like = sorted((s for s in stats.values() if looks_random(s.domain)), key=lambda s: -s.count)
    if random_like:
        finding("dominio-aleatorio", Severity.LOW, f"{len(random_like)} domínio(s) com aparência aleatória",
                "Nomes longos e sem sentido podem ser gerados por malware (DGA) ou usados para tunelar dados "
                "pelo DNS. Também podem ser de CDNs e serviços de nuvem não reconhecidos.",
                "Confira se os domínios pertencem a serviços que você usa.",
                "\n".join(line(s) for s in random_like[:15]), "dns_anormal",
                ",".join(sorted(s.domain for s in random_like))[:200])

    blocked = sorted((s for s in stats.values() if s.blocked), key=lambda s: -s.blocked)
    if blocked:
        finding("bloqueados", Severity.LOW, f"{len(blocked)} domínio(s) bloqueado(s) pelo seu filtro DNS",
                "O host do HA tentou acessar domínios que o seu AdGuard/Pi-hole bloqueia (anúncios, "
                "rastreadores ou listas de ameaças). Geralmente é telemetria de algum componente.",
                "Veja se algum domínio está em lista de ameaças (não só de anúncios).",
                "\n".join(line(s) for s in blocked[:20]), "dns_bloqueado",
                ",".join(sorted(s.domain for s in blocked))[:200])

    new = sorted((s for s in stats.values() if s.new), key=lambda s: -s.count)
    if new and not first_run:
        finding("novos", Severity.INFO, f"{len(new)} domínio(s) novo(s) desde a varredura anterior",
                "Domínios que o host do HA nunca tinha consultado. É normal depois de instalar ou atualizar "
                "algo; sem mudança na instalação, merece uma olhada.",
                "Confira se os domínios combinam com algo que você instalou ou atualizou.",
                "\n".join(line(s) for s in new[:30]), "dns_novo",
                ",".join(sorted(s.domain for s in new))[:200])
    return findings


# --- Scanner ------------------------------------------------------------------------


async def client_ips(ctx: ScanContext) -> list[str]:
    """IPs com que o HA aparece no servidor DNS: opção explícita ou IPs do host + hassio_dns."""
    if ctx.options.dns_client_ips:
        return list(dict.fromkeys(ctx.options.dns_client_ips))
    ips: list[str] = []
    if ctx.supervisor is not None:
        try:
            info = await ctx.supervisor.get("/network/info") or {}
            for iface in info.get("interfaces") or []:
                for fam in ("ipv4", "ipv6"):
                    for addr in (iface.get(fam) or {}).get("address") or []:
                        ip = ipaddress.ip_interface(str(addr)).ip
                        if not ip.is_link_local and not ip.is_loopback:
                            ips.append(str(ip))
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Não foi possível obter os IPs do host: %s", type(err).__name__)
    if ips:
        ips.append(HASSIO_DNS_IP)
    return list(dict.fromkeys(ips))


class DnsScanner:
    name = "dns"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        servers = ctx.options.dns_servers
        if not servers:
            return []
        findings: list[Finding] = []
        valid: list[tuple[DnsServer, str]] = []
        for srv in servers:
            if not srv.url:
                findings.append(_problem(f"{srv.label} sem URL", f"Configure a URL do {srv.label}.", srv))
                continue
            parts = urlsplit(srv.url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                findings.append(_problem(f"URL do {srv.label} inválida",
                                         f"'{parts.scheme}://…' não é http/https.", srv))
                continue
            valid.append((srv, parts.hostname.lower()))
            if parts.scheme == "http" and (srv.password or srv.username):
                findings.append(Finding(
                    component="dns", component_type=ComponentType.NETWORK, category="tls",
                    rule_id="auditor.dns.credenciais-sem-tls", severity=Severity.INFO,
                    title=f"Credenciais do {srv.label} enviadas sem criptografia",
                    explanation="A URL usa http://, então usuário e senha trafegam em texto na rede local.",
                    recommendation="Se o servidor oferecer HTTPS, use-o (ou dns_verify_tls: false para "
                                   "certificado próprio).",
                    source="dns", extra={"fingerprint_key": srv.kind},
                ))
        if not valid:
            return findings
        clients = await client_ips(ctx)
        if not clients:
            return [*findings, _problem("IPs do Home Assistant desconhecidos",
                                        "Não deu para descobrir os IPs do host; preencha dns_client_ips nas opções.")]

        since = datetime.now(UTC) - WINDOW
        queries: list[DnsQuery] = []
        per_server: dict[str, int] = {}
        for srv, host in valid:
            try:
                got = await self._fetch(ctx, srv, host, clients, since)
            except DnsProviderError as err:
                findings.append(_problem(f"Consulta ao {srv.label} falhou", str(err), srv))
                continue
            except (HttpError, EgressDeniedError, aiohttp.ClientError, TimeoutError, ValueError) as err:
                findings.append(_problem(f"Consulta ao {srv.label} falhou", f"{type(err).__name__}: {err}", srv))
                continue
            for q in got:
                q.server = srv.label
            queries.extend(got)
            per_server[srv.label] = len(got)
        if not per_server:
            return findings

        known = await _known(ctx)
        stats = aggregate(queries, known)
        findings.extend(analyze(stats, first_run=not known))
        await _remember(ctx, stats)
        top = sorted(stats.values(), key=lambda s: (-s.count, s.domain))[:TOP_DOMAINS]
        names = list(per_server)
        trafego = f"{len(queries)} consultas, {len(stats)} domínios nas últimas 24 h"
        if len(names) > 1:
            trafego += " (" + ", ".join(f"{n}: {c}" for n, c in per_server.items()) + ")"
        ctx.register_component(
            ComponentType.NETWORK, "dns",
            nome=f"Domínios consultados ({' + '.join(names)})",
            trafego=trafego,
            clientes=clients,
            servidores=names,
            aviso=AVISO,
            dominios=[
                {"dominio": s.domain, "consultas": s.count, "bloqueadas": s.blocked, "novo": s.new,
                 "servidores": sorted(s.servers),
                 "ultima": s.last.isoformat(timespec="seconds") if s.last else None}
                for s in top
            ],
            dominios_total=len(stats),
        )
        return findings

    async def _fetch(self, ctx: ScanContext, srv: DnsServer, host: str, clients: list[str],
                     since: datetime) -> list[DnsQuery]:
        # Um cliente HTTP por servidor: a senha de um nunca pode ir para o outro.
        http = SafeHttpClient(
            allowed_hosts=frozenset({host}),
            allow_http=True,
            verify_tls=ctx.options.dns_verify_tls,
            timeout=30,
        )
        provider = (
            AdGuardHome(http, srv.url or "", srv.username, srv.password)
            if srv.kind == "adguard"
            else PiHole6(http, srv.url or "", srv.password)
        )
        out: list[DnsQuery] = []
        try:
            for ip in clients:
                ctx.set_progress(self.name, f"{srv.label}: consultas de {ip}")
                out.extend(await provider.queries(ip, since))
        finally:
            await provider.close()
            await http.close()
        return out


async def _known(ctx: ScanContext) -> set[str]:
    return await asyncio.to_thread(ctx.storage.known_dns_domains)


async def _remember(ctx: ScanContext, stats: dict[str, DomainStats]) -> None:
    rows = [(s.domain, s.first.isoformat(timespec="seconds") if s.first else None,
             s.last.isoformat(timespec="seconds") if s.last else None, s.count) for s in stats.values()]
    await asyncio.to_thread(ctx.storage.upsert_dns_domains, rows)


def _problem(title: str, detail: str, srv: DnsServer | None = None) -> Finding:
    where = f"as consultas do {srv.label} ficaram de fora" if srv else "a etapa de DNS (Fase 3) não roda"
    opts = f"as opções {srv.kind}_* do add-on" if srv else "as opções de DNS do add-on"
    return Finding(
        component="dns", component_type=ComponentType.NETWORK, category="configuracao",
        rule_id="auditor.dns.falha", severity=Severity.LOW, title=title,
        explanation=f"{detail} Sem isso {where}.",
        recommendation=f"Revise {opts}.", source="dns",
        extra={"fingerprint_key": title},
    )
