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
import fnmatch
import ipaddress
import itertools
import logging
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from ..config import DnsServer
from ..i18n import Bi, english
from ..masking import shannon_entropy
from ..models import ComponentType, Finding, Severity, en_text
from ..net import EgressDeniedError, HttpError, SafeHttpClient
from .base import ScanContext

_LOGGER = logging.getLogger(__name__)

WINDOW = timedelta(hours=24)
MAX_PER_CLIENT = 20_000
PAGE = 500
HASSIO_DNS_IP = "172.30.32.3"
TOP_DOMAINS = 150
_PATTERN = re.compile(r"^[a-z0-9*?._-]+$")

AVISO = (
    "Atenção: o DNS de todos os add-ons e integrações passa pelo Home Assistant, então o servidor DNS "
    "vê todas as consultas vindas do mesmo cliente. Não é possível saber qual add-on ou integração "
    "consultou cada domínio."
)

AVISO_EN = (
    "Note: DNS for every add-on and integration goes through Home Assistant, so the DNS server sees all queries "
    "coming from the same client. It is not possible to tell which add-on or integration queried each domain."
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
    qtype: str = ""  # A, AAAA, TXT... (vazio se o servidor não informar)


@dataclass
class DomainStats:
    domain: str
    count: int = 0
    blocked: int = 0
    first: datetime | None = None
    last: datetime | None = None
    new: bool = False
    servers: set[str] = field(default_factory=set)
    types: dict[str, int] = field(default_factory=dict)
    times: list[float] = field(default_factory=list)  # para achar consultas em intervalo regular

    def add(self, q: DnsQuery) -> None:
        self.count += 1
        if q.qtype:
            self.types[q.qtype] = self.types.get(q.qtype, 0) + 1
        self.times.append(q.ts.timestamp())
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
                    raise DnsProviderError(Bi("o AdGuard Home recusou o usuário/senha", "AdGuard Home rejected the username/password")) from err
                raise
            entries = data.get("data") or []
            for e in entries:
                ts = _parse_rfc3339(str(e.get("time")))
                if ts < since:
                    return out
                if str(e.get("client", "")) != client:
                    continue  # "search" também casa com o texto do domínio
                question = e.get("question") or {}
                out.append(DnsQuery(ts, str(question.get("name", "")), client,
                                    str(e.get("reason", "")) in _ADGUARD_BLOCKED,
                                    qtype=str(question.get("type") or "").upper()))
            older_than = str(data.get("oldest") or "")
            if not entries or not older_than:
                break
        return out

    async def check(self) -> str | None:
        """Teste de conexão: autentica e lê o status. Devolve a versão do AdGuard Home."""
        try:
            data = await self._http.get_json(f"{self._base}/control/status", headers=self._headers)
        except HttpError as err:
            if err.status in (401, 403):
                raise DnsProviderError(Bi("o AdGuard Home recusou o usuário/senha", "AdGuard Home rejected the username/password")) from err
            if err.status == 404:
                raise DnsProviderError(Bi("API /control não encontrada: confira se a URL é do AdGuard Home",
                                          "/control API not found: check that the URL is AdGuard Home's")) from err
            raise
        return str((data or {}).get("version") or "") or None

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
                raise DnsProviderError(Bi("o Pi-hole recusou a senha (use a senha de app do Pi-hole v6)",
                                          "Pi-hole rejected the password (use a Pi-hole v6 app password)")) from err
            if err.status == 404:
                raise DnsProviderError(Bi("API /api não encontrada: só o Pi-hole v6 é suportado",
                                          "/api not found: only Pi-hole v6 is supported")) from err
            raise
        session = (data or {}).get("session") or {}
        if not session.get("valid"):
            raise DnsProviderError(Bi("o Pi-hole não abriu a sessão (senha incorreta?)",
                                      "Pi-hole did not open the session (wrong password?)"))
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
                    str(q.get("status", "")) in _PIHOLE_BLOCKED, qtype=str(q.get("type") or "").upper(),
                ))
            if len(items) < PAGE:
                break
            start += PAGE
            cursor = str(data["cursor"]) if data.get("cursor") is not None else cursor
        return out

    async def check(self) -> str | None:
        """Teste de conexão: abre a sessão (senha) e tenta ler a versão do Pi-hole."""
        await self._login()
        try:
            data = await self._http.get_json(f"{self._base}/api/info/version", headers=self._headers())
        except (HttpError, aiohttp.ClientError, ValueError):
            return None  # a versão é só informativa; o login já provou a conexão
        core = (((data or {}).get("version") or {}).get("core") or {}).get("local") or {}
        return str(core.get("version") or "") or None

    async def close(self) -> None:
        if self._sid:
            try:
                await self._http.delete(f"{self._base}/api/auth", headers=self._headers())
            except Exception:  # noqa: BLE001 - logout é cortesia; nunca falha a varredura
                _LOGGER.debug("Logout do Pi-hole falhou")
            self._sid = None


# --- Teste de conexão (na inicialização e pelo botão "Testar conexão") -------------------

CHECK_TIMEOUT = 10


async def check_server(srv: DnsServer, verify_tls: bool = True) -> dict[str, Any]:
    """Testa a conexão e o login num servidor DNS. Nunca levanta exceção; nada de senha no resultado."""
    started = time.monotonic()
    out: dict[str, Any] = {
        "servidor": srv.label, "tipo": srv.kind, "endereco": None, "ok": False, "mensagem": "", "versao": None,
        "verificado_em": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    parts = urlsplit(srv.url or "")
    if not srv.url:
        out["mensagem"] = "URL não configurada"
        out["mensagem_en"] = "URL not configured"
        return out
    if parts.scheme not in ("http", "https") or not parts.hostname:
        out["mensagem"] = "URL inválida (use http:// ou https://)"
        out["mensagem_en"] = "invalid URL (use http:// or https://)"
        return out
    out["endereco"] = parts.hostname + (f":{parts.port}" if parts.port else "")
    http = SafeHttpClient(allowed_hosts=frozenset({parts.hostname.lower()}), allow_http=True,
                          verify_tls=verify_tls, timeout=CHECK_TIMEOUT)
    provider = (AdGuardHome(http, srv.url, srv.username, srv.password) if srv.kind == "adguard"
                else PiHole6(http, srv.url, srv.password))
    try:
        out["versao"] = await provider.check()
        out["ok"] = True
        out["mensagem"] = "conectado"
        out["mensagem_en"] = "connected"
    except DnsProviderError as err:
        out["mensagem"] = str(err)
        out["mensagem_en"] = english(err.args[0] if err.args else err)
    except HttpError as err:
        out["mensagem"] = f"o servidor respondeu HTTP {err.status}"
        out["mensagem_en"] = f"the server answered HTTP {err.status}"
    except EgressDeniedError as err:
        out["mensagem"] = f"bloqueado pelo filtro de saída ({err})"
        out["mensagem_en"] = f"blocked by the outbound filter ({err})"
    except (aiohttp.ClientConnectorCertificateError, aiohttp.ClientSSLError):
        out["mensagem"] = "certificado TLS inválido (para certificado próprio, desative dns_verify_tls)"
        out["mensagem_en"] = "invalid TLS certificate (for a self-signed certificate, turn off dns_verify_tls)"
    except aiohttp.ClientConnectorError:
        out["mensagem"] = "não foi possível conectar (confira endereço e porta)"
        out["mensagem_en"] = "could not connect (check address and port)"
    except TimeoutError:
        out["mensagem"] = f"sem resposta em {CHECK_TIMEOUT} s"
        out["mensagem_en"] = f"no answer within {CHECK_TIMEOUT} s"
    except (aiohttp.ClientError, ValueError) as err:
        out["mensagem"] = f"erro de conexão ({type(err).__name__})"
        out["mensagem_en"] = f"connection error ({type(err).__name__})"
    finally:
        await provider.close()
        await http.close()
        out["ms"] = int((time.monotonic() - started) * 1000)
    return out


async def check_servers(servers: tuple[DnsServer, ...], verify_tls: bool = True) -> list[dict[str, Any]]:
    """Testa todos os servidores em paralelo e registra o resultado no log."""
    results = list(await asyncio.gather(*(check_server(s, verify_tls) for s in servers)))
    for r in results:
        where = f"{r['servidor']} ({r['endereco'] or 'sem URL'})"
        if r["ok"]:
            _LOGGER.info("DNS %s: conexão OK%s (%d ms)", where,
                         f", versão {r['versao']}" if r["versao"] else "", r.get("ms", 0))
        else:
            _LOGGER.warning("DNS %s: falha na conexão: %s (%d ms)", where, r["mensagem"], r.get("ms", 0))
    ok = sum(1 for r in results if r["ok"])
    _LOGGER.info("Teste de conexão DNS concluído: %d de %d servidor(es) OK", ok, len(results))
    return results


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


def ignore_pattern(text: str) -> str:
    """Valida e normaliza um padrão da lista de domínios ignorados (ex.: ``*.amazonaws.com``)."""
    pattern = (text or "").strip().lower().rstrip(".")
    if not pattern or len(pattern) > 253 or not _PATTERN.match(pattern):
        raise ValueError(Bi("Domínio inválido: use letras, números, ponto, hífen e os curingas * e ?",
                            "Invalid domain: use letters, digits, dots, hyphens and the * and ? wildcards"))
    if not re.search(r"[a-z0-9]", pattern) or ".." in pattern:
        raise ValueError(Bi("O padrão precisa de pelo menos um nome de domínio (só curingas ignoraria tudo)",
                            "The pattern needs at least one domain name (wildcards alone would ignore everything)"))
    return pattern


def is_ignored(domain: str, patterns: Iterable[str]) -> bool:
    """``*.exemplo.com`` vale para exemplo.com e para todos os subdomínios."""
    for p in patterns:
        if fnmatch.fnmatchcase(domain, p) or (p.startswith("*.") and domain == p[2:]):
            return True
    return False


# --- Contexto extra: listas de ameaças, quem usa cada domínio e mudanças recentes ----------

TUNNEL_MIN_NAMES = 50  # nomes diferentes sob o mesmo domínio em 24 h
TXT_MIN = 20  # consultas TXT ao mesmo domínio em 24 h
BEACON_MIN_INTERVALS = 10
BEACON_TOLERANCE = 0.10  # intervalo dentro de ±10% da mediana
BEACON_SHARE = 0.8  # fração dos intervalos que precisa ser regular
BEACON_RANGE = (30.0, 7200.0)  # segundos
BEACON_RECENT = timedelta(days=7)  # só domínios vistos pela primeira vez há menos que isto
CHANGE_BEFORE = timedelta(minutes=10)
CHANGE_AFTER = timedelta(minutes=60)


@dataclass
class DnsIntel:
    """O que se sabe além das consultas (tudo local ou baixado; nada da casa sai do add-on)."""

    threats: dict[str, str] = field(default_factory=dict)  # domínio -> entrada da lista de ameaças
    encrypted_dns: dict[str, str] = field(default_factory=dict)  # domínio -> entrada da lista de DNS cifrado
    users: Any = None  # função domínio -> {componente: arquivo} (domínios citados no código)
    changes: list[tuple[datetime, str, str]] = field(default_factory=list)  # (quando, nome, mudança)
    first_seen: dict[str, str | None] = field(default_factory=dict)

    def who(self, domain: str) -> dict[str, str]:
        return self.users(domain) if self.users else {}

    def first(self, s: DomainStats) -> datetime | None:
        raw = self.first_seen.get(s.domain)
        try:
            return datetime.fromisoformat(raw) if raw else s.first
        except ValueError:
            return s.first

    def change_before(self, s: DomainStats) -> tuple[datetime, str, str] | None:
        """A instalação/atualização logo antes da primeira consulta ao domínio (se houver)."""
        first = self.first(s)
        if first is None:
            return None
        near = [c for c in self.changes if c[0] - CHANGE_BEFORE <= first <= c[0] + CHANGE_AFTER]
        return min(near, key=lambda c: abs((first - c[0]).total_seconds())) if near else None


_CHANGE_PT = {"novo": "instalado", "atualizado": "atualizado", "removido": "removido"}
_CHANGE_EN = {"novo": "installed", "atualizado": "updated", "removido": "removed"}


def attribution(s: DomainStats, intel: DnsIntel) -> tuple[list[str], list[str]]:
    """Linhas "citado no código de…" e "apareceu depois de…", em português e inglês."""
    pt: list[str] = []
    en: list[str] = []
    users = intel.who(s.domain)
    if users:
        listed = ", ".join(f"{c.split('/', 1)[-1]} ({f})" for c, f in sorted(users.items())[:3])
        more = f" e mais {len(users) - 3}" if len(users) > 3 else ""
        more_en = f" and {len(users) - 3} more" if len(users) > 3 else ""
        pt.append(f"  citado no código de: {listed}{more}")
        en.append(f"  mentioned in the code of: {listed}{more_en}")
    change = intel.change_before(s)
    first = intel.first(s)
    if change and first:
        minutes = int((first - change[0]).total_seconds() // 60)
        when_pt = f"{minutes} min depois" if minutes >= 0 else f"{-minutes} min antes"
        when_en = f"{minutes} min after" if minutes >= 0 else f"{-minutes} min before"
        pt.append(f"  primeira consulta {when_pt} de: {change[1]} ({_CHANGE_PT.get(change[2], change[2])})")
        en.append(f"  first queried {when_en}: {change[1]} ({_CHANGE_EN.get(change[2], change[2])})")
    return pt, en


def _regular_interval(times: list[float]) -> float | None:
    """Mediana do intervalo entre consultas, se elas acontecem em ritmo regular; senão None."""
    moments: list[float] = []
    for t in sorted(times):
        if not moments or t - moments[-1] > 2.0:  # A e AAAA juntos contam como uma consulta
            moments.append(t)
    gaps = [b - a for a, b in itertools.pairwise(moments)]
    if len(gaps) < BEACON_MIN_INTERVALS:
        return None
    median = sorted(gaps)[len(gaps) // 2]
    if not BEACON_RANGE[0] <= median <= BEACON_RANGE[1]:
        return None
    regular = sum(1 for g in gaps if abs(g - median) <= BEACON_TOLERANCE * median)
    return median if regular / len(gaps) >= BEACON_SHARE else None


def analyze(stats: dict[str, DomainStats], first_run: bool, intel: DnsIntel | None = None) -> list[Finding]:
    findings: list[Finding] = []
    intel = intel or DnsIntel()

    def finding(rule: str, sev: Severity, title: str, why: str, todo: str, snippet: str,
                category: str, key: str = "", en: tuple[str, str, str] = ("", "", ""),
                snippet_en: str | None = None) -> None:
        findings.append(Finding(
            component="dns", component_type=ComponentType.NETWORK, category=category,
            rule_id=f"auditor.dns.{rule}", severity=sev, title=title,
            explanation=f"{why} {AVISO}", recommendation=todo, snippet=snippet, source="dns",
            en=en_text(en[0], f"{en[1]} {AVISO_EN}", en[2], snippet_en),
            # O trecho traz contagens e horários, que mudam a cada rodada: a identidade é só a chave.
            extra={"fingerprint_key": key, "chave_estavel": True},
        ))

    def line(s: DomainStats) -> str:
        last = s.last.astimezone().strftime("%d/%m %H:%M") if s.last else "?"
        extra = f", {s.blocked} bloqueada(s)" if s.blocked else ""
        return f"{s.domain}: {s.count} consulta(s){extra}, última {last}"

    def line_en(s: DomainStats) -> str:
        last = s.last.astimezone().strftime("%m-%d %H:%M") if s.last else "?"
        extra = f", {s.blocked} blocked" if s.blocked else ""
        return f"{s.domain}: {s.count} query(ies){extra}, last {last}"

    def detail(s: DomainStats, *extra: str) -> tuple[str, str]:
        """Linha do domínio + linhas extras + quem usa (português, inglês)."""
        who_pt, who_en = attribution(s, intel)
        pt = [line(s), *[e for e in extra[0::2]], *who_pt]
        en = [line_en(s), *[e for e in extra[1::2]], *who_en]
        return "\n".join(pt), "\n".join(en)

    for s in sorted(stats.values(), key=lambda s: s.domain):
        if _SUSPICIOUS.search(s.domain):
            finding("destino-suspeito", Severity.HIGH, f"Consulta a serviço suspeito: {s.domain}",
                    "O host do HA consultou um serviço usado com frequência para exfiltração de dados, "
                    "túneis reversos ou hospedagem de payloads.",
                    "Procure esse domínio no código das integrações e add-ons (os achados de análise "
                    "estática ajudam) e nos logs; pare o componente responsável se não houver explicação.",
                    detail(s)[0], "destino_suspeito", s.domain,
                    (f"Query to a suspicious service: {s.domain}",
                     ("The HA host queried a service often used for data exfiltration, reverse tunnels or hosting "
                     "payloads."),
                     ("Search for this domain in the integrations' and add-ons' code (the static analysis findings "
                     "help) and in the logs; stop the responsible component if there is no explanation.")),
                    detail(s)[1])
        elif _MINING.search(s.domain):
            finding("mineracao", Severity.HIGH, f"Consulta a pool de mineração: {s.domain}",
                    "Contato com pool de mineração de criptomoedas é o sinal típico de cryptojacking: alguém "
                    "usando o processador da sua máquina para minerar.",
                    "Veja nas estatísticas qual add-on está com CPU alta e investigue-o.",
                    detail(s)[0], "mineracao", s.domain,
                    (f"Query to a mining pool: {s.domain}",
                     ("Contact with a cryptocurrency mining pool is the typical sign of cryptojacking: someone using "
                     "your machine's processor to mine."),
                     "Check in the statistics which add-on has high CPU and investigate it."),
                    detail(s)[1])
        elif s.domain in intel.threats:
            entry = intel.threats[s.domain]
            only_blocked = s.blocked >= s.count
            listed_pt = f"na lista de ameaças do HaGeZi como {entry}"
            listed_en = f"on HaGeZi's threat list as {entry}"
            pt, en = detail(s, f"  {listed_pt}", f"  {listed_en}")
            finding("lista-ameacas", Severity.MEDIUM if only_blocked else Severity.HIGH,
                    f"Domínio em lista de ameaças: {s.domain}",
                    "O domínio está na lista de ameaças do HaGeZi (malware, phishing, comando e controle, golpes)."
                    + (" Todas as consultas foram bloqueadas pelo seu filtro, mas algo na instalação tentou "
                       "acessá-lo." if only_blocked else ""),
                    "Veja quem cita o domínio no código (abaixo, quando dá para saber) e investigue esse componente. "
                    "Sem explicação, pare-o e bloqueie o domínio no AdGuard/Pi-hole.",
                    pt, "lista_ameacas", s.domain,
                    (f"Domain on a threat list: {s.domain}",
                     "The domain is on HaGeZi's threat list (malware, phishing, command and control, scams)."
                     + (" Every query was blocked by your filter, but something in the installation tried to reach "
                        "it." if only_blocked else ""),
                     ("Check who mentions the domain in the code (below, when it can be told) and investigate that "
                     "component. Without an explanation, stop it and block the domain in AdGuard/Pi-hole.")),
                    en)
        if s.domain in intel.encrypted_dns:
            pt, en = detail(s)
            finding("dns-cifrado", Severity.MEDIUM, f"Consulta a servidor de DNS cifrado: {s.domain}",
                    "O host do HA procurou um servidor de DNS cifrado (DNS-over-HTTPS/TLS). Quem usa um desses "
                    "resolve nomes por fora do seu AdGuard/Pi-hole, e as consultas seguintes não aparecem nem são "
                    "filtradas. Navegadores (como o add-on Chromium) e algumas integrações fazem isso por conta "
                    "própria; código malicioso também.",
                    "Veja quem cita o domínio no código. Se for esperado, ignore o domínio; senão, bloqueie-o no "
                    "AdGuard/Pi-hole e bloqueie a porta 853 no roteador.",
                    pt, "dns_cifrado", s.domain,
                    (f"Query to an encrypted DNS server: {s.domain}",
                     ("The HA host looked up an encrypted DNS server (DNS-over-HTTPS/TLS). Whoever uses one resolves "
                     "names outside your AdGuard/Pi-hole, and the following queries are neither shown nor filtered. "
                     "Browsers (like the Chromium add-on) and some integrations do it on their own; so does "
                     "malicious code."),
                     ("Check who mentions the domain in the code. If it is expected, ignore the domain; otherwise "
                     "block it in AdGuard/Pi-hole and block port 853 on the router.")),
                    en)

    random_like = sorted((s for s in stats.values() if looks_random(s.domain)), key=lambda s: -s.count)
    if random_like:
        finding("dominio-aleatorio", Severity.LOW, f"{len(random_like)} domínio(s) com aparência aleatória",
                "Nomes longos e sem sentido podem ser gerados por malware (DGA) ou usados para tunelar dados "
                "pelo DNS. Também podem ser de CDNs e serviços de nuvem não reconhecidos.",
                "Confira se os domínios pertencem a serviços que você usa.",
                "\n".join(line(s) for s in random_like[:15]), "dns_anormal",
                ",".join(sorted(s.domain for s in random_like))[:200],
                (f"{len(random_like)} random-looking domain(s)",
                 ("Long, meaningless names can be generated by malware (DGA) or used to tunnel data over DNS. They "
                 "can also belong to unrecognised CDNs and cloud services."),
                 "Check that the domains belong to services you use."),
                "\n".join(line_en(s) for s in random_like[:15]))

    blocked = sorted((s for s in stats.values() if s.blocked), key=lambda s: -s.blocked)
    if blocked:
        finding("bloqueados", Severity.LOW, f"{len(blocked)} domínio(s) bloqueado(s) pelo seu filtro DNS",
                "O host do HA tentou acessar domínios que o seu AdGuard/Pi-hole bloqueia (anúncios, "
                "rastreadores ou listas de ameaças). Geralmente é telemetria de algum componente.",
                "Veja se algum domínio está em lista de ameaças (não só de anúncios).",
                "\n".join(line(s) for s in blocked[:20]), "dns_bloqueado",
                ",".join(sorted(s.domain for s in blocked))[:200],
                (f"{len(blocked)} domain(s) blocked by your DNS filter",
                 ("The HA host tried to reach domains your AdGuard/Pi-hole blocks (ads, trackers or threat lists). "
                 "It is usually some component's telemetry."),
                 "Check whether any domain is on a threat list (not just an ad list)."),
                "\n".join(line_en(s) for s in blocked[:20]))

    # Túnel por DNS: muitos nomes diferentes sob o mesmo domínio (cada nome carrega um pedaço de dado).
    by_base: dict[str, list[DomainStats]] = {}
    for s in stats.values():
        if not _RANDOM_OK.search(s.domain):
            by_base.setdefault(base_domain(s.domain), []).append(s)
    for base, items in sorted(by_base.items()):
        txt = sum(s.types.get("TXT", 0) for s in items)
        if len(items) < TUNNEL_MIN_NAMES and txt < TXT_MIN:
            continue
        first_labels = [s.domain[: -len(base) - 1].split(".")[0] for s in items if s.domain != base]
        avg = sum(map(len, first_labels)) / len(first_labels) if first_labels else 0
        tunnel = len(items) >= TUNNEL_MIN_NAMES
        sev = Severity.MEDIUM if (tunnel and (avg >= 20 or txt >= TXT_MIN)) else Severity.LOW
        sample = sorted(items, key=lambda s: -s.count)[:8]
        users = intel.who(base)
        who_pt = f"\n  citado no código de: {', '.join(c.split('/', 1)[-1] for c in sorted(users)[:3])}" if users else ""
        who_en = f"\n  mentioned in the code of: {', '.join(c.split('/', 1)[-1] for c in sorted(users)[:3])}" if users else ""
        head_pt = f"{len(items)} nome(s) diferente(s) sob {base}, {txt} consulta(s) TXT, tamanho médio do 1º rótulo {avg:.0f}"
        head_en = f"{len(items)} different name(s) under {base}, {txt} TXT query(ies), average first label length {avg:.0f}"
        finding("tunel", sev,
                f"Muitos nomes ou consultas TXT sob {base}" if tunnel else f"Muitas consultas TXT a {base}",
                "Túneis e exfiltração por DNS escondem dados nos nomes consultados (cada nome diferente leva um "
                "pedaço) ou nas respostas TXT. Serviços legítimos com muitos subdomínios (CDNs, nuvens de "
                "fabricantes) também geram esse padrão.",
                "Veja se o domínio é de um serviço que você usa. Nomes longos e aleatórios sob um domínio "
                "desconhecido merecem investigação.",
                head_pt + who_pt + "\n" + "\n".join(line(s) for s in sample), "dns_tunel", base,
                (f"Many names or TXT queries under {base}" if tunnel else f"Many TXT queries to {base}",
                 ("DNS tunnels and exfiltration hide data in the queried names (each different name carries a "
                 "piece) or in TXT answers. Legitimate services with many subdomains (CDNs, vendor clouds) also "
                 "produce this pattern."),
                 ("Check whether the domain belongs to a service you use. Long random names under an unknown domain "
                 "deserve investigation.")),
                head_en + who_en + "\n" + "\n".join(line_en(s) for s in sample))

    # "Batimento cardíaco": domínio recente, sem dono conhecido, consultado em ritmo regular.
    recent_cut = datetime.now(UTC) - BEACON_RECENT
    beacons = []
    for s in stats.values():
        first = intel.first(s)
        if (s.count < BEACON_MIN_INTERVALS or s.blocked >= s.count or _RANDOM_OK.search(s.domain)
                or first is None or first < recent_cut or intel.who(s.domain)):
            continue
        if (interval := _regular_interval(s.times)) is not None:
            beacons.append((s, interval))
    if beacons:
        beacons.sort(key=lambda b: -b[0].count)
        finding("batimento", Severity.LOW, f"{len(beacons)} domínio(s) novo(s) consultado(s) em ritmo regular",
                "Domínios vistos pela primeira vez nos últimos 7 dias, que nenhum componente cita no código, "
                "consultados em intervalos quase iguais. É o padrão de um programa \"chamando\" um servidor de "
                "comando, mas também de integrações oficiais do HA consultando uma nuvem (o cache do DNS deixa "
                "qualquer consulta periódica regular).",
                "Confira se os domínios combinam com algo que você usa. Os desconhecidos merecem a pergunta à IA.",
                "\n".join(f"{s.domain}: a cada ~{iv:.0f} s ({s.count} consultas)" for s, iv in beacons[:20]),
                "dns_batimento", ",".join(sorted(s.domain for s, _ in beacons))[:200],
                (f"{len(beacons)} new domain(s) queried at a regular pace",
                 ("Domains first seen in the last 7 days, not mentioned in any component's code, queried at almost "
                 "equal intervals. It is the pattern of a program \"calling\" a command server, but also of "
                 "official HA integrations polling a cloud (DNS caching makes any periodic query regular)."),
                 "Check whether the domains match something you use. Unknown ones deserve the AI question."),
                "\n".join(f"{s.domain}: every ~{iv:.0f} s ({s.count} queries)" for s, iv in beacons[:20]))

    new = sorted((s for s in stats.values() if s.new), key=lambda s: -s.count)
    if new and not first_run:
        finding("novos", Severity.INFO, f"{len(new)} domínio(s) novo(s) desde a varredura anterior",
                "Domínios que o host do HA nunca tinha consultado. É normal depois de instalar ou atualizar "
                "algo; sem mudança na instalação, merece uma olhada.",
                "Confira se os domínios combinam com algo que você instalou ou atualizou.",
                "\n".join(detail(s)[0] for s in new[:30]), "dns_novo",
                ",".join(sorted(s.domain for s in new))[:200],
                (f"{len(new)} new domain(s) since the previous scan",
                 ("Domains the HA host had never queried before. This is normal after installing or updating "
                 "something; without a change in the installation, it deserves a look."),
                 "Check that the domains match something you installed or updated."),
                "\n".join(detail(s)[1] for s in new[:30]))
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
        if not ctx.wants(ComponentType.NETWORK, "dns"):
            return []  # varredura de instalação: o DNS fica para a completa ou para a verificação de DNS
        if not servers or ctx.skipped(ComponentType.NETWORK, "dns", nome="Domínios consultados"):
            return []
        findings: list[Finding] = []
        valid: list[tuple[DnsServer, str]] = []
        for srv in servers:
            if not srv.url:
                findings.append(_problem(f"{srv.label} sem URL", f"Configure a URL do {srv.label}.", srv,
                                         f"{srv.label} without a URL", f"Set the {srv.label} URL."))
                continue
            parts = urlsplit(srv.url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                findings.append(_problem(f"URL do {srv.label} inválida",
                                         f"'{parts.scheme}://…' não é http/https.", srv,
                                         f"Invalid {srv.label} URL", f"'{parts.scheme}://…' is not http/https."))
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
                    en=en_text(f"{srv.label} credentials sent unencrypted",
                               "The URL uses http://, so the username and password travel as plain text on the "
                               "local network.",
                               "If the server offers HTTPS, use it (or dns_verify_tls: false for a self-signed "
                               "certificate)."),
                    source="dns", extra={"fingerprint_key": srv.kind},
                ))
        if not valid:
            return findings
        clients = await client_ips(ctx)
        if not clients:
            return [*findings, _problem("IPs do Home Assistant desconhecidos",
                                        "Não deu para descobrir os IPs do host; preencha dns_client_ips nas opções.",
                                        None, "Home Assistant IPs unknown",
                                        "The host IPs could not be discovered; fill in dns_client_ips in the options.")]

        since = datetime.now(UTC) - WINDOW
        queries: list[DnsQuery] = []
        per_server: dict[str, int] = {}
        for srv, host in valid:
            try:
                got = await self._fetch(ctx, srv, host, clients, since)
            except DnsProviderError as err:
                findings.append(_problem(f"Consulta ao {srv.label} falhou", str(err), srv,
                                         f"Query to {srv.label} failed", english(err.args[0] if err.args else err)))
                continue
            except (HttpError, EgressDeniedError, aiohttp.ClientError, TimeoutError, ValueError) as err:
                findings.append(_problem(f"Consulta ao {srv.label} falhou", f"{type(err).__name__}: {err}", srv,
                                         f"Query to {srv.label} failed", f"{type(err).__name__}: {err}"))
                continue
            for q in got:
                q.server = srv.label
            queries.extend(got)
            per_server[srv.label] = len(got)
        if not per_server:
            return findings

        seen = await asyncio.to_thread(ctx.storage.dns_first_seen)
        known = set(seen)
        stats = aggregate(queries, known)
        patterns = await asyncio.to_thread(ctx.storage.dns_ignored_patterns)
        active = {d: s for d, s in stats.items() if not is_ignored(d, patterns)}
        if len(active) < len(stats):
            _LOGGER.info("DNS: %d domínio(s) fora dos achados pela lista de domínios ignorados",
                         len(stats) - len(active))
        intel = await self._intel(ctx, stats, seen)
        findings.extend(analyze(active, first_run=not known, intel=intel))
        await _remember(ctx, stats)

        def discovered(s: DomainStats) -> str:
            return seen.get(s.domain) or (s.first.isoformat(timespec="seconds") if s.first else "")

        # Mais novos no topo (data da primeira consulta); empate: os mais consultados.
        top = sorted(stats.values(), key=lambda s: (-s.count, s.domain))
        top.sort(key=discovered, reverse=True)
        top = top[:TOP_DOMAINS]
        names = list(per_server)
        trafego = f"{len(queries)} consultas, {len(stats)} domínios nas últimas 24 h"
        trafego_en = f"{len(queries)} queries, {len(stats)} domains in the last 24 h"
        if len(names) > 1:
            per = " (" + ", ".join(f"{n}: {c}" for n, c in per_server.items()) + ")"
            trafego += per
            trafego_en += per
        ctx.register_component(
            ComponentType.NETWORK, "dns",
            nome=f"Domínios consultados ({' + '.join(names)})",
            nome_en=f"Queried domains ({' + '.join(names)})",
            trafego=trafego,
            trafego_en=trafego_en,
            aviso_en=AVISO_EN,
            clientes=clients,
            servidores=names,
            aviso=AVISO,
            dominios=[
                {"dominio": s.domain, "consultas": s.count, "bloqueadas": s.blocked, "novo": s.new,
                 "servidores": sorted(s.servers), "descoberto": discovered(s) or None,
                 "ultima": s.last.isoformat(timespec="seconds") if s.last else None,
                 **_row_extras(s, intel)}
                for s in top
            ],
            dominios_total=len(stats),
        )
        return findings

    async def _intel(self, ctx: ScanContext, stats: dict[str, DomainStats],
                     seen: dict[str, str | None]) -> DnsIntel:
        """Listas de ameaças e de DNS cifrado (baixadas), domínios do código e mudanças recentes."""
        from .. import code_hosts, threat_intel

        intel = DnsIntel(first_seen=dict(seen))
        domains = set(stats)
        cache = ctx.paths.cache_dir
        ctx.set_progress(self.name, "listas de ameaças")
        intel.threats, _ = await threat_intel.lookup(ctx.http, cache, "ameacas", domains)
        intel.encrypted_dns, _ = await threat_intel.lookup(ctx.http, cache, "dns_cifrado", domains)
        ctx.set_progress(self.name, "domínios citados no código")
        try:
            index = await asyncio.to_thread(code_hosts.build, ctx.inventory(), cache, ctx.paths.rules_dir)
            intel.users = index.users
        except OSError as err:
            _LOGGER.warning("Índice de domínios do código indisponível: %s", type(err).__name__)
        since = (datetime.now(UTC) - WINDOW - CHANGE_AFTER).isoformat(timespec="seconds")
        for when, name, change in await asyncio.to_thread(ctx.storage.recent_changes, since):
            try:
                intel.changes.append((datetime.fromisoformat(when), name, change))
            except ValueError:
                continue
        if intel.threats or intel.encrypted_dns:
            _LOGGER.info("DNS: %d domínio(s) em lista de ameaças, %d servidor(es) de DNS cifrado",
                         len(intel.threats), len(intel.encrypted_dns))
        return intel

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


def _row_extras(s: DomainStats, intel: DnsIntel) -> dict[str, Any]:
    """Colunas extras da tabela de domínios: quem cita no código, mudança logo antes, listas."""
    out: dict[str, Any] = {}
    users = intel.who(s.domain)
    if users:
        out["citado_em"] = sorted(c.split("/", 1)[-1] for c in users)[:5]
    change = intel.change_before(s)
    if change:
        out["depois_de"] = {"nome": change[1], "mudanca": change[2]}
    if s.domain in intel.threats:
        out["ameaca"] = intel.threats[s.domain]
    if s.domain in intel.encrypted_dns:
        out["dns_cifrado"] = True
    return out


async def _remember(ctx: ScanContext, stats: dict[str, DomainStats]) -> None:
    rows = [(s.domain, s.first.isoformat(timespec="seconds") if s.first else None,
             s.last.isoformat(timespec="seconds") if s.last else None, s.count) for s in stats.values()]
    await asyncio.to_thread(ctx.storage.upsert_dns_domains, rows)


def _problem(title: str, detail: str, srv: DnsServer | None = None,
             title_en: str | None = None, detail_en: str | None = None) -> Finding:
    where = f"as consultas do {srv.label} ficaram de fora" if srv else "a etapa de DNS (Fase 3) não roda"
    opts = f"as opções {srv.kind}_* do add-on" if srv else "as opções de DNS do add-on"
    where_en = f"the {srv.label} queries were left out" if srv else "the DNS step does not run"
    opts_en = f"the add-on's {srv.kind}_* options" if srv else "the add-on's DNS options"
    return Finding(
        component="dns", component_type=ComponentType.NETWORK, category="configuracao",
        rule_id="auditor.dns.falha", severity=Severity.LOW, title=title,
        explanation=f"{detail} Sem isso {where}.",
        recommendation=f"Revise {opts}.", source="dns",
        en=en_text(title_en or title, f"{detail_en or detail} Without it, {where_en}.", f"Review {opts_en}."),
        extra={"fingerprint_key": title},
    )
