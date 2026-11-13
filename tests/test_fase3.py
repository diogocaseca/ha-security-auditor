"""Fase 3: domínios consultados pelo host do HA (AdGuard Home / Pi-hole v6).

Os servidores DNS são simulados com servidores HTTP reais em localhost, para
exercitar o cliente de verdade (autenticação, paginação, logout).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aiohttp import web

from auditor.config import DnsServer, Options, Paths
from auditor.masking import Masker
from auditor.models import Severity
from auditor.net import EgressDeniedError, SafeHttpClient
from auditor.scanners.base import ScanContext
from auditor.scanners.dns import AVISO, DnsScanner, base_domain, client_ips, looks_random, normalize
from auditor.storage import Storage

from .test_fase1 import RULES

HA_IP = "192.168.1.10"
OTHER_IP = "192.168.1.50"


def _ts(minutes_ago: int) -> datetime:
    return datetime.now(UTC) - timedelta(minutes=minutes_ago)


# (minutos atrás, domínio, cliente, bloqueado)
QUERIES = [
    (5, "api.fabricante.com", HA_IP, False),
    (6, "api.fabricante.com", HA_IP, False),
    (7, "webhook.site", "172.30.32.3", False),
    (8, "pool.supportxmr.com", HA_IP, False),
    (9, "k8f2j9x7q1m4z6v3b5n0p2r8t4.example.org", HA_IP, False),
    (10, "ads.rastreador.com", HA_IP, True),
    (11, "pastebin.com", OTHER_IP, False),  # outro cliente da rede: deve ser ignorado
    (12, "10.1.168.192.in-addr.arpa", HA_IP, False),  # reverso: ignorado
    (13, "homeassistant.local", HA_IP, False),  # local: ignorado
    (60 * 30, "antigo.com", HA_IP, False),  # fora da janela de 24 h
]


def _paths(tmp_path: Path) -> Paths:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return Paths(config_dir=tmp_path / "config", data_dir=data, rules_dir=RULES)


def _ctx(tmp_path: Path, options: Options, supervisor=None, scan_id="1") -> ScanContext:
    paths = _paths(tmp_path)
    (tmp_path / "work").mkdir(exist_ok=True)
    return ScanContext(
        paths=paths, options=options, http=None, supervisor=supervisor,
        storage=Storage(paths.db_path, paths.reports_dir), masker=Masker(), workdir=tmp_path / "work",
        scan_id=scan_id,
    )


# --- AdGuard Home falso ---------------------------------------------------------------


def adguard_app(queries=QUERIES) -> web.Application:
    expected = "Basic " + base64.b64encode(b"admin:segredo-dns").decode()

    async def querylog(request: web.Request) -> web.Response:
        if request.headers.get("Authorization") != expected:
            return web.Response(status=401)
        search = request.query.get("search", "")
        older = request.query.get("older_than")
        rows = sorted(queries, key=lambda q: q[0])  # mais recente primeiro
        entries = [
            {
                # Formato real do AdGuard: RFC3339 com nanossegundos.
                "time": _ts(m).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123+00:00",
                "question": {"name": d + ".", "type": "A"},
                "client": c,
                "reason": "FilteredBlackList" if b else "NotFilteredNotFound",
            }
            for m, d, c, b in rows
            if search in c or search in d
        ]
        if older:
            entries = [e for e in entries if e["time"] < older]
        page = entries[:3]  # páginas pequenas para testar a paginação
        return web.json_response({"data": page, "oldest": page[-1]["time"] if page else ""})

    app = web.Application()
    app.router.add_get("/control/querylog", querylog)
    return app


def _adguard(server, password="segredo-dns") -> DnsServer:
    return DnsServer("adguard", str(server.make_url("")).rstrip("/"), "admin", password)


def _pihole(server, password="senha-app") -> DnsServer:
    return DnsServer("pihole", str(server.make_url("")).rstrip("/"), None, password)


def _dns_options(*servers: DnsServer, clients=(HA_IP, "172.30.32.3")) -> Options:
    return Options(dns_servers=servers, dns_client_ips=clients)


def _adguard_options(server, password="segredo-dns") -> Options:
    return _dns_options(_adguard(server, password))


async def test_adguard_detection(aiohttp_server, tmp_path):
    server = await aiohttp_server(adguard_app())
    ctx = _ctx(tmp_path, _adguard_options(server))
    findings = await DnsScanner().scan(ctx)
    rules = {f.rule_id: f for f in findings}

    assert rules["auditor.dns.destino-suspeito"].severity is Severity.HIGH
    assert "webhook.site" in rules["auditor.dns.destino-suspeito"].title
    assert rules["auditor.dns.mineracao"].severity is Severity.HIGH
    assert "k8f2j9x7q1m4z6v3b5n0p2r8t4.example.org" in rules["auditor.dns.dominio-aleatorio"].snippet
    assert "ads.rastreador.com" in rules["auditor.dns.bloqueados"].snippet
    assert "auditor.dns.credenciais-sem-tls" in rules  # http:// com senha
    # Primeira execução é a linha de base: nada de "novos".
    assert "auditor.dns.novos" not in rules
    # Todo achado traz o aviso de que não dá para atribuir a consulta a um add-on.
    assert all(AVISO in f.explanation for f in findings if f.rule_id != "auditor.dns.credenciais-sem-tls")

    meta = ctx.components[("rede", "dns")]
    domains = {d["dominio"]: d for d in meta["dominios"]}
    assert domains["api.fabricante.com"]["consultas"] == 2
    assert "pastebin.com" not in domains  # consultado por outro cliente
    assert "antigo.com" not in domains and "homeassistant.local" not in domains
    assert not any(d.endswith("in-addr.arpa") for d in domains)


async def test_adguard_new_domains_on_second_run(aiohttp_server, tmp_path):
    server = await aiohttp_server(adguard_app())
    await DnsScanner().scan(_ctx(tmp_path, _adguard_options(server)))

    server2 = await aiohttp_server(adguard_app([*QUERIES, (1, "novo-servico.io", HA_IP, False)]))
    findings = await DnsScanner().scan(_ctx(tmp_path, _adguard_options(server2), scan_id="2"))
    (novos,) = [f for f in findings if f.rule_id == "auditor.dns.novos"]
    assert novos.title.startswith("1 domínio(s) novo(s)") and "novo-servico.io" in novos.snippet


async def test_adguard_wrong_password(aiohttp_server, tmp_path):
    server = await aiohttp_server(adguard_app())
    findings = await DnsScanner().scan(_ctx(tmp_path, _adguard_options(server, password="errada")))
    falha = [f for f in findings if f.rule_id == "auditor.dns.falha"]
    assert len(falha) == 1 and "recusou" in falha[0].explanation


# --- Pi-hole v6 falso -----------------------------------------------------------------


def pihole_app(state: dict) -> web.Application:
    async def auth(request: web.Request) -> web.Response:
        body = await request.json()
        if body.get("password") != "senha-app":
            return web.json_response({"session": {"valid": False, "sid": None}}, status=401)
        return web.json_response({"session": {"valid": True, "sid": "SID123"}})

    async def logout(request: web.Request) -> web.Response:
        state["logout_sid"] = request.headers.get("X-FTL-SID")
        return web.Response(status=204)

    async def queries(request: web.Request) -> web.Response:
        if request.headers.get("X-FTL-SID") != "SID123":
            return web.Response(status=401)
        since = int(request.query["from"])
        client = request.query.get("client_ip")
        start, length = int(request.query["start"]), int(request.query["length"])
        rows = [
            {"time": _ts(m).timestamp(), "domain": d, "client": {"ip": c, "name": None},
             "status": "GRAVITY" if b else "FORWARDED", "type": "A"}
            for m, d, c, b in sorted(QUERIES, key=lambda q: q[0])
            if _ts(m).timestamp() >= since and (client is None or c == client)
        ]
        return web.json_response({"queries": rows[start : start + length], "cursor": 99, "recordsTotal": len(rows)})

    app = web.Application()
    app.router.add_post("/api/auth", auth)
    app.router.add_delete("/api/auth", logout)
    app.router.add_get("/api/queries", queries)
    return app


async def test_pihole_detection_and_logout(aiohttp_server, tmp_path):
    state: dict = {}
    server = await aiohttp_server(pihole_app(state))
    ctx = _ctx(tmp_path, _dns_options(_pihole(server)))
    findings = await DnsScanner().scan(ctx)
    rules = {f.rule_id for f in findings}
    assert {"auditor.dns.destino-suspeito", "auditor.dns.mineracao", "auditor.dns.bloqueados"} <= rules
    assert state["logout_sid"] == "SID123"  # sessão encerrada ao final
    assert "Pi-hole" in ctx.components[("rede", "dns")]["nome"]


async def test_pihole_wrong_password(aiohttp_server, tmp_path):
    server = await aiohttp_server(pihole_app({}))
    findings = await DnsScanner().scan(_ctx(tmp_path, _dns_options(_pihole(server, "x"), clients=(HA_IP,))))
    assert [f.rule_id for f in findings if f.severity > Severity.INFO] == ["auditor.dns.falha"]


# --- Configuração e utilitários -----------------------------------------------------------


async def test_disabled_and_misconfigured(tmp_path):
    assert await DnsScanner().scan(_ctx(tmp_path, Options())) == []
    (f,) = await DnsScanner().scan(_ctx(tmp_path, _dns_options(DnsServer("adguard", None))))
    assert f.rule_id == "auditor.dns.falha" and "URL do AdGuard Home" in f.explanation
    (f,) = await DnsScanner().scan(_ctx(tmp_path, _dns_options(DnsServer("pihole", "ftp://x"))))
    assert "inválida" in f.title and "Pi-hole" in f.title
    # Sem Supervisor e sem dns_client_ips não há como saber os IPs do HA.
    (f,) = await DnsScanner().scan(_ctx(tmp_path, _dns_options(DnsServer("adguard", "http://10.0.0.2"), clients=())))
    assert "dns_client_ips" in f.explanation


async def test_client_ips_from_supervisor(tmp_path):
    class Sup:
        async def get(self, path):
            assert path == "/network/info"
            return {"interfaces": [
                {"ipv4": {"address": ["192.168.1.10/24"]}, "ipv6": {"address": ["fe80::1/64", "2001:db8::5/64"]}},
            ]}

    ips = await client_ips(_ctx(tmp_path, Options(), supervisor=Sup()))
    assert ips == ["192.168.1.10", "2001:db8::5", "172.30.32.3"]


def test_dns_client_only_talks_to_configured_host():
    http = SafeHttpClient(allowed_hosts=frozenset({"192.168.1.2"}), allow_http=True)
    http.check_url("http://192.168.1.2:3000/control/querylog")
    with pytest.raises(EgressDeniedError):
        http.check_url("http://exfiltra.example.com/")
    # O cliente padrão (internet) continua exigindo HTTPS.
    with pytest.raises(EgressDeniedError):
        SafeHttpClient().check_url("http://api.github.com/")


@pytest.mark.parametrize(("domain", "expected"), [
    ("API.Exemplo.com.", "api.exemplo.com"),
    ("1.0.168.192.in-addr.arpa", None),
    ("nas.local", None),
    ("semponto", None),
])
def test_normalize(domain, expected):
    assert normalize(domain) == expected


def test_random_and_base_domain():
    assert looks_random("k8f2j9x7q1m4z6v3b5n0p2r8t4.example.org")
    assert not looks_random("d1a2b3c4e5f6g7h8i9j0k1l2.cloudfront.net")  # CDN conhecida
    assert not looks_random("updates.home-assistant.io")
    assert base_domain("a.b.exemplo.com.br") == "exemplo.com.br" and base_domain("x.y.io") == "y.io"


def test_options_parse_dns_legacy():
    o = Options.from_dict({"dns_provider": "AdGuard", "dns_url": " http://x:3000 ", "dns_password": "p",
                           "dns_client_ips": ["192.168.1.10", ""], "dns_username": ""})
    assert o.dns_servers == (DnsServer("adguard", "http://x:3000", None, "p"),)
    assert o.dns_client_ips == ("192.168.1.10",)


def test_options_parse_dns_both():
    o = Options.from_dict({"adguard_url": "http://ag:3000", "adguard_username": "admin", "adguard_password": "a",
                           "pihole_url": " http://pi.hole ", "pihole_password": "b",
                           "dns_provider": "pihole", "dns_url": "http://antigo"})  # antigo não duplica o Pi-hole
    assert o.dns_servers == (DnsServer("adguard", "http://ag:3000", "admin", "a"),
                             DnsServer("pihole", "http://pi.hole", None, "b"))
    assert Options.from_dict({"pihole_url": "", "dns_provider": "nenhum"}).dns_servers == ()
    # Opções novas + antigas de outro tipo: os dois são usados.
    o = Options.from_dict({"pihole_url": "http://pi.hole", "dns_provider": "adguard", "dns_url": "http://ag"})
    assert [s.kind for s in o.dns_servers] == ["pihole", "adguard"]


async def test_adguard_and_pihole_together(aiohttp_server, tmp_path):
    state: dict = {}
    ag = await aiohttp_server(adguard_app())
    pi = await aiohttp_server(pihole_app(state))
    ctx = _ctx(tmp_path, _dns_options(_adguard(ag), _pihole(pi)))
    findings = await DnsScanner().scan(ctx)
    meta = ctx.components[("rede", "dns")]
    assert meta["nome"] == "Domínios consultados (AdGuard Home + Pi-hole)"
    assert meta["servidores"] == ["AdGuard Home", "Pi-hole"]
    assert "AdGuard Home:" in meta["trafego"] and "Pi-hole:" in meta["trafego"]
    domains = {d["dominio"]: d for d in meta["dominios"]}
    assert domains["api.fabricante.com"]["consultas"] == 4  # 2 em cada servidor, somadas
    assert domains["api.fabricante.com"]["servidores"] == ["AdGuard Home", "Pi-hole"]
    # Achados não se repetem por servidor: um por regra.
    rules = [f.rule_id for f in findings if f.rule_id.startswith("auditor.dns.") and f.severity > Severity.INFO]
    assert rules.count("auditor.dns.destino-suspeito") == len({f.title for f in findings
                                                                 if f.rule_id == "auditor.dns.destino-suspeito"})
    assert state["logout_sid"] == "SID123"


async def test_one_dns_down_other_still_counts(aiohttp_server, tmp_path):
    ag = await aiohttp_server(adguard_app())
    pi = await aiohttp_server(pihole_app({}))
    ctx = _ctx(tmp_path, _dns_options(_adguard(ag, "errada"), _pihole(pi)))
    findings = await DnsScanner().scan(ctx)
    (falha,) = [f for f in findings if f.rule_id == "auditor.dns.falha"]
    assert "AdGuard Home" in falha.title and "ficaram de fora" in falha.explanation
    assert ctx.components[("rede", "dns")]["servidores"] == ["Pi-hole"]
    assert any(f.rule_id == "auditor.dns.mineracao" for f in findings)


def test_report_shows_server_column_only_with_two_servers():
    from auditor.models import ComponentSummary, ScanResult
    from auditor.report import render_html

    def html(servers):
        meta = {"nome": "Domínios consultados", "servidores": servers, "clientes": [HA_IP], "aviso": AVISO,
                "trafego": "", "dominios_total": 1,
                "dominios": [{"dominio": "a.com", "consultas": 2, "bloqueadas": 0, "novo": False,
                              "servidores": servers, "ultima": None}]}
        result = ScanResult(scan_id="x", started_at="2026-11-12T00:00:00+00:00", status="concluida",
                            components=[ComponentSummary("dns", "rede", metadata=meta)])
        return render_html(result, status={}, history=[], csrf_token="t")

    assert "<th>Servidor</th>" in html(["AdGuard Home", "Pi-hole"]) and "<td>ambos</td>" in html(["AdGuard Home", "Pi-hole"])
    assert "<th>Servidor</th>" not in html(["Pi-hole"])
