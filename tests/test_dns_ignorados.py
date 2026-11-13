"""Domínios ignorados na aba DNS e ordem da tabela de domínios (mais novos no topo)."""

from __future__ import annotations

import ipaddress

import pytest

from auditor.models import ComponentSummary, ScanResult
from auditor.report import render_html
from auditor.scanners.dns import DnsScanner, ignore_pattern, is_ignored

from .test_fase3 import HA_IP, QUERIES, _adguard_options, _ctx, adguard_app


@pytest.mark.parametrize("text, expected", [
    ("API.Exemplo.com.", "api.exemplo.com"),
    (" *.amazonaws.com ", "*.amazonaws.com"),
    ("tracker-??.net", "tracker-??.net"),
])
def test_ignore_pattern_normalizes(text, expected):
    assert ignore_pattern(text) == expected


@pytest.mark.parametrize("text", ["", "*", "*.*", "?.*", "a..b", "exemplo.com/x", "x" * 254, "exem plo.com"])
def test_ignore_pattern_rejects(text):
    with pytest.raises(ValueError):
        ignore_pattern(text)


def test_is_ignored():
    patterns = ["*.amazonaws.com", "api.exemplo.com"]
    assert is_ignored("amazonaws.com", patterns)  # *.x vale também para o próprio x
    assert is_ignored("s3.eu-west-1.amazonaws.com", patterns)
    assert is_ignored("api.exemplo.com", patterns)
    assert not is_ignored("exemplo.com", patterns) and not is_ignored("notamazonaws.com", patterns)


async def test_scanner_leaves_ignored_domains_out_of_findings(aiohttp_server, tmp_path):
    server = await aiohttp_server(adguard_app())
    ctx = _ctx(tmp_path, _adguard_options(server))
    ctx.storage.add_dns_ignored("*.example.org", "CDN conhecida", "2026-11-13T10:00:00+00:00")
    ctx.storage.add_dns_ignored("ads.rastreador.com", "sei o que é", "2026-11-13T10:00:00+00:00")
    rules = {f.rule_id: f for f in await DnsScanner().scan(ctx)}
    # Os dois únicos domínios aleatório/bloqueado foram ignorados: os achados somem.
    assert "auditor.dns.dominio-aleatorio" not in rules and "auditor.dns.bloqueados" not in rules
    assert "auditor.dns.mineracao" in rules  # o resto continua
    # Na tabela eles continuam (a página esconde), e todos os domínios ficam guardados.
    domains = {d["dominio"] for d in ctx.components[("rede", "dns")]["dominios"]}
    assert "ads.rastreador.com" in domains
    assert "ads.rastreador.com" in ctx.storage.known_dns_domains()


async def test_domain_table_newest_first(aiohttp_server, tmp_path):
    server = await aiohttp_server(adguard_app())
    await DnsScanner().scan(_ctx(tmp_path, _adguard_options(server)))
    # Segunda varredura: um domínio novo, consultado só uma vez, vai para o topo.
    server2 = await aiohttp_server(adguard_app([*QUERIES, (1, "novo-servico.io", HA_IP, False)]))
    ctx = _ctx(tmp_path, _adguard_options(server2), scan_id="2")
    await DnsScanner().scan(ctx)
    rows = ctx.components[("rede", "dns")]["dominios"]
    assert rows[0]["dominio"] == "novo-servico.io"
    dates = [r["descoberto"] for r in rows]
    assert dates == sorted(dates, reverse=True) and all(dates)


def _result_with(domains):
    comp = ComponentSummary(name="dns", component_type="rede", metadata={
        "dominios": [{"dominio": d, "consultas": 1, "bloqueadas": 0, "novo": False, "servidores": ["AdGuard"],
                      "descoberto": "2026-11-13T10:00:00+00:00", "ultima": None} for d in domains],
        "dominios_total": len(domains), "clientes": [HA_IP], "servidores": ["AdGuard"]})
    return ScanResult(scan_id="20261113T100000000000Z", started_at="2026-11-13T10:00:00+00:00",
                      status="concluida", components=[comp])


def test_page_hides_ignored_rows_and_lists_them():
    ignored = [{"id": 7, "pattern": "*.cdn.com", "reason": "CDN <b>", "created_at": "2026-11-13T10:00:00+00:00"}]
    html = render_html(_result_with(["a.cdn.com", "outro.com"]), status={}, history=[], csrf_token="t",
                       dns_ignored=ignored, lang="en")
    assert 'class="dns-ignored-row" hidden' in html and "Show ignored domains (1)" in html
    assert 'data-dns-ignore="outro.com"' in html and 'data-dns-ignore="a.cdn.com"' not in html
    assert 'data-dns-unignore="7"' in html and "CDN &lt;b&gt;" in html and "Discovered" in html


@pytest.fixture
async def client(aiohttp_client, tmp_path):
    from auditor.scheduler import Scheduler
    from auditor.storage import Storage
    from auditor.web import CSRF_HEADER, create_app

    storage = Storage(tmp_path / "db.sqlite", tmp_path / "reports")
    app = create_app(storage, Scheduler(lambda: None, 0, False), {}, allowed_peers={ipaddress.ip_address("127.0.0.1")})
    c = await aiohttp_client(app)
    html = await (await c.get("/")).text()
    token = html.split('name="csrf-token" content="')[1].split('"')[0]
    return c, {CSRF_HEADER: token}, storage


async def test_api_add_edit_remove(client):
    c, h, storage = client
    assert (await c.post("/api/dns/ignorados", json={"dominio": "x.com", "motivo": "a"})).status == 403  # sem CSRF
    resp = await c.post("/api/dns/ignorados", headers=h, json={"dominio": "*.Amazonaws.com.", "motivo": "nuvem"})
    assert resp.status == 201
    entry_id = (await resp.json())["id"]
    assert storage.dns_ignored_patterns() == ["*.amazonaws.com"]
    dup = await c.post("/api/dns/ignorados", headers=h, json={"dominio": "*.amazonaws.com", "motivo": ""})
    assert dup.status == 409
    bad = await c.post("/api/dns/ignorados", headers=h, json={"dominio": "*", "motivo": ""})
    assert bad.status == 400 and "wildcards" in (await bad.json())["error"]  # padrão: inglês
    assert (await c.post("/api/dns/ignorados", headers=h, data="{")).status == 400

    assert (await c.patch(f"/api/dns/ignorados/{entry_id}", headers=h, json={"reason": "S3"})).status == 200
    assert storage.list_dns_ignored()[0]["reason"] == "S3"
    assert (await c.delete(f"/api/dns/ignorados/{entry_id}", headers=h)).status == 204
    assert (await c.delete(f"/api/dns/ignorados/{entry_id}", headers=h)).status == 404
    assert storage.list_dns_ignored() == []


async def test_api_ignore_all(client):
    c, h, storage = client
    storage.add_dns_ignored("ja.com", "", "2026-11-13T10:00:00+00:00")
    resp = await c.post("/api/dns/ignorados", headers=h,
                        json={"dominios": ["a.com", "B.com", "a.com", "ja.com"], "motivo": "todos conhecidos"})
    assert resp.status == 201 and len((await resp.json())["ids"]) == 2  # repetidos e já ignorados são pulados
    assert sorted(storage.dns_ignored_patterns()) == ["a.com", "b.com", "ja.com"]
    assert (await c.post("/api/dns/ignorados", headers=h, json={"dominios": ["a.com"], "motivo": ""})).status == 409
    for bad in ([], ["*"], "a.com", [1]):
        assert (await c.post("/api/dns/ignorados", headers=h, json={"dominios": bad, "motivo": ""})).status == 400


def test_page_has_ignore_all_button():
    html = render_html(_result_with(["a.com", "b.com"]), status={}, history=[], csrf_token="t", lang="en")
    assert 'class="btn btn-ghost btn-sm dns-ignore-all">Ignore all…' in html
