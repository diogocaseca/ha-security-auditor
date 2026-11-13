"""Cancelamento da varredura, lista de ignorados e dados do filtro por nível."""

from __future__ import annotations

import asyncio
import ipaddress
import json

import pytest

from auditor.config import AllowlistEntry, Options
from auditor.models import Severity
from auditor.scheduler import Scheduler
from auditor.tools import run_tool
from auditor.web import CSRF_HEADER, InvalidEntryError, create_app, parse_ignore_entry

from .conftest import make_finding
from .test_engine_web import FakeScanner, _engine


class SubprocessScanner:
    """Fica preso num processo externo, como o Semgrep/Trivy numa varredura real."""

    name = "lento"

    def __init__(self):
        self.started = asyncio.Event()

    async def scan(self, ctx):
        self.started.set()
        await run_tool(["sleep", "30"], home=ctx.workdir, timeout=60)
        return []


async def _wait_idle(sched, tries=200):
    for _ in range(tries):
        if not sched.running:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("varredura não terminou")


# --- Cancelamento ----------------------------------------------------------------------


async def test_user_cancel_saves_cancelled_report_and_scheduler_survives(paths, storage, masker):
    slow = SubprocessScanner()
    engine = _engine(paths, storage, masker, Options(), [FakeScanner([make_finding()]), slow])
    sched = Scheduler(engine.run, 0, False)
    assert not sched.cancel_scan()  # nada rodando
    sched.start()
    try:
        assert sched.request_scan()
        await asyncio.wait_for(slow.started.wait(), 3)
        assert sched.cancel_scan()
        assert sched.status()["cancelling"]
        await _wait_idle(sched)
        assert sched.last_result.status == "cancelada"
        assert "Varredura cancelada pelo usuário" in sched.last_result.errors
        (row,) = storage.list_scans()
        assert row["status"] == "cancelada"
        assert storage.latest_completed_id() is None  # cancelada não vira linha de base
        assert not sched.status()["cancelling"]
        # O agendador continua vivo: aceita uma nova varredura.
        slow.started.clear()
        assert sched.request_scan()
        await asyncio.wait_for(slow.started.wait(), 3)
        assert sched.cancel_scan()
        await _wait_idle(sched)
        assert len(storage.list_scans()) == 2
    finally:
        await sched.stop()


async def test_cancel_endpoint(aiohttp_client, paths, storage, masker):
    slow = SubprocessScanner()
    engine = _engine(paths, storage, masker, Options(), [slow])
    sched = Scheduler(engine.run, 0, False)
    app = create_app(storage, sched, engine.progress, allowed_peers={ipaddress.ip_address("127.0.0.1")})
    client = await aiohttp_client(app)
    token = _csrf(await (await client.get("/")).text())
    assert (await client.post("/api/scan/cancel")).status == 403  # sem CSRF
    assert (await client.post("/api/scan/cancel", headers={CSRF_HEADER: token})).status == 409
    sched.start()
    try:
        await client.post("/api/scan", headers={CSRF_HEADER: token})
        await asyncio.wait_for(slow.started.wait(), 3)
        assert (await client.post("/api/scan/cancel", headers={CSRF_HEADER: token})).status == 202
        await _wait_idle(sched)
        assert sched.last_result.status == "cancelada"
    finally:
        await sched.stop()


# --- Lista de ignorados ----------------------------------------------------------------


def _csrf(html: str) -> str:
    return html.split('name="csrf-token" content="')[1].split('"')[0]


@pytest.fixture
async def ignore_client(aiohttp_client, paths, storage, masker):
    findings = [
        make_finding(),
        make_finding(rule_id="auditor.subprocess", severity=Severity.MEDIUM, snippet="os.system(x)", line=20),
        make_finding(component="outra", severity=Severity.LOW, snippet="eval(y)"),
    ]
    config = (AllowlistEntry(component="outra", rule="auditor.nada", reason="das configurações"),)
    engine = _engine(paths, storage, masker, Options(allowlist=config), [FakeScanner(findings)])
    await engine.run()
    changes = []

    async def on_change():
        changes.append(1)

    app = create_app(storage, Scheduler(engine.run, 0, False), engine.progress,
                     allowed_peers={ipaddress.ip_address("127.0.0.1")}, config_allowlist=config, on_change=on_change)
    client = await aiohttp_client(app)
    token = _csrf(await (await client.get("/")).text())
    return client, token, storage, engine, changes


async def test_ignore_single_finding_and_remove(ignore_client):
    client, token, storage, _, changes = ignore_client
    latest = storage.load_latest()
    target = next(f for f in latest.findings if f.rule_id == "auditor.subprocess")
    assert latest.counts()["medium"] == 1

    assert (await client.post("/api/ignored", json={"component": "x", "rule": "y"})).status == 403
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token}, json={
        "component": target.component, "rule": target.rule_id, "fingerprint": target.fingerprint,
        "reason": "uso legítimo", "title": target.title,
    })
    assert resp.status == 201
    entry_id = (await resp.json())["id"]
    assert changes == [1]  # sensores republicados

    # O relatório mais recente muda na hora, inclusive a tabela de componentes.
    latest = storage.load_latest()
    f = next(f for f in latest.findings if f.rule_id == "auditor.subprocess")
    assert f.suppressed and f.suppressed_by == entry_id and "uso legítimo" in f.suppression_reason
    assert latest.counts()["medium"] == 0
    comp = next(c for c in latest.components if c.name == "minha_integracao")
    assert comp.counts["medium"] == 0 and comp.counts["high"] == 1
    assert any(c.name == "limpa" and c.metadata.get("versao") == "1.0" for c in latest.components)

    listing = await (await client.get("/api/ignored")).json()
    assert listing["interface"][0]["fingerprint"] == target.fingerprint
    assert listing["configuracoes"][0]["reason"] == "das configurações"
    html = await (await client.get("/")).text()
    assert "Ignore list" in html and f'data-unignore="{entry_id}"' in html and "Configuration" in html

    resp = await client.delete(f"/api/ignored/{entry_id}", headers={CSRF_HEADER: token})
    assert resp.status == 204
    assert storage.load_latest().counts()["medium"] == 1
    assert (await client.delete(f"/api/ignored/{entry_id}", headers={CSRF_HEADER: token})).status == 404


async def test_ignore_rule_everywhere_applies_to_next_scan(ignore_client):
    client, token, storage, engine, _ = ignore_client
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "*", "rule": "auditor.eval-dinamico", "reason": "revisado"})
    assert resp.status == 201
    assert storage.load_latest().counts() == {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}
    result = await engine.run()  # a próxima varredura também respeita a lista
    assert sum(f.suppressed for f in result.findings) == 2
    assert not any(f.is_new for f in result.findings)


@pytest.mark.parametrize(("body", "msg"), [
    ({"component": "*", "rule": "*", "reason": "tudo"}, "ignorariam tudo"),
    ({"component": "*", "rule": "*", "severities": ["critical", "high", "medium", "low", "info"]}, "ignorariam tudo"),
    ({"component": "a", "rule": "*", "severities": ["urgente"]}, "Nível de severidade inválido"),
    ({"component": "a", "rule": "*", "severities": "low"}, "Nível de severidade inválido"),
    ({"component": "a", "reason": "sem regra"}, "Informe o componente e a regra"),
    ({"component": "a", "rule": "b", "fingerprint": "../../x"}, "Identificador"),
    ({"component": "a", "rule": "b", "reason": "x" * 501}, "grande demais"),
    ({"component": "a\nb", "rule": "b"}, "caracteres inválidos"),
    ({"component": 1, "rule": "b"}, "inválido"),
    (["lista"], "Corpo inválido"),
])
def test_parse_ignore_entry_rejects(body, msg):
    with pytest.raises(InvalidEntryError, match=msg):
        parse_ignore_entry(body)


async def test_ignore_api_rejects_bad_json(ignore_client):
    client, token, *_ = ignore_client
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token, "Content-Type": "application/json"},
                             data="{nao json")
    assert resp.status == 400 and (await resp.json())["error"] == "JSON inválido"
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "*", "rule": "*", "reason": "x"})
    assert resp.status == 400


# --- Filtro por nível na tabela de componentes ---------------------------------------------


async def test_component_rows_carry_severity_levels(ignore_client):
    client, *_ = ignore_client
    html = await (await client.get("/")).text()
    assert 'data-sevs="high medium "' in html
    assert 'data-sevs="low "' in html
    assert 'data-sevs=""' in html
    assert 'id="scan-cancel"' in html and "hidden" in html.split('id="scan-cancel"')[1].split(">")[0]
    assert '<option value="integracao">Integration</option>' in html


def test_reapply_is_json_roundtrip_safe(ignore_client):
    _, _, storage, *_ = ignore_client
    data = json.loads(storage.report_file(storage.latest_completed_id()).read_text())
    assert all("suppressed_by" in f for f in data["findings"])


# --- Ignorar por nível -------------------------------------------------------------------


def test_parse_ignore_entry_levels_ordered_and_deduped():
    e = parse_ignore_entry({"component": "*", "rule": "*", "severities": ["info", "low", "info"]})
    assert e["severities"] == ("low", "info")


async def test_ignore_whole_level_everywhere(ignore_client):
    client, token, storage, engine, _ = ignore_client
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "*", "rule": "*", "severities": ["medium", "low"], "reason": "depois"})
    assert resp.status == 201
    counts = storage.load_latest().counts()
    assert counts["medium"] == 0 and counts["low"] == 0 and counts["high"] == 1
    assert storage.list_ignored()[0]["severities"] == ["medium", "low"]
    html = await (await client.get("/")).text()
    assert "levels: Medium, Low" in html
    result = await engine.run()  # vale para as próximas varreduras
    assert {f.severity.key for f in result.findings if f.suppressed} == {"medium", "low"}


async def test_ignore_component_only_selected_levels(ignore_client):
    client, token, storage, *_ = ignore_client
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "minha_integracao", "rule": "*", "severities": ["medium"], "reason": "ok"})
    assert resp.status == 201
    comp = next(c for c in storage.load_latest().components if c.name == "minha_integracao")
    assert comp.counts["medium"] == 0 and comp.counts["high"] == 1  # o nível alto continua contando
    other = next(c for c in storage.load_latest().components if c.name == "outra")
    assert other.counts["low"] == 1


async def test_component_rows_have_ignore_button(ignore_client):
    client, *_ = ignore_client
    html = await (await client.get("/")).text()
    assert 'data-ignore-component="minha_integracao"' in html and 'data-ignore-component="outra"' in html
    assert 'data-ignore-component="limpa"' not in html  # componente sem achados
    assert 'id="ignore-levels"' in html


def test_storage_migrates_ignored_table_from_060(tmp_path):
    import sqlite3

    from auditor.storage import Storage

    db = tmp_path / "auditor.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE ignored (id INTEGER PRIMARY KEY AUTOINCREMENT, component TEXT NOT NULL, "
                     "rule TEXT NOT NULL, path TEXT, fingerprint TEXT, title TEXT, reason TEXT NOT NULL DEFAULT '', "
                     "created_at TEXT NOT NULL)")
        conn.execute("INSERT INTO ignored (component, rule, reason, created_at) VALUES ('a', 'b', 'r', 'x')")
    storage = Storage(db, tmp_path / "reports")
    (entry,) = storage.ignore_entries()
    assert entry.component == "a" and entry.severities == ()


def test_all_levels_means_no_level_restriction():
    e = parse_ignore_entry({"component": "a", "rule": "*",
                            "severities": ["critical", "high", "medium", "low", "info"]})
    assert e["severities"] == ()


async def test_edit_ignored_reason(ignore_client):
    client, token, storage, _, changes = ignore_client
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "*", "rule": "auditor.eval-dinamico", "reason": "antigo"})
    entry_id = (await resp.json())["id"]
    assert (await client.patch(f"/api/ignored/{entry_id}", json={"reason": "x"})).status == 403  # sem CSRF

    resp = await client.patch(f"/api/ignored/{entry_id}", headers={CSRF_HEADER: token},
                              json={"reason": "  revisado em 12/11  "})
    assert resp.status == 200 and (await resp.json())["reason"] == "revisado em 12/11"
    assert storage.list_ignored()[0]["reason"] == "revisado em 12/11"
    assert len(changes) == 2  # sensores republicados de novo
    # O relatório mais recente já mostra o motivo novo nos achados ignorados.
    reasons = {f.suppression_reason for f in storage.load_latest().findings if f.suppressed}
    assert reasons == {"revisado em 12/11 (lista de ignorados)"}
    html = await (await client.get("/")).text()
    assert f'data-edit-reason="{entry_id}"' in html and 'data-reason="revisado em 12/11"' in html

    bad = await client.patch(f"/api/ignored/{entry_id}", headers={CSRF_HEADER: token}, json={"reason": "a\nb"})
    assert bad.status == 400
    assert (await client.patch(f"/api/ignored/{entry_id}", headers={CSRF_HEADER: token}, json={})).status == 400
    assert (await client.patch("/api/ignored/999", headers={CSRF_HEADER: token}, json={"reason": "x"})).status == 404


# --- Componente ignorado por inteiro: pulado na varredura --------------------------------------


@pytest.mark.parametrize(("entry", "skips"), [
    (AllowlistEntry("meu_app", "*", ""), True),
    (AllowlistEntry("meu_*", "*", ""), True),
    (AllowlistEntry("meu_app", "*", "", severities=("critical", "high", "medium", "low", "info")), True),
    (AllowlistEntry("meu_app", "*", "", severities=("low", "info")), False),  # só alguns níveis
    (AllowlistEntry("meu_app", "auditor.eval-dinamico", ""), False),  # só uma regra
    (AllowlistEntry("meu_app", "*", "", path="*/vendor/*"), False),
    (AllowlistEntry("meu_app", "*", "", fingerprint="0" * 24), False),
    (AllowlistEntry("*", "*", ""), False),  # nunca pula tudo
    (AllowlistEntry("**", "*", ""), False),
])
def test_skips_whole_component(entry, skips):
    from auditor.allowlist import skips_whole_component

    assert skips_whole_component(entry) is skips


async def test_fully_ignored_integration_is_not_scanned(tmp_path, monkeypatch):
    from auditor.scanners import static as static_mod
    from auditor.scanners.static import StaticAnalysisScanner

    from .conftest import FIXTURES
    from .test_protecoes import _ctx

    seen = []

    async def fake_run_tool(args, **kw):
        seen.extend(str(a) for a in args)
        return __import__("auditor.tools", fromlist=["ToolResult"]).ToolResult(0, '{"results": [], "errors": []}', "")

    monkeypatch.setattr(static_mod, "run_tool", fake_run_tool)
    ctx = _ctx(tmp_path, config_dir=FIXTURES / "config")
    ctx.ignore_entries = (AllowlistEntry("ofuscada", "*", "meu app", entry_id=1),)
    await StaticAnalysisScanner().scan(ctx)
    assert seen and not any("/ofuscada/" in a for a in seen)  # nenhuma ferramenta olhou a pasta
    assert any("/adulterada/" in a for a in seen)
    meta = ctx.components[("integracao", "ofuscada")]
    assert meta["verificacao"].startswith("não verificado: ignorado por completo") and "meu app" in meta["verificacao"]


async def test_fully_ignored_addon_is_not_scanned(tmp_path, monkeypatch):
    from auditor.scanners import addon_image as image_mod
    from auditor.scanners.addon_image import AddonImageScanner
    from auditor.tools import ToolResult

    from .test_fase2 import FakeSupervisor, _addon
    from .test_protecoes import _ctx

    refs = []

    async def fake_run_tool(args, **kw):
        refs.append(args[-1])
        return ToolResult(0, '{"Results": []}', "")

    monkeypatch.setattr(image_mod, "run_tool", fake_run_tool)
    sup = FakeSupervisor([_addon(), _addon(slug="local_meu_app", repository="local", image="local/meu")])
    ctx = _ctx(tmp_path, sup)
    ctx.ignore_entries = (AllowlistEntry("abc123_*", "*", "confiável"),)
    findings = await AddonImageScanner().scan(ctx)
    assert refs == []  # a imagem do add-on ignorado não foi baixada
    assert [f.component for f in findings] == ["local_meu_app"]  # o outro segue normal
    assert "não verificado" in ctx.components[("addon", "abc123_exemplo")]["verificacao"]


async def test_ignored_list_marks_entries_that_skip_scan(ignore_client):
    client, token, *_ = ignore_client
    await client.post("/api/ignored", headers={CSRF_HEADER: token},
                      json={"component": "outra", "rule": "*", "reason": "meu"})
    await client.post("/api/ignored", headers={CSRF_HEADER: token},
                      json={"component": "minha_integracao", "rule": "*", "severities": ["low"], "reason": "x"})
    html = await (await client.get("/")).text()
    assert html.count("<strong>not scanned</strong>") == 1
