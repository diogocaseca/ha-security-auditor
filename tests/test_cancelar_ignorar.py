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
    assert resp.status == 400 and (await resp.json())["error"] == "Invalid JSON"
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
    # Ignorar o componente tira ele da varredura: vale também para componentes sem achados.
    assert 'data-ignore-component="limpa"' in html and 'data-skip-component' not in html
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


# --- "Não analisar": só com a marcação explícita o componente é pulado na varredura --------------


@pytest.mark.parametrize(("entry", "skips"), [
    (AllowlistEntry("meu_app", "*", "", skip=True), True),
    (AllowlistEntry("meu_*", "*", "", skip=True), True),
    # Ignorar todas as regras em todos os níveis só esconde os achados: o componente continua analisado.
    (AllowlistEntry("meu_app", "*", ""), False),
    (AllowlistEntry("meu_app", "*", "", severities=("critical", "high", "medium", "low", "info")), False),
    (AllowlistEntry("meu_app", "*", "", severities=("low", "info")), False),
    (AllowlistEntry("*", "*", "", skip=True), False),  # nunca pula tudo
    (AllowlistEntry("**", "*", "", skip=True), False),
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
    ctx.ignore_entries = (AllowlistEntry("ofuscada", "*", "meu app", entry_id=1, skip=True),)
    await StaticAnalysisScanner().scan(ctx)
    assert seen and not any("/ofuscada/" in a for a in seen)  # nenhuma ferramenta olhou a pasta
    assert any("/adulterada/" in a for a in seen)
    meta = ctx.components[("integracao", "ofuscada")]
    assert meta["verificacao"].startswith("não verificado: marcado para não ser analisado") and "meu app" in meta["verificacao"]


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
    ctx.ignore_entries = (AllowlistEntry("abc123_*", "*", "confiável", skip=True),)
    findings = await AddonImageScanner().scan(ctx)
    assert refs == []  # a imagem do add-on ignorado não foi baixada
    assert [f.component for f in findings] == ["local_meu_app"]  # o outro segue normal
    assert "não verificado" in ctx.components[("addon", "abc123_exemplo")]["verificacao"]


async def test_ignored_list_marks_entries_that_skip_scan(ignore_client):
    client, token, *_ = ignore_client
    await client.post("/api/ignored", headers={CSRF_HEADER: token},
                      json={"component": "outra", "rule": "*", "reason": "meu", "nao_analisar": True})
    # Todas as regras em todos os níveis, sem a marcação: só esconde os achados.
    await client.post("/api/ignored", headers={CSRF_HEADER: token},
                      json={"component": "terceira", "rule": "*", "reason": "x"})
    await client.post("/api/ignored", headers={CSRF_HEADER: token},
                      json={"component": "minha_integracao", "rule": "*", "severities": ["low"], "reason": "x"})
    html = await (await client.get("/")).text()
    assert html.count("<strong>not scanned</strong>") == 1


async def test_skip_entry_via_api(ignore_client):
    client, token, storage, *_ = ignore_client
    bad = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                            json={"component": "*", "rule": "*", "reason": "x", "nao_analisar": True})
    assert bad.status == 400
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "meu_app", "rule": "auditor.x", "severities": ["low"], "path": "a/*",
                                   "reason": "confio", "nao_analisar": True})
    assert resp.status == 201
    (entry,) = [e for e in storage.ignore_entries() if e.component == "meu_app"]
    # A marcação vale para o componente inteiro: regra, arquivo e níveis são descartados.
    assert entry.skip and (entry.rule, entry.path, entry.severities) == ("*", None, ())


def test_old_database_gets_skip_column(tmp_path):
    """Banco de antes da 0.20.0: o item de componente inteiro volta a tirar o componente da varredura."""
    import sqlite3

    from auditor.storage import Storage

    db = tmp_path / "db.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE ignored (id INTEGER PRIMARY KEY AUTOINCREMENT, component TEXT NOT NULL, "
                     "rule TEXT NOT NULL, path TEXT, fingerprint TEXT, severities TEXT, title TEXT, "
                     "reason TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)")
        conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        for component, rule, sevs in (("meu_app", "*", None), ("parcial", "*", "low"), ("todos", "*", None),
                                      ("regra", "auditor.x", None)):
            conn.execute("INSERT INTO ignored (component, rule, severities, reason, created_at) VALUES (?, ?, ?, 'x', 't')",
                         (component, rule, sevs))
        conn.execute("UPDATE ignored SET component = '*' WHERE component = 'todos'")
    storage = Storage(db, tmp_path / "reports")
    skips = {e.component: e.skip for e in storage.ignore_entries()}
    assert skips == {"meu_app": True, "parcial": False, "*": False, "regra": False}
    # Roda uma vez só: um item criado depois, mesmo igual, não é alterado ao reabrir.
    storage.add_ignored(component="outro", rule="*", reason="x", created_at="t")
    assert {e.component: e.skip for e in Storage(db, tmp_path / "reports").ignore_entries()}["outro"] is False


async def test_ignored_component_without_skip_is_still_scanned(tmp_path, monkeypatch):
    """Ignorar o componente inteiro (todas as regras e níveis) só esconde os achados: ele continua analisado."""
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
    assert any("/ofuscada/" in a for a in seen)  # as ferramentas olharam a pasta
    assert "verificacao" not in ctx.components[("integracao", "ofuscada")]


# --- Ignorar níveis: só os achados de agora; os novos continuam aparecendo ------------------------


async def test_ignore_levels_hides_only_current_findings(ignore_client):
    client, token, storage, engine, _ = ignore_client
    # Achados do cliente: dois altos/médios em minha_integracao e um baixo em "outra".
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "*", "rule": "*", "severities": ["high", "medium"],
                                   "reason": "revisados", "achados_atuais": True})
    assert resp.status == 201
    (entry,) = [e for e in storage.ignore_entries() if e.fingerprints]
    assert len(entry.fingerprints) == 2 and entry.severities == ("high", "medium")
    latest = storage.load_latest()
    assert latest.counts()["high"] == 0 and latest.counts()["medium"] == 0 and latest.counts()["low"] == 1

    # Próxima varredura: os mesmos achados continuam escondidos; um alto novo aparece.
    novo = make_finding(rule_id="auditor.novo", snippet="exec(z)", line=40)
    engine.scanners[0].findings = [*engine.scanners[0].findings, novo]
    result = await engine.run()
    visible = [f for f in result.findings if not f.suppressed]
    assert [f.rule_id for f in visible if f.severity is Severity.HIGH] == ["auditor.novo"]
    assert sum(1 for f in result.findings if f.suppressed and f.suppressed_by == entry.entry_id) == 2

    html = await (await client.get("/")).text()
    assert "2 current findings" in html


async def test_ignore_levels_without_current_findings(ignore_client):
    client, token, *_ = ignore_client
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "*", "rule": "*", "severities": ["critical"], "reason": "x",
                                   "achados_atuais": True})
    assert resp.status == 400 and "No current findings" in (await resp.json())["error"]


async def test_manual_component_rule_hides_future_findings(ignore_client):
    """Item manual (componente, regra "*", sem "Não analisar") é regra: esconde também os achados futuros."""
    client, token, storage, engine, _ = ignore_client
    await client.post("/api/ignored", headers={CSRF_HEADER: token},
                      json={"component": "minha_integracao", "rule": "*", "reason": "x"})
    engine.scanners[0].findings = [*engine.scanners[0].findings,
                                   make_finding(rule_id="auditor.novo", snippet="exec(z)", line=40)]
    result = await engine.run()
    assert all(f.suppressed for f in result.findings if f.component == "minha_integracao")


async def test_ignore_component_findings_by_level(ignore_client):
    """"Ignorar achados…" na linha: só os achados atuais do componente nos níveis escolhidos."""
    client, token, storage, engine, _ = ignore_client
    html = await (await client.get("/")).text()
    assert 'data-ignore-findings="minha_integracao"' in html and 'data-ignore-findings="limpa"' not in html
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "minha_integracao", "rule": "*", "severities": ["medium"],
                                   "reason": "revisado", "achados_atuais": True})
    assert resp.status == 201
    latest = storage.load_latest()
    hidden = {f.rule_id for f in latest.findings if f.suppressed}
    assert hidden == {"auditor.subprocess"}  # o alto do mesmo componente e o baixo de "outra" continuam
    # Todos os níveis do componente; um achado novo do componente aparece depois.
    await client.post("/api/ignored", headers={CSRF_HEADER: token},
                      json={"component": "minha_integracao", "rule": "*", "reason": "x", "achados_atuais": True})
    engine.scanners[0].findings = [*engine.scanners[0].findings,
                                   make_finding(rule_id="auditor.novo", snippet="exec(z)", line=40)]
    result = await engine.run()
    visible = {(f.component, f.rule_id) for f in result.findings if not f.suppressed}
    assert visible == {("minha_integracao", "auditor.novo"), ("outra", "auditor.eval-dinamico")}


async def test_ignore_all_levels_everywhere_hides_only_current(ignore_client):
    """"Ignorar estes níveis" com todos os níveis: todos os achados atuais; os novos aparecem."""
    client, token, storage, engine, _ = ignore_client
    resp = await client.post("/api/ignored", headers={CSRF_HEADER: token},
                             json={"component": "*", "rule": "*", "reason": "tudo revisado", "achados_atuais": True,
                                   "severities": ["critical", "high", "medium", "low", "info"]})
    assert resp.status == 201
    assert sum(storage.load_latest().counts().values()) == 0
    engine.scanners[0].findings = [*engine.scanners[0].findings,
                                   make_finding(rule_id="auditor.novo", snippet="exec(z)", line=40)]
    result = await engine.run()
    assert [f.rule_id for f in result.findings if not f.suppressed] == ["auditor.novo"]


async def test_unskip_component_from_row(ignore_client, paths, masker):
    """"Voltar a analisar" na linha de um componente ignorado remove o item que pula a varredura."""
    client, token, storage, engine, _ = ignore_client
    storage.add_ignored(component="minha_integracao", rule="*", reason="É meu", created_at="t", skip=True)
    storage.add_ignored(component="outr*", rule="*", reason="curinga", created_at="t", skip=True)
    # Um relatório que já mostra o componente como não verificado (como gera a varredura).
    latest = storage.load_latest()
    for c in latest.components:
        if c.name in ("minha_integracao", "outra"):
            c.metadata["verificacao"] = "não verificado: marcado para não ser analisado (É meu)"
    storage.save_scan(latest)
    html = await (await client.get("/")).text()
    assert 'data-unskip-component="minha_integracao"' in html and 'data-ignore-component="minha_integracao"' not in html
    assert "Scan again" in html

    assert (await client.post("/api/componentes/analisar", json={"nome": "minha_integracao"})).status == 403
    resp = await client.post("/api/componentes/analisar", headers={CSRF_HEADER: token}, json={"nome": "minha_integracao"})
    assert resp.status == 200 and (await resp.json())["removidos"] == 1
    assert not any(e.skip and e.component == "minha_integracao" for e in storage.ignore_entries())
    # Pulado por um curinga: não remove (pegaria outros componentes) e explica.
    resp = await client.post("/api/componentes/analisar", headers={CSRF_HEADER: token}, json={"nome": "outra"})
    assert resp.status == 409 and "outr*" in (await resp.json())["error"]
    resp = await client.post("/api/componentes/analisar", headers={CSRF_HEADER: token}, json={"nome": "limpa"})
    assert resp.status == 404
