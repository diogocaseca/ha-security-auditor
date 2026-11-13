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
    assert "Lista de ignorados" in html and f'data-unignore="{entry_id}"' in html and "Configurações" in html

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
    assert 'class="comp-row" data-sevs="high medium "' in html
    assert 'class="comp-row" data-sevs="low "' in html
    assert 'class="comp-row" data-sevs=""' in html  # componente limpo some ao filtrar
    assert 'id="scan-cancel"' in html and "hidden" in html.split('id="scan-cancel"')[1].split(">")[0]


def test_reapply_is_json_roundtrip_safe(ignore_client):
    _, _, storage, *_ = ignore_client
    data = json.loads(storage.report_file(storage.latest_completed_id()).read_text())
    assert all("suppressed_by" in f for f in data["findings"])
