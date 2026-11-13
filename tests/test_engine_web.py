import json
import asyncio
import ipaddress

import pytest

from auditor.config import AllowlistEntry, Options
from auditor.engine import ScanEngine
from auditor.models import Severity
from auditor.net import SafeHttpClient
from auditor.scheduler import Scheduler
from auditor.web import CSRF_HEADER, create_app

from .conftest import make_finding


class FakeScanner:
    name = "falso"

    def __init__(self, findings):
        self.findings = findings

    async def scan(self, ctx):
        ctx.register_component("integracao", "limpa", versao="1.0")
        return [f for f in self.findings]


class BrokenScanner:
    name = "quebrado"

    async def scan(self, ctx):
        raise RuntimeError("falha usando token-ultra-secreto-123")


def _engine(paths, storage, masker, options, scanners):
    return ScanEngine(
        paths=paths, options=options, storage=storage, masker=masker,
        http=SafeHttpClient(), supervisor=None, scanners=scanners,
    )


async def test_engine_full_cycle(paths, storage, masker):
    masker.add_known("token-ultra-secreto-123")
    options = Options(allowlist=(AllowlistEntry(component="*", rule="bandit.B101", reason="assert em testes"),))
    first = [
        make_finding(snippet='api = "token-ultra-secreto-123"'),
        make_finding(source="bandit", rule_id="bandit.B307", severity=Severity.MEDIUM, snippet="eval(payload)"),
        make_finding(rule_id="bandit.B101", file="x.py", category="assert", snippet="assert x"),
    ]
    engine = _engine(paths, storage, masker, options, [FakeScanner(first), BrokenScanner()])
    r1 = await engine.run()
    assert r1.status == "concluida"
    # Mesmo arquivo/linha/categoria do Semgrep e do Bandit -> um achado só, com as duas fontes.
    merged = [f for f in r1.findings if f.category == "execucao_dinamica"]
    assert len(merged) == 1 and merged[0].extra["sources"] == ["bandit", "semgrep"]
    assert merged[0].severity is Severity.HIGH
    assert all("token-ultra-secreto-123" not in (f.snippet or "") for f in r1.findings)
    assert len(r1.errors) == 1 and "token-ultra-secreto-123" not in r1.errors[0]
    assert [f.suppressed for f in r1.findings if f.rule_id == "bandit.B101"] == [True]
    assert {c.name for c in r1.components} == {"minha_integracao", "limpa"}
    assert not any(f.is_new for f in r1.findings)  # linha de base

    second = first + [make_finding(rule_id="auditor.novo", snippet="exec(x)", line=20)]
    engine.scanners = [FakeScanner(second)]
    r2 = await engine.run()
    assert [f.rule_id for f in r2.findings if f.is_new] == ["auditor.novo"]
    assert r2.previous_scan_id == r1.scan_id
    loaded = storage.load_latest()
    assert loaded.scan_id == r2.scan_id and loaded.new_count == 1
    assert len(storage.list_scans()) == 2


async def test_prune(paths, storage, masker):
    engine = _engine(paths, storage, masker, Options(report_retention=2), [])
    for _ in range(4):
        await engine.run()
    assert len(storage.list_scans()) == 2
    assert len(list(paths.reports_dir.glob("*.json"))) == 2


async def test_scheduler_manual_trigger_and_no_overlap():
    started = asyncio.Event()
    release = asyncio.Event()
    calls = []

    async def run_scan():
        calls.append(1)
        started.set()
        await release.wait()
        from auditor.models import ScanResult
        return ScanResult("x", "t", status="concluida")

    sched = Scheduler(run_scan, interval_hours=0, scan_on_start=False)
    sched.start()
    assert sched.request_scan()
    await asyncio.wait_for(started.wait(), 2)
    assert sched.running and not sched.request_scan()
    release.set()
    for _ in range(50):
        if not sched.running:
            break
        await asyncio.sleep(0.01)
    assert calls == [1] and sched.last_result.scan_id == "x" and sched.next_run is None
    await sched.stop()


@pytest.fixture
async def web_client(aiohttp_client, paths, storage, masker):
    engine = _engine(paths, storage, masker, Options(), [FakeScanner([make_finding(snippet="<script>alert(1)</script>")])])
    await engine.run()
    sched = Scheduler(engine.run, 0, False)
    app = create_app(storage, sched, engine.progress, allowed_peers={ipaddress.ip_address("127.0.0.1")})
    client = await aiohttp_client(app)
    return client, sched


async def test_web_index_escapes_and_headers(web_client):
    client, _ = web_client
    resp = await client.get("/")
    assert resp.status == 200
    html = await resp.text()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert "minha_integracao" in html


async def test_web_report_json_and_download(web_client):
    client, _ = web_client
    resp = await client.get("/api/report.json?download=1")
    assert resp.status == 200 and "attachment" in resp.headers["Content-Disposition"]
    data = await resp.json()
    assert data["counts"]["high"] == 1
    assert (await client.get("/api/report.json?scan=../../etc")).status == 404


async def test_web_scan_requires_csrf(web_client):
    client, sched = web_client
    assert (await client.post("/api/scan")).status == 403
    html = await (await client.get("/")).text()
    token = html.split('name="csrf-token" content="')[1].split('"')[0]
    sched.start()
    resp = await client.post("/api/scan", headers={CSRF_HEADER: token})
    assert resp.status == 202
    await sched.stop()


async def test_web_refuses_non_ingress_peer(aiohttp_client, storage):
    app = create_app(storage, Scheduler(lambda: None, 0, False), {})  # padrão: só 172.30.32.2
    client = await aiohttp_client(app)
    assert (await client.get("/")).status == 403


async def test_watchdog_health_endpoint(web_client):
    client, _ = web_client
    resp = await client.get("/api/status")
    assert resp.status == 200
    data = await resp.json()
    assert {"running", "next_run", "last_scan_id"} <= set(data)


def test_config_declares_watchdog_on_status_endpoint():
    import yaml
    from pathlib import Path

    cfg = yaml.safe_load((Path(__file__).parents[1] / "security_auditor/config.yaml").read_text())
    assert cfg["watchdog"].endswith(f":[PORT:{cfg['ingress_port']}]/api/status")


# --- Relatórios parciais nunca podem conter segredos ---------------------------------

SEGREDO = "token-que-nao-pode-vazar-987"


class SlowScanner:
    """Fica parado até ser cancelado (simula Trivy rodando durante uma atualização)."""

    name = "lento"

    def __init__(self):
        self.started = asyncio.Event()

    async def scan(self, ctx):
        self.started.set()
        await asyncio.Event().wait()


def _saved_reports(paths):
    return [p.read_text(encoding="utf-8") for p in paths.reports_dir.glob("*.json")]


async def test_cancelled_scan_saves_masked_partial_report(paths, storage, masker):
    masker.add_known(SEGREDO)
    slow = SlowScanner()
    engine = _engine(paths, storage, masker, Options(),
                     [FakeScanner([make_finding(snippet=f'api_key = "{SEGREDO}"',
                                                explanation=f"usa {SEGREDO}")]), slow])
    task = asyncio.create_task(engine.run())
    await asyncio.wait_for(slow.started.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    (report,) = _saved_reports(paths)
    assert SEGREDO not in report
    data = json.loads(report)
    assert data["status"] == "falhou" and "Varredura cancelada" in data["errors"]
    assert data["findings"] and "****" in data["findings"][0]["snippet"]


async def test_failed_finalize_saves_masked_report(paths, storage, masker, monkeypatch):
    import auditor.engine as engine_mod

    def boom(*args, **kwargs):
        raise RuntimeError("falha simulada na comparação")

    monkeypatch.setattr(engine_mod, "compare", boom)
    masker.add_known(SEGREDO)
    engine = _engine(paths, storage, masker, Options(),
                     [FakeScanner([make_finding(snippet=f"x = '{SEGREDO}'", title=f"t {SEGREDO}")])])
    result = await engine.run()
    assert result.status == "falhou"
    (report,) = _saved_reports(paths)
    assert SEGREDO not in report


async def test_history_pagination(aiohttp_client, paths, storage):
    from auditor.models import ScanResult

    for i in range(23):
        storage.save_scan(ScanResult(scan_id=f"20261101T0000{i:02d}000000Z", started_at="2026-11-01T00:00:00+00:00",
                                     finished_at="2026-11-01T00:01:30+00:00", status="concluida"))
    assert storage.count_scans() == 23
    assert [s["scan_id"][:15] for s in storage.list_scans(10, 20)] == [f"20261101T0000{i:02d}" for i in (2, 1, 0)]

    app = create_app(storage, Scheduler(lambda: None, 0, False), {}, allowed_peers={ipaddress.ip_address("127.0.0.1")})
    client = await aiohttp_client(app)
    html = await (await client.get("/?ver=historico&pagina=3")).text()
    assert html.count("./?scan=") == 3 and '<span class="pager-current" aria-current="page">3</span>' in html
    assert 'href="./?ver=historico&amp;pagina=2" rel="prev"' in html and "1 min 30 s" in html
    # Página inválida ou além do fim cai numa página válida.
    assert '<span class="pager-current" aria-current="page">3</span>' in await (await client.get("/?pagina=99")).text()
    assert '<span class="pager-current" aria-current="page">1</span>' in await (await client.get("/?pagina=x")).text()
