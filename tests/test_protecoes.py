"""Proteções contra sobrecarga: modos combináveis, guarda de recursos, horário fixo."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from auditor import resources
from auditor.config import DEFAULT_EXECUTION_MODES, Options, Paths
from auditor.masking import Masker
from auditor.resources import Profile, ResourceGuard, apply_low_priority, guard_from_options, profile_from_options
from auditor.scanners import addon_image as image_mod
from auditor.scanners import static as static_mod
from auditor.scanners.addon_image import AddonImageScanner
from auditor.scanners.base import ScanContext
from auditor.scanners.static import StaticAnalysisScanner, run_semgrep
from auditor.scheduler import Scheduler, next_daily_run
from auditor.storage import Storage
from auditor.tools import ToolResult

from .conftest import FIXTURES
from .test_fase1 import RULES
from .test_fase2 import FakeSupervisor, _addon

# --- Opções ------------------------------------------------------------------------


def test_modes_default_empty_and_unknown():
    assert Options.from_dict({}).execution_modes == frozenset(DEFAULT_EXECUTION_MODES)
    assert Options.from_dict({"modo_execucao": []}).execution_modes == frozenset()  # escolha do usuário
    o = Options.from_dict({"modo_execucao": ["modo_leve", "horario_fixo", "turbo", "MODO_LEVE"]})
    assert o.execution_modes == {"modo_leve", "horario_fixo"}
    assert o.has_mode("modo_leve") and not o.has_mode("prioridade_baixa")


@pytest.mark.parametrize(("raw", "parts"), [("04:15", (4, 15)), ("", (3, 30)), ("25:00", (3, 30)), ("4h", (3, 30))])
def test_scan_time(raw, parts):
    assert Options.from_dict({"horario_varredura": raw}).scan_time_parts == parts


def test_profile_and_guard_from_options():
    o = Options.from_dict({"modo_execucao": ["modo_leve", "aguardar_folga"], "memoria_minima_mb": 800,
                           "carga_maxima_por_cpu": 2})
    assert profile_from_options(o).light and profile_from_options(o).semgrep_jobs == 1
    g = guard_from_options(o)
    assert g.enabled and g.min_free_mb == 800 and g.max_load_per_cpu == 2.0
    assert not guard_from_options(Options(execution_modes=frozenset())).enabled
    assert Profile().semgrep_jobs == 2 and Profile().semgrep_max_memory_mb == 0 and Profile().trivy_parallel == 0


# --- Prioridade baixa ------------------------------------------------------------------


def test_apply_low_priority(monkeypatch):
    calls = {}
    monkeypatch.setattr(resources.os, "setpriority", lambda which, who, prio: calls.setdefault("nice", prio))

    class Done:
        returncode = 0
        stderr = b""

    monkeypatch.setattr(resources.subprocess, "run", lambda args, **kw: calls.setdefault("ionice", args) and Done())
    applied = apply_low_priority()
    assert calls["nice"] == 19
    assert calls["ionice"][:3] == ["ionice", "-c", "3"]
    assert len(applied) == 2


# --- Guarda de recursos (aguardar_folga) -----------------------------------------------------


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def now(self):
        return self.t

    async def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def _guard(loads, free=2000.0, **kw):
    clock = FakeClock()
    seq = iter(loads)
    last = [loads[-1]]

    def read_load():
        try:
            last[0] = next(seq)
        except StopIteration:
            pass
        return last[0]

    g = ResourceGuard(enabled=True, cpus=4, read_load=read_load, read_free_mb=lambda: free,
                      sleep=clock.sleep, clock=clock.now, poll_seconds=30, max_wait_seconds=120, **kw)
    return g, clock


async def test_guard_waits_until_idle():
    g, clock = _guard([12.0, 10.0, 2.0])  # 3.0 e 2.5 por núcleo (ocupado), depois 0.5
    assert await g.wait("teste") is None
    assert clock.sleeps == [30, 30]


async def test_guard_gives_up_after_max_wait():
    g, clock = _guard([20.0])
    reason = await g.wait("teste")
    assert reason and "carga do sistema alta" in reason and clock.t >= 120


async def test_guard_memory_and_disabled_and_unreadable():
    g, _ = _guard([0.1], free=300.0, min_free_mb=500)
    assert "pouca memória livre" in await g.wait("trivy")
    assert await g.wait("leve", need_mb=250) is None
    assert await ResourceGuard(enabled=False, read_load=lambda: 99.0).wait("x") is None

    def broken():
        raise OSError("sem /proc")

    assert await ResourceGuard(enabled=True, read_load=broken).wait("x") is None


# --- Integração com os scanners --------------------------------------------------------------


def _ctx(tmp_path: Path, supervisor=None, guard=None, profile=None, config_dir=None) -> ScanContext:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (tmp_path / "work").mkdir(exist_ok=True)
    paths = Paths(config_dir=config_dir or tmp_path / "config", data_dir=data, rules_dir=RULES)
    return ScanContext(
        paths=paths, options=Options(), http=None, supervisor=supervisor,
        storage=Storage(paths.db_path, paths.reports_dir), masker=Masker(), workdir=tmp_path / "work",
        scan_id="x", guard=guard or ResourceGuard(), profile=profile or Profile(),
    )


async def test_light_profile_semgrep_args(tmp_path, monkeypatch):
    seen = []

    async def fake_run_tool(args, **kw):
        seen.append(args)
        return ToolResult(0, json.dumps({"results": [], "errors": []}), "")

    monkeypatch.setattr(static_mod, "run_tool", fake_run_tool)
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    await run_semgrep(_ctx(tmp_path, profile=Profile(light=True)), [target], ("python",))
    args = seen[0]
    assert args[args.index("--jobs") + 1] == "1"
    assert args[args.index("--max-memory") + 1] == "768"
    await run_semgrep(_ctx(tmp_path), [target], ("python",))
    assert seen[1][seen[1].index("--jobs") + 1] == "2" and "--max-memory" not in seen[1]


async def test_light_profile_trivy_parallel(tmp_path, monkeypatch):
    seen = []

    async def fake_run_tool(args, **kw):
        seen.append(args)
        return ToolResult(0, '{"Results": []}', "")

    monkeypatch.setattr(image_mod, "run_tool", fake_run_tool)
    monkeypatch.setattr(Profile, "pause_seconds", property(lambda self: 0.0))
    await AddonImageScanner().scan(_ctx(tmp_path, FakeSupervisor([_addon()]), profile=Profile(light=True)))
    assert seen[0][seen[0].index("--parallel") + 1] == "1"


async def test_busy_system_postpones_image_scan(tmp_path, monkeypatch):
    called = []

    async def fake_run_tool(args, **kw):
        called.append(args)
        return ToolResult(0, '{"Results": []}', "")

    monkeypatch.setattr(image_mod, "run_tool", fake_run_tool)
    g, _ = _guard([0.1], free=100.0, min_free_mb=500)
    sup = FakeSupervisor([_addon(), _addon(slug="abc123_outro")])
    findings = await AddonImageScanner().scan(_ctx(tmp_path, sup, guard=g))
    assert called == []  # Trivy nem foi iniciado
    assert [f.rule_id for f in findings] == ["auditor.etapa-adiada"] * 2
    assert "pouca memória livre" in findings[0].explanation


async def test_busy_system_postpones_static_analysis(tmp_path, monkeypatch):
    async def must_not_run(args, **kw):
        raise AssertionError("ferramenta não deveria rodar")

    monkeypatch.setattr(static_mod, "run_tool", must_not_run)
    g, _ = _guard([40.0])
    findings = await StaticAnalysisScanner().scan(_ctx(tmp_path, guard=g, config_dir=FIXTURES / "config"))
    (adiada,) = [f for f in findings if f.rule_id == "auditor.etapa-adiada"]
    assert adiada.component == "auditor" and "Semgrep" in adiada.title


# --- Horário fixo ----------------------------------------------------------------------------


SP = ZoneInfo("America/Sao_Paulo")


def test_next_daily_run_same_day_and_next_day():
    now = datetime(2026, 11, 12, 2, 0, tzinfo=SP)
    assert next_daily_run(now, 3, 30, SP) == datetime(2026, 11, 12, 3, 30, tzinfo=SP).astimezone(UTC)
    now = datetime(2026, 11, 12, 3, 30, tzinfo=SP)  # exatamente no horário: próxima é amanhã
    assert next_daily_run(now, 3, 30, SP) == datetime(2026, 11, 13, 3, 30, tzinfo=SP).astimezone(UTC)


def test_next_daily_run_respects_dst():
    berlin = ZoneInfo("Europe/Berlin")
    # Noite da mudança para o horário de verão (29/03/2026): continua às 03:30 no relógio local.
    now = datetime(2026, 3, 28, 4, 0, tzinfo=berlin)
    nxt = next_daily_run(now, 3, 30, berlin).astimezone(berlin)
    assert (nxt.day, nxt.hour, nxt.minute) == (29, 3, 30)


async def test_scheduler_with_daily_time():
    async def run_scan():
        raise AssertionError("não deve rodar no teste")

    sched = Scheduler(run_scan, interval_hours=6, scan_on_start=False, daily_at=(3, 30), tz=SP,
                      modes=["horario_fixo", "prioridade_baixa"])
    sched.start()
    try:
        local = sched.next_run.astimezone(SP)
        assert (local.hour, local.minute) == (3, 30)
        st = sched.status()
        assert st["daily_at"] == "03:30" and st["modes"] == ["horario_fixo", "prioridade_baixa"]
    finally:
        await sched.stop()
