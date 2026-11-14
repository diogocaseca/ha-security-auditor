"""Data de descoberta: componentes e achados mais novos ficam no topo das tabelas."""

from __future__ import annotations

import itertools

import pytest

from auditor.config import Options
from auditor.models import Severity
from auditor.report import render_html
from auditor.storage import component_key

from .conftest import make_finding
from .test_engine_web import _engine


class Scanner:
    name = "falso"

    def __init__(self, components, findings):
        self.components, self.findings = components, findings

    async def scan(self, ctx):
        for name in self.components:
            ctx.register_component("integracao", name, versao="1.0")
        return list(self.findings)


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """Cada chamada ao relógio avança um minuto (varreduras no mesmo segundo teriam a mesma data)."""
    ticks = itertools.count()
    monkeypatch.setattr("auditor.engine.utcnow_iso", lambda: f"2026-11-13T10:{next(ticks):02d}:00+00:00")


def _f(component, **kw):
    return make_finding(component=component, file=f"custom_components/{component}/x.py",
                        snippet=f"eval({component})", **kw)


async def test_newest_component_and_finding_on_top(paths, storage, masker):
    old_crit = _f("antiga", severity=Severity.CRITICAL)
    r1 = await _engine(paths, storage, masker, Options(), [Scanner(["antiga", "limpa"], [old_crit])]).run()
    assert {c.first_seen for c in r1.components} == {r1.started_at}

    # Na segunda varredura chega um componente novo, com achado de nível mais baixo.
    new_low = _f("nova", severity=Severity.LOW)
    r2 = await _engine(paths, storage, masker, Options(),
                       [Scanner(["antiga", "limpa", "nova"], [old_crit, new_low])]).run()
    assert r2.started_at > r1.started_at
    assert r2.components[0].name == "nova" and r2.components[0].first_seen == r2.started_at
    # Os antigos mantêm a data da primeira vez e, entre si, a ordem pela nota de risco.
    assert [c.name for c in r2.components[1:]] == ["antiga", "limpa"]
    assert all(c.first_seen == r1.started_at for c in r2.components[1:])
    assert r2.findings[0].component == "nova" and r2.findings[1].first_seen == r1.started_at

    # A data sobrevive ao relatório salvo e aparece na tela.
    saved = storage.load_scan(r2.scan_id)
    assert saved.components[0].first_seen == r2.started_at
    html = render_html(saved, status={}, history=[], csrf_token="t", lang="en")
    assert "discovered " in html and "Discovered" in html


async def test_backfill_from_saved_reports(paths, storage, masker):
    r1 = await _engine(paths, storage, masker, Options(), [Scanner(["antiga"], [])]).run()
    # Simula a atualização: relatórios antigos existem, mas a tabela de datas ainda não.
    with storage._conn() as conn:
        conn.execute("DELETE FROM discovered")
    r2 = await _engine(paths, storage, masker, Options(), [Scanner(["antiga", "nova"], [])]).run()
    dates = {c.name: c.first_seen for c in r2.components}
    assert dates == {"antiga": r1.started_at, "nova": r2.started_at}
    assert storage.discovered([component_key("integracao", "antiga")], "x") == {
        component_key("integracao", "antiga"): r1.started_at}


def test_ignored_and_blocklist_newest_first(storage):
    first = storage.add_ignored(component="a", rule="*", reason="primeiro", created_at="2026-01-01")
    second = storage.add_ignored(component="b", rule="*", reason="segundo", created_at="2026-01-02")
    assert [e["id"] for e in storage.list_ignored()] == [second, first]


def test_ignored_card_counts_list_items(storage):
    """O número é o tamanho da lista, e o texto é só "Ignorados"."""
    from auditor.models import ScanResult

    hidden = make_finding(component="a", file="custom_components/a/x.py")
    hidden.suppressed = True
    result = ScanResult(scan_id="20261113T100000000000Z", started_at="2026-11-13T10:00:00+00:00",
                        status="concluida", findings=[hidden, _f("b")])
    entries = [{"id": i, "component": "c", "rule": "*", "reason": "r", "created_at": "2026-11-13", "severities": []}
               for i in range(8)]
    html = render_html(result, status={}, history=[], csrf_token="t", lang="pt", ignored=entries)
    card = html.split('id="toggle-ignored"')[1].split("</button>")[0]
    assert '<span class="card-count">8</span>' in card and '<span class="card-label">Ignorados</span>' in card
    html = render_html(result, status={}, history=[], csrf_token="t", lang="en", ignored=[])
    card = html.split('id="toggle-ignored"')[1].split("</button>")[0]
    assert '<span class="card-count">0</span>' in card and '<span class="card-label">Ignored</span>' in card
