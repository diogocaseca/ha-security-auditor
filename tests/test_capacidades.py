"""Perfil de capacidades, cadeias de comportamento e capacidade nova trazida por atualização."""

from __future__ import annotations

import itertools

import pytest

from auditor.capabilities import build_chains, profile
from auditor.config import AllowlistEntry, Options
from auditor.models import Severity
from auditor.report import render_html

from .conftest import make_finding
from .test_engine_web import _engine


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    ticks, ids = itertools.count(), itertools.count()
    monkeypatch.setattr("auditor.engine.utcnow_iso", lambda: f"2026-11-18T10:{next(ticks):02d}:00+00:00")
    monkeypatch.setattr("auditor.engine.new_scan_id", lambda: f"20261118T10{next(ids):04d}000000Z")


def _f(component, rule, line=1, **kw):
    return make_finding(component=component, rule_id=rule, file=f"custom_components/{component}/x.py", line=line,
                        snippet=f"{rule}({line})", **kw)


SECRETS = "auditor.py.acesso-secrets-yaml"
URL = "auditor.py.url-fixa"
EVAL = "auditor.py.eval-dinamico"
SHELL = "auditor.py.execucao-de-comandos"


def test_profile_and_chains():
    findings = [_f("ladra", SECRETS), _f("ladra", URL, 2), _f("normal", URL), _f("normal", SHELL, 2),
                _f("escondida", "auditor.ofuscacao.chr-concatenado"), _f("escondida", SHELL, 2),
                _f("baixa", URL), _f("baixa", EVAL, 2)]
    prof = profile(findings)
    assert set(prof[("integracao", "ladra")]) == {"segredos", "rede"}
    assert set(prof[("integracao", "normal")]) == {"rede", "shell"}
    chains = {(f.component, f.rule_id): f for f in build_chains(findings)}
    assert set(chains) == {("ladra", "auditor.cadeia.segredos-e-rede"),
                           ("escondida", "auditor.cadeia.escondido-e-perigoso"),
                           ("baixa", "auditor.cadeia.rede-e-execucao")}
    ladra = chains[("ladra", "auditor.cadeia.segredos-e-rede")]
    assert ladra.severity is Severity.CRITICAL and "custom_components/ladra/x.py:1" in ladra.snippet
    assert "[reads secrets or tokens]" in ladra.en["snippet"]


class Scanner:
    name = "falso"

    def __init__(self, version, findings):
        self.version, self.findings = version, findings

    async def scan(self, ctx):
        ctx.register_component("integracao", "minha", versao=self.version)
        return list(self.findings)


async def test_engine_adds_chain_and_capabilities_metadata(paths, storage, masker):
    result = await _engine(paths, storage, masker, Options(),
                           [Scanner("1.0", [_f("minha", SECRETS), _f("minha", URL, 2)])]).run()
    chain = next(f for f in result.findings if f.category == "cadeia")
    assert chain.rule_id == "auditor.cadeia.segredos-e-rede" and not chain.suppressed
    meta = {c.name: c.metadata for c in result.components}
    assert meta["minha"]["capacidades"] == ["rede", "segredos"]
    html = render_html(result, status={}, history=[], csrf_token="t", lang="en")
    assert 'class="cap-badge cap-segredos"' in html and "reads secrets or tokens" in html
    # Rodar de novo não duplica a cadeia (é recalculada), e ignorar as peças não esconde a cadeia.
    opts = Options(allowlist=(AllowlistEntry(component="minha", rule="auditor.py.*", reason="revisado"),))
    again = await _engine(paths, storage, masker, opts,
                          [Scanner("1.0", [_f("minha", SECRETS), _f("minha", URL, 2)])]).run()
    chains = [f for f in again.findings if f.category == "cadeia"]
    assert len(chains) == 1 and not chains[0].suppressed and not chains[0].is_new


async def test_new_capability_in_update(paths, storage, masker):
    async def run(version, findings):
        return await _engine(paths, storage, masker, Options(), [Scanner(version, findings)]).run()

    def change(result):
        return [f for f in result.findings if f.rule_id == "auditor.capacidade-nova"]

    assert change(await run("1.0", [_f("minha", URL)])) == []           # primeira vez: só guarda o perfil
    assert change(await run("1.0", [_f("minha", URL), _f("minha", SECRETS, 2)])) == []  # mesma versão: sem alerta
    r = await run("1.1", [_f("minha", URL), _f("minha", SECRETS, 2), _f("minha", SHELL, 3)])
    (alert,) = change(r)
    assert alert.severity is Severity.HIGH and "executa comandos" in alert.title and "1.0" in alert.explanation
    assert "segredos" not in alert.title  # já existia na 1.0 (mesmo surgindo depois): não é novidade da 1.1
    # Continua enquanto a versão não muda; some quando a próxima atualização não traz nada novo.
    assert len(change(await run("1.1", [_f("minha", URL), _f("minha", SECRETS, 2), _f("minha", SHELL, 3)]))) == 1
    assert change(await run("1.2", [_f("minha", URL), _f("minha", SECRETS, 2), _f("minha", SHELL, 3)])) == []
