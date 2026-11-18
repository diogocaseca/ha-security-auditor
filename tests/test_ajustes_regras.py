"""Ajustes de ruído vindos de um relatório real (0.29.2)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from auditor.capabilities import build_chains, profile
from auditor.engine import _group_repeats
from auditor.models import Severity
from auditor.scanners.static import _bandit_severity

from .conftest import make_finding

PY_RULES = Path(__file__).parents[1] / "security_auditor/app/rules/semgrep/python"
VENV_SEMGREP = Path(__file__).parents[1] / ".venv/bin/semgrep"

CODE = '''
DOMAIN = "minha"
LISTA = "https://raw.githubusercontent.com/home-assistant/core/dev/strings.json"
GIST = "https://gist.githubusercontent.com/x/y/raw/a.json"
EXFIL = "https://pastebin.com/raw/abc"
STORAGE_KEY = f"{DOMAIN}.storage"
proprio = hass.config.path(".storage", f"{DOMAIN}.json")
creds = hass.config.path(".storage", "core.config_entries")
auth = open("/config/.storage/auth")
'''


def _semgrep(tmp_path) -> dict[int, set[str]]:
    exe = shutil.which("semgrep") or (str(VENV_SEMGREP) if VENV_SEMGREP.exists() else None)
    if exe is None:
        pytest.skip("semgrep não instalado")
    f = tmp_path / "x.py"
    f.write_text(CODE)
    res = subprocess.run([exe, "scan", "--config", str(PY_RULES), "--json", "--quiet", "--metrics=off",
                          "--disable-version-check", "--oss-only", "--no-git-ignore", str(f)],
                         capture_output=True, text=True, timeout=180, check=False,
                         env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"})
    out: dict[int, set[str]] = {}
    for r in json.loads(res.stdout)["results"]:
        cid = r["check_id"]
        out.setdefault(r["start"]["line"], set()).add(cid[cid.rfind("auditor.") + len("auditor."):])
    return out


def _rule_meta(rule_id: str) -> dict:
    for path in PY_RULES.glob("*.yaml"):
        for rule in yaml.safe_load(path.read_text())["rules"]:
            if rule["id"] == rule_id:
                return rule["metadata"]
    raise KeyError(rule_id)


def test_github_raw_is_info_and_exfiltration_still_high(tmp_path):
    hits = _semgrep(tmp_path)
    assert "py.conteudo-github" in hits[3] and "py.destino-suspeito" not in hits[3]
    assert "py.conteudo-github" in hits[4] and "py.destino-suspeito" not in hits[4]
    assert "py.destino-suspeito" in hits[5]
    assert _rule_meta("auditor.py.conteudo-github")["severidade"] == "info"
    assert _rule_meta("auditor.py.destino-suspeito")["severidade"] == "alta"


def test_storage_rules(tmp_path):
    hits = _semgrep(tmp_path)
    assert "py.acesso-storage-auth" in hits[8] and "py.acesso-storage-auth" in hits[9]  # config_entries e auth
    assert "py.acesso-storage-auth" not in hits.get(7, set())  # arquivo da própria integração
    assert _rule_meta("auditor.py.acesso-storage")["severidade"] == "baixa"
    assert _rule_meta("auditor.py.acesso-storage-auth")["severidade"] == "critica"


def test_generic_storage_does_not_count_as_secrets():
    findings = [make_finding(component="c", rule_id="auditor.py.acesso-storage", line=1),
                make_finding(component="c", rule_id="auditor.py.url-fixa", line=2)]
    assert set(profile(findings)[("integracao", "c")]) == {"rede"}
    assert build_chains(findings) == []
    findings.append(make_finding(component="c", rule_id="auditor.py.acesso-storage-auth", line=3))
    assert [f.rule_id for f in build_chains(findings)] == ["auditor.cadeia.segredos-e-rede"]


def test_bandit_weak_hash_is_low():
    assert _bandit_severity("HIGH", "HIGH", "B324") is Severity.LOW
    assert _bandit_severity("HIGH", "HIGH", "B602") is Severity.HIGH


def test_group_repeats_same_rule_same_file():
    rep = [make_finding(component="c", rule_id="auditor.py.url-fixa", file="a.py", line=n, snippet=f"u{n}",
                        severity=Severity.INFO) for n in (30, 10, 20)]
    other_file = make_finding(component="c", rule_id="auditor.py.url-fixa", file="b.py", line=1, snippet="u")
    other_rule = make_finding(component="c", rule_id="auditor.py.eval-dinamico", file="a.py", line=5)
    incomplete = [make_finding(component="c", rule_id="auditor.analise-incompleta", file=f"{n}.js", line=None,
                               snippet=None, severity=Severity.INFO) for n in ("x", "y")]
    out = _group_repeats([*rep, other_file, other_rule, *incomplete])
    assert len(out) == 4
    grouped = next(f for f in out if f.file == "a.py" and f.rule_id == "auditor.py.url-fixa")
    assert grouped.line == 10 and grouped.extra["ocorrencias"] == 3 and grouped.extra["linhas"] == [10, 20, 30]
    inc = next(f for f in out if f.rule_id == "auditor.analise-incompleta")
    assert inc.extra["ocorrencias"] == 2 and inc.extra["arquivos"] == ["x.js", "y.js"]
    # A identidade não depende da contagem: o trecho do achado agrupado é o da primeira ocorrência.
    assert grouped.snippet == "u10"
