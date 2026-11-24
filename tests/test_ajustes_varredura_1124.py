"""Ajustes da varredura de 24/11: diff de linha longa, Bandit, arquivos de testes e DNS públicos."""

from __future__ import annotations

from auditor.capabilities import cap_test_files
from auditor.models import Severity
from auditor.scanners.integrity import _diff
from auditor.scanners.static import _bandit_severity, _tar_fallback

from .conftest import make_finding
from .test_ajustes_regras import _semgrep


def test_long_minified_line_shows_where_it_changed(tmp_path):
    base = "function t(t,e){" + "a" * 500
    up, local = tmp_path / "up.js", tmp_path / "local.js"
    up.write_text(base + "fetch('https://exemplo.com')}\n")
    local.write_text(base + "fetch('https://ladrao.example')}\n")
    out = _diff(up, local)
    assert "primeira diferença na coluna 532" in out
    assert "ladrao.example" in out and "exemplo.com" in out
    assert "function t(t,e)" not in out


def test_short_lines_keep_the_plain_diff(tmp_path):
    up, local = tmp_path / "up.py", tmp_path / "local.py"
    up.write_text("a = 1\nb = 2\n")
    local.write_text("a = 1\nb = 3\n")
    out = _diff(up, local)
    assert "-b = 2" in out and "+b = 3" in out and "coluna" not in out


def test_jinja_autoescape_and_pycryptodome_are_low():
    assert _bandit_severity("HIGH", "HIGH", "B701") is Severity.LOW
    assert _bandit_severity("HIGH", "HIGH", "B413") is Severity.LOW


def test_tar_extract_fallback_after_safe_filter(tmp_path):
    f = tmp_path / "bm.py"
    f.write_text(
        "with tarfile.open(p) as tar:\n"
        "    if hasattr(tarfile, 'data_filter'):\n"
        "        tar.extractall(d, filter=\"data\")\n"
        "    else:\n"
        "        tar.extractall(d)\n"
        "\n\n\n\n\n"
        "tar.extractall(outro)\n"
    )
    assert _tar_fallback(f, 5)
    assert not _tar_fallback(f, 11)
    assert not _tar_fallback(f, None)


def test_test_files_are_capped_at_low():
    findings = [
        make_finding(file="custom_components/c/tests/unit/test_a.py", severity=Severity.MEDIUM, source="semgrep",
                     en={"title": "t", "explanation": "e", "recommendation": "r"}),
        make_finding(file="custom_components/c/loader.py", severity=Severity.MEDIUM, source="semgrep"),
        make_finding(file="custom_components/c/tests/extra.py", severity=Severity.HIGH, source="integridade",
                     rule_id="auditor.integridade.arquivo-extra"),
    ]
    cap_test_files(findings)
    cap_test_files(findings)  # de novo (achados que vêm da base): não repete a nota
    test, normal, extra = findings
    assert test.severity is Severity.LOW and test.extra["arquivo_de_teste"]
    assert test.explanation.count("arquivo é de testes") == 1
    assert "test files" in test.en["explanation"]
    assert normal.severity is Severity.MEDIUM
    assert extra.severity is Severity.HIGH


def test_public_dns_resolvers_are_info(tmp_path):
    hits = _semgrep(tmp_path, (
        'UP = "1.1.1.1"\n'
        'AJUDA = "Upstream DNS resolver IP (e.g. 1.1.1.1); several may be comma-separated"\n'
        'G = ("8.8.4.4", 53)\n'
        'OUTRO = "1.1.1.12"\n'
        'SERV = "93.184.216.34"\n'
    ))
    for line in (1, 2, 3):
        assert hits[line] & {"py.ip-dns-publico"} and "py.ip-fixo-publico" not in hits[line]
    assert "py.ip-fixo-publico" in hits[4] and "py.ip-dns-publico" not in hits[4]
    assert "py.ip-fixo-publico" in hits[5]


def test_semgrep_error_keeps_line_and_message():
    from auditor.scanners.static import _semgrep_error
    partial = {"type": ["PartialParsing", [{"path": "a.py", "start": {"line": 3, "col": 7}}]],
               "message": "Syntax error at line a.py:3:\n `T =` was unexpected", "path": "a.py"}
    assert _semgrep_error(partial) == {"tipo": "PartialParsing", "linha": 3,
                                       "mensagem": "Syntax error at line a.py:3: `T =` was unexpected"}
    plain = {"type": "Syntax error", "spans": [{"file": "b.js", "start": {"line": 1}}], "message": "x"}
    assert _semgrep_error(plain)["linha"] == 1
    assert _semgrep_error({"type": "Timeout"}) == {"tipo": "Timeout", "linha": None, "mensagem": ""}


def test_incomplete_finding_shows_where_and_keeps_identity(tmp_path):
    from auditor.scanners.static import _incomplete_finding
    f = tmp_path / "x.py"
    f.write_text("a = 1\ndef g[T = int](x): ...\n")
    out = _incomplete_finding(type("C", (), {"name": "c", "component_type": "integracao"}),
                              "custom_components/c/x.py", f,
                              {"tipo": "Syntax error", "linha": 2, "mensagem": "`T =` was unexpected"})
    assert out.line == 2 and "def g" in (out.snippet or "")
    assert "na linha 2" in out.explanation and "Bandit" in out.explanation and "`T =`" in out.explanation
    old = _incomplete_finding(type("C", (), {"name": "c", "component_type": "integracao"}),
                              "custom_components/c/x.py", f, {"tipo": "Syntax error", "linha": None})
    assert old.fingerprint == out.fingerprint
