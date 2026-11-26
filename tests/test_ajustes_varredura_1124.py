"""Ajustes da varredura de 24/11: diff de linha longa, Bandit, arquivos de testes e DNS públicos."""

from __future__ import annotations

from pathlib import Path

import pytest

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
                                       "mensagem": "Syntax error at line 3: `T =` was unexpected"}
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


def test_semgrep_error_line_from_message():
    from auditor.scanners.static import _semgrep_error
    err = {"type": "Syntax error", "path": "/config/x/__init__.py",
           "message": "Syntax error at line /config/x/__init__.py:19: `ReplaceDeviceConfigEntry` was unexpected"}
    assert _semgrep_error(err) == {"tipo": "Syntax error", "linha": 19,
                                   "mensagem": "Syntax error at line 19: `ReplaceDeviceConfigEntry` was unexpected"}


def test_rewrite_new_python_type_syntax():
    from auditor.scanners.static import rewrite_new_syntax
    src = ("from x import ConfigEntry\n"
           "type MinhaConfigEntry = ConfigEntry[Dados]\n"
           "type Par[T] = tuple[T, T]\n"
           "def primeiro[T](itens: list[T]) -> T:\n"
           "    return itens[0]\n"
           "async def busca[T: int](x: T) -> T: ...\n"
           "class Caixa[T]:\n"
           "    tipo = 'type x = 1'\n")
    out = rewrite_new_syntax(src)
    assert out is not None and out.count("\n") == src.count("\n")
    compile(out, "x.py", "exec")  # continua Python válido
    assert "MinhaConfigEntry = ConfigEntry[Dados]" in out and "def primeiro(itens" in out
    assert "async def busca(x: T)" in out and "class Caixa:" in out and "'type x = 1'" in out
    assert rewrite_new_syntax("x = 1\n") is None


def test_trivy_platform_follows_machine_arch():
    from auditor.scanners.addon_image import platform_of
    assert platform_of("aarch64") == "linux/arm64"
    assert platform_of("amd64") == "linux/amd64"
    assert platform_of(None) is None


async def test_new_python_syntax_is_analysed_in_a_compatible_copy(tmp_path):
    # PEP 696 (``[T = int]``) o Semgrep local também não entende: serve para simular o erro do HA.
    import shutil as _shutil

    from auditor.scanners.static import run_semgrep

    from .test_protecoes import _ctx
    if _shutil.which("semgrep") is None and not (Path(__file__).parents[1] / ".venv/bin/semgrep").exists():
        pytest.skip("semgrep não instalado")
    target = tmp_path / "comp.py"
    target.write_text("import base64\n\ndef g[T = int](x: T) -> T:\n    return eval(base64.b64decode(x))\n")
    results, incomplete = await run_semgrep(_ctx(tmp_path), [target], ("python",))
    assert str(target) not in incomplete
    assert any(r["path"] == str(target) and r["start"]["line"] == 4 for r in results)
    assert not (tmp_path / "work" / "semgrep-compat").exists()


async def test_file_semgrep_could_not_open_is_analysed_in_a_copy(tmp_path, monkeypatch):
    # No HA o Semgrep não abre parte dos .js de /config ("Permission denied"), embora o auditor leia.
    import json as _json

    from auditor.scanners import static as static_mod
    from auditor.tools import ToolResult

    from .test_protecoes import _ctx
    card = tmp_path / "card.js"
    card.write_text("eval(x)\n")
    seen = []

    async def fake_run_tool(args, **kw):
        files = [a for a in args if a.endswith(".js")]
        seen.append(files)
        if files == [str(card)]:
            err = {"type": "Other syntax error", "path": str(card),
                   "message": f"Other syntax error at line {card}:1: Unix_error: Permission denied open {card}"}
            return ToolResult(1, _json.dumps({"results": [], "errors": [err]}), "")
        (copy,) = files
        assert copy != str(card) and Path(copy).read_text() == "eval(x)\n"
        hit = {"check_id": "auditor.js.eval-dinamico", "path": copy, "start": {"line": 1}, "end": {"line": 1}}
        return ToolResult(1, _json.dumps({"results": [hit], "errors": []}), "")

    monkeypatch.setattr(static_mod, "run_tool", fake_run_tool)
    results, incomplete = await static_mod.run_semgrep(_ctx(tmp_path), [card], ("javascript",))
    assert len(seen) == 2 and incomplete == {}
    assert [r["path"] for r in results] == [str(card)]


def test_file_size_limit_option():
    from auditor.config import Options
    assert Options.from_dict({}).max_file_bytes == 6 * 1024 * 1024
    assert Options.from_dict({"limite_arquivo_mb": 12}).max_file_bytes == 12 * 1024 * 1024
    assert Options.from_dict({"limite_arquivo_mb": 0}).max_file_mb == 1
    assert Options.from_dict({"limite_arquivo_mb": 500}).max_file_mb == 64


def test_code_hosts_reread_when_limit_changes(tmp_path):
    from auditor import code_hosts
    from auditor.inventory import discover

    from .test_ajustes_regras import PY_RULES
    rules = PY_RULES.parents[1]
    comp = tmp_path / "config" / "custom_components" / "c"
    comp.mkdir(parents=True)
    (comp / "manifest.json").write_text('{"domain": "c", "name": "c", "version": "1"}')
    (comp / "api.py").write_text('URL = "https://servidor-estranho.com/x"\n' + "#" * 2_000_000 + "\n")
    cache = tmp_path / "cache"
    small = code_hosts.build(discover(tmp_path / "config"), cache, rules, 1024 * 1024)
    assert "servidor-estranho.com" not in small.per_component.get("integracao/c", {})
    big = code_hosts.build(discover(tmp_path / "config"), cache, rules, 4 * 1024 * 1024)
    assert "servidor-estranho.com" in big.per_component["integracao/c"]


async def test_semgrep_crash_isolates_the_file(tmp_path, monkeypatch):
    # Um card enorme fazia o Semgrep ser morto por falta de memória e a análise de código inteira se perdia.
    import json as _json

    from auditor.scanners import static as static_mod
    from auditor.tools import ToolResult

    from .test_protecoes import _ctx
    files = [tmp_path / f"f{n}.js" for n in range(5)]
    for f in files:
        f.write_text("eval(x)\n")
    bad = str(files[3])

    async def fake_run_tool(args, **kw):
        targets = [a for a in args if a.endswith(".js")]
        if bad in targets:
            return ToolResult(2, "", "You are seeing this because the engine was killed.")
        hits = [{"check_id": "auditor.js.eval-dinamico", "path": t, "start": {"line": 1}, "end": {"line": 1}}
                for t in targets]
        return ToolResult(1, _json.dumps({"results": hits, "errors": []}), "")

    monkeypatch.setattr(static_mod, "run_tool", fake_run_tool)
    results, incomplete = await static_mod.run_semgrep(_ctx(tmp_path), files, ("javascript",))
    assert sorted(r["path"] for r in results) == sorted(str(f) for f in files if str(f) != bad)
    assert list(incomplete) == [bad] and incomplete[bad]["tipo"] == "Falha do Semgrep"
    assert "engine was killed" in incomplete[bad]["mensagem"]


async def test_bandit_still_runs_when_semgrep_fails(tmp_path, monkeypatch):
    from auditor.scanners import static as static_mod
    from auditor.scanners.static import StaticAnalysisScanner

    from .test_protecoes import _ctx
    comp = tmp_path / "config" / "custom_components" / "c"
    comp.mkdir(parents=True)
    (comp / "manifest.json").write_text('{"domain": "c", "name": "c", "version": "1"}')
    (comp / "__init__.py").write_text("x = 1\n")

    async def broken(*a, **kw):
        raise RuntimeError("semgrep quebrou")

    async def fake_bandit(self, ctx, inv, dirs):
        return ["bandit rodou"]

    monkeypatch.setattr(static_mod, "run_semgrep", broken)
    monkeypatch.setattr(StaticAnalysisScanner, "_bandit", fake_bandit)
    monkeypatch.setattr(static_mod, "_merge_same_line", lambda sg, bd: [*sg, *bd])
    out = await StaticAnalysisScanner().scan(_ctx(tmp_path))
    assert "bandit rodou" in out
    (failed,) = [f for f in out if getattr(f, "rule_id", "") == "auditor.semgrep-falhou"]
    assert "semgrep quebrou" in failed.explanation
