"""Heurísticas de ofuscação em Python e arquivos compilados sem fonte."""

from __future__ import annotations

from auditor.config import Paths
from auditor.models import Severity
from auditor.scanners.obfuscation import ObfuscationScanner

from .test_fase1 import RULES, _ctx


def _setup(tmp_path, files: dict[str, bytes | str], where="custom_components/sus"):
    config = tmp_path / "config"
    comp = config / where
    for rel, data in files.items():
        (comp / rel).parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            (comp / rel).write_text(data)
        else:
            (comp / rel).write_bytes(data)
    (tmp_path / "data").mkdir(exist_ok=True)
    return Paths(config_dir=config, data_dir=tmp_path / "data", rules_dir=RULES)


async def _rules(tmp_path, files, where="custom_components/sus"):
    paths = _setup(tmp_path, files, where)
    findings = await ObfuscationScanner().scan(_ctx(paths, tmp_path, http=None))
    return {(f.rule_id, f.file.rsplit("/", 1)[-1]): f for f in findings}


async def test_python_obfuscation_heuristics(tmp_path):
    chr_chain = "url = " + " + ".join(f"chr({ord(c)})" for c in "https://x.y/") + "\n"
    hexes = 'blob = "' + "".join(f"\\x{b:02x}" for b in b"import os;os.system('id')" * 3) + '"\n'
    names = "O0O0O0O0 = 1\nO0OO00O0 = 2\nlIlIlIlI = O0O0O0O0 + O0OO00O0\n"
    packed = "import zlib\npayload = b'...'\nexec(zlib.decompress(payload))\n"
    long_line = "x = [" + ", ".join(str(i) for i in range(800)) + "]\n"
    by = await _rules(tmp_path, {"a.py": chr_chain, "b.py": hexes, "c.py": names, "d.py": packed, "e.py": long_line})
    assert set(by) == {
        ("auditor.ofuscacao.chr-concatenado", "a.py"), ("auditor.ofuscacao.escapes-hex", "b.py"),
        ("auditor.ofuscacao.nomes-ofuscados", "c.py"), ("auditor.ofuscacao.descompacta-e-executa", "d.py"),
        ("auditor.ofuscacao.linha-enorme", "e.py"),
    }
    assert by[("auditor.ofuscacao.chr-concatenado", "a.py")].severity is Severity.HIGH
    assert by[("auditor.ofuscacao.descompacta-e-executa", "d.py")].line == 3
    assert "exec(zlib.decompress" in by[("auditor.ofuscacao.descompacta-e-executa", "d.py")].snippet


async def test_normal_python_has_no_findings(tmp_path):
    normal = (
        '"""Integração comum."""\nimport json, zlib\n\nOFFSET = 10\nLOG_LEVEL = "info"\n\n'
        "def parse(data):\n    return json.loads(zlib.decompress(data))  # descompacta, mas não executa\n\n"
        "letra = chr(65)\n# " + "comentário longo " * 200 + "\n"
    )
    assert await _rules(tmp_path, {"__init__.py": normal}) == {}


async def test_compiled_files_without_source(tmp_path):
    files = {
        "__init__.py": "x = 1\n",
        "helper.pyc": b"\x6f\x0d\x0d\x0a" + b"\x00" * 12,       # .pyc solto: o Python importa sem o .py
        "__pycache__/__init__.cpython-312.pyc": b"\x6f\x0d\x0d\x0a",  # gerado pelo HA: normal
        "lib/fast.so": b"\x7fELF\x02\x01\x01",
        "tool": b"\x7fELF\x02\x01\x01",                            # executável sem extensão
        "dados.bin.json": b'{"a": 1}',
    }
    by = await _rules(tmp_path, files)
    assert set(by) == {("auditor.compilado.pyc-solto", "helper.pyc"), ("auditor.compilado.binario", "fast.so"),
                       ("auditor.compilado.binario", "tool")}
    assert all(f.severity is Severity.HIGH for f in by.values())
    assert "ELF" in by[("auditor.compilado.binario", "tool")].title


async def test_cards_only_checked_for_binaries(tmp_path):
    """Cards são JavaScript empacotado (linhas enormes são normais): só binários contam."""
    by = await _rules(tmp_path, {"card.js": "a=1;" * 3000, "x.exe": b"MZ\x90\x00"}, where="www/community/meu-card")
    assert set(by) == {("auditor.compilado.binario", "x.exe")}
