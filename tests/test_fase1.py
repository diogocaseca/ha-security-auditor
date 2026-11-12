"""Fase 1: integrações customizadas (inventário, análise estática, dependências, integridade)."""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from auditor.config import Options, Paths
from auditor.engine import ScanEngine
from auditor.inventory import discover
from auditor.masking import Masker
from auditor.models import ComponentType, Severity
from auditor.net import HttpError
from auditor.scanners import deps as deps_mod
from auditor.scanners.base import ScanContext
from auditor.scanners.deps import DependencyScanner, PinnedReq, classify, findings_from_pip_audit
from auditor.scanners.integrity import IntegrityScanner, candidate_refs
from auditor.scanners.static import StaticAnalysisScanner
from auditor.tools import ToolNotFoundError, ToolResult, find_tool

from .conftest import FIXTURES

RULES = Path(__file__).parents[1] / "security_auditor/app/rules"


def _have(tool: str) -> bool:
    try:
        find_tool(tool)
        return True
    except ToolNotFoundError:
        return False


needs_tools = pytest.mark.skipif(not (_have("semgrep") and _have("bandit")), reason="semgrep/bandit ausentes")


# --- Infra de teste ------------------------------------------------------------


def _tar_of(prefix: str, files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _dir_files(root: Path, under: str) -> dict[str, bytes]:
    return {f"{under}/{p.relative_to(root).as_posix()}": p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


class FakeGitHub:
    """Imita o SafeHttpClient servindo conteúdo pré-definido por URL."""

    def __init__(self, routes: dict[str, bytes | dict]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    async def download(self, url: str, dest: Path, max_bytes: int = 0) -> Path:
        self.calls.append(url)
        if url not in self.routes:
            raise HttpError(404, url)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.routes[url])  # type: ignore[arg-type]
        return dest

    async def get_json(self, url: str, headers=None):
        self.calls.append(url)
        if url not in self.routes:
            raise HttpError(404, url)
        return self.routes[url]


def github_routes() -> dict[str, bytes | dict]:
    cc = FIXTURES / "config/custom_components"
    limpa = _tar_of("ha-limpa-1.0.0", _dir_files(cc / "limpa", "custom_components/limpa"))
    adulterada = _tar_of(
        "ha-adulterada-1.0.0",
        {**_dir_files(FIXTURES / "upstream/adulterada", "custom_components/adulterada"), "hacs.json": b'{"name": "x"}'},
    )
    return {
        # HACS gravou "v1.0.0": a tag existe assim.
        "https://codeload.github.com/exemplo/ha-limpa/tar.gz/v1.0.0": limpa,
        # HACS gravou "1.0.0" mas a tag é "v1.0.0": precisa tentar a variante.
        "https://codeload.github.com/exemplo/ha-adulterada/tar.gz/v1.0.0": adulterada,
    }


@pytest.fixture
def fixture_paths(tmp_path: Path) -> Paths:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return Paths(config_dir=FIXTURES / "config", data_dir=data, rules_dir=RULES)


def _ctx(paths: Paths, tmp_path: Path, http, storage=None, options: Options | None = None) -> ScanContext:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return ScanContext(
        paths=paths, options=options or Options(), http=http, supervisor=None, storage=storage,
        masker=Masker(), workdir=work, scan_id="t",
    )


def _by(findings, component):
    return [f for f in findings if f.component == component]


# --- Inventário ------------------------------------------------------------------


def test_inventory_discovers_components_and_hacs():
    inv = discover(FIXTURES / "config")
    assert [c.name for c in inv.integrations] == ["adulterada", "limpa", "ofuscada"]
    assert [c.name for c in inv.frontend] == ["card-suspeito"]
    by = {c.name: c for c in inv.integrations}
    assert by["limpa"].hacs.full_name == "exemplo/ha-limpa"
    assert by["limpa"].version == "v1.0.0"
    assert by["ofuscada"].hacs is None and by["ofuscada"].github_repo() is None
    assert by["adulterada"].github_repo() == ("exemplo", "ha-adulterada")
    assert inv.frontend[0].hacs.full_name == "exemplo/card-suspeito"
    assert "removida" not in {e.domain for e in inv.hacs_entries}


def test_candidate_refs_variants():
    inv = discover(FIXTURES / "config")
    by = {c.name: c for c in inv.integrations}
    assert candidate_refs(by["adulterada"]) == ["1.0.0", "v1.0.0"]
    assert candidate_refs(by["limpa"]) == ["v1.0.0", "1.0.0"]


# --- Análise estática --------------------------------------------------------------


@needs_tools
async def test_static_analysis_on_fixtures(fixture_paths, tmp_path):
    ctx = _ctx(fixture_paths, tmp_path, http=None)
    findings = await StaticAnalysisScanner().scan(ctx)

    # Limpa: nada acima de informativo.
    assert [f for f in _by(findings, "limpa") if f.severity > Severity.INFO] == []

    ofus = _by(findings, "ofuscada")
    rules = {f.rule_id for f in ofus}
    assert "auditor.py.ofuscacao-decodifica-e-executa" in rules
    assert "auditor.py.download-e-execucao" in rules
    assert "auditor.py.acesso-secrets-yaml" in rules
    assert "auditor.py.destino-suspeito" in rules
    assert max(f.severity for f in ofus) is Severity.CRITICAL
    # A ofuscação e o eval genérico na mesma linha viram um achado só.
    ofus_lines = [f.line for f in ofus if f.rule_id == "auditor.py.ofuscacao-decodifica-e-executa"]
    assert not any(f.rule_id == "auditor.py.eval-dinamico" and f.line in ofus_lines for f in ofus)
    # Bandit é absorvido pelo Semgrep na mesma linha.
    exec_line = next(f for f in ofus if f.rule_id == "auditor.py.ofuscacao-decodifica-e-executa")
    assert "bandit" in exec_line.extra.get("sources", [])
    assert exec_line.snippet and "exec(" in exec_line.snippet
    assert exec_line.file == "custom_components/ofuscada/__init__.py"

    adult = {f.rule_id for f in _by(findings, "adulterada")}
    assert {"auditor.py.acesso-storage-auth", "auditor.py.ip-fixo-publico"} <= adult

    card = _by(findings, "card-suspeito")
    assert {f.rule_id for f in card} >= {"auditor.js.acesso-token-ha", "auditor.js.destino-suspeito"}
    assert all(f.component_type == ComponentType.FRONTEND for f in card)


# --- Dependências ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "kind"),
    [
        ("requests==2.19.0", "fixado"),
        ("PyExemplo_Lib==1.0", "fixado"),
        ("requests>=2.0", "sem_versao"),
        ("requests==2.*", "sem_versao"),
        ("requests", "sem_versao"),
        ("git+https://example.com/lib.git", "url"),
        ("pkg @ https://example.com/pkg.whl", "url"),
        ("!!!", "invalido"),
    ],
)
def test_classify_requirements(raw, kind):
    assert classify(raw)[0] == kind


def test_pip_audit_output_mapping():
    inv = discover(FIXTURES / "config")
    comp = next(c for c in inv.integrations if c.name == "ofuscada")
    req = PinnedReq("requests", "2.19.0", "requests==2.19.0")
    data = {"dependencies": [
        {"name": "requests", "version": "2.19.0", "vulns": [
            {"id": "PYSEC-1", "fix_versions": ["2.32.0"], "aliases": ["CVE-2024-1", "GHSA-x"]},
            {"id": "PYSEC-2", "fix_versions": ["2.33.0"], "aliases": []},
        ]},
        {"name": "outro", "version": "1.0", "vulns": []},
    ]}
    (f,) = findings_from_pip_audit(data, {req: [comp]})
    assert f.severity is Severity.MEDIUM and f.component == "ofuscada"
    assert "CVE-2024-1" in f.explanation and "2.32.0" in f.explanation
    assert f.file == "custom_components/ofuscada/manifest.json"


async def test_dependency_scanner_uses_offline_flags(fixture_paths, tmp_path, monkeypatch):
    seen = {}

    async def fake_run_tool(args, **kw):
        seen["args"] = args
        seen["req"] = Path(args[args.index("-r") + 1]).read_text()
        return ToolResult(1, json.dumps({"dependencies": [
            {"name": "requests", "version": "2.19.0", "vulns": [{"id": "PYSEC-1", "fix_versions": [], "aliases": []}]}
        ]}), "")

    monkeypatch.setattr(deps_mod, "run_tool", fake_run_tool)
    findings = await DependencyScanner().scan(_ctx(fixture_paths, tmp_path, http=None))
    assert {"--no-deps", "--disable-pip"} <= set(seen["args"]) and "osv" in seen["args"]
    assert seen["req"] == "requests==2.19.0\n"
    rules = {(f.component, f.rule_id) for f in findings}
    assert ("ofuscada", "auditor.deps.vulnerabilidade-conhecida") in rules
    assert ("ofuscada", "auditor.deps.fonte-url") in rules
    assert ("limpa", "auditor.deps.sem-versao-fixa") in rules


# --- Integridade ------------------------------------------------------------------


async def test_integrity_clean_tampered_and_unknown(fixture_paths, tmp_path):
    gh = FakeGitHub(github_routes())
    ctx = _ctx(fixture_paths, tmp_path, http=gh)
    findings = await IntegrityScanner().scan(ctx)

    assert _by(findings, "limpa") == []
    assert ctx.components[("integracao", "limpa")]["integridade"].startswith("verificada contra exemplo/ha-limpa@v1.0.0")

    adult = {f.rule_id: f for f in _by(findings, "adulterada")}
    assert set(adult) == {"auditor.integridade.arquivo-alterado", "auditor.integridade.arquivo-extra"}
    mod = adult["auditor.integridade.arquivo-alterado"]
    assert mod.severity is Severity.HIGH and mod.file == "custom_components/adulterada/__init__.py"
    assert "+    hass.async_create_task(_cache.sincroniza(hass))" in mod.snippet
    extra = adult["auditor.integridade.arquivo-extra"]
    assert extra.file == "custom_components/adulterada/_cache.py" and "sincroniza" in extra.snippet

    (ofus,) = _by(findings, "ofuscada")
    assert ofus.rule_id == "auditor.integridade.origem-desconhecida"

    # Segunda varredura usa o cache: nenhum download novo.
    gh.calls.clear()
    ctx2 = _ctx(fixture_paths, tmp_path, http=gh)
    again = await IntegrityScanner().scan(ctx2)
    assert gh.calls == []
    assert {f.fingerprint for f in again} == {f.fingerprint for f in findings}


async def test_integrity_version_not_found(fixture_paths, tmp_path):
    findings = await IntegrityScanner().scan(_ctx(fixture_paths, tmp_path, http=FakeGitHub({})))
    limpa = _by(findings, "limpa")
    assert [f.rule_id for f in limpa] == ["auditor.integridade.nao-verificada"]
    assert limpa[0].severity is Severity.INFO and "v1.0.0" in limpa[0].explanation


async def test_integrity_rate_limit_message(fixture_paths, tmp_path):
    class Limited(FakeGitHub):
        async def download(self, url, dest, max_bytes=0):
            raise HttpError(403, url)

    findings = await IntegrityScanner().scan(_ctx(fixture_paths, tmp_path, http=Limited({})))
    assert "github_token" in _by(findings, "limpa")[0].explanation


async def test_integrity_zip_release_and_persistent_directory(tmp_path):
    # Integração distribuída como zip na release, com pasta de dados persistente.
    config = tmp_path / "config"
    comp = config / "custom_components/zipada"
    (comp / "dados").mkdir(parents=True)
    (comp / "__init__.py").write_text("X = 1\n")
    (comp / "manifest.json").write_text('{"domain": "zipada", "version": "2.0"}')
    (comp / "dados/estado.json").write_text("{}")  # criado em uso, protegido pelo persistent_directory
    (config / ".storage").mkdir()
    (config / ".storage/hacs.repositories").write_text(json.dumps({"data": {"1": {
        "full_name": "dono/zipada", "category": "integration", "domain": "zipada", "version_installed": "2.0"}}}))
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("__init__.py", "X = 1\n")
        zf.writestr("manifest.json", '{"domain": "zipada", "version": "2.0"}')
    routes = {
        "https://codeload.github.com/dono/zipada/tar.gz/2.0": _tar_of("zipada-2.0", {
            "hacs.json": b'{"zip_release": true, "filename": "zipada.zip", "persistent_directory": "dados"}'}),
        "https://api.github.com/repos/dono/zipada/releases/tags/2.0": {
            "assets": [{"name": "zipada.zip", "browser_download_url": "https://github.com/dono/zipada/zipada.zip"}]},
        "https://github.com/dono/zipada/zipada.zip": zbuf.getvalue(),
    }
    data = tmp_path / "data"
    data.mkdir()
    paths = Paths(config_dir=config, data_dir=data, rules_dir=RULES)
    ctx = _ctx(paths, tmp_path, http=FakeGitHub(routes))
    assert await IntegrityScanner().scan(ctx) == []
    assert "zipada@2.0" in ctx.components[("integracao", "zipada")]["integridade"]


# --- Ponta a ponta ------------------------------------------------------------------


@needs_tools
async def test_end_to_end_report(fixture_paths, tmp_path, monkeypatch, storage):
    async def fake_pip_audit(args, **kw):
        return ToolResult(0, '{"dependencies": []}', "")

    monkeypatch.setattr(deps_mod, "run_tool", fake_pip_audit)
    masker = Masker()
    masker.load_secrets_yaml(fixture_paths.config_dir / "secrets.yaml")
    engine = ScanEngine(
        paths=fixture_paths, options=Options(), storage=storage, masker=masker,
        http=FakeGitHub(github_routes()), supervisor=None,
        scanners=[StaticAnalysisScanner(), DependencyScanner(), IntegrityScanner()],
    )
    result = await engine.run()
    assert result.status == "concluida", result.errors
    scores = {c.name: c.score for c in result.components}
    assert scores["limpa"] == 0
    assert scores["ofuscada"] == 100 and scores["adulterada"] >= 40
    assert result.counts()["critical"] >= 3
    report = json.dumps(result.to_dict(), ensure_ascii=False)
    assert "SenhaDeTesteDoAuditor42" not in report


def test_fixture_tree_is_untouched():
    # Garante que nenhum teste escreveu na pasta de fixtures (ela simula o /config somente leitura).
    names = sorted(p.name for p in (FIXTURES / "config/custom_components/adulterada").iterdir())
    assert names == ["__init__.py", "_cache.py", "const.py", "manifest.json"]
    assert not any(p.name == "__pycache__" for p in (FIXTURES / "config").rglob("*"))
