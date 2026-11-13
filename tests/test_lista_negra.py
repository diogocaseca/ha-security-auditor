"""Lista negra (fase 1): formato, comparação local e exibição."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from auditor.blocklist import Blocklist, BlocklistError, load, load_file, parse, personal_path, version_affected
from auditor.models import ComponentType, Severity
from auditor.report import render_html
from auditor.scanners.blocklist import BlocklistScanner

from .conftest import FIXTURES
from .test_fase2 import FakeSupervisor, _addon
from .test_protecoes import _ctx


def _item(**kw) -> dict:
    base = {"id": "T-1", "nivel": "alta", "categoria": "malicioso", "motivo": "Envia o token para fora."}
    base.update(kw)
    return base


def _list(*items) -> dict:
    return {"versao": 1, "itens": list(items)}


# --- Formato ------------------------------------------------------------------------------------


def test_parse_valid_and_invalid_items():
    entries, errors = parse(_list(
        _item(id="ok-1", github="Dono/Repo", versoes="<1.4.2", evidencias=["https://github.com/x/y/issues/1"]),
        _item(id="ok-2", nome="meu_*", tipo="integracao"),
        _item(id="ok-1", github="a/b"),  # id repetido
        _item(id="sem-alvo"),
        _item(id="nivel", github="a/b", nivel="urgente"),
        _item(id="link", github="a/b", evidencias=["javascript:alert(1)"]),
        _item(id="versao", github="a/b", versoes="depois da 2"),
        _item(id="curinga", nome="*"),
        _item(id="tipo", github="a/b", tipo="tema"),
        "texto",
    ), "pessoal")
    assert [e.id for e in entries] == ["ok-1", "ok-2"]
    assert entries[0].severity is Severity.HIGH and entries[0].origem == "pessoal"
    assert len(errors) == 8
    assert any("repetido" in e for e in errors) and any("https://" in e for e in errors)


@pytest.mark.parametrize("data", [[], {"versao": 2, "itens": []}, {"versao": 1}, {"versao": 1, "itens": {}}])
def test_parse_rejects_unknown_format(data):
    with pytest.raises(BlocklistError):
        parse(data, "pessoal")


@pytest.mark.parametrize(("spec", "installed", "affected"), [
    ("", "1.0.0", True),
    ("<1.4.2", "1.4.1", True),
    ("<1.4.2", "v1.4.2", False),
    (">=1.0,<1.2", "1.1.5", True),
    (">=1.0,<1.2", "0.9", False),
    ("<2.0", None, True),  # versão desconhecida: melhor avisar
    ("<2.0", "nightly-abc", True),  # não comparável: melhor avisar
])
def test_version_affected(spec, installed, affected):
    assert version_affected(spec, installed) is affected


def test_matches_rules():
    entries, _ = parse(_list(
        _item(id="gh", github="exemplo/HA-Adulterada"),
        _item(id="nome", nome="ofusc*", tipo="integracao", nivel="critica"),
        _item(id="outro-projeto", nome="limpa", github="outro/limpa"),
        _item(id="img", imagem="ghcr.io/terceiro/{arch}-addon-exemplo", tipo="addon"),
        _item(id="corrigido", github="exemplo/ha-limpa", versoes="<1.0.0"),
    ), "comunitária")
    bl = Blocklist(entries)
    (m,) = bl.matches(ComponentType.INTEGRATION, "adulterada", github=["exemplo/ha-adulterada"])
    assert m.entry.id == "gh" and m.strong  # GitHub sem diferenciar maiúsculas
    (m,) = bl.matches(ComponentType.INTEGRATION, "ofuscada")
    assert m.entry.id == "nome" and not m.strong
    assert bl.matches(ComponentType.FRONTEND, "ofuscada") == []  # tipo diferente
    # Mesmo nome, mas o componente tem outro repositório: é outro projeto.
    assert bl.matches(ComponentType.INTEGRATION, "limpa", github=["exemplo/ha-limpa"], version="1.0.0") == []
    (m,) = bl.matches(ComponentType.ADDON, "abc123_exemplo", image="ghcr.io/terceiro/amd64-addon-exemplo")
    assert m.entry.id == "img" and m.strong
    # Versão fora da faixa afetada não gera aviso.
    assert bl.matches(ComponentType.INTEGRATION, "x", github=["exemplo/ha-limpa"], version="v1.0.0") == []


def test_load_file_errors(tmp_path):
    assert load_file(tmp_path / "nao-existe.json", "pessoal") == ([], [])
    bad = tmp_path / "lista.json"
    bad.write_text("{ quebrado")
    entries, errors = load_file(bad, "pessoal")
    assert entries == [] and "não é um JSON válido" in errors[0]
    bad.write_text(json.dumps({"versao": 9, "itens": []}))
    assert "formato desconhecido" in load_file(bad, "pessoal")[1][0]


# --- Scanner ------------------------------------------------------------------------------------


@pytest.fixture
def config_with_list(tmp_path) -> Path:
    config = tmp_path / "config"
    shutil.copytree(FIXTURES / "config", config, symlinks=True)
    path = personal_path(config)
    path.parent.mkdir()
    path.write_text(json.dumps(_list(
        _item(id="P-1", github="exemplo/ha-adulterada", nivel="critica", categoria="comprometido",
              versoes="<=1.0.0", evidencias=["https://github.com/exemplo/ha-adulterada/issues/7"]),
        _item(id="P-2", nome="ofuscada", tipo="integracao", nivel="alta", categoria="malicioso"),
        _item(id="P-3", github="exemplo/ha-limpa", versoes="<1.0.0", categoria="vulneravel"),  # já corrigido
        _item(id="P-4", imagem="ghcr.io/terceiro/{arch}-addon-exemplo", categoria="telemetria", nivel="aviso"),
        _item(id="ruim", nivel="x", github="a/b"),
    )))
    return config


async def test_scanner_reports_and_marks_components(tmp_path, config_with_list):
    sup = FakeSupervisor([_addon(image="ghcr.io/terceiro/amd64-addon-exemplo")])
    ctx = _ctx(tmp_path, sup, config_dir=config_with_list)
    findings = await BlocklistScanner().scan(ctx)
    by = {f.component: f for f in findings}

    adulterada = by["adulterada"]
    assert adulterada.severity is Severity.CRITICAL and adulterada.rule_id == "auditor.lista-negra.comprometido"
    assert adulterada.title.startswith("Na lista negra pessoal") and "P-1" in adulterada.snippet
    assert adulterada.extra["evidencias"] == ["https://github.com/exemplo/ha-adulterada/issues/7"]
    # Só pelo nome: severidade um nível abaixo e texto de "possível correspondência".
    assert by["ofuscada"].severity is Severity.MEDIUM and by["ofuscada"].title.startswith("Possível")
    assert "limpa" not in by  # versão instalada já corrigida
    assert by["abc123_exemplo"].severity is Severity.LOW
    # Item inválido vira aviso de arquivo com erro, sem derrubar o resto.
    assert by["auditor"].rule_id == "auditor.lista-negra.arquivo-invalido"

    meta = ctx.components[(ComponentType.INTEGRATION, "adulterada")]["lista_negra"]
    assert meta == {"id": "P-1", "categoria": "comprometido", "nivel": "critica", "forte": True,
                    "origem": "pessoal", "total": 1}
    assert ctx.components[(ComponentType.INTEGRATION, "ofuscada")]["lista_negra"]["forte"] is False


async def test_scanner_without_list_does_nothing(tmp_path):
    ctx = _ctx(tmp_path, config_dir=FIXTURES / "config")
    assert await BlocklistScanner().scan(ctx) == []
    assert not any("lista_negra" in m for m in ctx.components.values())


def test_load_merges_community_cache_and_personal(tmp_path, config_with_list):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "lista_comunitaria.json").write_text(json.dumps(_list(_item(id="C-1", github="x/y"))))
    bl = load(config_with_list, cache)
    assert {e.origem for e in bl.entries} == {"comunitária", "pessoal"}
    assert bl.sources == ["lista comunitária (1 itens)", "lista pessoal (4 itens)"]


async def test_badge_and_evidence_links_in_report(tmp_path, config_with_list):
    from auditor.models import ScanResult
    from auditor.scoring import summarize

    ctx = _ctx(tmp_path, FakeSupervisor([]), config_dir=config_with_list)
    findings = await BlocklistScanner().scan(ctx)
    result = ScanResult(scan_id="x", started_at="2026-11-13T00:00:00+00:00", status="concluida",
                        findings=findings, components=summarize(findings, ctx.components))
    html = " ".join(render_html(result, status={}, history=[], csrf_token="t").split())
    assert 'badge sev-critical badge-blocklist" title="Item P-1 da lista pessoal · comprometido"> Lista negra</span>' in html
    assert "Lista negra?</span>" in html  # correspondência só pelo nome
    assert ('<a href="https://github.com/exemplo/ha-adulterada/issues/7" target="_blank" '
            'rel="noopener noreferrer">') in html
