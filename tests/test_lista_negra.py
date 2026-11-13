"""Lista negra (fase 1): formato, comparação local e exibição."""

from __future__ import annotations

import json

import pytest

from auditor.blocklist import Blocklist, BlocklistError, load, load_file, parse, version_affected
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
        _item(id="futuro", github="a/b", categoria="categoria-do-futuro"),  # ignorado, sem erro
        _item(id="link", github="a/b", evidencias=["javascript:alert(1)"]),
        _item(id="versao", github="a/b", versoes="depois da 2"),
        _item(id="curinga", nome="*"),
        _item(id="tipo", github="a/b", tipo="tema"),  # tipo de versão futura: ignorado, sem erro
        "texto",
    ), "pessoal")
    assert [e.id for e in entries] == ["ok-1", "ok-2"]
    assert entries[0].severity is Severity.HIGH and entries[0].origem == "pessoal"
    assert len(errors) == 7
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


PERSONAL = [
    _item(id="P-1", github="exemplo/ha-adulterada", nivel="critica", categoria="comprometido",
          versoes="<=1.0.0", evidencias=["https://github.com/exemplo/ha-adulterada/issues/7"]),
    _item(id="P-2", nome="ofuscada", tipo="integracao", nivel="alta", categoria="malicioso"),
    _item(id="P-3", github="exemplo/ha-limpa", versoes="<1.0.0", categoria="vulneravel"),  # já corrigido
    _item(id="P-4", imagem="ghcr.io/terceiro/{arch}-addon-exemplo", categoria="telemetria", nivel="aviso"),
    _item(id="ruim", nivel="x", github="a/b"),  # gravado sem validar, para testar o aviso de erro
]


def _ctx_with_personal(tmp_path, supervisor=None):
    ctx = _ctx(tmp_path, supervisor, config_dir=FIXTURES / "config")
    for item in PERSONAL:
        ctx.storage.save_blocklist_item(item, "2026-11-13T00:00:00+00:00", create=True)
    return ctx


async def test_scanner_reports_and_marks_components(tmp_path):
    sup = FakeSupervisor([_addon(image="ghcr.io/terceiro/amd64-addon-exemplo")])
    ctx = _ctx_with_personal(tmp_path, sup)
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
    # Item inválido vira aviso de erro, sem derrubar o resto.
    assert by["auditor"].rule_id == "auditor.lista-negra.item-invalido"

    meta = ctx.components[(ComponentType.INTEGRATION, "adulterada")]["lista_negra"]
    assert meta == {"id": "P-1", "categoria": "comprometido", "nivel": "critica", "forte": True,
                    "origem": "pessoal", "total": 1}
    assert ctx.components[(ComponentType.INTEGRATION, "ofuscada")]["lista_negra"]["forte"] is False


async def test_scanner_without_list_does_nothing(tmp_path):
    ctx = _ctx(tmp_path, config_dir=FIXTURES / "config")
    assert await BlocklistScanner().scan(ctx) == []
    assert not any("lista_negra" in m for m in ctx.components.values())


def test_load_merges_community_cache_and_personal(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "lista_comunitaria.json").write_text(json.dumps(_list(_item(id="C-1", github="x/y"))))
    bl = load(cache, True, PERSONAL)
    assert {e.origem for e in bl.entries} == {"comunitária", "pessoal"}
    assert bl.sources == ["lista pessoal (4 itens)", "lista comunitária (1 itens)"]
    assert [e.origem for e in load(cache, False, PERSONAL).entries] == ["pessoal"] * 4


async def test_legacy_personal_file_is_ignored_with_warning(tmp_path, caplog):
    import logging
    import shutil

    config = tmp_path / "config"
    shutil.copytree(FIXTURES / "config", config, symlinks=True)
    (config / "security_auditor").mkdir()
    (config / "security_auditor" / "lista_negra.json").write_text(json.dumps(_list(PERSONAL[0])))
    caplog.set_level(logging.WARNING, logger="auditor")
    ctx = _ctx(tmp_path, config_dir=config)
    assert await BlocklistScanner().scan(ctx) == []  # o arquivo não é lido
    assert "não é mais lido" in caplog.text


async def test_badge_and_evidence_links_in_report(tmp_path):
    from auditor.models import ScanResult
    from auditor.scoring import summarize

    ctx = _ctx_with_personal(tmp_path, FakeSupervisor([]))
    findings = await BlocklistScanner().scan(ctx)
    result = ScanResult(scan_id="x", started_at="2026-11-13T00:00:00+00:00", status="concluida",
                        findings=findings, components=summarize(findings, ctx.components))
    html = " ".join(render_html(result, status={}, history=[], csrf_token="t").split())
    assert 'badge sev-critical badge-blocklist" title="Item P-1 da lista pessoal · comprometido"> Lista negra</span>' in html
    assert "Lista negra?</span>" in html  # correspondência só pelo nome
    assert 'id="only-blocklist"' in html  # filtro aparece quando há componente marcado
    assert 'data-blocklist="forte"' in html and 'data-blocklist="possivel"' in html and 'data-blocklist=""' in html
    assert ('<a href="https://github.com/exemplo/ha-adulterada/issues/7" target="_blank" '
            'rel="noopener noreferrer">') in html


async def test_new_categories_and_source(tmp_path):
    from auditor.blocklist import Match
    from auditor.scanners.blocklist import _finding

    entries, errors = parse(_list(
        _item(id="hacs-x", github="dono/card", nivel="aviso", categoria="removido", fonte="hacs",
              motivo="Removido da lista padrão do HACS: Repository is archived"),
        _item(id="ha-spook", nome="spook", tipo="integracao", versoes="<4.0.0", categoria="incompativel",
              fonte="home-assistant", motivo="O Home Assistant bloqueia: breaks the template engine"),
        _item(id="fonte-ruim", github="a/b", fonte="blog"),
    ), "comunitária")
    assert [e.id for e in entries] == ["hacs-x", "ha-spook"] and errors == []  # fonte nova: ignorada
    f = _finding(ComponentType.INTEGRATION, "spook", "3.2.0", Match(entries[1], False, "nome spook"))
    assert "Fonte: lista de bloqueados do Home Assistant" in f.snippet
    assert f.rule_id == "auditor.lista-negra.incompativel" and "versão bloqueada" in f.title
    assert Blocklist(entries).matches(ComponentType.INTEGRATION, "spook", version="4.0.1") == []
    (m,) = Blocklist(entries).matches(ComponentType.INTEGRATION, "spook", version="3.2.0")
    assert m.strong  # o HA bloqueia pelo domínio: correspondência forte


# --- Lista pessoal pela interface ----------------------------------------------------------


@pytest.fixture
async def bl_client(aiohttp_client, tmp_path):
    import ipaddress

    from auditor.scheduler import Scheduler
    from auditor.storage import Storage
    from auditor.web import create_app

    storage = Storage(tmp_path / "db.sqlite", tmp_path / "reports")
    cache = tmp_path / "cache"
    cache.mkdir()
    app = create_app(storage, Scheduler(lambda: None, 0, False), {}, allowed_peers={ipaddress.ip_address("127.0.0.1")},
                     blocklist_cache_dir=cache)
    client = await aiohttp_client(app)
    html = await (await client.get("/")).text()
    token = html.split('name="csrf-token" content="')[1].split('"')[0]
    return client, token, storage


async def test_ui_blocklist_crud(bl_client):
    from auditor.web import CSRF_HEADER

    client, token, storage = bl_client
    h = {CSRF_HEADER: token}
    item = {"tipo": "integracao", "github": " dono/repo ", "nome": "", "versoes": "<2.0", "nivel": "critica",
            "categoria": "malicioso", "motivo": "Envia o token.", "evidencias": ["https://x.example/1", ""]}
    assert (await client.post("/api/lista-negra", json=item)).status == 403  # sem CSRF
    resp = await client.post("/api/lista-negra", headers=h, json=item)
    assert resp.status == 201
    new_id = (await resp.json())["id"]
    (saved,) = storage.list_blocklist_items()
    assert saved["item"] == {"id": new_id, "tipo": "integracao", "github": "dono/repo", "versoes": "<2.0",
                             "nivel": "critica", "categoria": "malicioso", "motivo": "Envia o token.",
                             "evidencias": ["https://x.example/1"]}

    # Edição mantém o id; validação igual à do arquivo.
    resp = await client.put(f"/api/lista-negra/{new_id}", headers=h, json={**item, "nivel": "aviso"})
    assert resp.status == 200 and storage.list_blocklist_items()[0]["item"]["nivel"] == "aviso"
    bad = await client.put(f"/api/lista-negra/{new_id}", headers=h, json={**item, "evidencias": ["javascript:x"]})
    assert bad.status == 400 and "https://" in (await bad.json())["error"]
    assert (await client.post("/api/lista-negra", headers=h,
                              json={"nivel": "alta", "categoria": "malicioso", "motivo": "x"})).status == 400
    assert (await client.put("/api/lista-negra/nao-existe", headers=h, json=item)).status == 404
    # id repetido é recusado.
    dup = await client.post("/api/lista-negra", headers=h, json={**item, "id": new_id})
    assert dup.status == 409

    html = await (await client.get("/?ver=listanegra")).text()
    assert f'data-bl-edit="{new_id}"' in html and "dono/repo" in html
    assert "Arquivo</td>" not in html and "lista_negra.json" not in html
    listing = await (await client.get("/api/lista-negra")).json()
    assert listing["interface"][0]["item"]["id"] == new_id and "arquivo" not in listing

    assert (await client.delete(f"/api/lista-negra/{new_id}", headers=h)).status == 204
    assert storage.list_blocklist_items() == []


async def test_scanner_uses_ui_items(tmp_path):
    ctx = _ctx(tmp_path, config_dir=FIXTURES / "config")
    ctx.storage.save_blocklist_item({"id": "ui-1", "github": "exemplo/ha-limpa", "nivel": "media",
                                     "categoria": "telemetria", "motivo": "Teste pela tela."},
                                    "2026-11-13T00:00:00+00:00", create=True)
    findings = await BlocklistScanner().scan(ctx)
    (f,) = [f for f in findings if f.component == "limpa"]
    assert f.severity is Severity.MEDIUM and "ui-1" in f.snippet and "pessoal" in f.title
