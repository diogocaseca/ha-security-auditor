"""Registro do HACS: formato antigo (hacs.repositories) e novo (hacs.data)."""

from __future__ import annotations

import json
import logging

from auditor.inventory import discover, load_hacs


def _store(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "minor_version": 1, "key": path.name, "data": data}))


def _install(config, *, integration="minha", card="meu-card"):
    (config / f"custom_components/{integration}").mkdir(parents=True)
    (config / f"custom_components/{integration}/__init__.py").write_text("x = 1")
    (config / f"www/community/{card}").mkdir(parents=True)
    (config / f"www/community/{card}/{card}.js").write_text("x")


def test_new_format_hacs_data_only(tmp_path):
    _install(tmp_path)
    _store(tmp_path / ".storage/hacs.data", {"repositories": {
        "integration": [{"id": "1", "full_name": "dono/ha-minha", "domain": "minha", "installed": True,
                         "version_installed": "1.2.0"},
                        {"id": "2", "full_name": "outro/catalogo"}],  # só no catálogo: não baixado
        "plugin": [{"id": "3", "full_name": "dono/meu-card", "installed": True, "version_installed": "v2.0.0"}],
    }})
    inv = discover(tmp_path)
    by = {c.name: c for c in inv.integrations + inv.frontend}
    assert by["minha"].hacs.full_name == "dono/ha-minha" and by["minha"].hacs.category == "integration"
    assert by["meu-card"].hacs.version_installed == "v2.0.0"
    assert by["meu-card"].metadata()["origem"] == "HACS"
    assert [e.full_name for e in inv.hacs_entries] == ["dono/ha-minha", "dono/meu-card"]


def test_old_format_ignores_catalog_entries(tmp_path):
    _install(tmp_path)
    _store(tmp_path / ".storage/hacs.repositories", {
        "1": {"full_name": "dono/ha-minha", "category": "integration", "domain": "minha", "installed": True,
              "version_installed": "1.2.0"},
        "9": {"full_name": "alguem/meu-card", "category": "plugin"},  # catálogo com o mesmo nome do card
        "3": {"full_name": "dono/meu-card", "category": "plugin", "installed": True, "version_installed": "v2.0.0"},
    })
    inv = discover(tmp_path)
    by = {c.name: c for c in inv.integrations + inv.frontend}
    assert by["meu-card"].hacs.full_name == "dono/meu-card"


def test_both_files_are_merged_by_id(tmp_path):
    _store(tmp_path / ".storage/hacs.repositories", {
        "1": {"full_name": "dono/a", "category": "plugin", "installed": True}})
    _store(tmp_path / ".storage/hacs.data", {"repositories": {"plugin": [
        {"id": "1", "full_name": "dono/a", "installed": True}, {"id": "2", "full_name": "dono/b", "installed": True}]}})
    assert sorted(e.full_name for e in load_hacs(tmp_path)) == ["dono/a", "dono/b"]


def test_unknown_format_is_logged(tmp_path, caplog):
    (tmp_path / ".storage").mkdir()
    (tmp_path / ".storage/hacs.marketplace").write_text("{}")
    with caplog.at_level(logging.WARNING):
        assert load_hacs(tmp_path) == []
    assert "hacs.marketplace" in caplog.text


def test_marketplace_files(tmp_path, caplog):
    """O HACS virou Marketplace: os arquivos passaram a ser .storage/marketplace.*."""
    _install(tmp_path)
    _store(tmp_path / ".storage/marketplace.repositories", {
        "1": {"full_name": "dono/ha-minha", "category": "integration", "domain": "minha", "installed": True,
              "version_installed": "1.2.0"},
        "3": {"full_name": "dono/meu-card", "category": "plugin", "installed": True, "version_installed": "v2.0.0"},
        "7": {"full_name": "outro/catalogo", "category": "plugin"},
    })
    (tmp_path / ".storage/marketplace.critical").write_text("{}")
    with caplog.at_level(logging.INFO):
        inv = discover(tmp_path)
    by = {c.name: c for c in inv.integrations + inv.frontend}
    assert by["minha"].hacs.full_name == "dono/ha-minha" and by["meu-card"].hacs.full_name == "dono/meu-card"
    assert "marketplace.repositories" in caplog.text and "2 repositório(s) baixado(s) de 3" in caplog.text


def test_registry_without_downloaded_entries_warns(tmp_path, caplog):
    _store(tmp_path / ".storage/marketplace.repositories", {"7": {"full_name": "outro/catalogo", "category": "plugin"}})
    with caplog.at_level(logging.WARNING):
        assert load_hacs(tmp_path) == []
    assert "nenhum marcado como baixado" in caplog.text


def test_unknown_marketplace_format_is_logged(tmp_path, caplog):
    (tmp_path / ".storage").mkdir()
    (tmp_path / ".storage/marketplace.critical").write_text("{}")
    (tmp_path / ".storage/marketplace.repositories").write_text('{"version": 9, "data": []}')
    with caplog.at_level(logging.WARNING):
        assert load_hacs(tmp_path) == []
    assert "marketplace.critical" in caplog.text and "marketplace.repositories" in caplog.text
