"""Botão "Excluir…": tira o componente da tabela até ele ser reinstalado, atualizado ou sumir."""

from __future__ import annotations

import ipaddress
import itertools
import os

import pytest

from auditor.config import Options
from auditor.scheduler import Scheduler
from auditor.web import CSRF_HEADER, create_app

from .conftest import make_finding
from .test_engine_web import _engine


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    ids = itertools.count()
    monkeypatch.setattr("auditor.engine.new_scan_id", lambda: f"20261114T10{next(ids):04d}000000Z")


class Inventario:
    """Usa o inventário de verdade (respeita exclusões) e devolve um achado por integração."""

    name = "falso"

    async def scan(self, ctx):
        inv = ctx.inventory()
        return [make_finding(component=c.name, file=f"custom_components/{c.name}/x.py", snippet=f"eval({c.name})")
                for c in inv.integrations]


def _write(path, text="x = 1"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
async def client(aiohttp_client, paths, storage, masker):
    _write(paths.config_dir / "custom_components/removida/__init__.py")
    _write(paths.config_dir / "custom_components/fica/__init__.py")
    engine = _engine(paths, storage, masker, Options(), [Inventario()])
    await engine.run()
    app = create_app(storage, Scheduler(engine.run, 0, False), engine.progress,
                     allowed_peers={ipaddress.ip_address("127.0.0.1")}, config_dir=paths.config_dir)
    c = await aiohttp_client(app)
    html = await (await c.get("/")).text()
    token = html.split('name="csrf-token" content="')[1].split('"')[0]
    return c, {CSRF_HEADER: token}, engine


def _names(result):
    return {c.name for c in result.components}, {f.component for f in result.findings}


async def test_exclude_hides_until_reinstalled(client, paths, storage):
    c, h, engine = client
    html = await (await c.get("/")).text()
    assert 'data-exclude-component="removida"' in html and "Remove…" in html
    assert 'data-skip-component="removida"' in html and "Don&#39;t scan…" in html

    assert (await c.post("/api/componentes/excluidos", json={"tipo": "integracao", "nome": "removida"})).status == 403
    resp = await c.post("/api/componentes/excluidos", headers=h, json={"tipo": "integracao", "nome": "removida"})
    assert resp.status == 201
    # Sai do relatório na hora, sem esperar a varredura.
    assert _names(storage.load_latest()) == ({"fica"}, {"fica"})
    html = await (await c.get("/")).text()
    assert "Components removed from the table (1)" in html and 'data-restore-component="removida"' in html

    # Nas varreduras seguintes continua fora, enquanto os arquivos não mudarem.
    assert _names(await engine.run()) == ({"fica"}, {"fica"})
    assert ("integracao", "removida") in storage.excluded_map()

    # Reinstalada (arquivos mudam): volta a ser analisada e a exclusão some.
    p = paths.config_dir / "custom_components/removida/__init__.py"
    p.write_text("x = 2  # versão nova")
    os.utime(p, ns=(1, 1))
    assert _names(await engine.run()) == ({"fica", "removida"}, {"fica", "removida"})
    assert storage.excluded_map() == {}


async def test_exclusion_forgotten_when_folder_disappears(client, paths, storage):
    c, h, engine = client
    await c.post("/api/componentes/excluidos", headers=h, json={"tipo": "integracao", "nome": "removida"})
    folder = paths.config_dir / "custom_components/removida"
    (folder / "__init__.py").unlink()
    folder.rmdir()
    await engine.run()
    assert storage.excluded_map() == {}
    # Instalada de novo no futuro: é analisada normalmente.
    _write(folder / "__init__.py")
    assert "removida" in _names(await engine.run())[0]


async def test_restore(client, storage):
    c, h, engine = client
    await c.post("/api/componentes/excluidos", headers=h, json={"tipo": "integracao", "nome": "removida"})
    assert (await c.delete("/api/componentes/excluidos/integracao/removida", headers=h)).status == 204
    assert (await c.delete("/api/componentes/excluidos/integracao/removida", headers=h)).status == 404
    assert "removida" in _names(await engine.run())[0]


@pytest.mark.parametrize("body, status", [
    ({"tipo": "integracao", "nome": "nao_existe"}, 404),
    ({"tipo": "rede", "nome": "dns"}, 400),
    ({"tipo": "integracao", "nome": "../segredo"}, 400),
    ({"tipo": "integracao"}, 400),
])
async def test_exclude_rejects(client, body, status):
    c, h, _ = client
    assert (await c.post("/api/componentes/excluidos", headers=h, json=body)).status == status


async def test_partial_scan_keeps_component_excluded(client, storage):
    """A verificação de instalações não traz de volta um componente excluído que não mudou."""
    c, h, engine = client
    await c.post("/api/componentes/excluidos", headers=h, json={"tipo": "integracao", "nome": "removida"})
    part = await engine.run([{"tipo": "integracao", "nome": "removida", "mudanca": "atualizado"}])
    assert "removida" not in _names(part)[0] and ("integracao", "removida") in storage.excluded_map()
