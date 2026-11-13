"""Lista negra comunitária (fase 2): download, assinatura, cache e avisos."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditor import blocklist_update as upd
from auditor.blocklist import community_cache_path, load
from auditor.config import Options
from auditor.net import SafeHttpClient
from auditor.scanners.blocklist import BlocklistScanner

from .test_protecoes import _ctx

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KID = hashlib.sha256(PUB).hexdigest()[:16]
KEYS = {KID: base64.b64encode(PUB).decode()}


def _doc(date="2026-11-13", *ids):
    items = [{"id": i, "github": f"mau/{i}", "nivel": "alta", "categoria": "malicioso", "motivo": "Teste."}
             for i in ids]
    return (json.dumps({"versao": 1, "atualizado_em": date, "itens": items}, indent=2) + "\n").encode()


def _sig(data: bytes, key=KEY, kid=KID) -> str:
    return json.dumps({"versao": 1, "algoritmo": "ed25519", "chave": kid,
                       "assinatura": base64.b64encode(key.sign(data)).decode()})


class Server:
    """Servidor falso no lugar do raw.githubusercontent.com."""

    def __init__(self):
        self.data = _doc("2026-11-13", "A-1")
        self.sig = _sig(self.data)
        self.fail = False
        self.hits = 0

    def app(self) -> web.Application:
        async def lista(request):
            self.hits += 1
            if self.fail:
                return web.Response(status=503)
            return web.Response(body=self.data)

        async def sig(request):
            return web.Response(status=503) if self.fail else web.Response(text=self.sig)

        app = web.Application()
        app.router.add_get("/lista.json", lista)
        app.router.add_get("/lista.json.sig", sig)
        return app


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    srv = Server()
    server = await aiohttp_server(srv.app())
    base = str(server.make_url("")).rstrip("/")
    http = SafeHttpClient(allowed_hosts=frozenset({"127.0.0.1"}), allow_http=True)
    cache = tmp_path / "cache"

    async def run(**kw):
        return await upd.update(http, cache, keys=KEYS, list_url=f"{base}/lista.json",
                                sig_url=f"{base}/lista.json.sig", **kw)

    yield srv, run, cache
    await http.close()


async def test_downloads_verifies_and_caches(env):
    srv, run, cache = env
    r = await run()
    assert r.status == "atualizada" and r.items == 1 and r.list_date == "2026-11-13"
    assert community_cache_path(cache).read_bytes() == srv.data
    state = upd.read_state(cache)
    assert state["chave"] == KID and state["itens"] == 1
    # Logo em seguida não baixa de novo.
    assert (await run()).status == "recente" and srv.hits == 1
    # Forçando, baixa e percebe que nada mudou.
    assert (await run(force=True)).status == "sem_mudancas"


async def test_refreshes_after_interval(env):
    srv, run, _ = env
    await run()
    srv.data = _doc("2026-11-14", "A-1", "A-2")
    srv.sig = _sig(srv.data)
    later = datetime.now(UTC) + upd.REFRESH_EVERY + timedelta(minutes=1)
    r = await run(now=later)
    assert r.status == "atualizada" and r.items == 2


@pytest.mark.parametrize(("tamper", "msg"), [
    ("conteudo", "assinatura inválida"),
    ("chave", "chave desconhecida"),
    ("formato", "malformada"),
])
async def test_rejects_bad_signature_and_keeps_previous(env, tamper, msg):
    srv, run, cache = env
    await run()
    good = community_cache_path(cache).read_bytes()
    srv.data = _doc("2026-11-14", "A-1", "MALICIOSO")
    if tamper == "conteudo":
        srv.sig = _sig(_doc("2026-11-14", "A-1"))  # assinatura de outro conteúdo
    elif tamper == "chave":
        srv.sig = _sig(srv.data, key=Ed25519PrivateKey.generate(), kid="0123456789abcdef")
    else:
        srv.sig = "não é json"
    r = await run(force=True)
    assert r.status == "falhou" and msg in r.message
    assert community_cache_path(cache).read_bytes() == good  # cópia anterior intacta


async def test_rejects_older_list(env):
    srv, run, cache = env
    await run()
    srv.data = _doc("2026-11-01")  # assinada de verdade, mas antiga e sem itens
    srv.sig = _sig(srv.data)
    r = await run(force=True)
    assert r.status == "falhou" and "mais antiga" in r.message
    assert b"A-1" in community_cache_path(cache).read_bytes()


async def test_rejects_invalid_format_even_if_signed(env):
    srv, run, cache = env
    srv.data = b'{"versao": 9, "itens": []}'
    srv.sig = _sig(srv.data)
    r = await run()
    assert r.status == "falhou" and "formato inválido" in r.message
    assert not community_cache_path(cache).exists()


async def test_download_failure(env):
    srv, run, _ = env
    srv.fail = True
    r = await run()
    assert r.status == "falhou" and "não foi possível baixar" in r.message and r.downloaded_at is None


def test_is_stale():
    now = datetime(2026, 11, 13, tzinfo=UTC)
    fresh = upd.UpdateResult("falhou", "x", downloaded_at=(now - timedelta(days=2)).isoformat())
    old = upd.UpdateResult("falhou", "x", downloaded_at=(now - timedelta(days=8)).isoformat())
    assert not upd.is_stale(fresh, now) and upd.is_stale(old, now)
    assert upd.is_stale(upd.UpdateResult("falhou", "x"), now)


def test_embedded_public_key_is_valid():
    for kid, b64 in upd.PUBLIC_KEYS.items():
        raw = base64.b64decode(b64)
        assert len(raw) == 32 and upd.key_id(raw) == kid


# --- No scanner ---------------------------------------------------------------------------------


async def test_scanner_status_findings(tmp_path, monkeypatch):
    calls = []

    def fake(result):
        async def update(http, cache_dir, **kw):
            calls.append(cache_dir)
            return result
        return update

    ctx = _ctx(tmp_path)
    ctx.http = object()  # só precisa não ser None
    monkeypatch.setattr(upd, "update", fake(upd.UpdateResult("falhou", "sem rede")))
    (f,) = await BlocklistScanner().scan(ctx)
    assert f.rule_id == "auditor.lista-negra.indisponivel" and "sem rede" in f.explanation

    old = (datetime.now(UTC) - timedelta(days=10)).isoformat(timespec="seconds")
    monkeypatch.setattr(upd, "update", fake(upd.UpdateResult("falhou", "HTTP 503", downloaded_at=old)))
    (f,) = await BlocklistScanner().scan(ctx)
    assert f.rule_id == "auditor.lista-negra.desatualizada"

    monkeypatch.setattr(upd, "update", fake(upd.UpdateResult("recente", "ok", downloaded_at=datetime.now(UTC)
                                                                 .isoformat(timespec="seconds"))))
    assert await BlocklistScanner().scan(ctx) == []

    # Opção desligada: não baixa nem usa a cópia em cache.
    calls.clear()
    community_cache_path(ctx.paths.cache_dir).parent.mkdir(parents=True, exist_ok=True)
    community_cache_path(ctx.paths.cache_dir).write_bytes(_doc("2026-11-13", "A-1"))
    ctx.options = Options(community_blocklist=False)
    assert await BlocklistScanner().scan(ctx) == [] and calls == []
    assert load(ctx.paths.config_dir, ctx.paths.cache_dir, community=False).entries == []


def test_option_parsing():
    assert Options.from_dict({}).community_blocklist is True
    assert Options.from_dict({"lista_comunitaria": False}).community_blocklist is False
