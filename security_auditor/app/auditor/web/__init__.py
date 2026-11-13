"""Servidor web do Ingress."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import secrets
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aiohttp import web

from ..allowlist import reapply
from ..config import AllowlistEntry
from ..report import render_html, to_json
from ..scheduler import Scheduler
from ..storage import Storage

_LOGGER = logging.getLogger(__name__)

_STATIC = Path(__file__).resolve().parent / "static"

# O Ingress do Supervisor sempre conecta a partir deste endereço.
INGRESS_PEER = ipaddress.ip_address("172.30.32.2")

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

CSRF_HEADER = "X-Auditor-CSRF"

_FINGERPRINT = re.compile(r"^[0-9a-f]{24}$")
_LIMITS = {"component": 200, "rule": 200, "path": 500, "reason": 500, "title": 300}
MAX_IGNORED = 500


class InvalidEntryError(ValueError):
    """Entrada da lista de ignorados recusada (mensagem mostrada ao usuário)."""


def parse_ignore_entry(body: Any) -> dict[str, str | None]:
    """Valida o corpo de POST /api/ignored."""
    if not isinstance(body, dict):
        raise InvalidEntryError("Corpo inválido")
    out: dict[str, str | None] = {}
    for key, limit in _LIMITS.items():
        value = body.get(key)
        if value is None:
            out[key] = None
            continue
        if not isinstance(value, str):
            raise InvalidEntryError(f"Campo {key} inválido")
        value = value.strip()
        if len(value) > limit or any(ord(ch) < 32 for ch in value):
            raise InvalidEntryError(f"Campo {key} grande demais ou com caracteres inválidos")
        out[key] = value or None
    fp = body.get("fingerprint")
    if fp is not None and (not isinstance(fp, str) or not _FINGERPRINT.match(fp)):
        raise InvalidEntryError("Identificador do achado inválido")
    out["fingerprint"] = fp
    if not out["component"] or not out["rule"]:
        raise InvalidEntryError("Informe o componente e a regra (use * para qualquer um)")
    if out["component"] == "*" and out["rule"] == "*" and not out["path"] and not fp:
        raise InvalidEntryError("Componente e regra \"*\" juntos ignorariam tudo; restrinja um deles")
    return out


def _allowed_peers() -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    peers: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = {INGRESS_PEER}
    # Só para desenvolvimento fora do HA; nunca definido dentro do add-on.
    if os.environ.get("AUDITOR_DEV_ALLOW_LOCAL") == "1":
        peers |= {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
    return peers


def create_app(
    storage: Storage,
    scheduler: Scheduler,
    progress: dict[str, str],
    allowed_peers: set | None = None,
    config_allowlist: tuple[AllowlistEntry, ...] = (),
    on_change: Callable[[], Awaitable[None]] | None = None,
) -> web.Application:
    peers = allowed_peers if allowed_peers is not None else _allowed_peers()
    csrf_token = secrets.token_urlsafe(32)

    @web.middleware
    async def guard(request: web.Request, handler: Callable[[web.Request], Awaitable[web.StreamResponse]]):
        try:
            remote = ipaddress.ip_address(request.remote or "")
        except ValueError:
            remote = None
        if remote not in peers:
            _LOGGER.warning("Acesso recusado de %s (somente via Ingress)", request.remote)
            raise web.HTTPForbidden(text="Acesso permitido somente pelo Ingress do Home Assistant")
        if request.method not in ("GET", "HEAD") and not secrets.compare_digest(
            request.headers.get(CSRF_HEADER, ""), csrf_token
        ):
            raise web.HTTPForbidden(text="Token CSRF inválido")
        response = await handler(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    async def index(request: web.Request) -> web.Response:
        scan_id = request.query.get("scan")
        latest_id = await asyncio.to_thread(storage.latest_completed_id)
        if scan_id:
            result = await asyncio.to_thread(storage.load_scan, scan_id)
            if result is None:
                raise web.HTTPNotFound(text="Varredura não encontrada")
        else:
            result = await asyncio.to_thread(storage.load_latest)
        history = await asyncio.to_thread(storage.list_scans, 30)
        ignored = await asyncio.to_thread(storage.list_ignored)
        html = render_html(
            result,
            status={**scheduler.status(), "progress": dict(progress)},
            history=history,
            csrf_token=csrf_token,
            viewing_latest=result is None or result.scan_id == latest_id,
            ignored=ignored,
            config_allowlist=config_allowlist,
        )
        return web.Response(text=html, content_type="text/html", charset="utf-8")

    async def status(request: web.Request) -> web.Response:
        return web.json_response({**scheduler.status(), "progress": dict(progress)})

    async def scan_now(request: web.Request) -> web.Response:
        accepted = scheduler.request_scan()
        return web.json_response({"accepted": accepted}, status=202 if accepted else 409)

    async def cancel_scan(request: web.Request) -> web.Response:
        accepted = scheduler.cancel_scan()
        return web.json_response({"accepted": accepted}, status=202 if accepted else 409)

    def _refresh_latest() -> None:
        # Aplica a lista atual no relatório mais recente, sem precisar varrer de novo.
        result = storage.load_latest()
        if result is not None:
            reapply(result, config_allowlist + tuple(storage.ignore_entries()))
            storage.save_scan(result)

    async def _changed() -> None:
        await asyncio.to_thread(_refresh_latest)
        if on_change:
            try:
                await on_change()
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Falha ao atualizar os sensores")

    async def list_ignored(request: web.Request) -> web.Response:
        entries = await asyncio.to_thread(storage.list_ignored)
        config = [{"component": e.component, "rule": e.rule, "path": e.path, "reason": e.reason}
                  for e in config_allowlist]
        return web.json_response({"interface": entries, "configuracoes": config})

    async def add_ignored(request: web.Request) -> web.Response:
        try:
            entry = parse_ignore_entry(await request.json())
        except (InvalidEntryError, ValueError) as err:
            msg = str(err) if isinstance(err, InvalidEntryError) else "JSON inválido"
            return web.json_response({"error": msg}, status=400)
        if len(await asyncio.to_thread(storage.list_ignored)) >= MAX_IGNORED:
            return web.json_response({"error": f"Limite de {MAX_IGNORED} itens na lista"}, status=400)
        entry_id = await asyncio.to_thread(
            lambda: storage.add_ignored(
                component=entry["component"] or "", rule=entry["rule"] or "", reason=entry["reason"] or "",
                path=entry["path"], fingerprint=entry["fingerprint"], title=entry["title"],
                created_at=datetime.now(UTC).isoformat(timespec="seconds"),
            )
        )
        _LOGGER.info("Incluído na lista de ignorados: %s / %s (#%d)", entry["component"], entry["rule"], entry_id)
        await _changed()
        return web.json_response({"id": entry_id}, status=201)

    async def remove_ignored(request: web.Request) -> web.Response:
        try:
            entry_id = int(request.match_info["entry_id"])
        except ValueError:
            raise web.HTTPNotFound() from None
        if not await asyncio.to_thread(storage.remove_ignored, entry_id):
            raise web.HTTPNotFound(text="Item não encontrado")
        _LOGGER.info("Removido da lista de ignorados: #%d", entry_id)
        await _changed()
        return web.Response(status=204)

    async def report_json(request: web.Request) -> web.StreamResponse:
        scan_id = request.query.get("scan") or await asyncio.to_thread(storage.latest_completed_id)
        if not scan_id:
            raise web.HTTPNotFound(text="Nenhuma varredura concluída ainda")
        result = await asyncio.to_thread(storage.load_scan, scan_id)
        if result is None:
            raise web.HTTPNotFound(text="Varredura não encontrada")
        resp = web.Response(text=to_json(result), content_type="application/json", charset="utf-8")
        if request.query.get("download") == "1":
            resp.headers["Content-Disposition"] = f'attachment; filename="security-auditor-{result.scan_id}.json"'
        return resp

    async def scans(request: web.Request) -> web.Response:
        return web.json_response(await asyncio.to_thread(storage.list_scans, 100))

    app = web.Application(middlewares=[guard], client_max_size=64 * 1024)
    app.add_routes(
        [
            web.get("/", index),
            web.get("/api/status", status),
            web.post("/api/scan", scan_now),
            web.post("/api/scan/cancel", cancel_scan),
            web.get("/api/ignored", list_ignored),
            web.post("/api/ignored", add_ignored),
            web.delete("/api/ignored/{entry_id}", remove_ignored),
            web.get("/api/report.json", report_json),
            web.get("/api/scans", scans),
            web.static("/static", _STATIC, follow_symlinks=False),
        ]
    )
    return app
