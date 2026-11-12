"""Servidor web do Ingress."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path

from aiohttp import web

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
        html = render_html(
            result,
            status={**scheduler.status(), "progress": dict(progress)},
            history=history,
            csrf_token=csrf_token,
            viewing_latest=result is None or result.scan_id == latest_id,
        )
        return web.Response(text=html, content_type="text/html", charset="utf-8")

    async def status(request: web.Request) -> web.Response:
        return web.json_response({**scheduler.status(), "progress": dict(progress)})

    async def scan_now(request: web.Request) -> web.Response:
        accepted = scheduler.request_scan()
        return web.json_response({"accepted": accepted}, status=202 if accepted else 409)

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
            web.get("/api/report.json", report_json),
            web.get("/api/scans", scans),
            web.static("/static", _STATIC, follow_symlinks=False),
        ]
    )
    return app
