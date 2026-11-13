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

from .. import blocklist_update
from ..ai import AiError, check_domain
from ..allowlist import reapply, skips_whole_component
from ..blocklist import BlocklistError, validate_item
from ..config import AllowlistEntry
from ..i18n import LANGS, Bi, english, normalize
from ..models import Severity
from ..report import render_html, to_json
from ..scanners.dns import ignore_pattern
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
MAX_BLOCKLIST_ITEMS = 1000
_BLOCKLIST_FIELDS = ("id", "tipo", "github", "nome", "imagem", "versoes", "nivel", "categoria", "motivo")
HISTORY_PAGE_SIZE = 10
_SEVERITY_KEYS = [s.key for s in sorted(Severity, reverse=True)]


class InvalidEntryError(ValueError):
    """Entrada da lista de ignorados recusada (mensagem mostrada ao usuário)."""


def blocklist_item_from_body(body: Any, item_id: str | None = None) -> dict[str, Any]:
    """Monta e valida um item da lista negra pessoal a partir do formulário da interface."""
    if not isinstance(body, dict):
        raise InvalidEntryError(Bi("Corpo inválido", "Invalid body"))
    item: dict[str, Any] = {}
    for key in _BLOCKLIST_FIELDS:
        value = body.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise InvalidEntryError(Bi(f"Campo {key} inválido", f"Invalid field {key}"))
        if value.strip():
            item[key] = value.strip()
    if item_id is not None:
        item["id"] = item_id
    elif "id" not in item:
        item["id"] = "p-" + datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    evid = body.get("evidencias") or []
    if isinstance(evid, str):
        evid = evid.splitlines()
    if not isinstance(evid, list) or not all(isinstance(e, str) for e in evid):
        raise InvalidEntryError(Bi("Evidências inválidas", "Invalid evidence"))
    evid = [e.strip() for e in evid if e.strip()]
    if evid:
        item["evidencias"] = evid
    try:
        validate_item(item)
    except BlocklistError as err:
        raise InvalidEntryError(Bi(f"Item inválido: {err}", f"Invalid item: {english(err.args[0] if err.args else err)}")) from err
    return item


def parse_reason(body: Any) -> str:
    """Valida o corpo de PATCH /api/ignored/{id}: só o motivo pode ser editado."""
    if not isinstance(body, dict) or not isinstance(body.get("reason"), str):
        raise InvalidEntryError(Bi("Informe o motivo", "Provide the reason"))
    reason = body["reason"].strip()
    if len(reason) > _LIMITS["reason"] or any(ord(ch) < 32 for ch in reason):
        raise InvalidEntryError(Bi("Motivo grande demais ou com caracteres inválidos", "Reason too long or with invalid characters"))
    return reason


def parse_ignore_entry(body: Any) -> dict[str, Any]:
    """Valida o corpo de POST /api/ignored."""
    if not isinstance(body, dict):
        raise InvalidEntryError(Bi("Corpo inválido", "Invalid body"))
    out: dict[str, str | None] = {}
    for key, limit in _LIMITS.items():
        value = body.get(key)
        if value is None:
            out[key] = None
            continue
        if not isinstance(value, str):
            raise InvalidEntryError(Bi(f"Campo {key} inválido", f"Invalid field {key}"))
        value = value.strip()
        if len(value) > limit or any(ord(ch) < 32 for ch in value):
            raise InvalidEntryError(Bi(f"Campo {key} grande demais ou com caracteres inválidos",
                                        f"Field {key} too long or with invalid characters"))
        out[key] = value or None
    fp = body.get("fingerprint")
    if fp is not None and (not isinstance(fp, str) or not _FINGERPRINT.match(fp)):
        raise InvalidEntryError(Bi("Identificador do achado inválido", "Invalid finding identifier"))
    out["fingerprint"] = fp
    sevs = body.get("severities") or []
    if not isinstance(sevs, list) or any(s not in _SEVERITY_KEYS for s in sevs):
        raise InvalidEntryError(Bi("Nível de severidade inválido", "Invalid severity level"))
    severities = tuple(k for k in _SEVERITY_KEYS if k in sevs)  # ordem fixa, sem repetição
    if not out["component"] or not out["rule"]:
        raise InvalidEntryError(Bi("Informe o componente e a regra (use * para qualquer um)",
                                   "Provide the component and the rule (use * for any)"))
    every_level = not severities or len(severities) == len(_SEVERITY_KEYS)
    if len(severities) == len(_SEVERITY_KEYS):
        severities = ()  # todos os níveis = sem restrição de nível
    if out["component"] == "*" and out["rule"] == "*" and not out["path"] and not fp and every_level:
        raise InvalidEntryError(Bi("Componente e regra \"*\" em todos os níveis ignorariam tudo; restrinja algum deles",
                                   "Component and rule \"*\" at every level would ignore everything; narrow one of them"))
    return {**out, "severities": severities}


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
    dns_state: dict[str, Any] | None = None,
    dns_check: Callable[[], Awaitable[list[dict[str, Any]]]] | None = None,
    blocklist_cache_dir: Path | None = None,  # onde fica a lista comunitária baixada
    community_enabled: bool = True,
    ai: dict[str, Any] | None = None,  # {"label", "modelo", "ask": async (dominio, idioma) -> resposta}
) -> web.Application:
    dns = dns_state if dns_state is not None else {"configurado": False, "testando": False, "resultados": []}
    peers = allowed_peers if allowed_peers is not None else _allowed_peers()
    csrf_token = secrets.token_urlsafe(32)
    ai_lock = asyncio.Lock()  # uma consulta à IA por vez

    async def _say(text: str) -> str:
        """Mensagem para a interface no idioma escolhido (texto Bi traz as duas versões)."""
        lang = normalize(await asyncio.to_thread(storage.get_setting, "idioma"))
        return english(text) if lang == "en" else str(text)

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
        # Paginação do histórico (?pagina=N, 10 por página).
        total = await asyncio.to_thread(storage.count_scans)
        pages = max(1, -(-total // HISTORY_PAGE_SIZE))
        try:
            page = min(max(1, int(request.query.get("pagina", "1"))), pages)
        except ValueError:
            page = 1
        history = await asyncio.to_thread(storage.list_scans, HISTORY_PAGE_SIZE, (page - 1) * HISTORY_PAGE_SIZE)
        ignored = await asyncio.to_thread(storage.list_ignored)
        dns_ignored = await asyncio.to_thread(storage.list_dns_ignored)
        blocklist = await asyncio.to_thread(_blocklist_view)
        lang = normalize(await asyncio.to_thread(storage.get_setting, "idioma"))
        for row, entry in zip(ignored, await asyncio.to_thread(storage.ignore_entries), strict=True):
            row["pula_varredura"] = skips_whole_component(entry)
        html = render_html(
            result,
            status={**scheduler.status(), "progress": dict(progress), "dns": dns},
            history=history,
            csrf_token=csrf_token,
            viewing_latest=result is None or result.scan_id == latest_id,
            ignored=ignored,
            config_allowlist=config_allowlist,
            history_page={"page": page, "pages": pages, "total": total, "scan": scan_id},
            blocklist=blocklist,
            dns_ignored=dns_ignored,
            lang=lang,
            ai={"label": ai["label"], "modelo": ai["modelo"]} if ai else None,
            dns_ai=await asyncio.to_thread(storage.dns_ai) if ai else None,
        )
        return web.Response(text=html, content_type="text/html", charset="utf-8")

    async def status(request: web.Request) -> web.Response:
        return web.json_response({**scheduler.status(), "progress": dict(progress), "dns": dns})

    async def dns_check_now(request: web.Request) -> web.Response:
        if dns_check is None or not dns.get("configurado"):
            return web.json_response({"error": await _say(Bi("Nenhum servidor DNS configurado",
                                                             "No DNS server configured"))}, status=409)
        if dns.get("testando"):
            return web.json_response({"error": await _say(Bi("Teste já em andamento", "Test already running"))},
                                     status=409)
        _LOGGER.info("Teste de conexão DNS solicitado pela interface")
        return web.json_response({"resultados": await dns_check()})

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
            msg = await _say(err.args[0] if isinstance(err, InvalidEntryError) else Bi("JSON inválido", "Invalid JSON"))
            return web.json_response({"error": msg}, status=400)
        if len(await asyncio.to_thread(storage.list_ignored)) >= MAX_IGNORED:
            return web.json_response({"error": await _say(Bi(f"Limite de {MAX_IGNORED} itens na lista",
                                                             f"Limit of {MAX_IGNORED} items in the list"))}, status=400)
        entry_id = await asyncio.to_thread(
            lambda: storage.add_ignored(
                component=entry["component"] or "", rule=entry["rule"] or "", reason=entry["reason"] or "",
                path=entry["path"], fingerprint=entry["fingerprint"], title=entry["title"],
                severities=entry["severities"],
                created_at=datetime.now(UTC).isoformat(timespec="seconds"),
            )
        )
        _LOGGER.info("Incluído na lista de ignorados: %s / %s %s(#%d)", entry["component"], entry["rule"],
                     f"[{','.join(entry['severities'])}] " if entry["severities"] else "", entry_id)
        await _changed()
        return web.json_response({"id": entry_id}, status=201)

    async def edit_ignored(request: web.Request) -> web.Response:
        try:
            entry_id = int(request.match_info["entry_id"])
        except ValueError:
            raise web.HTTPNotFound() from None
        try:
            reason = parse_reason(await request.json())
        except (InvalidEntryError, ValueError) as err:
            msg = await _say(err.args[0] if isinstance(err, InvalidEntryError) else Bi("JSON inválido", "Invalid JSON"))
            return web.json_response({"error": msg}, status=400)
        if not await asyncio.to_thread(storage.update_ignored_reason, entry_id, reason):
            raise web.HTTPNotFound(text="Item não encontrado")
        _LOGGER.info("Motivo editado na lista de ignorados: #%d", entry_id)
        await _changed()  # o motivo aparece nos achados ignorados do relatório
        return web.json_response({"id": entry_id, "reason": reason})

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

    # --- Domínios ignorados (aba DNS): valem na próxima varredura ----------------------

    def _entry_id(request: web.Request) -> int:
        try:
            return int(request.match_info["entry_id"])
        except ValueError:
            raise web.HTTPNotFound() from None

    async def add_dns_ignored(request: web.Request) -> web.Response:
        """Inclui um domínio ({"dominio"}) ou vários de uma vez ({"dominios": [...]}, "Ignorar todos")."""
        try:
            body = await request.json()
            if not isinstance(body, dict):
                raise InvalidEntryError(Bi("Informe o domínio", "Provide the domain"))
            many = body.get("dominios")
            if many is not None:
                if (not isinstance(many, list) or not many or len(many) > MAX_IGNORED
                        or not all(isinstance(d, str) for d in many)):
                    raise InvalidEntryError(Bi("Lista de domínios inválida", "Invalid domain list"))
                patterns = list(dict.fromkeys(ignore_pattern(d) for d in many))
            elif isinstance(body.get("dominio"), str):
                patterns = [ignore_pattern(body["dominio"])]
            else:
                raise InvalidEntryError(Bi("Informe o domínio", "Provide the domain"))
            reason = parse_reason({"reason": body.get("motivo") if isinstance(body.get("motivo"), str) else ""})
        except InvalidEntryError as err:
            return web.json_response({"error": await _say(err.args[0])}, status=400)
        except ValueError as err:
            msg = err.args[0] if err.args and isinstance(err.args[0], Bi) else Bi("JSON inválido", "Invalid JSON")
            return web.json_response({"error": await _say(msg)}, status=400)
        if len(await asyncio.to_thread(storage.list_dns_ignored)) + len(patterns) > MAX_IGNORED:
            return web.json_response({"error": await _say(Bi(f"Limite de {MAX_IGNORED} itens na lista",
                                                             f"Limit of {MAX_IGNORED} items in the list"))}, status=400)
        now = datetime.now(UTC).isoformat(timespec="seconds")
        ids = [i for p in patterns if (i := await asyncio.to_thread(storage.add_dns_ignored, p, reason, now))]
        if not ids:
            what = patterns[0] if len(patterns) == 1 else f"{len(patterns)}"
            return web.json_response({"error": await _say(Bi(f"{what} já está na lista",
                                                             f"{what} is already in the list"))}, status=409)
        _LOGGER.info("Domínio(s) incluído(s) na lista de ignorados do DNS: %d de %d (%s)", len(ids), len(patterns),
                     ", ".join(patterns[:5]) + (" …" if len(patterns) > 5 else ""))
        return web.json_response({"id": ids[0], "ids": ids, "dominio": patterns[0]}, status=201)

    async def edit_dns_ignored(request: web.Request) -> web.Response:
        entry_id = _entry_id(request)
        try:
            reason = parse_reason(await request.json())
        except (InvalidEntryError, ValueError) as err:
            msg = await _say(err.args[0] if isinstance(err, InvalidEntryError) else Bi("JSON inválido", "Invalid JSON"))
            return web.json_response({"error": msg}, status=400)
        if not await asyncio.to_thread(storage.update_dns_ignored_reason, entry_id, reason):
            raise web.HTTPNotFound(text="Item não encontrado")
        _LOGGER.info("Motivo editado na lista de domínios ignorados: #%d", entry_id)
        return web.json_response({"id": entry_id, "reason": reason})

    async def remove_dns_ignored(request: web.Request) -> web.Response:
        entry_id = _entry_id(request)
        if not await asyncio.to_thread(storage.remove_dns_ignored, entry_id):
            raise web.HTTPNotFound(text="Item não encontrado")
        _LOGGER.info("Domínio removido da lista de ignorados do DNS: #%d", entry_id)
        return web.Response(status=204)

    async def ask_ai(request: web.Request) -> web.Response:
        """Pergunta à IA sobre um domínio da tabela de DNS ({"dominio", "refazer"}).

        Só o nome do domínio sai do add-on, e só para o provedor configurado (opção ia_provedor).
        """
        if ai is None:
            return web.json_response({"error": await _say(Bi("Nenhuma IA configurada (opção ia_provedor)",
                                                             "No AI configured (ia_provedor option)"))}, status=409)
        try:
            body = await request.json()
            domain = check_domain(body.get("dominio") if isinstance(body, dict) else None)
        except ValueError as err:
            msg = err.args[0] if err.args and isinstance(err.args[0], Bi) else Bi("JSON inválido", "Invalid JSON")
            return web.json_response({"error": await _say(msg)}, status=400)
        # Só domínios que o auditor viu nas consultas do HA: o botão não vira um consultor genérico.
        if domain not in await asyncio.to_thread(storage.known_dns_domains):
            return web.json_response({"error": await _say(Bi("Este domínio não está na tabela de DNS",
                                                             "This domain is not in the DNS table"))}, status=404)
        cached = (await asyncio.to_thread(storage.dns_ai, domain)).get(domain)
        if cached and not body.get("refazer"):
            return web.json_response({**cached, "dominio": domain, "guardada": True})
        if ai_lock.locked():
            return web.json_response({"error": await _say(Bi("Outra consulta à IA está em andamento",
                                                             "Another AI query is in progress"))}, status=409)
        lang = normalize(await asyncio.to_thread(storage.get_setting, "idioma"))
        async with ai_lock:
            try:
                answer = await ai["ask"](domain, lang)
            except AiError as err:
                _LOGGER.warning("Consulta à IA sobre %s falhou: %s", domain, err.args[0])
                return web.json_response({"error": await _say(err.args[0])}, status=502)
        now = datetime.now(UTC).isoformat(timespec="seconds")
        await asyncio.to_thread(storage.save_dns_ai, domain, answer, lang, now)
        return web.json_response({**answer, "idioma": lang, "data": now, "dominio": domain, "guardada": False})

    # --- Idioma da interface (guardado no add-on: vale em qualquer navegador) ---------

    async def set_language(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except ValueError:
            return web.json_response({"error": "invalid JSON"}, status=400)
        lang = body.get("idioma") if isinstance(body, dict) else None
        if lang not in LANGS:
            return web.json_response({"error": f"idioma must be one of {', '.join(LANGS)}"}, status=400)
        await asyncio.to_thread(storage.set_setting, "idioma", lang)
        _LOGGER.info("Idioma da interface alterado para %s", lang)
        if on_change:  # republica os sensores com os nomes no idioma novo
            try:
                await on_change()
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Falha ao atualizar os sensores")
        return web.json_response({"idioma": lang})

    # --- Lista negra pessoal (aba "Lista negra") ----------------------------------

    def _blocklist_view() -> dict[str, Any]:
        view: dict[str, Any] = {"interface": storage.list_blocklist_items(), "comunitaria": {"ativa": community_enabled}}
        if blocklist_cache_dir is not None:
            view["comunitaria"].update(blocklist_update.read_state(blocklist_cache_dir))
        return view

    async def blocklist_list(request: web.Request) -> web.Response:
        return web.json_response(await asyncio.to_thread(_blocklist_view))

    async def blocklist_add(request: web.Request) -> web.Response:
        try:
            item = blocklist_item_from_body(await request.json())
        except (InvalidEntryError, ValueError) as err:
            msg = await _say(err.args[0] if isinstance(err, InvalidEntryError) else Bi("JSON inválido", "Invalid JSON"))
            return web.json_response({"error": msg}, status=400)
        if len(await asyncio.to_thread(storage.list_blocklist_items)) >= MAX_BLOCKLIST_ITEMS:
            return web.json_response({"error": await _say(Bi(f"Limite de {MAX_BLOCKLIST_ITEMS} itens",
                                                             f"Limit of {MAX_BLOCKLIST_ITEMS} items"))}, status=400)
        now = datetime.now(UTC).isoformat(timespec="seconds")
        if not await asyncio.to_thread(lambda: storage.save_blocklist_item(item, now, create=True)):
            return web.json_response({"error": await _say(Bi(f"O id {item['id']} já existe",
                                                             f"The id {item['id']} already exists"))}, status=409)
        _LOGGER.info("Lista negra pessoal: item %s incluído pela interface", item["id"])
        return web.json_response({"id": item["id"]}, status=201)

    async def blocklist_edit(request: web.Request) -> web.Response:
        item_id = request.match_info["item_id"]
        try:
            item = blocklist_item_from_body(await request.json(), item_id=item_id)
        except (InvalidEntryError, ValueError) as err:
            msg = await _say(err.args[0] if isinstance(err, InvalidEntryError) else Bi("JSON inválido", "Invalid JSON"))
            return web.json_response({"error": msg}, status=400)
        now = datetime.now(UTC).isoformat(timespec="seconds")
        if not await asyncio.to_thread(lambda: storage.save_blocklist_item(item, now, create=False)):
            raise web.HTTPNotFound(text="Item não encontrado")
        _LOGGER.info("Lista negra pessoal: item %s editado pela interface", item_id)
        return web.json_response({"id": item_id})

    async def blocklist_remove(request: web.Request) -> web.Response:
        item_id = request.match_info["item_id"]
        if not await asyncio.to_thread(storage.remove_blocklist_item, item_id):
            raise web.HTTPNotFound(text="Item não encontrado")
        _LOGGER.info("Lista negra pessoal: item %s removido pela interface", item_id)
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
            web.post("/api/dns/check", dns_check_now),
            web.get("/api/ignored", list_ignored),
            web.post("/api/ignored", add_ignored),
            web.patch("/api/ignored/{entry_id}", edit_ignored),
            web.delete("/api/ignored/{entry_id}", remove_ignored),
            web.post("/api/dns/ignorados", add_dns_ignored),
            web.patch("/api/dns/ignorados/{entry_id}", edit_dns_ignored),
            web.delete("/api/dns/ignorados/{entry_id}", remove_dns_ignored),
            web.post("/api/dns/ia", ask_ai),
            web.post("/api/idioma", set_language),
            web.get("/api/lista-negra", blocklist_list),
            web.post("/api/lista-negra", blocklist_add),
            web.put("/api/lista-negra/{item_id}", blocklist_edit),
            web.delete("/api/lista-negra/{item_id}", blocklist_remove),
            web.get("/api/report.json", report_json),
            web.get("/api/scans", scans),
            web.static("/static", _STATIC, follow_symlinks=False),
        ]
    )
    return app
