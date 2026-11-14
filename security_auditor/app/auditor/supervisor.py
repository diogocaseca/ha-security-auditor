"""Clientes da API do Supervisor e da API do Core (via proxy do Supervisor).

A role ``manager`` permitiria escritas no Supervisor; a garantia de que o
auditor só lê está AQUI, no código:
 - ``SupervisorClient`` só faz GET, e só em caminhos de uma lista fixa;
 - ``CoreStatesPublisher`` só faz POST em ``/core/api/states/sensor.security_auditor_*``;
 - ``CoreNotifier`` só cria notificações ``security_auditor_*`` e dispara o evento
   ``security_auditor_alerta`` (avisos de instalação).
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

_SLUG = r"[a-z0-9_]+"
_READ_ONLY_PATHS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"^/addons$",
        rf"^/addons/{_SLUG}/info$",
        rf"^/addons/{_SLUG}/stats$",
        r"^/store$",
        r"^/store/repositories$",
        rf"^/store/repositories/{_SLUG}$",
        rf"^/store/addons/{_SLUG}$",
        r"^/info$",
        r"^/core/info$",
        r"^/supervisor/info$",
        r"^/network/info$",
        r"^/addons/self/info$",
    )
)
_STATE_ENTITY = re.compile(r"^sensor\.security_auditor_[a-z0-9_]+$")
_NOTIFICATION_ID = re.compile(r"^security_auditor_[a-z0-9_]{1,80}$")
ALERT_EVENT = "security_auditor_alerta"


class ForbiddenPathError(Exception):
    """Caminho fora da lista do que o auditor tem permissão de acessar."""


class SupervisorError(Exception):
    pass


def _token() -> str | None:
    return os.environ.get("SUPERVISOR_TOKEN")


def _base_url() -> str:
    return os.environ.get("SUPERVISOR_URL", "http://supervisor").rstrip("/")


class SupervisorClient:
    """Cliente somente leitura da API do Supervisor."""

    def __init__(self, session: aiohttp.ClientSession, token: str | None = None, base_url: str | None = None) -> None:
        self._session = session
        self._token = token if token is not None else _token()
        self._base = (base_url or _base_url()).rstrip("/")
        self._self_slug: str | None = None
        self._self_panel = False

    @property
    def available(self) -> bool:
        return bool(self._token)

    async def get(self, path: str) -> Any:
        if not any(p.match(path) for p in _READ_ONLY_PATHS):
            raise ForbiddenPathError(f"Acesso ao Supervisor não permitido: {path}")
        if not self._token:
            raise SupervisorError("SUPERVISOR_TOKEN ausente (fora do Home Assistant?)")
        async with self._session.get(
            f"{self._base}{path}",
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            payload = await resp.json(content_type=None)
            if resp.status >= 400 or not isinstance(payload, dict) or payload.get("result") != "ok":
                message = payload.get("message") if isinstance(payload, dict) else None
                raise SupervisorError(f"Supervisor respondeu {resp.status} em {path}: {message or 'erro'}")
            return payload.get("data")

    async def addons(self) -> list[dict[str, Any]]:
        data = await self.get("/addons")
        return list((data or {}).get("addons", []))

    async def self_slug(self) -> str | None:
        """Slug do próprio auditor, para não se auditar (o painel dele seria só ruído)."""
        if self._self_slug is None:
            try:
                info = await self.get("/addons/self/info") or {}
            except SupervisorError as err:
                _LOGGER.warning("Não foi possível identificar o próprio add-on: %s", err)
                return None
            self._self_slug = str(info.get("slug") or "")
            self._self_panel = bool(info.get("ingress_panel"))
        return self._self_slug or None

    async def self_page(self) -> str | None:
        """Caminho, dentro do HA, para abrir o auditor (link dos avisos).

        Com "Mostrar na barra lateral" ligado, o painel fica em ``/<slug>``; sem ele, abre a página
        do add-on (``/config/app/<slug>/info``). O antigo ``/hassio/ingress/<slug>`` não existe mais
        no HA e cai no dashboard padrão.
        """
        slug = await self.self_slug()
        if not slug:
            return None
        return f"/{slug}" if self._self_panel else f"/config/app/{slug}/info"

    async def addon_info(self, slug: str) -> dict[str, Any]:
        return await self.get(f"/addons/{slug}/info") or {}

    async def addon_stats(self, slug: str) -> dict[str, Any]:
        return await self.get(f"/addons/{slug}/stats") or {}

    async def store_repositories(self) -> list[dict[str, Any]]:
        return list(await self.get("/store/repositories") or [])

    async def info(self) -> dict[str, Any]:
        return await self.get("/info") or {}


class CoreStatesPublisher:
    """Publica estados de sensores no Core. Só aceita entidades sensor.security_auditor_*."""

    def __init__(self, session: aiohttp.ClientSession, token: str | None = None, base_url: str | None = None) -> None:
        self._session = session
        self._token = token if token is not None else _token()
        self._base = (base_url or _base_url()).rstrip("/")

    @property
    def available(self) -> bool:
        return bool(self._token)

    async def set_state(self, entity_id: str, state: str | int, attributes: dict[str, Any]) -> None:
        if not _STATE_ENTITY.match(entity_id):
            raise ForbiddenPathError(f"Entidade não permitida: {entity_id}")
        if not self._token:
            raise SupervisorError("SUPERVISOR_TOKEN ausente; sensores não publicados")
        async with self._session.post(
            f"{self._base}/core/api/states/{entity_id}",
            headers={"Authorization": f"Bearer {self._token}"},
            json={"state": str(state), "attributes": attributes},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status >= 400:
                raise SupervisorError(f"Core respondeu {resp.status} ao publicar {entity_id}")


class CoreNotifier:
    """Avisos no Home Assistant: notificação persistente (sino) e evento para automações.

    Só dois caminhos fixos do Core; o conteúdo vem do relatório já mascarado.
    """

    def __init__(self, session: aiohttp.ClientSession, token: str | None = None, base_url: str | None = None) -> None:
        self._session = session
        self._token = token if token is not None else _token()
        self._base = (base_url or _base_url()).rstrip("/")

    @property
    def available(self) -> bool:
        return bool(self._token)

    async def _post(self, path: str, body: dict[str, Any]) -> None:
        if not self._token:
            raise SupervisorError("SUPERVISOR_TOKEN ausente; aviso não enviado")
        async with self._session.post(
            f"{self._base}{path}",
            headers={"Authorization": f"Bearer {self._token}"},
            json=body,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status >= 400:
                raise SupervisorError(f"Core respondeu {resp.status} em {path}")

    async def notify(self, notification_id: str, title: str, message: str) -> None:
        if not _NOTIFICATION_ID.match(notification_id):
            raise ForbiddenPathError(f"Notificação não permitida: {notification_id}")
        await self._post("/core/api/services/persistent_notification/create",
                         {"notification_id": notification_id, "title": title, "message": message})

    async def fire_alert(self, data: dict[str, Any]) -> None:
        await self._post(f"/core/api/events/{ALERT_EVENT}", data)
