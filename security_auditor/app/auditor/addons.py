"""Coleta de informações dos add-ons instalados pela API do Supervisor (somente GET)."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .supervisor import SupervisorClient, SupervisorError

_LOGGER = logging.getLogger(__name__)

_GITHUB = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?(?:$|[/#?])")

OFFICIAL_REPOSITORIES = {"core": "https://github.com/home-assistant/addons"}


@dataclass
class AddonInfo:
    slug: str
    name: str
    version: str | None
    version_latest: str | None
    repository: str
    info: dict[str, Any]
    repository_source: str | None = None  # URL do repositório na loja
    errors: list[str] = field(default_factory=list)

    @property
    def inner_slug(self) -> str:
        """Slug dentro do repositório (sem o prefixo do repositório na loja)."""
        prefix = f"{self.repository}_"
        return self.slug[len(prefix):] if self.slug.startswith(prefix) else self.slug

    @property
    def image(self) -> str | None:
        img = self.info.get("image")
        return str(img) if img else None

    @property
    def is_local_build(self) -> bool:
        return self.repository == "local" or bool(self.info.get("build")) or not self.image

    def github_candidates(self) -> list[tuple[str, str]]:
        """Repositórios do GitHub onde o código-fonte pode estar, em ordem de preferência."""
        out: list[tuple[str, str]] = []
        for url in (self.info.get("url"), self.repository_source):
            m = _GITHUB.search(str(url or "") + "/")
            if m:
                pair = (m.group(1), m.group(2))
                if pair not in out:
                    out.append(pair)
        return out

    def metadata(self) -> dict[str, Any]:
        return {
            "nome": self.name,
            "versao": self.version,
            "versao_disponivel": self.version_latest,
            "repositorio": self.repository_source or self.repository,
            "estado": self.info.get("state"),
            "nota_seguranca": self.info.get("rating"),
            "imagem": self.image,
        }


async def collect(supervisor: SupervisorClient, include: Callable[[str], bool] | None = None) -> list[AddonInfo]:
    """Add-ons instalados; ``include`` filtra pelo slug antes de pedir os detalhes."""
    repos: dict[str, str] = dict(OFFICIAL_REPOSITORIES)
    try:
        for r in await supervisor.store_repositories():
            if r.get("slug") and r.get("source"):
                repos[str(r["slug"])] = str(r["source"])
    except SupervisorError as err:
        _LOGGER.warning("Não foi possível listar os repositórios da loja: %s", err)

    own = await supervisor.self_slug()
    result: list[AddonInfo] = []
    for item in await supervisor.addons():
        slug = str(item.get("slug", ""))
        if not slug:
            continue
        if slug == own:
            _LOGGER.debug("Ignorando o próprio auditor (%s)", slug)
            continue
        if include is not None and not include(slug):
            continue
        try:
            info = await supervisor.addon_info(slug)
        except SupervisorError as err:
            _LOGGER.warning("Sem informações do add-on %s: %s", slug, err)
            info = dict(item)
        repo = str(info.get("repository") or item.get("repository") or "")
        result.append(
            AddonInfo(
                slug=slug,
                name=str(info.get("name") or item.get("name") or slug),
                version=str(info["version"]) if info.get("version") else None,
                version_latest=str(info["version_latest"]) if info.get("version_latest") else None,
                repository=repo,
                info=info,
                repository_source=repos.get(repo),
            )
        )
    return result
