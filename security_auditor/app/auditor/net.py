"""Cliente HTTP único para saídas à internet, com allowlist de hosts.

O AppArmor não filtra rede por domínio, então toda chamada externa feita
em Python passa por aqui. Regras:
 - só HTTPS;
 - o host de cada requisição, inclusive de cada redirecionamento, precisa
   estar na allowlist;
 - o token do GitHub só é enviado para hosts do próprio GitHub, nunca para
   CDNs para onde a API redireciona;
 - downloads têm limite de tamanho.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import aiohttp

from . import __version__

_LOGGER = logging.getLogger(__name__)

# Saídas permitidas: GitHub (código e releases), registros de imagens e
# bases de vulnerabilidades. Nada mais.
DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        # GitHub
        "api.github.com",
        "github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "raw.githubusercontent.com",
        # Registros de imagens
        "ghcr.io",
        "pkg-containers.githubusercontent.com",
        "registry-1.docker.io",
        "auth.docker.io",
        "index.docker.io",
        "production.cloudflare.docker.com",
        "mirror.gcr.io",
        # Bases de vulnerabilidades
        "api.osv.dev",
    }
)

_GITHUB_TOKEN_HOSTS = frozenset({"api.github.com", "github.com", "codeload.github.com"})
_MAX_REDIRECTS = 5
DEFAULT_MAX_DOWNLOAD = 100 * 1024 * 1024  # 100 MiB


class EgressDeniedError(Exception):
    """Tentativa de acesso a um host fora da allowlist."""


class DownloadTooLargeError(Exception):
    """Resposta maior que o limite permitido."""


class HttpError(Exception):
    def __init__(self, status: int, url: str) -> None:
        super().__init__(f"HTTP {status} em {_redact_url(url)}")
        self.status = status


def _redact_url(url: str) -> str:
    """URL sem query string (assinaturas de CDN), seguro para log."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.hostname}{parts.path}"


class SafeHttpClient:
    def __init__(
        self,
        allowed_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS,
        github_token: str | None = None,
        timeout: float = 60.0,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self._allowed = frozenset(h.lower() for h in allowed_hosts)
        self._github_token = github_token
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session = session
        self._own_session = session is None

    async def __aenter__(self) -> SafeHttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=self._timeout,
                headers={"User-Agent": f"ha-security-auditor/{__version__}"},
            )
        return self._session

    async def close(self) -> None:
        if self._session is not None and self._own_session:
            await self._session.close()
            self._session = None

    def check_url(self, url: str) -> None:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https":
            raise EgressDeniedError(f"Somente HTTPS é permitido: {_redact_url(url)}")
        if host not in self._allowed:
            raise EgressDeniedError(f"Host fora da allowlist de saída: {host}")

    def _headers_for(self, url: str, extra: dict[str, str] | None) -> dict[str, str]:
        headers = dict(extra or {})
        host = (urlsplit(url).hostname or "").lower()
        if self._github_token and host in _GITHUB_TOKEN_HOSTS:
            headers["Authorization"] = f"Bearer {self._github_token}"
        if host == "api.github.com":
            headers.setdefault("Accept", "application/vnd.github+json")
            headers.setdefault("X-GitHub-Api-Version", "2022-11-28")
        return headers

    async def _open(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
    ) -> aiohttp.ClientResponse:
        """Abre a requisição seguindo redirecionamentos manualmente, checando cada salto."""
        session = self._get_session()
        current = url
        for _ in range(_MAX_REDIRECTS + 1):
            self.check_url(current)
            resp = await session.request(
                method,
                current,
                headers=self._headers_for(current, headers),
                json=json_body,
                allow_redirects=False,
            )
            if resp.status in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                location = urljoin(current, resp.headers["Location"])
                resp.release()
                if resp.status == 303:
                    method, json_body = "GET", None
                current = location
                continue
            return resp
        raise EgressDeniedError(f"Redirecionamentos demais a partir de {_redact_url(url)}")

    async def get_json(self, url: str, headers: dict[str, str] | None = None) -> Any:
        resp = await self._open("GET", url, headers=headers)
        async with resp:
            if resp.status >= 400:
                raise HttpError(resp.status, url)
            return await resp.json(content_type=None)

    async def post_json(self, url: str, body: Any) -> Any:
        resp = await self._open("POST", url, json_body=body)
        async with resp:
            if resp.status >= 400:
                raise HttpError(resp.status, url)
            return await resp.json(content_type=None)

    async def download(self, url: str, dest: Path, max_bytes: int = DEFAULT_MAX_DOWNLOAD) -> Path:
        """Baixa para ``dest`` respeitando ``max_bytes``. Remove o arquivo se falhar."""
        resp = await self._open("GET", url)
        dest.parent.mkdir(parents=True, exist_ok=True)
        total = 0
        try:
            async with resp:
                if resp.status >= 400:
                    raise HttpError(resp.status, url)
                if resp.content_length and resp.content_length > max_bytes:
                    raise DownloadTooLargeError(f"{_redact_url(url)} excede {max_bytes} bytes")
                with dest.open("wb") as fh:
                    async for chunk in resp.content.iter_chunked(64 * 1024):
                        total += len(chunk)
                        if total > max_bytes:
                            raise DownloadTooLargeError(f"{_redact_url(url)} excede {max_bytes} bytes")
                        await asyncio.to_thread(fh.write, chunk)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
        _LOGGER.debug("Baixado %s (%d bytes)", _redact_url(url), total)
        return dest
