"""Listas públicas de ameaças e de DNS cifrado, baixadas do GitHub e comparadas localmente.

- **Ameaças:** *Threat Intelligence Feeds* do HaGeZi, versão média (malware, phishing, C2, golpes;
  centenas de milhares de domínios, atualizada várias vezes por dia).
- **DNS cifrado:** *Encrypted DNS Bypass* do HaGeZi (servidores DoH/DoT/DoQ conhecidos).

Nada sai do add-on: as listas são só baixadas (``raw.githubusercontent.com``, como as outras listas
do auditor) e guardadas por ``FEED_TTL``. A comparação lê o arquivo linha a linha procurando só os
nomes de interesse, sem carregar a lista inteira na memória.

Uma entrada da lista vale para o domínio e para todos os subdomínios dele.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

import aiohttp

from .net import DownloadTooLargeError, EgressDeniedError, HttpError, SafeHttpClient

_LOGGER = logging.getLogger(__name__)

_BASE = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
FEEDS = {
    "ameacas": (_BASE + "tif.medium-onlydomains.txt", "HaGeZi Threat Intelligence Feeds (medium)"),
    "dns_cifrado": (_BASE + "doh-onlydomains.txt", "HaGeZi Encrypted DNS Bypass"),
}
FEED_TTL = 12 * 3600
MAX_FEED_BYTES = 64 * 1024 * 1024
_locks: dict[str, asyncio.Lock] = {}

# Usada se a lista de DNS cifrado não puder ser baixada (nunca há só "nada").
DOH_FALLBACK = frozenset({
    "dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "dns9.quad9.net",
    "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "doh.familyshield.opendns.com", "dns.adguard-dns.com",
    "dns.adguard.com", "unfiltered.adguard-dns.com", "family.adguard-dns.com", "doh.cleanbrowsing.org",
    "dns.nextdns.io", "doh.mullvad.net", "dns.mullvad.net", "dns.controld.com", "freedns.controld.com",
    "doh.dns.sb", "dns.alidns.com", "doh.pub", "dns.pub", "doh.360.cn", "dns0.eu", "doh.libredns.gr",
    "dns.digitale-gesellschaft.ch", "doh.ffmuc.net", "dns.twnic.tw",
})


def suffixes(domain: str) -> list[str]:
    """O próprio domínio e os pais com pelo menos dois rótulos: a.b.exemplo.com -> ..., exemplo.com."""
    labels = domain.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


async def feed_path(http: SafeHttpClient, cache_dir: Path, name: str) -> Path | None:
    """Lista ``name`` no cache, baixando se não existir ou tiver mais de ``FEED_TTL``.

    Se o download falhar, usa a cópia antiga (se houver). None = indisponível.
    """
    url, _ = FEEDS[name]
    path = cache_dir / "listas" / f"{name}.txt"
    lock = _locks.setdefault(name, asyncio.Lock())
    async with lock:
        try:
            if time.time() - path.stat().st_mtime < FEED_TTL:
                return path
        except OSError:
            pass
        if getattr(http, "download", None) is None:  # sem cliente de rede (testes, modo offline)
            return path if path.exists() else None
        tmp = path.with_suffix(".tmp")
        try:
            await http.download(url, tmp, max_bytes=MAX_FEED_BYTES)
            os.replace(tmp, path)
            _LOGGER.info("Lista %s atualizada (%d KiB)", FEEDS[name][1], path.stat().st_size // 1024)
            return path
        except (HttpError, EgressDeniedError, DownloadTooLargeError, aiohttp.ClientError, TimeoutError,
                OSError) as err:
            _LOGGER.warning("Não foi possível baixar a lista %s: %s", FEEDS[name][1], type(err).__name__)
            return path if path.exists() else None


def matches(path: Path | None, names: set[str]) -> set[str]:
    """Entradas da lista que estão em ``names`` (passe os domínios e os pais, ver ``suffixes``)."""
    if path is None or not names:
        return set()
    found: set[str] = set()
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = line.strip().lower()
                if entry and entry[0] != "#" and entry in names:
                    found.add(entry)
    except OSError as err:
        _LOGGER.warning("Não foi possível ler a lista %s: %s", path.name, type(err).__name__)
    return found


def listed(domain: str, entries: set[str]) -> str | None:
    """A entrada da lista que cobre ``domain`` (ele próprio ou um pai), ou None."""
    return next((s for s in suffixes(domain) if s in entries), None)


async def lookup(http: SafeHttpClient, cache_dir: Path, name: str, domains: set[str]) -> tuple[dict[str, str], bool]:
    """({domínio: entrada da lista}, lista disponível?) para os ``domains`` dados."""
    path = await feed_path(http, cache_dir, name)
    candidates = {s for d in domains for s in suffixes(d)}
    entries = await asyncio.to_thread(matches, path, candidates)
    if path is None and name == "dns_cifrado":
        entries = candidates & DOH_FALLBACK
    out = {d: e for d in domains if (e := listed(d, entries))}
    return out, path is not None or name == "dns_cifrado"
