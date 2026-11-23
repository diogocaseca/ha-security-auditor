"""Domínios citados no código das integrações e dos cards (para dizer "quem usa este domínio").

O DNS não diz qual componente fez cada consulta (todas chegam pelo mesmo cliente). Este índice
procura nomes de domínio no texto dos arquivos de cada componente; quando um domínio consultado
aparece no código de um componente, dá para apontar o provável responsável.

- Só nomes **numa URL** (``https://api.exemplo.com/…``) ou **sozinhos entre aspas**
  (``"api.exemplo.com"``, com porta ou caminho opcionais), e cujo último rótulo é um TLD real (lista
  da IANA em ``rules/tlds.txt``). Chamadas como ``console.info(`` ou ``performance.now()`` também
  parecem domínios (.info e .now existem, e há golpistas com esses nomes registrados): por isso o
  contexto é exigido.
- Cada componente tem a sua entrada no cache, com uma "foto" (nome, tamanho e data dos arquivos);
  só os componentes que mudaram são relidos.
- Código do Home Assistant em si e dos add-ons (imagens) não é lido: domínios usados só por eles
  ficam sem responsável conhecido.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from .inventory import MAX_ANALYZED_FILE, Component, Inventory

_LOGGER = logging.getLogger(__name__)

_TEXT_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".json", ".yaml", ".yml", ".html", ".htm", ".txt", ".md",
                  ".toml", ".cfg", ".ini", ".sh")
_NAME = r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))"
# Numa URL (com usuário opcional) ou sozinho entre aspas (com porta e caminho opcionais).
_IN_URL = re.compile(r"\b(?:https?|wss?|ftp)://(?:[^\s/\"'`@]*@)?" + _NAME + r"(?![a-z0-9_-])")
_QUOTED = re.compile(r"[\"'`]" + _NAME + r"(?::\d{1,5})?(?:/[^\s\"'`]*)?[\"'`]")
MAX_HOSTS_PER_COMPONENT = 5000
CACHE_VERSION = 2
_TLDS: frozenset[str] | None = None


def load_tlds(rules_dir: Path) -> frozenset[str]:
    global _TLDS
    if _TLDS is None:
        try:
            lines = (rules_dir / "tlds.txt").read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        _TLDS = frozenset(x.strip().lower() for x in lines if x.strip() and not x.startswith("#"))
    return _TLDS


def label(comp: Component) -> str:
    return f"{comp.component_type}/{comp.name}"


def _fingerprint(comp: Component) -> str:
    h = hashlib.sha256()
    for f in comp.files:
        try:
            st = f.stat()
        except OSError:
            continue
        h.update(f"{f}\x1f{st.st_size}\x1f{st.st_mtime_ns}\n".encode())
    return h.hexdigest()[:24]


def url_hosts_in_text(text: str, tlds: frozenset[str]) -> set[str]:
    """Hosts que aparecem dentro de uma URL (o sinal forte)."""
    return {m.group(1) for m in _IN_URL.finditer(text.lower()) if m.group(2) in tlds}


def hosts_in_text(text: str, tlds: frozenset[str]) -> set[str]:
    """Hosts numa URL ou sozinhos entre aspas (este pode ser só um nome parecido, ex.: "profile.name")."""
    low = text.lower()
    return {m.group(1) for rx in (_IN_URL, _QUOTED) for m in rx.finditer(low) if m.group(2) in tlds}


def _scan_component(comp: Component, inv: Inventory, tlds: frozenset[str]) -> tuple[dict[str, str], list[str]]:
    """({host: primeiro arquivo (relativo a /config) onde aparece}, hosts vistos numa URL)."""
    found: dict[str, str] = {}
    in_url: set[str] = set()
    for path in comp.files:
        if not path.name.lower().endswith(_TEXT_SUFFIXES):
            continue
        try:
            if path.stat().st_size > MAX_ANALYZED_FILE:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = inv.rel(path)
        urls = url_hosts_in_text(text, tlds)
        for host in hosts_in_text(text, tlds) | urls:
            found.setdefault(host, rel)
        in_url |= urls
        if len(found) >= MAX_HOSTS_PER_COMPONENT:
            break
    return found, sorted(in_url & set(found))


class CodeHosts:
    """Índice host -> {componente: arquivo}, e o mesmo pelo domínio base."""

    def __init__(self, per_component: dict[str, dict[str, str]],
                 in_url: dict[str, set[str]] | None = None) -> None:
        self.per_component = per_component
        self.in_url = in_url or {}  # componente -> hosts vistos dentro de uma URL
        self.exact: dict[str, dict[str, str]] = {}
        for comp, hosts in per_component.items():
            for host, rel in hosts.items():
                self.exact.setdefault(host, {})[comp] = rel

    def users(self, domain: str) -> dict[str, str]:
        """Componentes que citam ``domain`` ou um domínio pai dele (ex.: o código cita ``exemplo.com``)."""
        from .threat_intel import suffixes

        out: dict[str, str] = {}
        for name in suffixes(domain):
            for comp, rel in self.exact.get(name, {}).items():
                out.setdefault(comp, rel)
        return out


def build(inv: Inventory, cache_dir: Path, rules_dir: Path) -> CodeHosts:
    """Índice de todos os componentes, com cache em disco: só relê os que mudaram desde a última vez."""
    tlds = load_tlds(rules_dir)
    path = cache_dir / "dominios_no_codigo.json"
    try:
        cached: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        if cached.get("versao") != CACHE_VERSION:
            cached = {}
    except (OSError, json.JSONDecodeError):
        cached = {}
    entries: dict[str, Any] = cached.get("componentes") or {}
    out: dict[str, Any] = {}
    reread = 0
    for comp in [*inv.integrations, *inv.frontend]:
        key = label(comp)
        old = entries.get(key)
        fp = _fingerprint(comp)
        if old and old.get("foto") == fp:
            out[key] = old
            continue
        hosts, urls = _scan_component(comp, inv, tlds)
        out[key] = {"foto": fp, "hosts": hosts, "url": urls}
        reread += 1
    if reread or set(out) != set(entries):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"versao": CACHE_VERSION, "componentes": out}), encoding="utf-8")
            tmp.replace(path)
        except OSError as err:
            _LOGGER.warning("Não foi possível guardar o índice de domínios do código: %s", type(err).__name__)
        _LOGGER.info("Domínios citados no código: %d componente(s) relido(s) de %d", reread, len(out))
    return CodeHosts({k: v.get("hosts") or {} for k, v in out.items()},
                     {k: set(v.get("url") or []) for k, v in out.items()})
