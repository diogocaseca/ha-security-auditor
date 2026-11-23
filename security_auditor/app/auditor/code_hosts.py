"""Domínios citados no código das integrações e dos cards (para dizer "quem usa este domínio").

O DNS não diz qual componente fez cada consulta (todas chegam pelo mesmo cliente). Este índice
procura nomes de domínio no texto dos arquivos de cada componente; quando um domínio consultado
aparece no código de um componente, dá para apontar o provável responsável.

- Só nomes cujo último rótulo é um TLD real (lista da IANA em ``rules/tlds.txt``): assim
  ``e.target`` ou ``this.props`` do JavaScript não entram.
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
_HOST = re.compile(r"(?<![a-z0-9_.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![a-z0-9_-])")
MAX_HOSTS_PER_COMPONENT = 5000
CACHE_VERSION = 1
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


def hosts_in_text(text: str, tlds: frozenset[str]) -> set[str]:
    return {m.group(1) for m in _HOST.finditer(text.lower()) if m.group(2) in tlds}


def _scan_component(comp: Component, inv: Inventory, tlds: frozenset[str]) -> dict[str, str]:
    """{host: primeiro arquivo (relativo a /config) onde aparece}."""
    found: dict[str, str] = {}
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
        for host in hosts_in_text(text, tlds):
            found.setdefault(host, rel)
            if len(found) >= MAX_HOSTS_PER_COMPONENT:
                return found
    return found


class CodeHosts:
    """Índice host -> {componente: arquivo}, e o mesmo pelo domínio base."""

    def __init__(self, per_component: dict[str, dict[str, str]]) -> None:
        self.per_component = per_component
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
        out[key] = {"foto": fp, "hosts": _scan_component(comp, inv, tlds)}
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
    return CodeHosts({k: v.get("hosts") or {} for k, v in out.items()})
