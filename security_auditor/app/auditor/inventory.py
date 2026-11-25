"""Inventário de integrações customizadas e recursos de frontend em /config."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import ComponentType

_LOGGER = logging.getLogger(__name__)

SKIP_DIRS = frozenset({"__pycache__", ".git", "node_modules"})
SKIP_SUFFIXES = (".pyc", ".pyo")
MAX_ANALYZED_FILE = 6 * 1024 * 1024  # padrão; o limite usado vem da opção limite_arquivo_mb
_GITHUB_URL = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


@dataclass
class HacsEntry:
    full_name: str  # "dono/repositorio"
    category: str
    version_installed: str | None
    installed_commit: str | None
    domain: str | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def owner_repo(self) -> tuple[str, str]:
        owner, _, repo = self.full_name.partition("/")
        return owner, repo


@dataclass
class Component:
    name: str
    component_type: str
    path: Path  # diretório no disco
    rel_path: str  # relativo a /config
    files: list[Path] = field(default_factory=list)
    symlinks: list[str] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    hacs: HacsEntry | None = None

    @property
    def version(self) -> str | None:
        if self.hacs and self.hacs.version_installed:
            return self.hacs.version_installed
        v = self.manifest.get("version")
        return str(v) if v else None

    def github_repo(self) -> tuple[str, str] | None:
        """Repositório de origem: HACS primeiro; depois URLs do manifest."""
        if self.hacs and "/" in self.hacs.full_name:
            return self.hacs.owner_repo
        for key in ("issue_tracker", "documentation", "codeowners_url"):
            m = _GITHUB_URL.search(str(self.manifest.get(key) or ""))
            if m:
                return m.group(1), m.group(2).removesuffix(".git")
        return None

    def metadata(self) -> dict[str, Any]:
        repo = self.github_repo()
        return {
            "caminho": self.rel_path,
            "versao": self.version,
            "repositorio": f"{repo[0]}/{repo[1]}" if repo else None,
            "origem": "HACS" if self.hacs else "manual",
            "arquivos": len(self.files),
        }


@dataclass
class Inventory:
    config_dir: Path
    integrations: list[Component] = field(default_factory=list)
    frontend: list[Component] = field(default_factory=list)
    hacs_entries: list[HacsEntry] = field(default_factory=list)

    @property
    def components(self) -> list[Component]:
        return self.integrations + self.frontend

    def owner_of(self, path: Path) -> Component | None:
        best: Component | None = None
        for comp in self.components:
            if path.is_relative_to(comp.path) and (best is None or len(comp.path.parts) > len(best.path.parts)):
                best = comp
        return best

    def rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.config_dir))
        except ValueError:
            return str(path)


def walk_files(root: Path) -> tuple[list[Path], list[str]]:
    """Lista arquivos sem seguir links simbólicos; os links são devolvidos à parte."""
    files: list[Path] = []
    links: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        keep = []
        for d in dirnames:
            if (base / d).is_symlink():
                links.append(str((base / d).relative_to(root)))
            elif d not in SKIP_DIRS:
                keep.append(d)
        dirnames[:] = sorted(keep)
        for name in sorted(filenames):
            p = base / name
            if p.is_symlink():
                links.append(str(p.relative_to(root)))
            elif not name.endswith(SKIP_SUFFIXES):
                files.append(p)
    return files, links


def _read_store(path: Path) -> dict[str, Any] | None:
    """Conteúdo ("data") de um arquivo de armazenamento do HA em .storage; None se não existir ou falhar."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as err:
        _LOGGER.warning("Não foi possível ler %s: %s", path.name, type(err).__name__)
        return None
    inner = data.get("data") if isinstance(data, dict) else None
    return inner if isinstance(inner, dict) else None


# O HACS passou a se chamar Marketplace e grava em .storage/marketplace.* (antes, .storage/hacs.*).
_STORE_PREFIXES = ("marketplace", "hacs")


def _hacs_raw_entries(storage: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Repositórios guardados pelo HACS/Marketplace e os arquivos de onde vieram.

    Formatos conhecidos (com o prefixo ``marketplace.`` ou ``hacs.``):
    - ``<prefixo>.repositories``: ``{"data": {"<id>": {"full_name", "category", "installed", ...}}}``;
    - ``<prefixo>.data``: ``{"data": {"repositories": {"<categoria>": [{"id", "full_name", ...}]}}}``.
      Aqui a categoria é a chave da lista, não um campo do repositório.
    Podem existir vários; as entradas são juntadas pelo id (o primeiro arquivo vence).
    """
    found: dict[str, dict[str, Any]] = {}
    sources: list[str] = []
    for prefix in _STORE_PREFIXES:
        old = _read_store(storage / f"{prefix}.repositories")
        if old:
            sources.append(f"{prefix}.repositories")
            for key, raw in old.items():
                if isinstance(raw, dict):
                    found.setdefault(str(raw.get("id") or key), raw)
        new = _read_store(storage / f"{prefix}.data")
        repos = new.get("repositories") if new else None
        if isinstance(repos, dict):
            sources.append(f"{prefix}.data")
            for category, items in repos.items():
                for raw in items if isinstance(items, list) else []:
                    if isinstance(raw, dict):
                        found.setdefault(str(raw.get("id") or raw.get("full_name")), {"category": category, **raw})
    return list(found.values()), sources


def load_hacs(config_dir: Path) -> list[HacsEntry]:
    storage = config_dir / ".storage"
    raws, sources = _hacs_raw_entries(storage)
    entries = []
    for raw in raws:
        if not raw.get("full_name"):
            continue
        # Só os baixados: o HACS guarda também o catálogo (repositórios que você nunca instalou).
        if raw.get("installed") is not True and not raw.get("version_installed") and not raw.get("installed_commit"):
            continue
        entries.append(
            HacsEntry(
                full_name=str(raw["full_name"]),
                category=str(raw.get("category", "")),
                version_installed=(str(raw["version_installed"]) if raw.get("version_installed") else None),
                installed_commit=(str(raw["installed_commit"]) if raw.get("installed_commit") else None),
                domain=(str(raw["domain"]) if raw.get("domain") else None),
                raw=raw,
            )
        )
    if sources and raws and not entries:
        _LOGGER.warning("Registro do HACS/Marketplace (%s) com %d repositório(s), mas nenhum marcado como baixado; "
                        "integrações e cards vão aparecer como instalados manualmente", ", ".join(sources), len(raws))
    elif sources:
        _LOGGER.info("Registro do HACS/Marketplace (%s): %d repositório(s) baixado(s) de %d guardado(s)",
                     ", ".join(sources), len(entries), len(raws))
    else:
        try:
            names = sorted(p.name for prefix in _STORE_PREFIXES for p in storage.glob(f"{prefix}*"))
        except OSError:
            names = []
        if names:
            _LOGGER.warning("Registro do HACS/Marketplace não reconhecido: há %s em .storage, mas em nenhum formato "
                            "conhecido; integrações e cards vão aparecer como instalados manualmente", ", ".join(names))
    return entries


def discover(config_dir: Path) -> Inventory:
    inv = Inventory(config_dir=config_dir, hacs_entries=load_hacs(config_dir))
    by_domain = {e.domain: e for e in inv.hacs_entries if e.category == "integration" and e.domain}
    by_repo_name = {e.full_name.split("/")[-1].lower(): e for e in inv.hacs_entries}

    cc = config_dir / "custom_components"
    if cc.is_dir():
        for d in sorted(cc.iterdir()):
            if not d.is_dir() or d.is_symlink() or d.name in SKIP_DIRS or d.name.startswith("."):
                continue
            manifest: dict[str, Any] = {}
            try:
                manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
                if not isinstance(manifest, dict):
                    manifest = {}
            except (OSError, json.JSONDecodeError):
                manifest = {}
            files, links = walk_files(d)
            inv.integrations.append(
                Component(
                    name=d.name,
                    component_type=ComponentType.INTEGRATION,
                    path=d,
                    rel_path=inv.rel(d),
                    files=files,
                    symlinks=links,
                    manifest=manifest,
                    hacs=by_domain.get(d.name),
                )
            )

    www = config_dir / "www"
    if www.is_dir():
        community = www / "community"
        if community.is_dir() and not community.is_symlink():
            folders = {d.name for d in community.iterdir() if d.is_dir() and not d.is_symlink()}
            exact = {e.full_name.split("/")[-1]: e for e in inv.hacs_entries if e.category != "integration"}

            def card_entry(folder: str) -> HacsEntry | None:
                """O HACS instala na pasta com o nome exato do repositório. Outra pasta que só difere em
                maiúsculas (uma instalação manual ou antiga) não herda o registro."""
                if folder in exact:
                    return exact[folder]
                entry = by_repo_name.get(folder.lower())
                if entry is not None and entry.full_name.split("/")[-1] in folders:
                    return None
                return entry

            for d in sorted(community.iterdir()):
                if d.is_dir() and not d.is_symlink():
                    files, links = walk_files(d)
                    inv.frontend.append(
                        Component(
                            name=d.name,
                            component_type=ComponentType.FRONTEND,
                            path=d,
                            rel_path=inv.rel(d),
                            files=files,
                            symlinks=links,
                            hacs=card_entry(d.name),
                        )
                    )
        # Demais arquivos de www/ (fora de community/) formam o componente "www".
        files, links = walk_files(www)
        rest = [f for f in files if not f.is_relative_to(community)]
        if rest or links:
            inv.frontend.append(
                Component(
                    name="www",
                    component_type=ComponentType.FRONTEND,
                    path=www,
                    rel_path="www",
                    files=rest,
                    symlinks=[x for x in links if not x.startswith("community")],
                )
            )
    return inv
