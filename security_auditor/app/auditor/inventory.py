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
MAX_ANALYZED_FILE = 5 * 1024 * 1024
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


def load_hacs(config_dir: Path) -> list[HacsEntry]:
    path = config_dir / ".storage" / "hacs.repositories"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as err:
        _LOGGER.warning("Não foi possível ler hacs.repositories: %s", type(err).__name__)
        return []
    entries = []
    for raw in (data.get("data") or {}).values():
        if not isinstance(raw, dict) or not raw.get("full_name"):
            continue
        if raw.get("installed") is False:
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
                            hacs=by_repo_name.get(d.name.lower()),
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
