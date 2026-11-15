"""Contrato comum dos scanners."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from ..resources import Profile, ResourceGuard

if TYPE_CHECKING:
    from ..config import Options, Paths
    from ..masking import Masker
    from ..models import Finding
    from ..net import SafeHttpClient
    from ..storage import Storage
    from ..supervisor import SupervisorClient


@dataclass
class ScanContext:
    paths: Paths
    options: Options
    http: SafeHttpClient
    supervisor: SupervisorClient | None
    storage: Storage
    masker: Masker
    workdir: Path  # diretório temporário exclusivo desta varredura
    scan_id: str
    # Componentes auditados, inclusive os sem achados: (tipo, nome) -> metadados
    components: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    progress: dict[str, Any] = field(default_factory=dict)
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("auditor.scan"))
    guard: ResourceGuard = field(default_factory=ResourceGuard)  # desligado por padrão
    profile: Profile = field(default_factory=Profile)
    # Lista de ignorados + allowlist: componentes ignorados por inteiro não são varridos.
    ignore_entries: tuple[Any, ...] = ()
    # Varredura parcial (instalação ou atualização): só estes (tipo, nome). None = todos.
    only: frozenset[tuple[str, str]] | None = None

    @property
    def partial(self) -> bool:
        return self.only is not None

    def wants(self, component_type: str, name: str) -> bool:
        return self.only is None or (component_type, name) in self.only

    def skipped(self, component_type: str, name: str, **metadata: Any) -> bool:
        """True se o componente está marcado com "Não analisar"; registra-o como "não verificado"."""
        from ..allowlist import describe, skip_entry_for

        entry = skip_entry_for(name, self.ignore_entries)
        if entry is None:
            return False
        self.register_component(component_type, name, **metadata,
                                verificacao=f"não verificado: marcado para não ser analisado ({describe(entry)})",
                                verificacao_en=f"not scanned: marked as don't scan ({entry.reason or 'no reason given'})")
        self.logger.info("Componente %s pulado: marcado para não ser analisado", name)
        return True

    async def wait_resources(self, label: str, need_mb: float | None = None) -> str | None:
        """Modo aguardar_folga: None = seguir; texto = motivo para adiar a etapa."""
        reason = await self.guard.wait(label, need_mb)
        if reason is None and self.guard.enabled:
            self.set_progress(label)
        return reason

    async def pause(self) -> None:
        """Modo leve: pausa curta entre componentes para o sistema respirar."""
        if self.profile.pause_seconds:
            await asyncio.sleep(self.profile.pause_seconds)

    _excluded: Any = None

    def excluded(self) -> dict[tuple[str, str], str]:
        """Componentes excluídos da tabela ("Excluir…"): (tipo, nome) -> foto guardada."""
        if self._excluded is None:
            self._excluded = self.storage.excluded_map() if self.storage is not None else {}
        return self._excluded

    def is_excluded(self, component_type: str, name: str, fingerprint: str | None) -> bool:
        """True se o componente continua excluído (a foto não mudou).

        Se mudou (reinstalado ou atualizado), a exclusão é apagada e ele volta a ser analisado.
        """
        saved = self.excluded().get((component_type, name))
        if saved is None:
            return False
        if fingerprint is not None and fingerprint == saved:
            return True
        self.storage.remove_excluded(component_type, name)
        self._excluded.pop((component_type, name), None)
        self.logger.info("Componente %s voltou a ser analisado: mudou desde que foi excluído da tabela", name)
        return False

    def forget_missing_excluded(self, component_type: str, present: set[str]) -> None:
        """Excluídos que sumiram (desinstalados): a exclusão some; se voltarem, são analisados."""
        for ctype, name in list(self.excluded()):
            if ctype == component_type and name not in present:
                self.storage.remove_excluded(ctype, name)
                self._excluded.pop((ctype, name), None)
                self.logger.info("Componente excluído %s não está mais instalado: exclusão apagada", name)

    _inventory: Any = None

    def inventory(self) -> Any:
        """Inventário de /config, calculado uma vez por varredura e compartilhado."""
        if self._inventory is None:
            from ..inventory import discover
            from ..watcher import component_fingerprint

            inv = discover(self.paths.config_dir)
            for ctype, comps in (("integracao", inv.integrations), ("frontend", inv.frontend)):
                self.forget_missing_excluded(ctype, {c.name for c in comps})
            keep = lambda c: (self.wants(c.component_type, c.name)  # noqa: E731
                              and not self.is_excluded(c.component_type, c.name,
                                                       component_fingerprint(c.component_type, c.path))
                              and not self.skipped(c.component_type, c.name, **c.metadata()))
            inv.integrations = [c for c in inv.integrations if keep(c)]
            inv.frontend = [c for c in inv.frontend if keep(c)]
            for comp in inv.components:
                self.register_component(comp.component_type, comp.name, **comp.metadata())
            self._inventory = inv
        return self._inventory

    _addons: Any = None

    async def addons(self) -> list[Any]:
        """Add-ons instalados (via Supervisor), coletados uma vez por varredura.

        Sem Supervisor (fora do HA), devolve lista vazia.
        """
        if self._addons is None:
            if self.supervisor is None or not self.options.addons_scan:
                self._addons = []
            else:
                from ..addons import collect

                found = await collect(self.supervisor, include=lambda slug: self.wants("addon", slug))
                if not self.partial:
                    self.forget_missing_excluded("addon", {a.slug for a in found})
                self._addons = [a for a in found
                                if not self.is_excluded("addon", a.slug, a.version or "")
                                and not self.skipped("addon", a.slug, **a.metadata())]
                for a in self._addons:
                    self.register_component("addon", a.slug, **a.metadata())
        return self._addons

    def register_component(self, component_type: str, name: str, **metadata: Any) -> None:
        self.components.setdefault((component_type, name), {}).update(metadata)

    def set_progress(self, step: str, detail: str = "") -> None:
        self.progress.update(step=step, detail=detail)


class Scanner(Protocol):
    """Um scanner tem um nome (para logs e erros) e um método ``scan``."""

    name: str

    async def scan(self, ctx: ScanContext) -> list[Finding]: ...
