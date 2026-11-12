"""Contrato comum dos scanners."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

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

    _inventory: Any = None

    def inventory(self) -> Any:
        """Inventário de /config, calculado uma vez por varredura e compartilhado."""
        if self._inventory is None:
            from ..inventory import discover

            self._inventory = discover(self.paths.config_dir)
            for comp in self._inventory.components:
                self.register_component(comp.component_type, comp.name, **comp.metadata())
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

                self._addons = await collect(self.supervisor)
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
