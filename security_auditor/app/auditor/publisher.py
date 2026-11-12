"""Publicação do resultado como sensores do Home Assistant.

Estados criados via API não sobrevivem a um reinício do Core; por isso
o add-on republica ao iniciar, após cada varredura e periodicamente.
"""

from __future__ import annotations

import logging
from typing import Any

from .models import ScanResult
from .supervisor import CoreStatesPublisher, SupervisorError

_LOGGER = logging.getLogger(__name__)

PREFIX = "sensor.security_auditor_"

_COUNT_SENSORS = (
    ("alertas_criticos", "critical", "Alertas críticos", "mdi:shield-alert"),
    ("alertas_altos", "high", "Alertas altos", "mdi:shield-alert-outline"),
    ("alertas_medios", "medium", "Alertas médios", "mdi:shield-half-full"),
    ("alertas_baixos", "low", "Alertas baixos", "mdi:shield-outline"),
)


def build_states(result: ScanResult | None, status: str) -> dict[str, tuple[Any, dict[str, Any]]]:
    """Monta {entity_id: (estado, atributos)}. Nada de segredos ou trechos de código aqui."""
    states: dict[str, tuple[Any, dict[str, Any]]] = {}
    counts = result.counts() if result else {}
    for suffix, key, name, icon in _COUNT_SENSORS:
        states[PREFIX + suffix] = (
            counts.get(key, 0) if result else "unknown",
            {
                "friendly_name": f"Security Auditor {name}",
                "icon": icon,
                "unit_of_measurement": "achados",
                "state_class": "measurement",
            },
        )
    states[PREFIX + "novos_achados"] = (
        result.new_count if result else "unknown",
        {
            "friendly_name": "Security Auditor Novos achados",
            "icon": "mdi:new-box",
            "unit_of_measurement": "achados",
            "state_class": "measurement",
        },
    )
    states[PREFIX + "ultima_varredura"] = (
        (result.finished_at or result.started_at) if result else "unknown",
        {
            "friendly_name": "Security Auditor Última varredura",
            "icon": "mdi:clock-check-outline",
            "device_class": "timestamp",
            "scan_id": result.scan_id if result else None,
            "erros": len(result.errors) if result else 0,
        },
    )
    states[PREFIX + "status"] = (
        status,
        {"friendly_name": "Security Auditor Status", "icon": "mdi:shield-search"},
    )
    return states


class SensorPublisher:
    def __init__(self, core: CoreStatesPublisher) -> None:
        self._core = core
        self._warned = False

    async def publish(self, result: ScanResult | None, status: str) -> bool:
        if not self._core.available:
            if not self._warned:
                _LOGGER.warning("Sem SUPERVISOR_TOKEN: sensores não serão publicados")
                self._warned = True
            return False
        ok = True
        for entity_id, (state, attrs) in build_states(result, status).items():
            try:
                await self._core.set_state(entity_id, state, attrs)
            except (SupervisorError, OSError) as err:
                ok = False
                _LOGGER.warning("Falha ao publicar %s: %s", entity_id, err)
            except Exception as err:  # noqa: BLE001 - publicação nunca derruba a varredura
                ok = False
                _LOGGER.warning("Erro inesperado ao publicar %s: %s", entity_id, type(err).__name__)
        return ok
