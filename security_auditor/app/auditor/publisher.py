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
    ("alertas_criticos", "critical", "Alertas críticos", "Critical alerts", "mdi:shield-alert"),
    ("alertas_altos", "high", "Alertas altos", "High alerts", "mdi:shield-alert-outline"),
    ("alertas_medios", "medium", "Alertas médios", "Medium alerts", "mdi:shield-half-full"),
    ("alertas_baixos", "low", "Alertas baixos", "Low alerts", "mdi:shield-outline"),
)
# Nomes exibidos no HA, conforme o idioma escolhido na interface. Os entity_id, os valores de
# estado e a unidade não mudam (automações e estatísticas continuam funcionando).
_NAMES = {
    "novos_achados": ("Novos achados", "New findings"),
    "ultima_varredura": ("Última varredura", "Last scan"),
    "status": ("Status", "Status"),
}


def build_states(result: ScanResult | None, status: str, lang: str = "pt") -> dict[str, tuple[Any, dict[str, Any]]]:
    """Monta {entity_id: (estado, atributos)}. Nada de segredos ou trechos de código aqui."""
    en = lang == "en"

    def name(key: str) -> str:
        return _NAMES[key][1] if en else _NAMES[key][0]

    states: dict[str, tuple[Any, dict[str, Any]]] = {}
    counts = result.counts() if result else {}
    for suffix, key, name_pt, name_en, icon in _COUNT_SENSORS:
        states[PREFIX + suffix] = (
            counts.get(key, 0) if result else "unknown",
            {
                "friendly_name": f"Security Auditor {name_en if en else name_pt}",
                "icon": icon,
                "unit_of_measurement": "achados",
                "state_class": "measurement",
            },
        )
    states[PREFIX + "novos_achados"] = (
        result.new_count if result else "unknown",
        {
            "friendly_name": f"Security Auditor {name('novos_achados')}",
            "icon": "mdi:new-box",
            "unit_of_measurement": "achados",
            "state_class": "measurement",
        },
    )
    states[PREFIX + "ultima_varredura"] = (
        (result.finished_at or result.started_at) if result else "unknown",
        {
            "friendly_name": f"Security Auditor {name('ultima_varredura')}",
            "icon": "mdi:clock-check-outline",
            "device_class": "timestamp",
            "scan_id": result.scan_id if result else None,
            "erros": len(result.errors) if result else 0,
        },
    )
    states[PREFIX + "status"] = (
        status,
        {"friendly_name": f"Security Auditor {name('status')}", "icon": "mdi:shield-search"},
    )
    return states


class SensorPublisher:
    def __init__(self, core: CoreStatesPublisher) -> None:
        self._core = core
        self._warned = False

    async def publish(self, result: ScanResult | None, status: str, lang: str = "pt") -> bool:
        if not self._core.available:
            if not self._warned:
                _LOGGER.warning("Sem SUPERVISOR_TOKEN: sensores não serão publicados")
                self._warned = True
            return False
        ok = True
        for entity_id, (state, attrs) in build_states(result, status, lang).items():
            try:
                await self._core.set_state(entity_id, state, attrs)
            except (SupervisorError, OSError) as err:
                ok = False
                _LOGGER.warning("Falha ao publicar %s: %s", entity_id, err)
            except Exception as err:  # noqa: BLE001 - publicação nunca derruba a varredura
                ok = False
                _LOGGER.warning("Erro inesperado ao publicar %s: %s", entity_id, type(err).__name__)
        return ok
