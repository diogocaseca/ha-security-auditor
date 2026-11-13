"""Leitura das opções do add-on (/data/options.json) e caminhos de trabalho."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Modos de execução (proteções contra sobrecarga), combináveis entre si.
MODE_LOW_PRIORITY = "prioridade_baixa"
MODE_LIGHT = "modo_leve"
MODE_WAIT_IDLE = "aguardar_folga"
MODE_FIXED_TIME = "horario_fixo"
EXECUTION_MODES = (MODE_LOW_PRIORITY, MODE_LIGHT, MODE_WAIT_IDLE, MODE_FIXED_TIME)
DEFAULT_EXECUTION_MODES = (MODE_LOW_PRIORITY, MODE_WAIT_IDLE)
DEFAULT_SCAN_TIME = "03:30"
_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


@dataclass(frozen=True)
class AllowlistEntry:
    component: str  # nome do componente ou "*"
    rule: str  # id da regra, aceita glob (ex.: "semgrep.*") ou "*"
    reason: str
    path: str | None = None  # glob opcional de arquivo
    fingerprint: str | None = None  # só um achado específico (lista de ignorados da interface)
    entry_id: int | None = None  # id na lista de ignorados; None = allowlist das configurações
    severities: tuple[str, ...] = ()  # só achados destes níveis (critical, high...); vazio = todos


DNS_LABELS = {"adguard": "AdGuard Home", "pihole": "Pi-hole"}


@dataclass(frozen=True)
class DnsServer:
    kind: str  # adguard | pihole
    url: str | None
    username: str | None = None
    password: str | None = None

    @property
    def label(self) -> str:
        return DNS_LABELS.get(self.kind, self.kind)


def _text(value: Any) -> str | None:
    return (str(value).strip() or None) if value else None


def _dns_servers(raw: dict[str, Any]) -> tuple[DnsServer, ...]:
    """AdGuard Home e/ou Pi-hole, usados juntos quando os dois estão configurados."""
    servers: list[DnsServer] = []
    if url := _text(raw.get("adguard_url")):
        servers.append(DnsServer("adguard", url, _text(raw.get("adguard_username")),
                                 str(raw["adguard_password"]) if raw.get("adguard_password") else None))
    if url := _text(raw.get("pihole_url")):
        servers.append(DnsServer("pihole", url, None,
                                 str(raw["pihole_password"]) if raw.get("pihole_password") else None))
    return tuple(servers)


@dataclass(frozen=True)
class Paths:
    config_dir: Path
    data_dir: Path
    rules_dir: Path

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "auditor.db"


@dataclass(frozen=True)
class Options:
    scan_interval_hours: int = 24
    scan_on_start: bool = True
    log_level: str = "info"
    github_token: str | None = None
    report_retention: int = 10
    allowlist: tuple[AllowlistEntry, ...] = field(default_factory=tuple)
    addons_scan: bool = True
    image_scan: bool = True
    image_scan_skip: tuple[str, ...] = field(default_factory=tuple)
    stats_interval_minutes: int = 5
    dns_servers: tuple[DnsServer, ...] = field(default_factory=tuple)
    dns_client_ips: tuple[str, ...] = field(default_factory=tuple)
    dns_verify_tls: bool = True
    community_blocklist: bool = True  # baixar a lista negra comunitária (assinada)
    watch_installs: bool = True  # varrer logo depois de instalar/atualizar um componente
    alert_min_level: str = "alta"  # critica | alta | media | baixa | desligado
    execution_modes: frozenset[str] = frozenset(DEFAULT_EXECUTION_MODES)
    scan_time: str = DEFAULT_SCAN_TIME  # HH:MM, usado com horario_fixo
    min_free_memory_mb: int = 500
    max_load_per_cpu: float = 1.5

    def has_mode(self, mode: str) -> bool:
        return mode in self.execution_modes

    @property
    def scan_time_parts(self) -> tuple[int, int]:
        m = _TIME.match(self.scan_time)
        h, mi = (m.group(1), m.group(2)) if m else DEFAULT_SCAN_TIME.split(":")
        return int(h), int(mi)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Options:
        entries = []
        for item in raw.get("allowlist") or []:
            try:
                entries.append(
                    AllowlistEntry(
                        component=str(item["component"]).strip(),
                        rule=str(item["rule"]).strip(),
                        reason=str(item.get("reason", "")).strip(),
                        path=(str(item["path"]).strip() or None) if item.get("path") else None,
                    )
                )
            except (KeyError, TypeError):
                _LOGGER.warning("Entrada inválida na allowlist ignorada (precisa de component e rule)")
        token = raw.get("github_token") or None
        return cls(
            scan_interval_hours=max(0, int(raw.get("scan_interval_hours", 24))),
            scan_on_start=bool(raw.get("scan_on_start", True)),
            log_level=str(raw.get("log_level", "info")).lower(),
            github_token=str(token).strip() if token else None,
            report_retention=max(1, int(raw.get("report_retention", 10))),
            allowlist=tuple(entries),
            addons_scan=bool(raw.get("addons_scan", True)),
            image_scan=bool(raw.get("image_scan", True)),
            image_scan_skip=tuple(str(x).strip() for x in (raw.get("image_scan_skip") or []) if str(x).strip()),
            stats_interval_minutes=max(0, min(60, int(raw.get("stats_interval_minutes", 5)))),
            dns_servers=_dns_servers(raw),
            dns_client_ips=tuple(str(x).strip() for x in (raw.get("dns_client_ips") or []) if str(x).strip()),
            dns_verify_tls=bool(raw.get("dns_verify_tls", True)),
            community_blocklist=bool(raw.get("lista_comunitaria", True)),
            watch_installs=bool(raw.get("verificar_instalacoes", True)),
            alert_min_level=_alert_level(raw.get("aviso_nivel_minimo")),
            execution_modes=_parse_modes(raw.get("modo_execucao")),
            scan_time=_parse_time(raw.get("horario_varredura")),
            min_free_memory_mb=max(64, int(raw.get("memoria_minima_mb", 500))),
            max_load_per_cpu=max(0.2, float(raw.get("carga_maxima_por_cpu", 1.5))),
        )


def _parse_modes(raw: Any) -> frozenset[str]:
    """Lista de modos; ausente = padrão; lista vazia = nenhuma proteção (escolha do usuário)."""
    if raw is None:
        return frozenset(DEFAULT_EXECUTION_MODES)
    modes = {str(x).strip().lower() for x in raw if str(x).strip()}
    unknown = modes - set(EXECUTION_MODES)
    if unknown:
        _LOGGER.warning("Modos de execução desconhecidos ignorados: %s", ", ".join(sorted(unknown)))
    return frozenset(modes & set(EXECUTION_MODES))


def _parse_time(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return DEFAULT_SCAN_TIME
    if not _TIME.match(text):
        _LOGGER.warning("horario_varredura inválido (%s); usando %s", text, DEFAULT_SCAN_TIME)
        return DEFAULT_SCAN_TIME
    return text


def load_paths() -> Paths:
    """Caminhos padrão do add-on; variáveis AUDITOR_* permitem rodar fora do HA."""
    app_dir = Path(__file__).resolve().parent.parent
    return Paths(
        config_dir=Path(os.environ.get("AUDITOR_CONFIG_DIR", "/config")),
        data_dir=Path(os.environ.get("AUDITOR_DATA_DIR", "/data")),
        rules_dir=Path(os.environ.get("AUDITOR_RULES_DIR", str(app_dir / "rules"))),
    )


ALERT_LEVELS = ("critica", "alta", "media", "baixa", "desligado")


def _alert_level(value: Any) -> str:
    text = str(value or "alta").strip().lower()
    if text not in ALERT_LEVELS:
        _LOGGER.warning("aviso_nivel_minimo inválido (%s); usando alta", text)
        return "alta"
    return text


def load_options(data_dir: Path) -> Options:
    path = Path(os.environ.get("AUDITOR_OPTIONS", str(data_dir / "options.json")))
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _LOGGER.warning("Arquivo de opções %s não encontrado; usando padrões", path)
        raw = {}
    except (OSError, json.JSONDecodeError) as err:
        _LOGGER.error("Opções inválidas em %s (%s); usando padrões", path, type(err).__name__)
        raw = {}
    return Options.from_dict(raw)
