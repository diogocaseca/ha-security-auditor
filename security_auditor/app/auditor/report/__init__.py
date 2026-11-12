"""Renderização do relatório (HTML) e exportação (JSON)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ComponentType, ScanResult, Severity

_TEMPLATES = Path(__file__).resolve().parent.parent / "web" / "templates"

COMPONENT_TYPE_LABELS = {
    ComponentType.INTEGRATION: "Integração",
    ComponentType.FRONTEND: "Frontend (www)",
    ComponentType.ADDON: "Add-on",
    ComponentType.NETWORK: "Rede/DNS",
    ComponentType.SYSTEM: "Sistema",
}


def _fmt_dt(value: str | None) -> str:
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    return dt.astimezone().strftime("%d/%m/%Y %H:%M")


# Metadados exibidos na tabela de componentes, na ordem: (chave, rótulo).
_DETAIL_KEYS = (
    ("nome", ""),
    ("versao", "versão"),
    ("origem", "origem"),
    ("integridade", "integridade"),
    ("codigo_fonte", "código"),
    ("envio_medio", "envio médio"),
    ("envio_maximo", "pico de envio"),
    ("trafego", "tráfego"),
)


def component_details(meta: dict) -> list[str]:
    out = []
    for key, label in _DETAIL_KEYS:
        value = meta.get(key)
        if value not in (None, ""):
            out.append(f"{label}: {value}" if label else str(value))
    cves = meta.get("cves")
    if isinstance(cves, dict) and any(cves.values()):
        out.append(f"CVEs: {cves.get('critical', 0)} críticas, {cves.get('high', 0)} altas")
    return out


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["dt"] = _fmt_dt
    env.globals["type_label"] = lambda t: COMPONENT_TYPE_LABELS.get(t, t)
    env.globals["severities"] = sorted(Severity, reverse=True)
    env.globals["component_details"] = component_details
    return env


_ENV = _environment()


def render_html(
    result: ScanResult | None,
    *,
    status: dict[str, Any],
    history: list[dict[str, Any]],
    csrf_token: str,
    viewing_latest: bool = True,
) -> str:
    template = _ENV.get_template("report.html")
    return template.render(
        result=result,
        report=result.to_dict() if result else None,
        status=status,
        history=history,
        csrf_token=csrf_token,
        viewing_latest=viewing_latest,
    )


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
