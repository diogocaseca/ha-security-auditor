"""Comparação com a varredura anterior: o que é novo e o que foi resolvido."""

from __future__ import annotations

from .models import ScanResult


def compare(current: ScanResult, previous: ScanResult | None) -> None:
    """Marca ``is_new`` nos achados e preenche ``current.resolved``.

    Sem varredura anterior, nada é marcado como novo: a primeira varredura
    é a linha de base.
    """
    if previous is None:
        current.previous_scan_id = None
        current.resolved = []
        for f in current.findings:
            f.is_new = False
        return

    current.previous_scan_id = previous.scan_id
    prev_fps = {f.fingerprint for f in previous.findings}
    cur_fps = set()
    for f in current.findings:
        fp = f.fingerprint
        cur_fps.add(fp)
        f.is_new = fp not in prev_fps

    current.resolved = [
        {
            "fingerprint": f.fingerprint,
            "component": f.component,
            "component_type": f.component_type,
            "rule_id": f.rule_id,
            "title": f.title,
            "title_en": (f.en or {}).get("title"),
            "severity": f.severity.key,
            "severity_label": f.severity.label,
            "file": f.file,
        }
        for f in previous.findings
        if f.fingerprint not in cur_fps and not f.suppressed
    ]
