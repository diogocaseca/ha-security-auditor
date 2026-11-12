"""Aplicação da lista de exceções (allowlist) configurada pelo usuário."""

from __future__ import annotations

from fnmatch import fnmatchcase

from .config import AllowlistEntry
from .models import Finding


def _match(pattern: str, value: str | None) -> bool:
    if pattern in ("", "*"):
        return True
    return value is not None and fnmatchcase(value, pattern)


def entry_matches(entry: AllowlistEntry, finding: Finding) -> bool:
    if not _match(entry.component, finding.component):
        return False
    if not _match(entry.rule, finding.rule_id):
        return False
    return entry.path is None or _match(entry.path, finding.file)


def apply_allowlist(findings: list[Finding], entries: tuple[AllowlistEntry, ...]) -> int:
    """Marca como suprimidos os achados cobertos por alguma exceção.

    Achados suprimidos continuam no relatório; só deixam de contar nos
    totais, sensores e pontuação. Retorna quantos foram suprimidos.
    """
    suppressed = 0
    for finding in findings:
        for entry in entries:
            if entry_matches(entry, finding):
                finding.suppressed = True
                finding.suppression_reason = entry.reason or "Exceção configurada pelo usuário"
                suppressed += 1
                break
    return suppressed
