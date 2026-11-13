"""Aplicação das exceções: allowlist das configurações e lista de ignorados da interface."""

from __future__ import annotations

from fnmatch import fnmatchcase

from .config import AllowlistEntry
from .models import Finding, ScanResult
from .scoring import summarize


def _match(pattern: str, value: str | None) -> bool:
    if pattern in ("", "*"):
        return True
    return value is not None and fnmatchcase(value, pattern)


def entry_matches(entry: AllowlistEntry, finding: Finding) -> bool:
    if entry.fingerprint and entry.fingerprint != finding.fingerprint:
        return False
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
                finding.suppression_reason = describe(entry)
                finding.suppressed_by = entry.entry_id
                suppressed += 1
                break
    return suppressed


def describe(entry: AllowlistEntry) -> str:
    origin = "lista de ignorados" if entry.entry_id is not None else "allowlist das configurações"
    return f"{entry.reason or 'sem motivo informado'} ({origin})"


def reapply(result: ScanResult, entries: tuple[AllowlistEntry, ...]) -> None:
    """Refaz as supressões de um relatório já salvo (após incluir/remover da lista).

    Recalcula as contagens e notas dos componentes, preservando os metadados.
    """
    for finding in result.findings:
        finding.suppressed = False
        finding.suppression_reason = None
        finding.suppressed_by = None
    apply_allowlist(result.findings, entries)
    known = {(c.component_type, c.name): c.metadata for c in result.components}
    result.components = summarize(result.findings, known)
