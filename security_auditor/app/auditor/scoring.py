"""Pontuação de risco por componente.

A nota (0 a 100) só ordena o que revisar primeiro; não é uma probabilidade
de o componente ser malicioso.
"""

from __future__ import annotations

from collections import defaultdict

from .models import ComponentSummary, Finding, Severity

WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
MAX_SCORE = 100


def score(findings: list[Finding]) -> int:
    total = sum(WEIGHTS[f.severity] for f in findings if not f.suppressed)
    return min(MAX_SCORE, total)


def summarize(
    findings: list[Finding],
    known_components: dict[tuple[str, str], dict] | None = None,
) -> list[ComponentSummary]:
    """Agrupa os achados por componente e calcula a nota de cada um.

    ``known_components`` inclui componentes sem achados (para aparecerem
    como "limpos" no relatório), com metadados opcionais.
    """
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.component_type, f.component)].append(f)
    keys = set(groups) | set(known_components or {})
    summaries = []
    for ctype, name in keys:
        items = groups.get((ctype, name), [])
        counts = {sev.key: 0 for sev in Severity}
        for f in items:
            if not f.suppressed:
                counts[f.severity.key] += 1
        summaries.append(
            ComponentSummary(
                name=name,
                component_type=ctype,
                score=score(items),
                counts=counts,
                metadata=dict((known_components or {}).get((ctype, name), {})),
            )
        )
    summaries.sort(key=lambda s: (-s.score, s.component_type, s.name))
    return summaries
