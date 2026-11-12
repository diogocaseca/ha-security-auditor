"""Scanners: cada um recebe um ScanContext e devolve uma lista de Finding."""

from __future__ import annotations

from .base import Scanner, ScanContext
from .deps import DependencyScanner
from .integrity import IntegrityScanner
from .static import StaticAnalysisScanner

__all__ = ["ScanContext", "Scanner", "default_scanners"]


def default_scanners() -> list[Scanner]:
    """Scanners ativos, na ordem de execução."""
    return [StaticAnalysisScanner(), DependencyScanner(), IntegrityScanner()]
