"""Scanners: cada um recebe um ScanContext e devolve uma lista de Finding."""

from __future__ import annotations

from .base import Scanner, ScanContext

__all__ = ["ScanContext", "Scanner", "default_scanners"]


def default_scanners() -> list[Scanner]:
    """Scanners ativos. As fases seguintes acrescentam itens aqui."""
    return []
