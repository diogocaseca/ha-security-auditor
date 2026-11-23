"""Scanners: cada um recebe um ScanContext e devolve uma lista de Finding."""

from __future__ import annotations

from .addon_image import AddonImageScanner
from .addon_perms import AddonPermissionsScanner
from .addon_source import AddonSourceScanner
from .base import ScanContext, Scanner
from .blocklist import BlocklistScanner
from .code_threats import CodeThreatScanner
from .deps import DependencyScanner
from .dns import DnsScanner
from .integrity import IntegrityScanner
from .obfuscation import ObfuscationScanner
from .repo_signals import RepoSignalsScanner
from .static import StaticAnalysisScanner
from .traffic import TrafficScanner

__all__ = ["ScanContext", "Scanner", "default_scanners"]


def default_scanners() -> list[Scanner]:
    """Scanners ativos, na ordem de execução."""
    return [
        # Lista negra (comunitária e pessoal): comparação local, rápida
        BlocklistScanner(),
        # Fase 1: integrações customizadas e www/
        StaticAnalysisScanner(),
        ObfuscationScanner(),
        DependencyScanner(),
        IntegrityScanner(),
        RepoSignalsScanner(),
        # Domínios citados no código contra a lista de ameaças (baixada do GitHub, comparada aqui)
        CodeThreatScanner(),
        # Fase 2: outros add-ons
        AddonPermissionsScanner(),
        AddonSourceScanner(),
        TrafficScanner(),
        # Fase 3: domínios consultados (AdGuard Home / Pi-hole)
        DnsScanner(),
        AddonImageScanner(),  # por último: é a etapa mais demorada
    ]
