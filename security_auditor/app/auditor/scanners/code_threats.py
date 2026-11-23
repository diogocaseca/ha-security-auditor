"""Domínios citados no código das integrações e dos cards que estão em lista de ameaças.

Usa o índice de ``code_hosts`` (todos os nomes de domínio que aparecem no código, não só os dos
achados) e a lista de ameaças do HaGeZi (``threat_intel``), baixada do GitHub e comparada aqui
dentro: nada da instalação sai do add-on. Um domínio da lista no código é Alto mesmo que nunca
tenha sido consultado no DNS (pode estar esperando um gatilho).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from .. import code_hosts, threat_intel
from ..inventory import Component, Inventory
from ..models import Finding, Severity, en_text
from .base import ScanContext

_LOGGER = logging.getLogger(__name__)


def _line_of(path: Path, host: str) -> tuple[int | None, str | None]:
    """Primeira linha do arquivo que cita ``host`` (e o texto dela, curto)."""
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for n, text in enumerate(fh, 1):
                if host in text.lower():
                    text = text.strip()
                    return n, (text if len(text) <= 300 else text[:300] + " …")
    except OSError:
        pass
    return None, None


class CodeThreatScanner:
    name = "ameacas_codigo"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        inv: Inventory = ctx.inventory()
        comps = [c for c in [*inv.integrations, *inv.frontend] if ctx.wants(c.component_type, c.name)]
        if not comps:
            return []
        ctx.set_progress(self.name, "domínios citados no código")
        index = await asyncio.to_thread(code_hosts.build, inv, ctx.paths.cache_dir, ctx.paths.rules_dir)
        per_comp = {code_hosts.label(c): c for c in comps}
        domains = {h for key in per_comp for h in index.per_component.get(key, {})}
        ctx.set_progress(self.name, "lista de ameaças")
        hits, available = await threat_intel.lookup(ctx.http, ctx.paths.cache_dir, "ameacas", domains)
        if not available:
            return []
        findings: list[Finding] = []
        for key, comp in sorted(per_comp.items()):
            for host, rel in sorted(index.per_component.get(key, {}).items()):
                if host in hits:
                    line, text = await asyncio.to_thread(_line_of, inv.config_dir / rel, host)
                    findings.append(_finding(comp, host, hits[host], rel, line, text,
                                             in_url=host in index.in_url.get(key, set())))
        if findings:
            _LOGGER.info("Domínios em lista de ameaças no código: %d", len(findings))
        return findings


def _finding(comp: Component, host: str, entry: str, rel: str, line: int | None, text: str | None,
             in_url: bool = True) -> Finding:
    quoted_pt = ("" if in_url else " Ele aparece só entre aspas, não numa URL: pode ser apenas um nome parecido com "
                 "um domínio (uma chave de tradução, por exemplo).")
    quoted_en = ("" if in_url else " It only appears between quotes, not in a URL: it may just be a name that looks "
                 "like a domain (a translation key, for example).")
    return Finding(
        component=comp.name, component_type=comp.component_type, category="lista_ameacas",
        rule_id="auditor.codigo.dominio-em-lista-de-ameacas", severity=Severity.HIGH if in_url else Severity.MEDIUM,
        title=f"Domínio em lista de ameaças no código: {host}",
        explanation=(f"O código cita {host}, que está na lista de ameaças do HaGeZi (como {entry}): malware, "
                     "phishing, comando e controle ou golpes. Pode ser um endereço antigo que mudou de dono, mas "
                     "também o servidor para onde o componente manda dados." + quoted_pt),
        recommendation=("Veja no trecho como o domínio é usado e pergunte à IA sobre ele. Sem explicação do autor, "
                        "desative o componente e bloqueie o domínio no AdGuard/Pi-hole."),
        en=en_text(f"Domain on a threat list in the code: {host}",
                   f"The code mentions {host}, which is on HaGeZi's threat list (as {entry}): malware, phishing, "
                   "command and control or scams. It may be an old address that changed owners, but also the "
                   "server the component sends data to." + quoted_en,
                   "Check in the snippet how the domain is used and ask the AI about it. Without an explanation "
                   "from the author, disable the component and block the domain in AdGuard/Pi-hole."),
        file=rel, line=line, snippet=text, source="auditor",
        extra={"fingerprint_key": host, "chave_estavel": True},
    )
