"""Compara os componentes instalados com a lista negra (comunitária e pessoal).

Tudo local: o auditor não pergunta a ninguém se um componente está na lista.
O texto é sempre "reportado na lista", nunca um veredito.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from .. import blocklist_update
from ..blocklist import CATEGORIES, SOURCES, Blocklist, Match, load, personal_path
from ..models import ComponentType, Finding, Severity
from .base import ScanContext

_LOGGER = logging.getLogger(__name__)

_ADVICE = {
    "malicioso": "Remova o componente até revisar as evidências. Se ele teve acesso ao HA, troque senhas e tokens.",
    "comprometido": "Atualize para uma versão fora da faixa afetada ou remova; confira as evidências.",
    "vulneravel": "Atualize para uma versão corrigida ou desative o componente até haver correção.",
    "abandonado": "Procure uma alternativa mantida; sem correções, falhas futuras não serão consertadas.",
    "telemetria": "Confira as evidências e decida se aceita o envio desses dados; desative se não aceitar.",
    "removido": "Veja o motivo da remoção; se o projeto foi abandonado ou substituído, procure a alternativa indicada.",
    "incompativel": "Atualize para uma versão fora da faixa bloqueada; o Home Assistant não carrega a versão afetada.",
}

_LOWER = {Severity.CRITICAL: Severity.HIGH, Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW,
          Severity.LOW: Severity.INFO, Severity.INFO: Severity.INFO}


class BlocklistScanner:
    name = "lista_negra"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        community = ctx.options.community_blocklist
        if community and ctx.http is not None:
            ctx.set_progress(self.name, "atualizando a lista comunitária")
            result = await blocklist_update.update(ctx.http, ctx.paths.cache_dir)
            findings.extend(_community_status(result))
        elif not community:
            _LOGGER.info("Lista negra comunitária desativada nas opções")
        ui_items = [r["item"] for r in await asyncio.to_thread(ctx.storage.list_blocklist_items)]
        bl: Blocklist = await asyncio.to_thread(load, ctx.paths.config_dir, ctx.paths.cache_dir, community, ui_items)
        findings.extend(_invalid(err) for err in bl.errors[:5])
        if not bl.entries:
            return findings
        ctx.set_progress(self.name, f"{len(bl.entries)} itens")

        for comp in ctx.inventory().components:
            repo = comp.github_repo()
            matches = bl.matches(comp.component_type, comp.name, github=[f"{repo[0]}/{repo[1]}"] if repo else [],
                                 version=comp.version)
            findings.extend(self._report(ctx, comp.component_type, comp.name, comp.version, matches))

        for addon in await ctx.addons():
            matches = bl.matches(
                ComponentType.ADDON, addon.slug, aliases=(addon.inner_slug,),
                github=[f"{o}/{r}" for o, r in addon.github_candidates()],
                image=addon.image, version=addon.version,
            )
            findings.extend(self._report(ctx, ComponentType.ADDON, addon.slug, addon.version, matches))
        return findings

    def _report(self, ctx: ScanContext, ctype: str, name: str, version: str | None,
                matches: list[Match]) -> list[Finding]:
        if not matches:
            return []
        # Selo na tabela de componentes: a entrada mais grave (e as correspondências fortes primeiro).
        best = max(matches, key=lambda m: (m.strong, int(m.entry.severity)))
        ctx.register_component(ctype, name, lista_negra={
            "id": best.entry.id, "categoria": best.entry.categoria, "nivel": best.entry.nivel,
            "forte": best.strong, "origem": best.entry.origem, "total": len(matches),
        })
        _LOGGER.warning("Componente %s está na lista negra %s (%s, %s)", name, best.entry.origem,
                        best.entry.id, best.entry.categoria)
        return [_finding(ctype, name, version, m) for m in matches]


def _finding(ctype: str, name: str, version: str | None, m: Match) -> Finding:
    e = m.entry
    sev = e.severity if m.strong else _LOWER[e.severity]
    what = CATEGORIES.get(e.categoria, e.categoria)
    if m.strong:
        title = f"Na lista negra {e.origem}: {what}"
        how = f"Corresponde pelo {m.how}."
    else:
        title = f"Possível correspondência na lista negra {e.origem}: {what}"
        how = (f"Corresponde só pelo {m.how}; o repositório não pôde ser confirmado, então pode ser outro "
               "projeto com o mesmo nome.")
    faixa = f"versões {e.versoes}" if e.versoes else "todas as versões"
    lines = [f"Item {e.id} · {faixa} · instalada: {version or 'desconhecida'}"]
    if e.adicionado_em:
        lines[0] += f" · incluído em {e.adicionado_em}"
    if e.fonte:
        lines.append(f"Fonte: {SOURCES.get(e.fonte, e.fonte)}")
    lines += [f"Evidência: {url}" for url in e.evidencias]
    return Finding(
        component=name,
        component_type=ctype,
        category="lista_negra",
        rule_id=f"auditor.lista-negra.{e.categoria}",
        severity=sev,
        title=title,
        explanation=(
            f"Este componente foi reportado na lista negra {e.origem}: {e.motivo} {how} "
            "A lista registra relatos com evidências; confira os links antes de decidir."
        ),
        recommendation=_ADVICE.get(e.categoria, "Confira as evidências e decida."),
        snippet="\n".join(lines),
        source="lista_negra",
        extra={"fingerprint_key": e.id, "evidencias": list(e.evidencias), "origem": e.origem},
    )


def _community_status(result: blocklist_update.UpdateResult) -> list[Finding]:
    """Avisa quando a lista comunitária nunca chegou ou ficou velha (atualizações falhando)."""
    if result.downloaded_at is None:
        return [Finding(
            component="auditor", component_type=ComponentType.SYSTEM, category="configuracao",
            rule_id="auditor.lista-negra.indisponivel", severity=Severity.INFO,
            title="Lista negra comunitária indisponível",
            explanation=f"A lista comunitária ainda não pôde ser obtida: {result.message}. "
                        "Só a lista pessoal (se houver) foi usada nesta varredura.",
            recommendation="Confira a conexão com o GitHub. Se não quiser usar a lista, desligue "
                           "a opção lista_comunitaria.",
            source="lista_negra", extra={"fingerprint_key": "indisponivel"},
        )]
    if blocklist_update.is_stale(result):
        return [Finding(
            component="auditor", component_type=ComponentType.SYSTEM, category="configuracao",
            rule_id="auditor.lista-negra.desatualizada", severity=Severity.LOW,
            title="Lista negra comunitária desatualizada",
            explanation=f"A cópia local é de {result.downloaded_at[:10]} e as atualizações estão falhando "
                        f"({result.message}). Componentes reportados depois disso não serão avisados.",
            recommendation="Confira a conexão com o GitHub e o log do add-on.",
            source="lista_negra", extra={"fingerprint_key": "desatualizada"},
        )]
    return []


def _invalid(error: str) -> Finding:
    return Finding(
        component="auditor",
        component_type=ComponentType.SYSTEM,
        category="configuracao",
        rule_id="auditor.lista-negra.arquivo-invalido",
        severity=Severity.LOW,
        title="Lista negra com erro",
        explanation=f"Parte da lista negra foi ignorada: {error}.",
        recommendation=f"Corrija o arquivo (a lista pessoal fica em {personal_path(Path('/config'))}).",
        source="lista_negra",
        extra={"fingerprint_key": error[:80]},
    )

