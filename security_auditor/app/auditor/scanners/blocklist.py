"""Compara os componentes instalados com a lista negra (comunitária e pessoal).

Tudo local: o auditor não pergunta a ninguém se um componente está na lista.
O texto é sempre "reportado na lista", nunca um veredito.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from .. import blocklist_update
from ..blocklist import CATEGORIES, SOURCES, Blocklist, Match, load

# Arquivo da lista pessoal das versões 0.9 a 0.11; não é mais lido (a lista fica na interface).
LEGACY_PERSONAL_FILE = Path("security_auditor") / "lista_negra.json"
from ..models import ComponentType, Finding, Severity, en_text
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

_ADVICE_EN = {
    "malicioso": "Remove the component until you review the evidence. If it had access to HA, change passwords and "
                 "tokens.",
    "comprometido": "Update to a version outside the affected range or remove it; check the evidence.",
    "vulneravel": "Update to a fixed version or disable the component until a fix exists.",
    "abandonado": "Look for a maintained alternative; without fixes, future flaws will not be corrected.",
    "telemetria": "Check the evidence and decide whether you accept sending this data; disable it if you do not.",
    "removido": "See why it was removed; if the project was abandoned or replaced, look for the suggested "
                "alternative.",
    "incompativel": "Update to a version outside the blocked range; Home Assistant does not load the affected "
                    "version.",
}
_CATEGORIES_EN = {
    "malicioso": "reported as malicious",
    "comprometido": "reported as compromised (account or tampered version)",
    "vulneravel": "with a known serious vulnerability",
    "abandonado": "abandoned, with no security fixes",
    "telemetria": "sends data to third parties without clear notice",
    "removido": "removed or blocked in an official store (e.g. HACS)",
    "incompativel": "version blocked by Home Assistant itself",
}
_ORIGIN_EN = {"pessoal": "personal", "comunitária": "community"}
_SOURCES_EN = {"hacs": "HACS removed list", "home-assistant": "Home Assistant blocked list",
               "comunidade": "community report"}
_HOW_EN = (("repositório ", "repository "), ("imagem ", "image "), ("nome ", "name "))

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
        legacy = ctx.paths.config_dir / LEGACY_PERSONAL_FILE
        if await asyncio.to_thread(legacy.exists):
            _LOGGER.warning("O arquivo %s não é mais lido: recrie os itens na aba Lista negra da interface "
                            "e apague o arquivo", "/config/" + str(LEGACY_PERSONAL_FILE))
        ui_items = [r["item"] for r in await asyncio.to_thread(ctx.storage.list_blocklist_items)]
        bl: Blocklist = await asyncio.to_thread(load, ctx.paths.cache_dir, community, ui_items)
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
    # Inglês
    what_en = _CATEGORIES_EN.get(e.categoria, e.categoria)
    origin_en = _ORIGIN_EN.get(e.origem, e.origem)
    how_en = m.how
    for pt, en in _HOW_EN:
        if how_en.startswith(pt):
            how_en = en + how_en[len(pt):]
    if m.strong:
        title_en, match_en = f"On the {origin_en} blocklist: {what_en}", f"Matched by {how_en}."
    else:
        title_en = f"Possible match on the {origin_en} blocklist: {what_en}"
        match_en = (f"Matched only by {how_en}; the repository could not be confirmed, so it may be another "
                    "project with the same name.")
    source_en = f" Source: {_SOURCES_EN.get(e.fonte, e.fonte)}." if e.fonte else ""
    range_en = f"versions {e.versoes}" if e.versoes else "all versions"
    lines_en = [f"Item {e.id} · {range_en} · installed: {version or 'unknown'}"]
    if e.adicionado_em:
        lines_en[0] += f" · added on {e.adicionado_em}"
    if e.fonte:
        lines_en.append(f"Source: {_SOURCES_EN.get(e.fonte, e.fonte)}")
    lines_en += [f"Evidence: {url}" for url in e.evidencias]
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
        en=en_text(
            title_en,
            f"This component was reported on the {origin_en} blocklist: {e.motivo} {match_en}{source_en} "
            "The list records reports with evidence; check the links before deciding.",
            _ADVICE_EN.get(e.categoria, "Check the evidence and decide."),
            "\n".join(lines_en),
        ),
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
            en=en_text("Community blocklist unavailable",
                       f"The community list could not be obtained yet: {result.message}. Only the personal list "
                       "(if any) was used in this scan.",
                       "Check the connection to GitHub. If you do not want to use the list, turn off the "
                       "lista_comunitaria option."),
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
            en=en_text("Community blocklist out of date",
                       f"The local copy is from {result.downloaded_at[:10]} and updates are failing "
                       f"({result.message}). Components reported after that will not be flagged.",
                       "Check the connection to GitHub and the add-on log."),
            source="lista_negra", extra={"fingerprint_key": "desatualizada"},
        )]
    return []


def _invalid(error: str) -> Finding:
    return Finding(
        component="auditor",
        component_type=ComponentType.SYSTEM,
        category="configuracao",
        rule_id="auditor.lista-negra.item-invalido",
        severity=Severity.LOW,
        title="Lista negra com erro",
        explanation=f"Parte da lista negra foi ignorada: {error}.",
        recommendation=("Itens da lista pessoal podem ser corrigidos na aba Lista negra; erros na lista "
                        "comunitária devem ser avisados no repositório diogocaseca/ha-security-blocklist."),
        en=en_text("Blocklist with errors", f"Part of the blocklist was ignored: {error}.",
                   "Personal list items can be fixed in the Blocklist tab; errors in the community list should be "
                   "reported in the diogocaseca/ha-security-blocklist repository."),
        source="lista_negra",
        extra={"fingerprint_key": error[:80]},
    )

