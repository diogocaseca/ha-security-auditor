"""Sinais de cadeia de suprimentos no GitHub (só leitura), para componentes instalados pelo HACS.

- **Tag reescrita:** a tag da versão instalada passou a apontar para outro commit desde a primeira vez
  que o auditor a viu. Em projeto honesto isso quase nunca acontece; é o jeito de trocar o código de
  uma versão sem mudar o número.
- **Repositório transferido ou renomeado:** o nome que o HACS guardou não é mais o nome atual do
  repositório (a API do GitHub redireciona). Pode ser só uma mudança de organização, mas também
  pode ser o projeto passando para outras mãos.
- **Repositório arquivado:** o autor encerrou a manutenção; o código não recebe mais correções.

Cada repositório é consultado no máximo uma vez por dia (o resultado fica guardado), para não gastar
o limite de requisições do GitHub. Falhas de rede ou de limite apenas pulam a verificação.
"""

from __future__ import annotations

import asyncio
import time

import aiohttp

from ..inventory import Component, Inventory
from ..models import Finding, Severity, en_text
from ..net import EgressDeniedError, HttpError
from .base import ScanContext
from .integrity import _COMMITISH

CHECK_TTL = 24 * 3600


class RepoSignalsScanner:
    name = "repositorios"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        if ctx.storage is None:
            return []
        inv: Inventory = ctx.inventory()
        findings: list[Finding] = []
        for comp in [*inv.integrations, *inv.frontend]:
            if comp.hacs is None or "/" not in comp.hacs.full_name:
                continue
            ctx.set_progress(self.name, comp.name)
            try:
                findings += await self._check(ctx, comp)
            except (HttpError, EgressDeniedError, aiohttp.ClientError, TimeoutError, ValueError) as err:
                ctx.logger.debug("Sinais do GitHub de %s indisponíveis: %s", comp.name, type(err).__name__)
        return findings

    async def _check(self, ctx: ScanContext, comp: Component) -> list[Finding]:
        hacs = comp.hacs
        recorded = hacs.full_name
        owner, name = hacs.owner_repo
        out: list[Finding] = []
        info = await self._cached(ctx, f"repo:{recorded.lower()}",
                                  lambda: ctx.http.get_json(f"https://api.github.com/repos/{owner}/{name}"))
        current = str(info.get("full_name") or "")
        if current and current.lower() != recorded.lower():
            out.append(_moved(comp, recorded, current))
        if info.get("archived"):
            out.append(_archived(comp, current or recorded))
        tag = (hacs.version_installed or "").strip()
        if tag and not _COMMITISH.match(tag) and "/" not in tag and ".." not in tag:
            ref = await self._cached(ctx, f"tag:{recorded.lower()}:{tag}", lambda: ctx.http.get_json(
                f"https://api.github.com/repos/{owner}/{name}/git/ref/tags/{tag}"))
            sha = str((ref.get("object") or {}).get("sha") or "")
            if sha:
                first = await asyncio.to_thread(ctx.storage.first_tag_sha, recorded.lower(), tag, sha,
                                                ctx.scan_id)
                if first != sha:
                    out.append(_retagged(comp, recorded, tag, first, sha))
        return out

    async def _cached(self, ctx: ScanContext, key: str, fetch) -> dict:
        """Resposta guardada por até um dia; senão consulta o GitHub e guarda."""
        row = await asyncio.to_thread(ctx.storage.github_cache, key)
        if row and time.time() - row[1] < CHECK_TTL:
            return row[0]
        try:
            data = await fetch()
        except HttpError as err:
            if err.status != 404:
                raise
            data = {}
        data = data if isinstance(data, dict) else {}
        await asyncio.to_thread(ctx.storage.set_github_cache, key, data, time.time())
        return data


def _moved(comp: Component, recorded: str, current: str) -> Finding:
    return Finding(
        component=comp.name, component_type=comp.component_type, category="cadeia_suprimentos",
        rule_id="auditor.repositorio.transferido", severity=Severity.MEDIUM,
        title="Repositório mudou de nome ou de dono",
        explanation=(f"O HACS instalou a partir de {recorded}, mas hoje o repositório se chama {current}. Pode ser só "
                     "uma mudança de organização, mas também pode ser o projeto passando para outras mãos."),
        recommendation=("Confira no GitHub quem mantém o repositório agora e se a mudança foi anunciada. Fique atento "
                        "às próximas atualizações."),
        en=en_text("Repository changed name or owner",
                   f"HACS installed from {recorded}, but today the repository is called {current}. It may just be an "
                   "organisation change, but it can also be the project passing into other hands.",
                   "Check on GitHub who maintains the repository now and whether the change was announced. Keep an "
                   "eye on the next updates."),
        source="github", extra={"fingerprint_key": current.lower(), "repositorio": current},
    )


def _archived(comp: Component, repo: str) -> Finding:
    return Finding(
        component=comp.name, component_type=comp.component_type, category="cadeia_suprimentos",
        rule_id="auditor.repositorio.arquivado", severity=Severity.INFO,
        title="Repositório arquivado (sem manutenção)",
        explanation=f"O repositório {repo} foi arquivado pelo autor: o código não recebe mais correções de segurança.",
        recommendation="Procure uma alternativa mantida se o componente for importante.",
        en=en_text("Repository archived (no longer maintained)",
                   f"The repository {repo} was archived by its author: the code no longer gets security fixes.",
                   "Look for a maintained alternative if the component matters to you."),
        source="github", extra={"fingerprint_key": repo.lower(), "repositorio": repo},
    )


def _retagged(comp: Component, repo: str, tag: str, first: str, sha: str) -> Finding:
    return Finding(
        component=comp.name, component_type=comp.component_type, category="cadeia_suprimentos",
        rule_id="auditor.repositorio.tag-reescrita", severity=Severity.HIGH,
        title=f"A versão {tag} foi reescrita no GitHub",
        explanation=(f"A tag {tag} de {repo} apontava para o commit {first[:12]} e agora aponta para {sha[:12]}. "
                     "Reescrever uma versão já publicada troca o código sem mudar o número, e quem reinstalar recebe "
                     "o código novo."),
        recommendation=("Compare os dois commits no GitHub. Se o autor não explicar a mudança, não reinstale nem "
                        "atualize esta versão e avise o autor."),
        en=en_text(f"Version {tag} was rewritten on GitHub",
                   f"The tag {tag} of {repo} pointed to commit {first[:12]} and now points to {sha[:12]}. Rewriting an "
                   "already published version swaps the code without changing the number, and whoever reinstalls "
                   "gets the new code.",
                   "Compare both commits on GitHub. If the author does not explain the change, do not reinstall or "
                   "update this version and let the author know."),
        snippet=f"{tag}: {first} → {sha}", source="github",
        extra={"fingerprint_key": f"{tag}:{first}>{sha}", "repositorio": repo},
    )

