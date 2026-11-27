"""Vulnerabilidades conhecidas nos requirements do manifest.json (pip-audit + OSV).

O pip-audit roda com ``--no-deps --disable-pip``: só consulta a base OSV e
nunca instala nem resolve pacotes (resolver poderia executar ``setup.py`` de
terceiros). Consequência: só requisitos com versão exata (``==``) podem ser
auditados; os demais viram achados informativos.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from ..inventory import Component, Inventory
from ..models import ComponentType, Finding, Severity, en_text
from ..tools import run_tool
from .base import ScanContext
from .deps_malicious import malicious_details, malicious_ids, malicious_verdict, normalize, texts, typosquat_of

_LOGGER = logging.getLogger(__name__)

PIP_AUDIT_TIMEOUT = 600


@dataclass(frozen=True)
class PinnedReq:
    name: str  # normalizado
    version: str
    raw: str


def classify(raw: str) -> tuple[str, PinnedReq | None]:
    """Classifica um requirement: ('fixado'|'sem_versao'|'url'|'invalido', PinnedReq)."""
    text = raw.strip()
    if "://" in text or text.startswith(("git+", "hg+", "svn+", "bzr+")):
        return "url", None
    try:
        req = Requirement(text)
    except InvalidRequirement:
        return "invalido", None
    if req.url:
        return "url", None
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        name = req.name.lower().replace("_", "-").replace(".", "-")
        return "fixado", PinnedReq(name=name, version=specs[0].version, raw=text)
    return "sem_versao", None


class DependencyScanner:
    name = "dependencias"

    async def _malicious(self, ctx: ScanContext, named):
        ctx.set_progress(self.name, "pacotes maliciosos e typosquatting")
        return await _check_malicious(ctx, named)

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        inv: Inventory = ctx.inventory()
        findings: list[Finding] = []
        pinned: dict[PinnedReq, list[Component]] = {}

        named: dict[str, list[tuple[Component, str]]] = {}  # nome normalizado -> (componente, requisito)
        for comp in inv.integrations:
            reqs = comp.manifest.get("requirements") or []
            if not isinstance(reqs, list):
                continue
            for raw in reqs:
                kind, req = classify(str(raw))
                if kind in ("fixado", "sem_versao"):
                    try:
                        named.setdefault(normalize(Requirement(str(raw).strip()).name), []).append((comp, str(raw)))
                    except InvalidRequirement:
                        pass
                if kind == "fixado" and req:
                    pinned.setdefault(req, []).append(comp)
                elif kind == "url":
                    findings.append(_finding(
                        comp, str(raw), Severity.MEDIUM, "auditor.deps.fonte-url",
                        "Dependência instalada de URL/repositório",
                        "O pacote é instalado direto de uma URL ou repositório, não do PyPI. Ele não tem "
                        "versão verificável e o conteúdo pode mudar a qualquer momento sem mudar a integração.",
                        "Veja o que a URL aponta e prefira uma versão publicada no PyPI.",
                        en=en_text(
                            "Dependency installed from a URL/repository",
                            "The package is installed straight from a URL or repository, not from PyPI. It has no "
                            "verifiable version and its content can change at any time without the integration "
                            "changing.",
                            "Check what the URL points to and prefer a version published on PyPI.",
                        ),
                    ))
                elif kind == "sem_versao":
                    findings.append(_finding(
                        comp, str(raw), Severity.INFO, "auditor.deps.sem-versao-fixa",
                        "Dependência sem versão exata",
                        "Sem versão exata (==) não dá para saber qual versão está instalada, então ela "
                        "não pôde ser auditada contra vulnerabilidades conhecidas.",
                        "Nenhuma ação obrigatória; o autor pode fixar a versão no manifest.json.",
                        en=en_text(
                            "Dependency without an exact version",
                            "Without an exact version (==) it is not possible to know which version is installed, "
                            "so it could not be audited against known vulnerabilities.",
                            "No action required; the author can pin the version in manifest.json.",
                        ),
                    ))
                else:
                    findings.append(_finding(
                        comp, str(raw), Severity.LOW, "auditor.deps.requisito-invalido",
                        "Requisito inválido no manifest.json",
                        "O texto do requisito não segue o formato do pip.",
                        "Confira o manifest.json da integração.",
                        en=en_text("Invalid requirement in manifest.json",
                                   "The requirement text does not follow the pip format.",
                                   "Check the integration's manifest.json."),
                    ))

        findings.extend(await self._malicious(ctx, named))
        if not pinned:
            return findings

        ctx.set_progress(self.name, f"pip-audit em {len(pinned)} pacotes")
        data: dict[str, Any] = {"dependencies": []}
        for n, group in enumerate(audit_groups(pinned)):
            req_file = ctx.workdir / f"requirements-auditoria-{n}.txt"
            req_file.write_text("".join(f"{name}=={version}\n" for name, version in group), encoding="utf-8")
            res = await run_tool(
                [
                    "pip-audit", "-r", str(req_file), "--no-deps", "--disable-pip",
                    "-s", "osv", "-f", "json", "--progress-spinner", "off",
                    "--cache-dir", str(ctx.paths.cache_dir / "pip-audit"),
                ],
                home=ctx.workdir / "pip-audit-home",
                timeout=PIP_AUDIT_TIMEOUT,
            )
            text = res.stdout
            if res.returncode not in (0, 1) or "{" not in text:
                raise RuntimeError(f"pip-audit terminou com código {res.returncode}: {res.stderr[-300:]}")
            data["dependencies"] += json.loads(text[text.index("{") :]).get("dependencies", [])
        findings.extend(findings_from_pip_audit(data, pinned))
        return findings


async def _check_malicious(ctx: ScanContext, named: dict[str, list[tuple[Component, str]]]) -> list[Finding]:
    """Pacotes maliciosos catalogados (OSV MAL-…) e nomes de typosquatting."""
    out: list[Finding] = []
    for name, uses in sorted(named.items()):
        if popular := typosquat_of(name):
            sev, title, why, todo, en = texts("typosquatting", nome=name, popular=popular)
            out += [_finding(comp, raw, sev, "auditor.deps.typosquatting", title, why, todo, en=en,
                             fingerprint_key=popular) for comp, raw in uses]
    if not named:
        return out
    try:
        bad = await malicious_ids(ctx.http, list(named))
    except Exception as err:  # noqa: BLE001 - a consulta é um extra: sem ela, o resto do scanner segue
        _LOGGER.warning("Consulta de pacotes maliciosos na OSV falhou: %s", type(err).__name__)
        return out
    details = await malicious_details(ctx.http, [i for ids in bad.values() for i in ids])
    for name, ids in sorted(bad.items()):
        affected = [a for i in ids if i in details for a in details[i]] if all(i in details for i in ids) else None
        for comp, raw in named.get(name, []):
            verdict, versions = malicious_verdict(raw, name, affected)
            listed = ", ".join(versions) or "versões não informadas"
            if verdict == "afetada":
                sev, title, why, todo, en = texts("malicioso", ids=", ".join(ids))
                rule, key = "auditor.deps.pacote-malicioso", ",".join(ids)
            elif verdict == "faixa":
                sev, title, why, todo, en = texts("malicioso_faixa", ids=", ".join(ids), versoes=listed, pedido=raw)
                rule, key = "auditor.deps.pacote-malicioso-faixa", ",".join(ids)
            else:
                sev, title, why, todo, en = texts("malicioso_outra_versao", ids=", ".join(ids), versoes=listed,
                                                  pedido=raw)
                rule, key = "auditor.deps.pacote-malicioso-outra-versao", ",".join(ids)
            out.append(_finding(comp, raw, sev, rule, title, why, todo, en=en, fingerprint_key=key,
                                category="dependencia_maliciosa"))
    return out


def audit_groups(pinned: dict[PinnedReq, list[Component]]) -> list[list[tuple[str, str]]]:
    """Listas para o pip-audit sem nomes repetidos (ele recusa a lista inteira se um pacote aparece duas vezes).

    O mesmo pacote e versão pedidos por várias integrações (ou escritos de jeitos diferentes, como
    ``tinytuya==1.21.1`` e ``TinyTuya == 1.21.1``) viram uma linha só; versões diferentes do mesmo pacote vão
    para listas separadas.
    """
    versions: dict[str, list[str]] = {}
    for req in pinned:
        found = versions.setdefault(req.name, [])
        if req.version not in found:
            found.append(req.version)
    groups: list[list[tuple[str, str]]] = []
    for name in sorted(versions):
        for i, version in enumerate(sorted(versions[name])):
            if i == len(groups):
                groups.append([])
            groups[i].append((name, version))
    return groups


def findings_from_pip_audit(data: dict, pinned: dict[PinnedReq, list[Component]]) -> list[Finding]:
    index = {(r.name, r.version): (r, comps) for r, comps in pinned.items()}
    out: list[Finding] = []
    for dep in data.get("dependencies", []):
        name = str(dep.get("name", "")).lower().replace("_", "-").replace(".", "-")
        key = (name, str(dep.get("version", "")))
        if key not in index or not dep.get("vulns"):
            continue
        req, comps = index[key]
        vulns = dep["vulns"]
        ids = []
        fixes: set[str] = set()
        for v in vulns:
            aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            ids.append(f"{v['id']}" + (f" ({', '.join(aliases)})" if aliases else ""))
            fixes.update(v.get("fix_versions") or [])
        fix_text = f" Versões com correção: {', '.join(sorted(fixes))}." if fixes else " Ainda não há versão corrigida."
        fix_en = f" Fixed versions: {', '.join(sorted(fixes))}." if fixes else " No fixed version yet."
        for comp in comps:
            out.append(_finding(
                comp, req.raw, Severity.HIGH if len(vulns) >= 5 else Severity.MEDIUM,
                "auditor.deps.vulnerabilidade-conhecida",
                f"{req.name} {req.version}: {len(vulns)} vulnerabilidade(s) conhecida(s)",
                f"A versão pedida no manifest.json tem vulnerabilidades publicadas: {'; '.join(ids)}."
                f"{fix_text} O Home Assistant pode ter instalado outra versão se outra integração exigir.",
                "Atualize a integração; se o autor não corrigir, abra uma issue pedindo a atualização da dependência.",
                fingerprint_key=",".join(sorted(v["id"] for v in vulns)),
                category="dependencia_vulneravel",
                en=en_text(
                    f"{req.name} {req.version}: {len(vulns)} known vulnerability(ies)",
                    f"The version required in manifest.json has published vulnerabilities: {'; '.join(ids)}."
                    f"{fix_en} Home Assistant may have installed another version if another integration requires it.",
                    "Update the integration; if the author does not fix it, open an issue asking to update the "
                    "dependency.",
                ),
            ))
    return out


def _finding(
    comp: Component,
    requirement: str,
    severity: Severity,
    rule_id: str,
    title: str,
    explanation: str,
    recommendation: str,
    fingerprint_key: str = "",
    category: str = "dependencia",
    en: dict[str, str] | None = None,
) -> Finding:
    return Finding(
        component=comp.name,
        component_type=ComponentType.INTEGRATION,
        category=category,
        rule_id=rule_id,
        severity=severity,
        title=title,
        explanation=explanation,
        recommendation=recommendation,
        file=f"{comp.rel_path}/manifest.json",
        snippet=requirement,
        en=en,
        source="pip-audit" if category == "dependencia_vulneravel" else "auditor",
        extra={"fingerprint_key": f"{requirement}|{fingerprint_key}"},
    )
