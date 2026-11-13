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

from packaging.requirements import InvalidRequirement, Requirement

from ..inventory import Component, Inventory
from ..models import ComponentType, Finding, Severity, en_text
from ..tools import run_tool
from .base import ScanContext

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

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        inv: Inventory = ctx.inventory()
        findings: list[Finding] = []
        pinned: dict[PinnedReq, list[Component]] = {}

        for comp in inv.integrations:
            reqs = comp.manifest.get("requirements") or []
            if not isinstance(reqs, list):
                continue
            for raw in reqs:
                kind, req = classify(str(raw))
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

        if not pinned:
            return findings

        ctx.set_progress(self.name, f"pip-audit em {len(pinned)} pacotes")
        req_file = ctx.workdir / "requirements-auditoria.txt"
        req_file.write_text("".join(f"{r.name}=={r.version}\n" for r in pinned), encoding="utf-8")
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
        data = json.loads(text[text.index("{") :])
        findings.extend(findings_from_pip_audit(data, pinned))
        return findings


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
