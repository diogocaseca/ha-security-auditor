"""Varredura das imagens dos add-ons direto no registro, com Trivy em modo remoto.

Sem daemon Docker: o Trivy baixa só o manifesto e as camadas da imagem do
registro (ghcr.io, Docker Hub) e procura CVEs e segredos embutidos.
Telemetria e checagem de versão do Trivy ficam desligadas.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from ..addons import AddonInfo
from ..models import ComponentType, Finding, Severity
from ..tools import ToolTimeoutError, run_tool
from .base import ScanContext

_LOGGER = logging.getLogger(__name__)

TRIVY_TIMEOUT = 20 * 60
_TOP = 8


class AddonImageScanner:
    name = "imagens_addons"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.options.image_scan:
            return []
        skip = set(ctx.options.image_scan_skip)
        findings: list[Finding] = []
        for addon in await ctx.addons():
            if addon.slug in skip or addon.inner_slug in skip:
                continue
            ref = image_ref(addon)
            if ref is None:
                findings.append(_not_scanned(addon, "add-on construído localmente (sem imagem no registro)"))
                continue
            ctx.set_progress(self.name, ref)
            try:
                data = await self._trivy(ctx, ref)
            except ToolTimeoutError as err:
                findings.append(_not_scanned(addon, str(err)))
                continue
            except RuntimeError as err:
                findings.append(_not_scanned(addon, str(err)))
                continue
            found, summary = findings_from_trivy(addon, ref, data)
            findings.extend(found)
            ctx.register_component(ComponentType.ADDON, addon.slug, cves=summary)
        return findings

    async def _trivy(self, ctx: ScanContext, ref: str) -> dict[str, Any]:
        res = await run_tool(
            [
                "trivy", "image",
                "--image-src", "remote",
                "--scanners", "vuln,secret",
                "--format", "json",
                "--quiet",
                "--disable-telemetry",
                "--skip-version-check",
                "--skip-java-db-update",
                "--cache-dir", str(ctx.paths.cache_dir / "trivy"),
                "--timeout", f"{TRIVY_TIMEOUT // 60 - 1}m",
                ref,
            ],
            home=ctx.workdir / "trivy-home",
            timeout=TRIVY_TIMEOUT,
        )
        if res.returncode != 0 or not res.stdout.strip().startswith("{"):
            raise RuntimeError(_trivy_error(res.stderr))
        return json.loads(res.stdout)


def image_ref(addon: AddonInfo) -> str | None:
    if addon.is_local_build or not addon.version:
        return None
    image = addon.image or ""
    if "@" in image or ":" in image.rsplit("/", 1)[-1]:
        return image
    return f"{image}:{addon.version}"


def _trivy_error(stderr: str) -> str:
    text = stderr.strip().splitlines()
    last = next((line for line in reversed(text) if line.strip()), "erro desconhecido")
    if "UNAUTHORIZED" in stderr or "authentication required" in stderr:
        return "o registro exige autenticação (imagem privada?)"
    if "MANIFEST_UNKNOWN" in stderr or "not found" in stderr.lower():
        return "imagem/versão não encontrada no registro"
    return f"falha do Trivy: {last[-200:]}"


def findings_from_trivy(addon: AddonInfo, ref: str, data: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    fixable = {"CRITICAL": 0, "HIGH": 0}
    top: list[tuple[int, str]] = []
    seen: set[tuple[str, str]] = set()
    secrets: list[Finding] = []
    for result in data.get("Results") or []:
        target = str(result.get("Target", ""))
        for v in result.get("Vulnerabilities") or []:
            key = (str(v.get("VulnerabilityID")), str(v.get("PkgName")))
            if key in seen:
                continue
            seen.add(key)
            sev = str(v.get("Severity", "UNKNOWN")).upper()
            counts[sev if sev in counts else "UNKNOWN"] += 1
            fixed = v.get("FixedVersion")
            if sev in fixable and fixed:
                fixable[sev] += 1
            if sev in ("CRITICAL", "HIGH"):
                rank = (0 if sev == "CRITICAL" else 2) + (0 if fixed else 1)
                top.append((rank, f"{key[0]} [{sev.lower()}] {key[1]} {v.get('InstalledVersion', '?')}"
                                  + (f" → {fixed}" if fixed else " (sem correção)")))
        for s in result.get("Secrets") or []:
            secrets.append(Finding(
                component=addon.slug,
                component_type=ComponentType.ADDON,
                category="segredo_embutido",
                rule_id=f"trivy.secret.{s.get('RuleID', 'desconhecido')}",
                severity=Severity.HIGH,
                title=f"Segredo embutido na imagem: {s.get('Title') or s.get('Category') or 'segredo'}",
                explanation=(
                    "O Trivy encontrou o que parece ser um segredo (chave, token, senha) gravado dentro da "
                    "imagem do add-on. Quem baixar a imagem também tem acesso a ele; se for uma credencial "
                    "do autor, pode ser usada para adulterar futuras versões."
                ),
                recommendation="Avise o autor do add-on para revogar o segredo e removê-lo da imagem.",
                file=f"{ref}:{target}",
                line=s.get("StartLine"),
                snippet=str(s.get("Match") or "")[:300] or None,
                source="trivy",
            ))

    findings = list(secrets)
    total = sum(counts.values())
    if counts["CRITICAL"] or counts["HIGH"]:
        if fixable["CRITICAL"]:
            sev = Severity.HIGH
        elif fixable["HIGH"]:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW
        top.sort()
        ids = sorted(line.split(" ", 1)[0] for _, line in top)
        lines = [line for _, line in top[:_TOP]]
        if len(top) > _TOP:
            lines.append(f"… e mais {len(top) - _TOP}")
        findings.append(Finding(
            component=addon.slug,
            component_type=ComponentType.ADDON,
            category="cve",
            rule_id="trivy.vulnerabilidades",
            severity=sev,
            title=(f"{counts['CRITICAL']} CVE(s) crítica(s) e {counts['HIGH']} alta(s) na imagem"),
            explanation=(
                f"A imagem {ref} tem {total} vulnerabilidades conhecidas em pacotes do sistema ou "
                f"bibliotecas ({fixable['CRITICAL']} críticas e {fixable['HIGH']} altas já têm correção). "
                "Nem toda CVE é explorável no uso do add-on, mas as com correção indicam imagem desatualizada."
            ),
            recommendation=(
                "Atualize o add-on se houver versão nova; se não houver, avise o autor que a imagem base "
                "está desatualizada."
            ),
            file=ref,
            snippet="\n".join(lines),
            source="trivy",
            extra={"fingerprint_key": hashlib.sha256(",".join(ids).encode()).hexdigest()[:16], "contagem": counts},
        ))
    return findings, {k.lower(): v for k, v in counts.items()}


def _not_scanned(addon: AddonInfo, reason: str) -> Finding:
    return Finding(
        component=addon.slug,
        component_type=ComponentType.ADDON,
        category="analise_incompleta",
        rule_id="trivy.nao-analisada",
        severity=Severity.INFO,
        title="Imagem não analisada",
        explanation=f"A imagem do add-on não pôde ser varrida: {reason}.",
        recommendation="Nenhuma ação obrigatória. Add-ons locais são cobertos só pela análise do código-fonte.",
        source="trivy",
        extra={"fingerprint_key": reason[:60]},
    )
