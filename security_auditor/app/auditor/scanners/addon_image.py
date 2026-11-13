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
from ..models import ComponentType, Finding, Severity, en_text
from ..resources import postponed
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
                findings.append(_not_scanned(addon, "add-on construído localmente (sem imagem no registro)",
                                             "add-on built locally (no image in a registry)"))
                continue
            if (reason := await ctx.wait_resources(self.name)) is not None:
                findings.append(postponed(addon.slug, ComponentType.ADDON, "varredura da imagem (Trivy)", reason))
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
            await ctx.pause()
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
                "--parallel", str(ctx.profile.trivy_parallel),
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
                en=en_text(
                    f"Secret embedded in the image: {s.get('Title') or s.get('Category') or 'secret'}",
                    "Trivy found what looks like a secret (key, token, password) stored inside the add-on image. "
                    "Anyone who downloads the image also gets it; if it is an author credential, it can be used "
                    "to tamper with future versions.",
                    "Tell the add-on author to revoke the secret and remove it from the image.",
                ),
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
            en=en_text(
                f"{counts['CRITICAL']} critical and {counts['HIGH']} high CVE(s) in the image",
                f"The image {ref} has {total} known vulnerabilities in system packages or libraries "
                f"({fixable['CRITICAL']} critical and {fixable['HIGH']} high ones already have a fix). Not every "
                "CVE is exploitable in the add-on's use, but the fixable ones point to an outdated image.",
                "Update the add-on if a new version exists; if not, tell the author the base image is outdated.",
            ),
            file=ref,
            snippet="\n".join(lines),
            source="trivy",
            extra={"fingerprint_key": hashlib.sha256(",".join(ids).encode()).hexdigest()[:16], "contagem": counts},
        ))
    return findings, {k.lower(): v for k, v in counts.items()}


_REASONS_EN = {
    "o registro exige autenticação (imagem privada?)": "the registry requires authentication (private image?)",
    "imagem/versão não encontrada no registro": "image/version not found in the registry",
}


def _not_scanned(addon: AddonInfo, reason: str, reason_en: str | None = None) -> Finding:
    if reason_en is None:
        reason_en = _REASONS_EN.get(reason) or reason.replace("falha do Trivy:", "Trivy failure:").replace(
            " excedeu ", " exceeded ")
    return Finding(
        component=addon.slug,
        component_type=ComponentType.ADDON,
        category="analise_incompleta",
        rule_id="trivy.nao-analisada",
        severity=Severity.INFO,
        title="Imagem não analisada",
        explanation=f"A imagem do add-on não pôde ser varrida: {reason}.",
        recommendation="Nenhuma ação obrigatória. Add-ons locais são cobertos só pela análise do código-fonte.",
        en=en_text("Image not analysed", f"The add-on image could not be scanned: {reason_en}.",
                   "No action required. Local add-ons are covered only by the source code analysis."),
        source="trivy",
        extra={"fingerprint_key": reason[:60]},
    )
