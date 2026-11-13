"""Análise estática com Semgrep (regras próprias) e Bandit.

Importante: a lista de arquivos é montada pelo auditor e passada
explicitamente ao Semgrep. Assim os ignores padrão dele (``*.min.js``,
``tests/``...) não se aplicam: código malicioso costuma se esconder
justamente nesses lugares.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..inventory import MAX_ANALYZED_FILE, Component, Inventory
from ..models import ComponentType, Finding, Severity, en_text
from ..resources import postponed
from ..tools import run_tool
from .base import ScanContext

_LOGGER = logging.getLogger(__name__)

PY_SUFFIXES = (".py",)
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts")
SEMGREP_BATCH = 300
SEMGREP_TIMEOUT = 1800
BANDIT_TIMEOUT = 900

SEVERITY_BY_LABEL = {
    "critica": Severity.CRITICAL,
    "alta": Severity.HIGH,
    "media": Severity.MEDIUM,
    "baixa": Severity.LOW,
    "informativa": Severity.INFO,
}

# Regras genéricas que perdem para uma regra mais específica na mesma linha.
GENERIC_RULES = frozenset(
    {
        "auditor.py.eval-dinamico",
        "auditor.py.execucao-de-comandos",
        "auditor.py.marshal-loads",
        "auditor.py.url-fixa",
        "auditor.py.acesso-storage",
        "auditor.js.eval-dinamico",
    }
)

# Bandit: testes que só repetem regras próprias ou geram ruído demais.
BANDIT_SKIP = "B101,B110,B112,B311,B404,B603"

_BANDIT_INFO: dict[str, tuple[str, str, str]] = {
    # test_id: (categoria, título, explicação)
    "B102": ("execucao_dinamica", "Uso de exec", "exec executa texto como código Python."),
    "B307": ("execucao_dinamica", "Uso de eval", "eval executa texto como código Python."),
    "B301": ("desserializacao", "Desserialização com pickle",
             "pickle pode executar código arbitrário ao carregar dados; nunca deve ler dados não confiáveis."),
    "B302": ("desserializacao", "Desserialização com marshal", "marshal carrega objetos de código Python."),
    "B403": ("desserializacao", "Importação de pickle", "O módulo pickle permite executar código ao carregar dados."),
    "B602": ("execucao_de_comandos", "subprocess com shell=True",
             "O comando passa pelo shell, o que permite injeção de comandos."),
    "B605": ("execucao_de_comandos", "Comando executado via shell",
             "os.system/os.popen executam o texto num shell."),
    "B606": ("execucao_de_comandos", "Processo iniciado sem shell", "A integração inicia outro programa."),
    "B607": ("execucao_de_comandos", "Programa chamado por caminho parcial",
             "O programa é procurado no PATH; outro executável com o mesmo nome poderia ser chamado."),
    "B609": ("execucao_de_comandos", "Curinga em comando", "Curingas em comandos podem virar injeção de argumentos."),
    "B310": ("rede", "urlopen com esquema livre",
             "urlopen aceita file:// e outros esquemas, permitindo ler arquivos locais."),
    "B501": ("tls", "Verificação de certificado desativada",
             "Sem verificar o certificado TLS, a conexão pode ser interceptada (homem no meio)."),
    "B104": ("rede", "Escuta em todas as interfaces", "A integração abre um servidor acessível de toda a rede."),
    "B105": ("segredo_embutido", "Possível senha fixa no código", "Há um valor que parece uma senha embutida no código."),
    "B106": ("segredo_embutido", "Possível senha fixa no código", "Há um valor que parece uma senha embutida no código."),
    "B107": ("segredo_embutido", "Possível senha fixa no código", "Há um valor que parece uma senha embutida no código."),
    "B108": ("arquivo_temporario", "Arquivo temporário previsível",
             "Caminhos fixos em /tmp podem ser explorados por outro processo."),
    "B324": ("criptografia_fraca", "Hash fraco (MD5/SHA1)",
             "MD5/SHA1 não são seguros para fins de segurança; para identificadores não há problema."),
    "B303": ("criptografia_fraca", "Hash fraco (MD5/SHA1)", "MD5/SHA1 não são seguros para fins de segurança."),
    "B413": ("criptografia_fraca", "Biblioteca pyCrypto", "pyCrypto não é mantida e tem vulnerabilidades conhecidas."),
}

# Mesmos testes, em inglês: test_id -> (título, explicação).
_BANDIT_EN: dict[str, tuple[str, str]] = {
    "B102": ("Use of exec", "exec runs text as Python code."),
    "B307": ("Use of eval", "eval runs text as Python code."),
    "B301": ("Deserialization with pickle",
             "pickle can execute arbitrary code when loading data; it must never read untrusted data."),
    "B302": ("Deserialization with marshal", "marshal loads Python code objects."),
    "B403": ("pickle import", "The pickle module allows code execution when loading data."),
    "B602": ("subprocess with shell=True", "The command goes through the shell, which allows command injection."),
    "B605": ("Command executed through a shell", "os.system/os.popen run the text in a shell."),
    "B606": ("Process started without a shell", "The integration starts another program."),
    "B607": ("Program called by a partial path",
             "The program is looked up in PATH; another executable with the same name could be called."),
    "B609": ("Wildcard in a command", "Wildcards in commands can turn into argument injection."),
    "B310": ("urlopen with any scheme", "urlopen accepts file:// and other schemes, allowing local files to be read."),
    "B501": ("Certificate verification disabled",
             "Without verifying the TLS certificate, the connection can be intercepted (man in the middle)."),
    "B104": ("Listening on all interfaces", "The integration opens a server reachable from the whole network."),
    "B105": ("Possible hard-coded password", "There is a value that looks like a password embedded in the code."),
    "B106": ("Possible hard-coded password", "There is a value that looks like a password embedded in the code."),
    "B107": ("Possible hard-coded password", "There is a value that looks like a password embedded in the code."),
    "B108": ("Predictable temporary file", "Fixed paths in /tmp can be exploited by another process."),
    "B324": ("Weak hash (MD5/SHA1)", "MD5/SHA1 are not safe for security purposes; for identifiers they are fine."),
    "B303": ("Weak hash (MD5/SHA1)", "MD5/SHA1 are not safe for security purposes."),
    "B413": ("pyCrypto library", "pyCrypto is unmaintained and has known vulnerabilities."),
}
_BANDIT_RECOMMENDATION_EN = "Read the snippet and confirm the use is safe in this context."
_MANUAL_REVIEW_EN = "If the component is not well known, review this file manually."


PHASE1_RULE_DIRS = ("python", "javascript")


async def run_semgrep(
    ctx: ScanContext, targets: list[Path], rule_dirs: tuple[str, ...]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Roda o Semgrep em lotes sobre ``targets`` com as pastas de regras indicadas.

    Devolve (resultados brutos, {arquivo: tipo de erro} dos analisados só em parte).
    """
    if not targets:
        return [], {}
    configs: list[str] = []
    for d in rule_dirs:
        configs += ["--config", str(ctx.paths.rules_dir / "semgrep" / d)]
    home = ctx.workdir / "semgrep-home"
    results: list[dict[str, Any]] = []
    incomplete: dict[str, str] = {}
    extra: list[str] = []
    if ctx.profile.semgrep_max_memory_mb:
        extra += ["--max-memory", str(ctx.profile.semgrep_max_memory_mb)]
    for i in range(0, len(targets), SEMGREP_BATCH):
        if i:
            await ctx.pause()
        batch = targets[i : i + SEMGREP_BATCH]
        res = await run_tool(
            [
                "semgrep", "scan", *configs,
                "--json", "--quiet",
                "--metrics=off", "--disable-version-check", "--oss-only",
                "--no-git-ignore", "--x-ignore-semgrepignore-files", "--no-rewrite-rule-ids",
                "--max-target-bytes", str(MAX_ANALYZED_FILE),
                "--timeout", "30", "--timeout-threshold", "3",
                "--jobs", str(ctx.profile.semgrep_jobs),
                *extra,
                *[str(p) for p in batch],
            ],
            home=home,
            timeout=SEMGREP_TIMEOUT,
        )
        if res.returncode not in (0, 1) or not res.stdout.strip():
            raise RuntimeError(f"semgrep terminou com código {res.returncode}: {res.stderr[-300:]}")
        data = json.loads(res.stdout)
        results.extend(data.get("results", []))
        for err in data.get("errors", []):
            path = err.get("path") or (err.get("spans") or [{}])[0].get("file")
            if path:
                incomplete.setdefault(path, str(err.get("type", "erro")))
    return results, incomplete


class StaticAnalysisScanner:
    name = "analise_estatica"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        inv: Inventory = ctx.inventory()
        findings: list[Finding] = []
        semgrep_targets: list[Path] = []
        bandit_dirs: list[Path] = []

        for comp in inv.components:
            findings.extend(_symlink_findings(comp, inv))
            if comp.component_type == ComponentType.INTEGRATION and any(f.suffix == ".py" for f in comp.files):
                bandit_dirs.append(comp.path)
            for f in comp.files:
                if not f.name.endswith(PY_SUFFIXES + JS_SUFFIXES) or f.name.endswith(".d.ts"):
                    continue
                try:
                    size = f.stat().st_size
                except OSError:
                    continue
                if size > MAX_ANALYZED_FILE:
                    findings.append(_big_file_finding(comp, inv, f, size))
                    continue
                semgrep_targets.append(f)

        need = ctx.guard.min_free_mb / 2
        if semgrep_targets and (reason := await ctx.wait_resources(self.name, need)):
            findings.append(postponed("auditor", ComponentType.SYSTEM, "análise estática (Semgrep/Bandit)", reason))
            return findings
        ctx.set_progress(self.name, f"Semgrep em {len(semgrep_targets)} arquivos")
        sg = await self._semgrep(ctx, inv, semgrep_targets)
        await ctx.pause()
        ctx.set_progress(self.name, f"Bandit em {len(bandit_dirs)} integrações")
        bd = await self._bandit(ctx, inv, bandit_dirs)
        findings.extend(_merge_same_line(sg, bd))
        return findings

    # --- Semgrep ------------------------------------------------------------

    async def _semgrep(self, ctx: ScanContext, inv: Inventory, targets: list[Path]) -> list[Finding]:
        raw, incomplete = await run_semgrep(ctx, targets, PHASE1_RULE_DIRS)
        results = [f for f in (_from_semgrep(r, inv) for r in raw) if f]
        for path, kind in incomplete.items():
            p = Path(path)
            comp = inv.owner_of(p)
            if comp:
                results.append(
                    Finding(
                        component=comp.name,
                        component_type=comp.component_type,
                        category="analise_incompleta",
                        rule_id="auditor.analise-incompleta",
                        severity=Severity.INFO,
                        title="Arquivo analisado só em parte",
                        explanation=(
                            f"O Semgrep não conseguiu analisar o arquivo inteiro ({kind}). É comum em "
                            "scripts minificados, mas também pode ser proposital para fugir da análise."
                        ),
                        recommendation="Se o componente for pouco conhecido, revise este arquivo manualmente.",
                        en=en_text(
                            "File only partially analysed",
                            f"Semgrep could not analyse the whole file ({kind}). This is common in minified "
                            "scripts, but it can also be deliberate to evade analysis.",
                            _MANUAL_REVIEW_EN,
                        ),
                        file=inv.rel(p),
                        source="semgrep",
                        extra={"fingerprint_key": kind},
                    )
                )
        return results

    # --- Bandit -------------------------------------------------------------

    async def _bandit(self, ctx: ScanContext, inv: Inventory, dirs: list[Path]) -> list[Finding]:
        if not dirs:
            return []
        res = await run_tool(
            ["bandit", "-r", "-f", "json", "-q", "--skip", BANDIT_SKIP, "-x", "__pycache__", *[str(d) for d in dirs]],
            home=ctx.workdir / "bandit-home",
            timeout=BANDIT_TIMEOUT,
        )
        if res.returncode not in (0, 1) or not res.stdout.strip():
            raise RuntimeError(f"bandit terminou com código {res.returncode}: {res.stderr[-300:]}")
        data = json.loads(res.stdout)
        out = []
        for r in data.get("results", []):
            f = _from_bandit(r, inv)
            if f:
                out.append(f)
        return out


# --- Conversões ---------------------------------------------------------------


def _from_semgrep(r: dict[str, Any], inv: Inventory) -> Finding | None:
    path = Path(r["path"])
    comp = inv.owner_of(path)
    if comp is None:
        return None
    meta = (r.get("extra") or {}).get("metadata") or {}
    check_id = str(r.get("check_id", ""))
    rule_id = check_id[check_id.find("auditor.") :] if "auditor." in check_id else check_id
    start = r.get("start") or {}
    end = r.get("end") or {}
    return Finding(
        component=comp.name,
        component_type=comp.component_type,
        category=str(meta.get("categoria", "semgrep")),
        rule_id=rule_id,
        severity=SEVERITY_BY_LABEL.get(str(meta.get("severidade", "media")), Severity.MEDIUM),
        title=str(meta.get("titulo") or (r.get("extra") or {}).get("message") or rule_id),
        explanation=" ".join(str(meta.get("explicacao", "")).split()),
        recommendation=" ".join(str(meta.get("recomendacao", "Revise o trecho.")).split()),
        en=en_text(
            str(meta.get("titulo_en") or (r.get("extra") or {}).get("message") or rule_id),
            " ".join(str(meta.get("explicacao_en", "")).split()),
            " ".join(str(meta.get("recomendacao_en", "Review the snippet.")).split()),
        ) if meta.get("titulo_en") else None,
        file=inv.rel(path),
        line=start.get("line"),
        snippet=read_snippet(path, start.get("line"), end.get("line"), start.get("col"), end.get("col")),
        source="semgrep",
    )


def _bandit_severity(sev: str, conf: str) -> Severity:
    sev, conf = sev.upper(), conf.upper()
    if sev == "HIGH":
        return Severity.HIGH if conf == "HIGH" else Severity.MEDIUM
    if sev == "MEDIUM":
        return Severity.MEDIUM if conf in ("HIGH", "MEDIUM") else Severity.LOW
    return Severity.LOW


def _from_bandit(r: dict[str, Any], inv: Inventory) -> Finding | None:
    path = Path(r["filename"])
    comp = inv.owner_of(path)
    if comp is None:
        return None
    test_id = str(r.get("test_id", ""))
    category, title, explanation = _BANDIT_INFO.get(
        test_id,
        ("bandit", str(r.get("test_name", test_id)).replace("_", " "),
         f"O Bandit sinalizou: {r.get('issue_text', '')} (texto original em inglês)."),
    )
    title_en, explanation_en = _BANDIT_EN.get(
        test_id,
        (str(r.get("test_name", test_id)).replace("_", " "), f"Bandit reported: {r.get('issue_text', '')}"),
    )
    line = r.get("line_number")
    line_range = r.get("line_range") or [line]
    return Finding(
        component=comp.name,
        component_type=comp.component_type,
        category=category,
        rule_id=f"bandit.{test_id}",
        severity=_bandit_severity(str(r.get("issue_severity", "LOW")), str(r.get("issue_confidence", "LOW"))),
        title=title,
        explanation=explanation,
        recommendation="Leia o trecho e confirme se o uso é seguro neste contexto.",
        en=en_text(title_en, explanation_en, _BANDIT_RECOMMENDATION_EN),
        file=inv.rel(path),
        line=line,
        snippet=read_snippet(path, line, max(line_range) if line_range else line),
        source="bandit",
        extra={"bandit_cwe": (r.get("issue_cwe") or {}).get("id")},
    )


def _merge_same_line(semgrep: list[Finding], bandit: list[Finding]) -> list[Finding]:
    """Remove redundâncias na mesma linha.

    - regra genérica do Semgrep some se houver regra específica igual ou mais grave;
    - achado do Bandit é absorvido por achado do Semgrep igual ou mais grave
      (a fonte "bandit" é registrada no achado que ficou).
    """
    by_line: dict[tuple[str, str | None, int | None], list[Finding]] = defaultdict(list)
    for f in semgrep:
        by_line[(f.component, f.file, f.line)].append(f)
    kept: list[Finding] = []
    for f in semgrep:
        if f.rule_id in GENERIC_RULES and f.line is not None:
            if any(
                o is not f and o.rule_id not in GENERIC_RULES and o.severity >= f.severity
                for o in by_line[(f.component, f.file, f.line)]
            ):
                continue
        kept.append(f)
    kept_by_line: dict[tuple, list[Finding]] = defaultdict(list)
    for f in kept:
        kept_by_line[(f.component, f.file, f.line)].append(f)
    for b in bandit:
        peers = [o for o in kept_by_line.get((b.component, b.file, b.line), []) if o.severity >= b.severity]
        if peers:
            top = max(peers, key=lambda o: o.severity)
            top.extra["sources"] = sorted(set(top.extra.get("sources", [top.source])) | {"bandit"})
            continue
        kept.append(b)
    return kept


def _symlink_findings(comp: Component, inv: Inventory) -> list[Finding]:
    return [
        Finding(
            component=comp.name,
            component_type=comp.component_type,
            category="link_simbolico",
            rule_id="auditor.link-simbolico",
            severity=Severity.LOW,
            title="Link simbólico dentro do componente",
            explanation=(
                "Links simbólicos não são seguidos pela análise. Um link pode apontar para "
                "arquivos sensíveis (como o secrets.yaml) ou para código fora do componente."
            ),
            recommendation="Confira para onde o link aponta.",
            en=en_text(
                "Symbolic link inside the component",
                "Symbolic links are not followed by the analysis. A link can point to sensitive files (such as "
                "secrets.yaml) or to code outside the component.",
                "Check where the link points to.",
            ),
            file=f"{comp.rel_path}/{link}",
            source="auditor",
        )
        for link in comp.symlinks
    ]


def _big_file_finding(comp: Component, inv: Inventory, path: Path, size: int) -> Finding:
    return Finding(
        component=comp.name,
        component_type=comp.component_type,
        category="analise_incompleta",
        rule_id="auditor.arquivo-grande",
        severity=Severity.INFO,
        title="Arquivo grande não analisado",
        explanation=f"O arquivo tem {size // 1024} KiB, acima do limite de análise estática.",
        recommendation="Se o componente for pouco conhecido, revise este arquivo manualmente.",
        en=en_text("Large file not analysed",
                   f"The file is {size // 1024} KiB, above the static analysis limit.", _MANUAL_REVIEW_EN),
        file=inv.rel(path),
        source="auditor",
    )


_MAX_LINES = 6
_MAX_LINE_CHARS = 240


def read_snippet(
    path: Path,
    start: int | None,
    end: int | None = None,
    start_col: int | None = None,
    end_col: int | None = None,
) -> str | None:
    """Lê o trecho do próprio arquivo (o Semgrep OSS não devolve as linhas no JSON).

    Em linhas enormes (código minificado), recorta uma janela em volta do achado.
    """
    if not start:
        return None
    end = end or start
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            lines = []
            for n, text in enumerate(fh, start=1):
                if n > end or n >= start + _MAX_LINES:
                    break
                if n >= start:
                    lines.append(text.rstrip("\n"))
    except OSError:
        return None
    out = []
    for i, text in enumerate(lines):
        if len(text) > _MAX_LINE_CHARS:
            col = (start_col or 1) - 1 if i == 0 else 0
            left = max(0, col - 60)
            right = left + _MAX_LINE_CHARS
            text = ("…" if left else "") + text[left:right] + ("…" if right < len(text) else "")
        out.append(text)
    return "\n".join(out) or None
