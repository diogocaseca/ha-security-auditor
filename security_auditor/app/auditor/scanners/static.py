"""Análise estática com Semgrep (regras próprias) e Bandit.

Importante: a lista de arquivos é montada pelo auditor e passada
explicitamente ao Semgrep. Assim os ignores padrão dele (``*.min.js``,
``tests/``...) não se aplicam: código malicioso costuma se esconder
justamente nesses lugares.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..inventory import Component, Inventory
from ..models import ComponentType, Finding, Severity, en_text
from ..resources import postponed
from ..tools import ToolTimeoutError, run_tool
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
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Roda o Semgrep em lotes sobre ``targets`` com as pastas de regras indicadas.

    Devolve (resultados brutos, {arquivo: {tipo, linha, mensagem}} dos analisados só em parte).
    """
    if not targets:
        return [], {}
    configs: list[str] = []
    for d in rule_dirs:
        configs += ["--config", str(ctx.paths.rules_dir / "semgrep" / d)]
    home = ctx.workdir / "semgrep-home"
    results: list[dict[str, Any]] = []
    incomplete: dict[str, dict[str, Any]] = {}
    extra: list[str] = []
    if ctx.profile.semgrep_max_memory_mb:
        extra += ["--max-memory", str(ctx.profile.semgrep_max_memory_mb)]
    for i in range(0, len(targets), SEMGREP_BATCH):
        if i:
            await ctx.pause()
        data = await _semgrep_resilient(ctx, configs, extra, home, targets[i : i + SEMGREP_BATCH])
        results.extend(data.get("results", []))
        for err in data.get("errors", []):
            path = err.get("path") or (err.get("spans") or [{}])[0].get("file")
            if path and path not in incomplete:
                incomplete[path] = _semgrep_error(err)
    if retry := [Path(p) for p, err in incomplete.items() if p.endswith(".py") or _unreadable(err)]:
        await _retry_in_copies(ctx, configs, extra, home, retry, results, incomplete)
    return results, incomplete


async def _semgrep_batch(ctx: ScanContext, configs: list[str], extra: list[str], home: Path,
                         batch: list[Path]) -> dict[str, Any]:
    res = await run_tool(
        [
            "semgrep", "scan", *configs,
            "--json", "--quiet",
            "--metrics=off", "--disable-version-check", "--oss-only",
            "--no-git-ignore", "--x-ignore-semgrepignore-files", "--no-rewrite-rule-ids",
            "--max-target-bytes", str(ctx.options.max_file_bytes),
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
    return json.loads(res.stdout)


async def _semgrep_resilient(ctx: ScanContext, configs: list[str], extra: list[str], home: Path,
                             batch: list[Path]) -> dict[str, Any]:
    """Um lote do Semgrep que não se perde inteiro por causa de um arquivo.

    Se o Semgrep morrer (memória, por exemplo), o lote é dividido ao meio e repetido até isolar o arquivo, que
    fica marcado como não analisado; os outros seguem normalmente. Estouro de tempo não é repetido (repetir
    custaria o mesmo tempo de novo): os arquivos do lote ficam marcados.
    """
    try:
        return await _semgrep_batch(ctx, configs, extra, home, batch)
    except ToolTimeoutError as err:
        return _batch_failure(batch, "Tempo esgotado", str(err))
    except (RuntimeError, ValueError) as err:
        if len(batch) == 1:
            return _batch_failure(batch, "Falha do Semgrep", str(err))
        _LOGGER.warning("Semgrep falhou num lote de %d arquivos; dividindo para achar o arquivo: %s", len(batch),
                        str(err)[:200])
        half = len(batch) // 2
        first = await _semgrep_resilient(ctx, configs, extra, home, batch[:half])
        await ctx.pause()
        second = await _semgrep_resilient(ctx, configs, extra, home, batch[half:])
        return {"results": first.get("results", []) + second.get("results", []),
                "errors": first.get("errors", []) + second.get("errors", [])}


def _batch_failure(batch: list[Path], kind: str, message: str) -> dict[str, Any]:
    # Só a última linha útil: a mensagem do Semgrep traz um texto longo de ajuda.
    text = " ".join(message.split())[-200:]
    return {"results": [], "errors": [{"type": kind, "path": str(p), "message": text} for p in batch]}


# Sintaxe nova de tipos (PEP 695, Python 3.12+) que o analisador de Python do Semgrep nem sempre entende. É
# padrão nas integrações atuais (``type MinhaConfigEntry = ConfigEntry[...]``) e fazia o arquivo inteiro ficar
# sem análise. Numa cópia, a linha vira a forma antiga equivalente para a análise (sem mudar o número de
# linhas); os achados voltam para o arquivo original.
_NEW_SYNTAX = (
    (re.compile(r"^(\s*)type\s+(\w+)\s*(?:\[[^\]\n]*\])?\s*=", re.MULTILINE), r"\1\2 ="),
    (re.compile(r"^(\s*(?:async\s+)?def\s+\w+)\s*\[[^\]\n]*\]\s*\(", re.MULTILINE), r"\1("),
    (re.compile(r"^(\s*class\s+\w+)\s*\[[^\]\n]*\]", re.MULTILINE), r"\1"),
)


def rewrite_new_syntax(text: str) -> str | None:
    """Troca a sintaxe nova de tipos pela antiga; None se não havia nada para trocar."""
    out = text
    for pattern, repl in _NEW_SYNTAX:
        out = pattern.sub(repl, out)
    return out if out != text else None


def _unreadable(err: dict[str, Any]) -> bool:
    """O Semgrep não conseguiu abrir o arquivo (no HA acontece em parte dos .js de /config, mas o auditor lê)."""
    return "Permission denied" in str(err.get("mensagem") or "")


async def _retry_in_copies(ctx: ScanContext, configs: list[str], extra: list[str], home: Path,
                           files: list[Path], results: list[dict[str, Any]],
                           incomplete: dict[str, dict[str, Any]]) -> None:
    """Repete a análise numa cópia na pasta de trabalho: arquivos que o Semgrep não abriu e .py com a sintaxe nova
    de tipos (reescrita na forma antiga). Os achados voltam para o arquivo original; o que continuar com erro na
    cópia fica como estava."""
    work = ctx.workdir / "semgrep-compat"
    copies: dict[str, str] = {}
    for n, original in enumerate(files):
        unreadable = _unreadable(incomplete.get(str(original)) or {})
        try:
            data = original.read_bytes()
        except OSError:
            continue
        if original.suffix == ".py":
            try:
                rewritten = rewrite_new_syntax(data.decode("utf-8"))
            except UnicodeDecodeError:
                rewritten = None
            if rewritten is not None:
                data = rewritten.encode("utf-8")
            elif not unreadable:
                continue
        copy = work / str(n) / original.name
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(data)
        copies[str(copy)] = str(original)
    if not copies:
        return
    paths = [Path(c) for c in copies]
    data: dict[str, Any] = {"results": [], "errors": []}
    try:
        for i in range(0, len(paths), SEMGREP_BATCH):
            await ctx.pause()
            part = await _semgrep_batch(ctx, configs, extra, home, paths[i : i + SEMGREP_BATCH])
            data["results"] += part.get("results", [])
            data["errors"] += part.get("errors", [])
    except (RuntimeError, ValueError) as err:
        _LOGGER.warning("Nova análise do Semgrep nas cópias falhou: %s", err)
        return
    finally:
        shutil.rmtree(work, ignore_errors=True)
    errors: dict[str, dict[str, Any]] = {}
    for err in data.get("errors", []):
        path = err.get("path") or (err.get("spans") or [{}])[0].get("file")
        if path in copies and copies[path] not in errors:
            errors[copies[path]] = _semgrep_error(err)
    fixed = {original for original in copies.values() if original not in errors}
    # Os achados da cópia valem quando ela foi analisada por inteiro ou quando o original nem foi aberto.
    use = fixed | {o for o in copies.values() if _unreadable(incomplete.get(o) or {})}
    # Cópia de um arquivo que o Semgrep não abria: o erro que sobrar (de sintaxe, por exemplo) é o verdadeiro.
    for original, err in errors.items():
        if _unreadable(incomplete.get(original) or {}):
            incomplete[original] = err
    results[:] = [r for r in results if r.get("path") not in use]
    for r in data.get("results", []):
        original = copies.get(str(r.get("path")))
        if original in use:
            results.append({**r, "path": original})
    for original in fixed:
        incomplete.pop(original, None)
    if fixed:
        _LOGGER.info("Semgrep: %d arquivo(s) analisados numa cópia na pasta de trabalho", len(fixed))


_ERROR_LINE = re.compile(r"\bat line \S*?:(\d+)\b")
_ERROR_PATH = re.compile(r"(?<=at line )\S*?:(?=\d+\b)")


def _semgrep_error(err: dict[str, Any]) -> dict[str, Any]:
    """Tipo, linha e mensagem (primeira linha, curta) de um erro do Semgrep num arquivo."""
    kind = err.get("type", "erro")
    if isinstance(kind, list):  # ["PartialParsing", [trechos]]
        kind = kind[0] if kind else "erro"
    spans = err.get("spans") or []
    if not spans and isinstance(err.get("type"), list) and len(err["type"]) > 1:
        spans = err["type"][1] or []
    line = (spans[0].get("start") or {}).get("line") if spans and isinstance(spans[0], dict) else None
    message = " ".join(str(err.get("message") or "").split())
    if not isinstance(line, int) and (m := _ERROR_LINE.search(message)):
        line = int(m.group(1))
    # A mensagem traz o caminho completo do arquivo; o achado já mostra o arquivo.
    message = _ERROR_PATH.sub("", message)[:200]
    return {"tipo": str(kind), "linha": line if isinstance(line, int) else None, "mensagem": message}


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
                if size > ctx.options.max_file_bytes:
                    findings.append(_big_file_finding(comp, inv, f, size, ctx.options.max_file_mb))
                    continue
                semgrep_targets.append(f)

        need = ctx.guard.min_free_mb / 2
        if semgrep_targets and (reason := await ctx.wait_resources(self.name, need)):
            findings.append(postponed("auditor", ComponentType.SYSTEM, "análise estática (Semgrep/Bandit)", reason))
            return findings
        ctx.set_progress(self.name, f"Semgrep em {len(semgrep_targets)} arquivos")
        try:
            sg = await self._semgrep(ctx, inv, semgrep_targets)
        except (RuntimeError, ValueError, OSError, ToolTimeoutError) as err:
            # Sem o Semgrep, o Bandit (e o resto da varredura) continua: antes a etapa inteira se perdia.
            _LOGGER.exception("Semgrep falhou; seguindo com o Bandit")
            sg = [_semgrep_failed(err)]
        await ctx.pause()
        ctx.set_progress(self.name, f"Bandit em {len(bandit_dirs)} integrações")
        bd = await self._bandit(ctx, inv, bandit_dirs)
        findings.extend(_merge_same_line(sg, bd))
        return findings

    # --- Semgrep ------------------------------------------------------------

    async def _semgrep(self, ctx: ScanContext, inv: Inventory, targets: list[Path]) -> list[Finding]:
        raw, incomplete = await run_semgrep(ctx, targets, PHASE1_RULE_DIRS)
        results = [f for f in (_from_semgrep(r, inv) for r in raw) if f]
        for path, err in incomplete.items():
            p = Path(path)
            comp = inv.owner_of(p)
            if comp:
                results.append(_incomplete_finding(comp, inv.rel(p), p, err))
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


def _semgrep_failed(err: Exception) -> Finding:
    detail = " ".join(f"{type(err).__name__}: {err}".split())[-300:]
    return Finding(
        component="auditor",
        component_type=ComponentType.SYSTEM,
        category="analise_incompleta",
        rule_id="auditor.semgrep-falhou",
        severity=Severity.MEDIUM,
        title="Análise de código do Semgrep não rodou",
        explanation=("O Semgrep falhou e os achados de código desta varredura vêm só do Bandit (Python) e das "
                     f"outras etapas. Integrações e cards podem parecer mais seguros do que são. Erro: {detail}"),
        recommendation="Veja o log do app e rode a varredura completa de novo; se repetir, abra uma issue.",
        en=en_text("Semgrep code analysis did not run",
                   "Semgrep failed and this scan's code findings come only from Bandit (Python) and the other steps. "
                   f"Integrations and cards may look safer than they are. Error: {detail}",
                   "Check the app log and run the full scan again; if it repeats, open an issue."),
        source="auditor",
        extra={"fingerprint_key": "semgrep-falhou", "chave_estavel": True},
    )


def _incomplete_finding(comp: Any, rel: str, path: Path, err: dict[str, Any]) -> Finding:
    kind, line, message = err["tipo"], err.get("linha"), err.get("mensagem") or ""
    where = f" na linha {line}" if line else ""
    where_en = f" at line {line}" if line else ""
    bandit = (" O Bandit, que usa o analisador do próprio Python, continua analisando o arquivo."
              if path.suffix == ".py" else "")
    bandit_en = (" Bandit, which uses Python's own parser, still analyses the file." if path.suffix == ".py" else "")
    detail = f" Mensagem do Semgrep: {message}" if message else ""
    detail_en = f" Semgrep message: {message}" if message else ""
    return Finding(
        component=comp.name,
        component_type=comp.component_type,
        category="analise_incompleta",
        rule_id="auditor.analise-incompleta",
        severity=Severity.INFO,
        title="Arquivo analisado só em parte",
        explanation=(f"O Semgrep não conseguiu analisar o arquivo inteiro ({kind}{where}). É comum em scripts "
                     "minificados ou com sintaxe muito nova, mas também pode ser proposital para fugir da análise."
                     + bandit + detail),
        recommendation="Se o componente for pouco conhecido, revise este arquivo manualmente.",
        en=en_text("File only partially analysed",
                   f"Semgrep could not analyse the whole file ({kind}{where_en}). This is common in minified scripts "
                   "or with very new syntax, but it can also be deliberate to evade analysis." + bandit_en
                   + detail_en,
                   _MANUAL_REVIEW_EN),
        file=rel,
        line=line,
        snippet=read_snippet(path, line, line) if line else None,
        source="semgrep",
        extra={"fingerprint_key": kind, "chave_estavel": True},
    )


# Testes do Bandit cujo nível não combina com a busca por código malicioso (ex.: B324, md5/sha1 para gerar
# identificadores, é comum e inofensivo): nível fixo.
# B324: md5/sha1 para gerar identificadores. B104: qualquer texto "0.0.0.0", inclusive comparações e listas;
# abrir uma porta em todas as interfaces só às vezes é o caso.
# B701: autoescape do Jinja2 só protege HTML; nas integrações o Jinja monta templates do HA, não páginas.
# B413: o pycryptodome (mantido) usa o mesmo nome de pacote "Crypto" do pyCrypto antigo; a cifra fraca usada,
# quando houver, aparece à parte (B304/B305).
BANDIT_FIXED_SEVERITY = {"B324": Severity.LOW, "B104": Severity.LOW, "B701": Severity.LOW, "B413": Severity.LOW}


# B202 (tarfile.extractall sem filtro): é comum o caminho seguro (filter="data") com um "else" sem filtro só
# para Pythons antigos. O HA roda num Python que tem o filtro, então esse "else" nunca é usado.
_TAR_FILTER_GUARD = re.compile(r"\bdata_filter\b|\bfilter\s*=\s*[\"'](?:data|tar)[\"']")
_TAR_GUARD_LINES = 4


def _tar_fallback(path: Path, line: int | None) -> bool:
    """True se o extractall sem filtro (B202) está logo depois do mesmo extractall com filtro."""
    if not line:
        return False
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            text = fh.read().splitlines()
    except OSError:
        return False
    before = text[max(0, line - 1 - _TAR_GUARD_LINES):line - 1]
    return any(_TAR_FILTER_GUARD.search(t) for t in before)


# B506 (yaml.load): só é perigoso com um loader inseguro. O Bandit marca qualquer loader que não seja o
# SafeLoader, inclusive os do Home Assistant e loaders próprios derivados do seguro.
_UNSAFE_YAML_LOADER = re.compile(r"Loader\s*=\s*(?:\w+\.)*(?:Loader|UnsafeLoader|FullLoader)\b")
_ANY_YAML_LOADER = re.compile(r"\bLoader\s*=")


def _yaml_load_severity(code: str, severity: Severity) -> Severity:
    """B506: mantém a severidade sem loader (padrão antigo inseguro) ou com loader inseguro; senão, Baixa."""
    if not _ANY_YAML_LOADER.search(code) or _UNSAFE_YAML_LOADER.search(code):
        return severity
    return Severity.LOW


def _bandit_severity(sev: str, conf: str, test_id: str = "") -> Severity:
    if test_id in BANDIT_FIXED_SEVERITY:
        return BANDIT_FIXED_SEVERITY[test_id]
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
    snippet = read_snippet(path, line, max(line_range) if line_range else line)
    severity = _bandit_severity(str(r.get("issue_severity", "LOW")), str(r.get("issue_confidence", "LOW")), test_id)
    if test_id == "B506":
        severity = _yaml_load_severity(str(r.get("code") or snippet or ""), severity)
    elif test_id == "B202" and _tar_fallback(path, line):
        severity = Severity.LOW
    return Finding(
        component=comp.name,
        component_type=comp.component_type,
        category=category,
        rule_id=f"bandit.{test_id}",
        severity=severity,
        title=title,
        explanation=explanation,
        recommendation="Leia o trecho e confirme se o uso é seguro neste contexto.",
        en=en_text(title_en, explanation_en, _BANDIT_RECOMMENDATION_EN),
        file=inv.rel(path),
        line=line,
        snippet=snippet,
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


def _big_file_finding(comp: Component, inv: Inventory, path: Path, size: int, limit_mb: int = 6) -> Finding:
    return Finding(
        component=comp.name,
        component_type=comp.component_type,
        category="analise_incompleta",
        rule_id="auditor.arquivo-grande",
        severity=Severity.INFO,
        title="Arquivo grande não analisado",
        explanation=(f"O arquivo tem {size // 1024} KiB, acima do limite de análise estática ({limit_mb} MB, opção "
                     "limite_arquivo_mb)."),
        recommendation=("Se o componente for pouco conhecido, revise este arquivo manualmente ou aumente o limite "
                        "nas opções do app (a varredura fica mais lenta e usa mais memória)."),
        en=en_text("Large file not analysed",
                   f"The file is {size // 1024} KiB, above the static analysis limit ({limit_mb} MB, option "
                   "limite_arquivo_mb).",
                   "If the component is not well known, review this file manually or raise the limit in the app "
                   "options (the scan gets slower and uses more memory)."),
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
