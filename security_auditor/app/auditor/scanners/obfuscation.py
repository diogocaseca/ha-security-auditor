"""Ofuscação em Python e código compilado sem fonte, sem ferramentas externas.

Complementa as regras do Semgrep com heurísticas que são mais fáceis por texto:

- texto montado com ``chr()`` em sequência, longas sequências ``\\xNN``, nomes de variáveis do tipo
  ``O0O0O0``/``lIlIlI`` e linhas de código enormes (código "minificado" em Python não é normal);
- dados compactados (``zlib``/``lzma``/``bz2``/``gzip``/``marshal``) e ``exec``/``eval`` no mesmo arquivo;
- arquivos compilados ou binários dentro do componente: ``.pyc`` fora de ``__pycache__`` (o Python
  importa um ``.pyc`` solto mesmo sem o ``.py``, e ele não aparece na análise estática), bibliotecas
  nativas e executáveis (ELF, PE, Mach-O).
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

from ..inventory import MAX_ANALYZED_FILE, Component, Inventory
from ..models import ComponentType, Finding, Severity, en_text
from .base import ScanContext
from .static import read_snippet

_CHR_CHAIN = re.compile(r"(?:chr\(\s*\d{1,3}\s*\)\s*\+\s*){6,}chr\(\s*\d{1,3}\s*\)")
_HEX_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){48,}")
_WEIRD_NAME = re.compile(r"\b(?=\w*[O0]\w*[O0])(?=\w*O)[O0_]{8,}\b|\b(?=\w*[Il1]\w*[Il1])(?=\w*[Il])[Il1_]{8,}\b")
_DECOMPRESS = re.compile(r"\b(?:zlib|lzma|bz2|gzip)\.decompress\s*\(|\bmarshal\.loads\s*\(")
_EXEC = re.compile(r"\b(?:exec|eval)\s*\(")
LONG_LINE = 2000
_STRING = re.compile(r"""[rRbBfFuU]{0,2}(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')""")
_NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib", ".exe", ".bin")
_MAGIC = {b"\x7fELF": "ELF (Linux)", b"MZ": "PE (Windows)", b"\xcf\xfa\xed\xfe": "Mach-O (macOS)",
          b"\xfe\xed\xfa\xcf": "Mach-O (macOS)"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def _scan_python(text: str) -> list[tuple[str, int]]:
    """(regra, linha) das heurísticas de ofuscação num arquivo Python."""
    hits: list[tuple[str, int]] = []

    def line_of(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    for rule, rx in (("chr-concatenado", _CHR_CHAIN), ("escapes-hex", _HEX_RUN)):
        if m := rx.search(text):
            hits.append((rule, line_of(m.start())))
    names = list(_WEIRD_NAME.finditer(text))
    if len({m.group(0) for m in names}) >= 3:
        hits.append(("nomes-ofuscados", line_of(names[0].start())))
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > LONG_LINE and not line.lstrip().startswith("#") and not _is_prose(line):
            hits.append(("linha-enorme", n))
            break
    dec, ex = _DECOMPRESS.search(text), _EXEC.search(text)
    if dec and ex:
        hits.append(("descompacta-e-executa", line_of(ex.start())))
    return hits


def _is_prose(line: str) -> bool:
    """Linha que é quase só texto entre aspas, com palavras separadas por espaço (um prompt, uma mensagem).

    Código compactado ou ofuscado não tem esse formato; um texto codificado (base64, hex) não tem espaços.
    Se a linha executa o texto (exec/eval), não é prosa.
    """
    if _EXEC.search(line):
        return False
    literals = [m.group(0) for m in _STRING.finditer(line)]
    inside = sum(len(t) for t in literals)
    if inside < 0.9 * len(line.strip()):
        return False
    return sum(t.count(" ") for t in literals) >= 0.08 * inside


def _binary_kind(path: Path) -> str | None:
    """Tipo de arquivo compilado/binário que merece revisão, ou None."""
    name = path.name.lower()
    if name.endswith((".pyc", ".pyo")):
        return "pyc"
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return None
    for magic, label in _MAGIC.items():
        if head.startswith(magic) and (magic != b"MZ" or name.endswith((".exe", ".dll", ".pyd", ".bin"))):
            return label
    if name.endswith(_NATIVE_SUFFIXES):
        return "nativo"
    return None


def _all_files(root: Path) -> list[Path]:
    """Todos os arquivos (inclusive .pyc), sem seguir links e sem __pycache__/.git/node_modules."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not (Path(dirpath) / d).is_symlink())
        out += [Path(dirpath) / f for f in sorted(filenames) if not (Path(dirpath) / f).is_symlink()]
    return out


_TEXTS = {
    "chr-concatenado": (
        Severity.HIGH, "Texto montado com chr() em sequência",
        ("Montar texto caractere por caractere com chr() é uma técnica clássica para esconder URLs, comandos ou "
        "código de quem lê o arquivo e das ferramentas de análise."),
        "Text built with chr() in sequence",
        ("Building text character by character with chr() is a classic technique to hide URLs, commands or code "
        "from whoever reads the file and from analysis tools.")),
    "escapes-hex": (
        Severity.MEDIUM, "Longa sequência de escapes hexadecimais (\\xNN)",
        ("Uma sequência longa de \\xNN costuma esconder texto ou código. Pode ser só um dado binário, mas em "
        "integrações é incomum."),
        "Long run of hexadecimal escapes (\\xNN)",
        ("A long run of \\xNN usually hides text or code. It may just be binary data, but it is unusual in "
        "integrations.")),
    "nomes-ofuscados": (
        Severity.MEDIUM, "Nomes de variáveis ofuscados",
        "Vários nomes como O0O0O0 ou lIlIlI no mesmo arquivo são sinal de código passado por um ofuscador.",
        "Obfuscated variable names",
        "Several names like O0O0O0 or lIlIlI in the same file are a sign of code run through an obfuscator."),
    "linha-enorme": (
        Severity.MEDIUM, "Linha de código enorme",
        (f"Uma linha com mais de {LONG_LINE} caracteres não é comum em Python escrito por pessoas; costuma ser "
        "código compactado ou ofuscado para dificultar a leitura."),
        "Huge line of code",
        (f"A line over {LONG_LINE} characters is not common in Python written by people; it is usually code that "
        "was packed or obfuscated to make reading hard.")),
    "descompacta-e-executa": (
        Severity.HIGH, "Dados compactados e execução dinâmica no mesmo arquivo",
        ("O arquivo descompacta dados (zlib, lzma, bz2, gzip ou marshal) e usa exec/eval: é o jeito mais comum "
        "de esconder um payload dentro de uma integração."),
        "Compressed data and dynamic execution in the same file",
        ("The file decompresses data (zlib, lzma, bz2, gzip or marshal) and uses exec/eval: it is the most common "
        "way to hide a payload inside an integration.")),
}
_RECOMMEND = (("Veja o que o trecho produz (sem executar) e se o resto do componente explica o motivo. Código legítimo "
              "raramente precisa se esconder."),
              ("Check what the snippet produces (without running it) and whether the rest of the component explains "
              "why. Legitimate code rarely needs to hide."))


class ObfuscationScanner:
    name = "ofuscacao"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        inv: Inventory = ctx.inventory()
        comps = [c for c in [*inv.integrations, *inv.frontend] if c.name != "www"]
        return await asyncio.to_thread(self._scan_all, inv, comps, ctx.options.max_file_bytes)

    def _scan_all(self, inv: Inventory, comps: list[Component], max_bytes: int = MAX_ANALYZED_FILE) -> list[Finding]:
        findings: list[Finding] = []
        for comp in comps:
            for path in _all_files(comp.path):
                kind = _binary_kind(path)
                if kind is not None:
                    findings.append(_binary_finding(comp, inv, path, kind))
                    continue
                if comp.component_type != ComponentType.INTEGRATION or path.suffix != ".py":
                    continue
                try:
                    if path.stat().st_size > max_bytes:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for rule, line in _scan_python(text):
                    findings.append(_heuristic_finding(comp, inv, path, rule, line))
        return findings


def _heuristic_finding(comp: Component, inv: Inventory, path: Path, rule: str, line: int) -> Finding:
    sev, title, why, title_en, why_en = _TEXTS[rule]
    return Finding(
        component=comp.name, component_type=comp.component_type, category="ofuscacao",
        rule_id=f"auditor.ofuscacao.{rule}", severity=sev, title=title, explanation=why,
        recommendation=_RECOMMEND[0], en=en_text(title_en, why_en, _RECOMMEND[1]),
        file=inv.rel(path), line=line, snippet=read_snippet(path, line), source="auditor",
    )


def _binary_finding(comp: Component, inv: Inventory, path: Path, kind: str) -> Finding:
    if kind == "pyc":
        title, title_en = "Código Python compilado (.pyc) fora de __pycache__", "Compiled Python (.pyc) outside __pycache__"
        why = ("O Python importa um .pyc solto na pasta mesmo sem o .py correspondente. É código que não dá para ler "
               "e que nenhuma outra verificação do auditor analisa.")
        why_en = ("Python imports a loose .pyc in the folder even without the matching .py. It is code that cannot be "
                  "read and that no other check of the auditor analyses.")
    else:
        label = "biblioteca nativa" if kind == "nativo" else f"executável {kind}"
        label_en = "native library" if kind == "nativo" else f"{kind} executable"
        title, title_en = f"Arquivo compilado dentro do componente ({label})", f"Compiled file inside the component ({label_en})"
        why = ("Integrações e cards normalmente trazem só código-fonte. Um binário não pode ser revisado e pode fazer "
               "qualquer coisa quando carregado.")
        why_en = ("Integrations and cards normally ship only source code. A binary cannot be reviewed and can do "
                  "anything when loaded.")
    return Finding(
        component=comp.name, component_type=comp.component_type, category="codigo_compilado",
        rule_id="auditor.compilado.pyc-solto" if kind == "pyc" else "auditor.compilado.binario",
        severity=Severity.HIGH, title=title, explanation=why,
        recommendation="Confirme com o autor por que o arquivo existe. Se não houver explicação, remova o componente.",
        en=en_text(title_en, why_en,
                   "Ask the author why the file exists. If there is no explanation, remove the component."),
        file=inv.rel(path), source="auditor",
    )
