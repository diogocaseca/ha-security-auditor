"""Mascaramento de segredos em trechos de código, relatórios e logs.

Camadas:
 1. valores conhecidos (secrets.yaml, token do Supervisor, token do GitHub),
    mantidos apenas em memória;
 2. padrões de formatos conhecidos (JWT, tokens do GitHub/AWS/Slack,
    chaves privadas, URLs com senha);
 3. atribuições do tipo ``password = "..."``/``token: ...``.
"""

from __future__ import annotations

import logging
import math
import re
import threading
from collections import Counter
from pathlib import Path

import yaml

MASK = "****"
_MIN_KNOWN_SECRET_LEN = 6

_PATTERNS: list[re.Pattern[str]] = [
    # Bloco de chave privada PEM inteiro.
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)", re.S),
    # JWT (inclui long-lived access tokens do HA).
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # GitHub
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    # AWS
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    # Slack / Discord webhooks e tokens
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"https://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services)/[^\s'\"]+"),
    # Telegram bot token
    re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    # Google API key
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
]

# usuario:senha@ em URLs -> mantém o usuário, mascara a senha.
_URL_CREDENTIALS = re.compile(r"(?P<pre>[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@'\"]+:)(?P<pw>[^@/\s'\"]+)(?P<post>@)")

# chave sensível seguida de valor literal (Python, YAML, JSON, JS, shell).
_ASSIGNMENT = re.compile(
    r"""(?P<key>["']?[A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*["']?)"""
    r"""(?P<sep>\s*(?::|=|:=|=>)\s*)"""
    r"""(?P<q>["']?)(?P<val>[^\s"',;#)}\]]{4,})(?P=q)""",
    re.I,
)
# Valores que não são segredos (referências, variáveis, placeholders).
_ASSIGNMENT_SAFE = re.compile(
    r"^(?:!secret|none|null|true|false|self\.|os\.environ|getenv|\$\{?|<|\{\{|config\[|entry\.|data\[|hass\.|kwargs|args)",
    re.I,
)


class Masker:
    """Mascarador thread-safe; uma instância global é usada pelos logs."""

    def __init__(self) -> None:
        self._known: set[str] = set()
        self._lock = threading.Lock()
        self._known_re: re.Pattern[str] | None = None

    def add_known(self, *values: str | None) -> None:
        with self._lock:
            changed = False
            for v in values:
                if isinstance(v, str):
                    v = v.strip()
                    if len(v) >= _MIN_KNOWN_SECRET_LEN and v not in self._known:
                        self._known.add(v)
                        changed = True
            if changed:
                # Mais longos primeiro, para não mascarar só um pedaço.
                ordered = sorted(self._known, key=len, reverse=True)
                self._known_re = re.compile("|".join(re.escape(v) for v in ordered))

    @property
    def known_count(self) -> int:
        return len(self._known)

    def load_secrets_yaml(self, path: Path) -> int:
        """Carrega os valores do secrets.yaml só em memória, para mascarar.

        Nunca registra os valores nem as chaves. Retorna quantos foram lidos.
        """
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return 0
        except OSError as err:
            logging.getLogger(__name__).warning("Não foi possível ler %s: %s", path.name, type(err).__name__)
            return 0
        try:
            data = yaml.load(text, Loader=_TolerantLoader)  # noqa: S506 - loader seguro (SafeLoader)
        except yaml.YAMLError:
            logging.getLogger(__name__).warning("secrets.yaml inválido; mascaramento por valores desativado")
            return 0
        values: list[str] = []
        _collect_strings(data, values)
        before = self.known_count
        self.add_known(*values)
        return self.known_count - before

    def mask(self, text: str | None) -> str | None:
        if not text:
            return text
        known_re = self._known_re
        if known_re is not None:
            text = known_re.sub(MASK, text)
        for pattern in _PATTERNS:
            text = pattern.sub(MASK, text)
        text = _URL_CREDENTIALS.sub(lambda m: f"{m['pre']}{MASK}{m['post']}", text)
        text = _ASSIGNMENT.sub(_mask_assignment, text)
        return text


def _mask_assignment(m: re.Match[str]) -> str:
    val = m["val"]
    if _ASSIGNMENT_SAFE.match(val) or val == MASK or _looks_like_identifier(val):
        return m.group(0)
    # Sem aspas e com chamada/indexação é código (ex.: token = open(...)), não segredo.
    # Mascarar aqui esconderia justamente a evidência do achado.
    if not m["q"] and any(c in val for c in "([{"):
        return m.group(0)
    return f"{m['key']}{m['sep']}{m['q']}{MASK}{m['q']}"


def _looks_like_identifier(val: str) -> bool:
    """Nomes de variáveis/atributos (``token = entry_token``) não são segredos."""
    if "." in val and re.fullmatch(r"[A-Za-z_][\w.]*(?:\(\))?", val):
        return True
    if re.fullmatch(r"[a-z_][a-z0-9_]*", val) and shannon_entropy(val) < 3.5:
        return True
    return re.fullmatch(r"[A-Z_][A-Z0-9_]*", val) is not None  # CONSTANTE


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _collect_strings(node: object, out: list[str]) -> None:
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _collect_strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_strings(v, out)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        out.append(str(node))


class _TolerantLoader(yaml.SafeLoader):
    """SafeLoader que ignora tags do HA (!include, !env_var...) em vez de falhar."""


def _unknown_tag(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> None:
    return None


_TolerantLoader.add_multi_constructor("!", _unknown_tag)


# Instância global usada pelo filtro de log e pelo relatório.
masker = Masker()


class MaskingFilter(logging.Filter):
    """Aplica o mascaramento à mensagem final de cada registro de log."""

    def __init__(self, m: Masker | None = None) -> None:
        super().__init__()
        self._masker = m or masker

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - nunca derrubar o log
            return True
        if record.exc_info and record.exc_info[1] is not None:
            # O traceback pode carregar segredos (ex.: URL com token): entra no
            # texto mascarado em vez de ser formatado depois pelo handler.
            message = f"{message}\n{logging.Formatter().formatException(record.exc_info)}"
            record.exc_info = None
            record.exc_text = None
        record.msg = self._masker.mask(message)
        record.args = None
        return True
