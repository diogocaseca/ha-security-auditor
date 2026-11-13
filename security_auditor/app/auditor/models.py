"""Modelos de dados compartilhados por todos os scanners."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Severidade de um achado. A ordem numérica permite comparar e ordenar."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return _SEVERITY_LABELS[self]

    @property
    def key(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        text = str(value).strip().lower()
        for sev, label in _SEVERITY_LABELS.items():
            if text in (sev.name.lower(), label.lower()):
                return sev
        aliases = {"informativa": cls.INFO, "information": cls.INFO, "warning": cls.MEDIUM, "error": cls.HIGH}
        if text in aliases:
            return aliases[text]
        raise ValueError(f"Severidade desconhecida: {value!r}")


_SEVERITY_LABELS = {
    Severity.INFO: "Informativa",
    Severity.LOW: "Baixa",
    Severity.MEDIUM: "Média",
    Severity.HIGH: "Alta",
    Severity.CRITICAL: "Crítica",
}


class ComponentType:
    INTEGRATION = "integracao"
    FRONTEND = "frontend"
    ADDON = "addon"
    NETWORK = "rede"
    SYSTEM = "sistema"


_WS = re.compile(r"\s+")


def en_text(title: str, explanation: str, recommendation: str, snippet: str | None = None) -> dict[str, str]:
    """Texto do achado em inglês (o português vai nos campos normais do Finding).

    ``snippet`` só quando o trecho é texto explicativo (não código), ex.: linhas do DNS.
    """
    out = {"title": title, "explanation": explanation, "recommendation": recommendation}
    if snippet is not None:
        out["snippet"] = snippet
    return out


@dataclass
class Finding:
    """Um achado que merece revisão humana. Não é um veredito de malícia."""

    component: str
    component_type: str
    category: str  # tipo do achado, ex.: "ofuscacao", "integridade", "cve"
    rule_id: str
    severity: Severity
    title: str
    explanation: str
    recommendation: str
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    source: str = "auditor"  # ferramenta que gerou o achado
    extra: dict[str, Any] = field(default_factory=dict)
    # Texto em inglês (title, explanation, recommendation); o português fica nos campos acima.
    en: dict[str, str] | None = None
    # Preenchidos depois da varredura:
    suppressed: bool = False
    suppression_reason: str | None = None
    suppressed_by: int | None = None  # id na lista de ignorados da interface (None = configurações)
    is_new: bool = False
    first_seen: str | None = None  # primeira varredura em que o achado apareceu (ISO)

    @property
    def fingerprint(self) -> str:
        """Identidade estável do achado entre varreduras.

        Não usa o número da linha: se o código só mudar de lugar, o achado
        continua sendo o mesmo. Usa o trecho normalizado (sem espaços).
        """
        # "chave_estavel": a chave já identifica o achado e o trecho muda sozinho (ex.: DNS, com o
        # horário da última consulta); usar o trecho faria o mesmo achado parecer novo a cada rodada.
        snippet_norm = "" if self.extra.get("chave_estavel") else _WS.sub("", self.snippet or "")
        raw = "\x1f".join(
            [
                self.component_type,
                self.component,
                self.rule_id,
                self.file or "",
                hashlib.sha256(snippet_norm.encode()).hexdigest()[:16],
                str(self.extra.get("fingerprint_key", "")),
            ]
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.key
        data["severity_label"] = self.severity.label
        data["fingerprint"] = self.fingerprint
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        known = {f for f in cls.__dataclass_fields__}  # noqa: C416
        kwargs = {k: v for k, v in data.items() if k in known}
        kwargs["severity"] = Severity.parse(data["severity"])
        return cls(**kwargs)


@dataclass
class ComponentSummary:
    """Resumo por componente auditado (integração, add-on, ...)."""

    name: str
    component_type: str
    score: int = 0  # 0 = sem risco aparente, 100 = risco máximo
    counts: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    first_seen: str | None = None  # primeira varredura em que o componente apareceu (ISO)


@dataclass
class ScanResult:
    scan_id: str
    started_at: str
    finished_at: str | None = None
    status: str = "em_andamento"  # em_andamento | concluida | falhou | cancelada
    findings: list[Finding] = field(default_factory=list)
    components: list[ComponentSummary] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    previous_scan_id: str | None = None
    resolved: list[dict[str, Any]] = field(default_factory=list)
    version: str = ""
    kind: str = "completa"  # completa | parcial (instalação ou atualização)
    targets: list[dict[str, str]] = field(default_factory=list)  # parcial: [{tipo, nome, mudanca}]

    def counts(self, include_suppressed: bool = False) -> dict[str, int]:
        result = {sev.key: 0 for sev in Severity}
        for f in self.findings:
            if f.suppressed and not include_suppressed:
                continue
            result[f.severity.key] += 1
        return result

    @property
    def new_count(self) -> int:
        return sum(1 for f in self.findings if f.is_new and not f.suppressed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "version": self.version,
            "kind": self.kind,
            "targets": self.targets,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "previous_scan_id": self.previous_scan_id,
            "counts": self.counts(),
            "counts_including_suppressed": self.counts(include_suppressed=True),
            "new_count": self.new_count,
            "components": [asdict(c) for c in self.components],
            "findings": [f.to_dict() for f in self.findings],
            "resolved": self.resolved,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        return cls(
            scan_id=data["scan_id"],
            version=data.get("version", ""),
            kind=data.get("kind", "completa"),
            targets=data.get("targets", []),
            started_at=data["started_at"],
            finished_at=data.get("finished_at"),
            status=data.get("status", "concluida"),
            previous_scan_id=data.get("previous_scan_id"),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            components=[ComponentSummary(**c) for c in data.get("components", [])],
            resolved=data.get("resolved", []),
            errors=data.get("errors", []),
        )
