"""Orquestração de uma varredura completa."""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .allowlist import apply_allowlist
from .config import Options, Paths
from .diff import compare
from .masking import Masker
from .models import Finding, ScanResult
from .net import SafeHttpClient
from .resources import guard_from_options, profile_from_options
from .scanners.base import ScanContext, Scanner
from .scheduler import USER_CANCEL
from .scoring import summarize
from .storage import Storage
from .supervisor import SupervisorClient

_LOGGER = logging.getLogger(__name__)

_MAX_SNIPPET = 600


def new_scan_id(now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    return now.strftime("%Y%m%dT%H%M%S%fZ")


def utcnow_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class ScanEngine:
    def __init__(
        self,
        *,
        paths: Paths,
        options: Options,
        storage: Storage,
        masker: Masker,
        http: SafeHttpClient,
        supervisor: SupervisorClient | None,
        scanners: list[Scanner],
    ) -> None:
        self.paths = paths
        self.options = options
        self.storage = storage
        self.masker = masker
        self.http = http
        self.supervisor = supervisor
        self.scanners = scanners
        self.progress: dict[str, str] = {}

    async def run(self) -> ScanResult:
        scan_id = new_scan_id()
        result = ScanResult(scan_id=scan_id, started_at=utcnow_iso(), version=__version__)
        workdir = Path(tempfile.mkdtemp(prefix=f"auditor-{scan_id}-"))
        ctx = ScanContext(
            paths=self.paths,
            options=self.options,
            http=self.http,
            supervisor=self.supervisor,
            storage=self.storage,
            masker=self.masker,
            workdir=workdir,
            scan_id=scan_id,
            progress=self.progress,
            guard=guard_from_options(self.options),
            ignore_entries=self.options.allowlist + tuple(self.storage.ignore_entries()),
            profile=profile_from_options(self.options),
        )
        _LOGGER.info("Varredura %s iniciada (%d scanners)", scan_id, len(self.scanners))
        try:
            for scanner in self.scanners:
                ctx.set_progress(scanner.name)
                try:
                    found = await scanner.scan(ctx)
                    result.findings.extend(found)
                    _LOGGER.info("Scanner %s: %d achados", scanner.name, len(found))
                except asyncio.CancelledError:
                    raise
                except Exception as err:  # noqa: BLE001 - um scanner com erro não derruba os outros
                    message = self.masker.mask(f"{scanner.name}: {type(err).__name__}: {err}")
                    result.errors.append(message or scanner.name)
                    _LOGGER.exception("Scanner %s falhou", scanner.name)
            self._finalize(result, ctx)
            result.status = "concluida"
        except asyncio.CancelledError as err:
            if err.args and err.args[0] == USER_CANCEL:
                # Pedido do usuário: o cancelamento termina aqui e o parcial fica salvo.
                result.status = "cancelada"
                result.errors.append("Varredura cancelada pelo usuário")
                _LOGGER.info("Varredura %s cancelada pelo usuário", scan_id)
                task = asyncio.current_task()
                if task is not None:
                    task.uncancel()
            else:
                result.status = "falhou"
                result.errors.append("Varredura cancelada")
                raise
        except Exception as err:  # noqa: BLE001
            result.status = "falhou"
            result.errors.append(self.masker.mask(f"{type(err).__name__}: {err}") or "erro")
            _LOGGER.exception("Varredura %s falhou", scan_id)
        finally:
            result.finished_at = utcnow_iso()
            self.progress.clear()
            shutil.rmtree(workdir, ignore_errors=True)
            self._sanitize(result)
            await asyncio.to_thread(self._persist, result)
        _LOGGER.info(
            "Varredura %s %s: %s, %d novos, %d erros",
            scan_id,
            result.status,
            result.counts(),
            result.new_count,
            len(result.errors),
        )
        return result

    def _sanitize(self, result: ScanResult) -> None:
        """Mascara segredos em todos os textos do resultado. Idempotente.

        Roda SEMPRE antes de salvar, inclusive em varreduras canceladas (ex.:
        atualização do add-on) ou que falharam no meio: um relatório parcial
        nunca pode conter segredos.
        """
        for f in result.findings:
            f.snippet = _truncate(self.masker.mask(f.snippet))
            f.explanation = self.masker.mask(f.explanation) or ""
            f.title = self.masker.mask(f.title) or ""
            f.recommendation = self.masker.mask(f.recommendation) or ""
            if f.en:
                f.en = {k: self.masker.mask(str(v)) or "" for k, v in f.en.items()
                        if k in ("title", "explanation", "recommendation")}
            if f.file:
                f.file = self.masker.mask(f.file)
        result.errors = [self.masker.mask(e) or "" for e in result.errors]
        result.resolved = [
            {k: (self.masker.mask(v) if isinstance(v, str) else v) for k, v in r.items()} for r in result.resolved
        ]

    def _finalize(self, result: ScanResult, ctx: ScanContext) -> None:
        result.findings = _dedupe(result.findings)
        # Antes da comparação: a identidade de cada achado usa o trecho já mascarado.
        self._sanitize(result)
        apply_allowlist(result.findings, self.options.allowlist + tuple(self.storage.ignore_entries()))
        compare(result, self.storage.load_latest())
        result.findings.sort(key=lambda f: (-int(f.severity), not f.is_new, f.component, f.file or "", f.line or 0))
        result.components = summarize(result.findings, ctx.components)

    def _persist(self, result: ScanResult) -> None:
        try:
            self.storage.save_scan(result)
            self.storage.prune(self.options.report_retention)
        except OSError:
            _LOGGER.exception("Não foi possível salvar o relatório %s", result.scan_id)


def _truncate(text: str | None) -> str | None:
    if text and len(text) > _MAX_SNIPPET:
        return text[:_MAX_SNIPPET] + " …"
    return text


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Mescla achados iguais vindos de ferramentas diferentes (ex.: Bandit e Semgrep).

    Chave: componente, arquivo, linha e categoria. Fica o de maior
    severidade; as fontes são registradas em ``extra["sources"]``.
    """
    best: dict[tuple, Finding] = {}
    order: list[tuple] = []
    for f in findings:
        if f.file is None or f.line is None:
            key = ("fp", f.fingerprint)
        else:
            key = (f.component_type, f.component, f.file, f.line, f.category)
        current = best.get(key)
        if current is None:
            f.extra.setdefault("sources", [f.source])
            best[key] = f
            order.append(key)
            continue
        sources = sorted(set(current.extra.get("sources", [current.source])) | {f.source})
        if f.severity > current.severity:
            f.extra["sources"] = sources
            best[key] = f
        else:
            current.extra["sources"] = sources
    return [best[k] for k in order]
