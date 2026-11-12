"""Proteções contra sobrecarga do Home Assistant.

O HA OS não permite limitar CPU/memória de um add-on pelo config.yaml, então
o próprio auditor se contém. Os modos (combináveis) são:

 - prioridade_baixa: o processo inteiro (e tudo o que ele inicia: Semgrep,
   Bandit, pip-audit, Trivy) roda com nice 19 e I/O na classe "ociosa". Reduzir
   a própria prioridade não exige nenhuma capacidade do kernel. Limitação: o
   Docker põe cada container num grupo de CPU próprio; a prioridade vale dentro
   do container e no disco, mas não garante sozinha a CPU do HA Core;
 - modo_leve: 1 processo por ferramenta, teto de memória no Semgrep,
   paralelismo 1 no Trivy e pausas entre componentes;
 - aguardar_folga: antes de cada etapa pesada, confere a carga e a memória
   livre do host (/proc não é isolado no container: os números são do host);
   se estiver ocupado, espera; se não desocupar, adia a etapa e registra um
   achado informativo;
 - horario_fixo: tratado pelo agendador (scheduler.py).
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .config import MODE_LIGHT, MODE_LOW_PRIORITY, MODE_WAIT_IDLE, Options
from .models import Finding, Severity

_LOGGER = logging.getLogger(__name__)

NICE_LEVEL = 19


def apply_low_priority() -> list[str]:
    """Baixa a prioridade de CPU e de disco do processo atual (herdada pelos filhos)."""
    done: list[str] = []
    try:
        os.setpriority(os.PRIO_PROCESS, 0, NICE_LEVEL)
        done.append(f"CPU nice {NICE_LEVEL}")
    except OSError as err:
        _LOGGER.warning("Não foi possível baixar a prioridade de CPU: %s", err)
    try:
        # Classe 3 = "idle": só usa o disco quando ninguém mais está usando.
        res = subprocess.run(  # noqa: S603
            ["ionice", "-c", "3", "-p", str(os.getpid())],  # noqa: S607
            capture_output=True, timeout=5, check=False,
        )
        if res.returncode == 0:
            done.append("disco ocioso (ionice -c 3)")
        else:
            _LOGGER.warning("ionice falhou: %s", res.stderr.decode(errors="replace").strip()[:200])
    except (OSError, subprocess.TimeoutExpired) as err:
        _LOGGER.warning("Não foi possível baixar a prioridade de disco: %s", err)
    return done


@dataclass(frozen=True)
class Profile:
    """Parâmetros das ferramentas conforme o modo leve."""

    light: bool = False

    @property
    def semgrep_jobs(self) -> int:
        return 1 if self.light else 2

    @property
    def semgrep_max_memory_mb(self) -> int:
        return 768 if self.light else 0  # 0 = sem teto

    @property
    def trivy_parallel(self) -> int:
        return 1 if self.light else 0  # 0 = automático

    @property
    def pause_seconds(self) -> float:
        return 2.0 if self.light else 0.0


def _read_loadavg() -> float:
    with open("/proc/loadavg", encoding="ascii") as fh:
        return float(fh.read().split()[0])


def _read_mem_available_mb() -> float:
    with open("/proc/meminfo", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1024
    raise OSError("MemAvailable ausente em /proc/meminfo")


def _cpu_count() -> int:
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


@dataclass
class ResourceGuard:
    """Espera o host desocupar antes das etapas pesadas (modo aguardar_folga)."""

    enabled: bool = False
    max_load_per_cpu: float = 1.5
    min_free_mb: int = 500
    poll_seconds: float = 30.0
    max_wait_seconds: float = 600.0
    read_load: Callable[[], float] = _read_loadavg
    read_free_mb: Callable[[], float] = _read_mem_available_mb
    cpus: int = field(default_factory=_cpu_count)
    sleep: Callable[[float], object] = asyncio.sleep
    clock: Callable[[], float] = time.monotonic

    def busy_reason(self, need_mb: float) -> str | None:
        try:
            load = self.read_load() / self.cpus
            free = self.read_free_mb()
        except (OSError, ValueError):
            return None  # sem leitura, não bloqueia
        if load > self.max_load_per_cpu:
            return f"carga do sistema alta ({load:.1f} por núcleo; limite {self.max_load_per_cpu:g})"
        if free < need_mb:
            return f"pouca memória livre ({free:.0f} MB; precisa de {need_mb:.0f} MB)"
        return None

    async def wait(self, label: str, need_mb: float | None = None) -> str | None:
        """None = pode seguir; texto = motivo para adiar a etapa."""
        if not self.enabled:
            return None
        need = self.min_free_mb if need_mb is None else need_mb
        start = self.clock()
        reason = self.busy_reason(need)
        warned = False
        while reason:
            if self.clock() - start >= self.max_wait_seconds:
                _LOGGER.warning("Etapa '%s' adiada: %s", label, reason)
                return reason
            if not warned:
                _LOGGER.info("Aguardando o sistema desocupar antes de '%s': %s", label, reason)
                warned = True
            await self.sleep(self.poll_seconds)
            reason = self.busy_reason(need)
        return None


def guard_from_options(options: Options) -> ResourceGuard:
    return ResourceGuard(
        enabled=options.has_mode(MODE_WAIT_IDLE),
        max_load_per_cpu=options.max_load_per_cpu,
        min_free_mb=options.min_free_memory_mb,
    )


def profile_from_options(options: Options) -> Profile:
    return Profile(light=options.has_mode(MODE_LIGHT))


def wants_low_priority(options: Options) -> bool:
    return options.has_mode(MODE_LOW_PRIORITY)


def postponed(component: str, component_type: str, step: str, reason: str) -> Finding:
    return Finding(
        component=component,
        component_type=component_type,
        category="analise_incompleta",
        rule_id="auditor.etapa-adiada",
        severity=Severity.INFO,
        title=f"Etapa adiada: {step}",
        explanation=(
            f"O modo 'aguardar_folga' adiou esta etapa porque o sistema continuou ocupado: {reason}. "
            "Ela roda de novo na próxima varredura."
        ),
        recommendation=(
            "Nenhuma ação obrigatória. Se acontecer sempre, agende com 'horario_fixo' para um horário "
            "calmo ou ajuste carga_maxima_por_cpu / memoria_minima_mb."
        ),
        source="auditor",
        extra={"fingerprint_key": step},
    )
