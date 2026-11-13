"""Histórico de CPU, memória e rede dos add-ons e detecção de picos de saída.

O coletor roda em segundo plano (a cada ``stats_interval_minutes``) e grava
``/addons/<slug>/stats``. Os contadores de rede são acumulados desde o início
do container, então a taxa é a diferença entre duas amostras.

Um pico é registrado quando a taxa de envio (tx) passa, ao mesmo tempo, de:
 - média + 4 desvios-padrão do próprio add-on nos últimos 7 dias;
 - 3x a média;
 - 50 KiB/s (para não alertar sobre variações irrelevantes).

A varredura transforma os picos ainda não reportados em achados.

Limitação: add-ons com ``host_network`` usam a rede do host e o Docker não
separa o tráfego deles; para esses não há medição.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
from datetime import UTC, datetime, timedelta
from typing import Any

from ..models import ComponentType, Finding, Severity, en_text
from ..storage import Storage
from ..supervisor import SupervisorClient, SupervisorError
from .base import ScanContext

_LOGGER = logging.getLogger(__name__)

BASELINE = timedelta(days=7)
RETENTION = timedelta(days=30)
MIN_SAMPLES = 12
K_SIGMA = 4.0
MIN_RATIO = 3.0
MIN_RATE = 50 * 1024.0  # bytes/s


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def rates(samples: list[dict[str, Any]], field: str = "network_tx") -> list[tuple[str, float]]:
    """Taxas (bytes/s) entre amostras consecutivas; reinícios do container são ignorados."""
    out: list[tuple[str, float]] = []
    prev: tuple[datetime, float] | None = None
    for s in samples:
        value = s.get(field)
        if value is None:
            continue
        ts = _parse(s["ts"])
        if prev is not None:
            dt = (ts - prev[0]).total_seconds()
            if dt > 0 and value >= prev[1]:
                out.append((s["ts"], (value - prev[1]) / dt))
        prev = (ts, float(value))
    return out


def detect_spike(baseline: list[float], current: float) -> tuple[bool, float, float]:
    """(é pico?, média, desvio) comparando ``current`` com a linha de base."""
    if len(baseline) < MIN_SAMPLES:
        return False, 0.0, 0.0
    mean = statistics.fmean(baseline)
    std = statistics.pstdev(baseline)
    threshold = max(mean + K_SIGMA * std, mean * MIN_RATIO, MIN_RATE)
    return current > threshold, mean, std


def human_rate(bps: float) -> str:
    for unit in ("B/s", "KiB/s", "MiB/s"):
        if bps < 1024 or unit == "MiB/s":
            return f"{bps:.0f} {unit}" if unit == "B/s" else f"{bps:.1f} {unit}"
        bps /= 1024
    return f"{bps:.1f} MiB/s"


class TrafficCollector:
    """Coleta periódica das estatísticas (tarefa de fundo do add-on)."""

    def __init__(self, storage: Storage, supervisor: SupervisorClient, interval_minutes: int) -> None:
        self._storage = storage
        self._supervisor = supervisor
        self._interval = interval_minutes * 60
        self._last_prune: datetime | None = None

    async def run(self) -> None:
        if self._interval <= 0:
            _LOGGER.info("Coleta de estatísticas desativada")
            return
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - a coleta nunca derruba o add-on
                _LOGGER.exception("Falha na coleta de estatísticas")
            await asyncio.sleep(self._interval)

    async def tick(self, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        ts = _iso(now)
        try:
            addons = await self._supervisor.addons()
        except SupervisorError as err:
            _LOGGER.warning("Coleta: não foi possível listar add-ons: %s", err)
            return 0
        spikes = 0
        for item in addons:
            slug = str(item.get("slug", ""))
            if not slug or item.get("state") != "started" or slug == await self._supervisor.self_slug():
                continue
            try:
                stats = await self._supervisor.addon_stats(slug)
            except SupervisorError:
                continue
            await asyncio.to_thread(self._storage.add_addon_stats, slug, ts, stats)
            if await asyncio.to_thread(self._check, slug, now):
                spikes += 1
        if self._last_prune is None or now - self._last_prune > timedelta(days=1):
            await asyncio.to_thread(self._storage.prune_stats, _iso(now - RETENTION))
            self._last_prune = now
        return spikes

    def _check(self, slug: str, now: datetime) -> bool:
        samples = self._storage.addon_stats_since(slug, _iso(now - BASELINE))
        series = rates(samples)
        if len(series) < 2:
            return False
        current_ts, current = series[-1]
        spike, mean, std = detect_spike([r for _, r in series[:-1]], current)
        if spike:
            self._storage.add_traffic_event(slug, current_ts, current, mean, std)
            _LOGGER.warning(
                "Pico de tráfego de saída em %s: %s (média %s)", slug, human_rate(current), human_rate(mean)
            )
        return spike


class TrafficScanner:
    """Na varredura: resume o histórico e reporta picos ainda não reportados."""

    name = "trafego_addons"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        addons = await ctx.addons()
        if not addons:
            return []
        storage = ctx.storage
        since = _iso(datetime.now(UTC) - BASELINE)
        for addon in addons:
            samples = await asyncio.to_thread(storage.addon_stats_since, addon.slug, since)
            ctx.register_component(ComponentType.ADDON, addon.slug, **summarize(samples, addon.info))
        events = await asyncio.to_thread(storage.take_unreported_events, ctx.scan_id)
        return findings_from_events(events)


def summarize(samples: list[dict[str, Any]], info: dict[str, Any]) -> dict[str, Any]:
    if info.get("host_network"):
        return {"trafego": "não medido (usa a rede do host)"}
    tx = [r for _, r in rates(samples)]
    if len(tx) < MIN_SAMPLES:
        return {"trafego": f"coletando dados ({len(samples)} amostras)"}
    rx = [r for _, r in rates(samples, "network_rx")]
    cpu = [s["cpu_percent"] for s in samples if s.get("cpu_percent") is not None]
    mem = [s["memory_usage"] for s in samples if s.get("memory_usage") is not None]
    out: dict[str, Any] = {
        "envio_medio": human_rate(statistics.fmean(tx)),
        "envio_maximo": human_rate(max(tx)),
        "recebimento_medio": human_rate(statistics.fmean(rx)) if rx else None,
    }
    if cpu:
        out["cpu_media"] = f"{statistics.fmean(cpu):.1f}%"
    if mem:
        out["memoria_media"] = f"{statistics.fmean(mem) / 1024 / 1024:.0f} MiB"
    return out


def findings_from_events(events: list[dict[str, Any]]) -> list[Finding]:
    by_slug: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        by_slug.setdefault(e["slug"], []).append(e)
    out = []
    for slug, evs in by_slug.items():
        worst = max(evs, key=lambda e: e["rate"])
        ratio = worst["rate"] / worst["baseline_mean"] if worst["baseline_mean"] else float("inf")
        severe = ratio >= 20 and worst["rate"] >= 1024 * 1024
        lines = [
            f"{_parse(e['ts']).astimezone().strftime('%d/%m %H:%M')}: {human_rate(e['rate'])} "
            f"(média {human_rate(e['baseline_mean'])})"
            for e in evs[-10:]
        ]
        out.append(Finding(
            component=slug,
            component_type=ComponentType.ADDON,
            category="trafego_anormal",
            rule_id="auditor.addon.pico-trafego-saida",
            severity=Severity.HIGH if severe else Severity.MEDIUM,
            title=f"{len(evs)} pico(s) de tráfego de saída desde a última varredura",
            explanation=(
                f"O add-on enviou dados bem acima do próprio padrão (pico de {human_rate(worst['rate'])}, "
                f"{ratio:.0f}x a média). Pode ser um backup, upload ou atualização legítima, mas também é "
                "o sinal típico de exfiltração de dados."
            ),
            recommendation=(
                "Compare os horários com o que o add-on deveria estar fazendo (backups, envios agendados). "
                "Se não houver explicação, verifique o log do add-on e considere pará-lo."
            ),
            en=en_text(
                f"{len(evs)} outbound traffic spike(s) since the last scan",
                f"The add-on sent data well above its own pattern (peak of {human_rate(worst['rate'])}, "
                f"{ratio:.0f}x the average). It may be a legitimate backup, upload or update, but it is also "
                "the typical sign of data exfiltration.",
                "Compare the times with what the add-on should be doing (backups, scheduled uploads). If there is "
                "no explanation, check the add-on log and consider stopping it.",
            ),
            snippet="\n".join(lines),
            source="estatisticas",
            extra={"fingerprint_key": evs[0]["ts"]},
        ))
    return out
