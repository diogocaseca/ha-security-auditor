"""Agendamento das varreduras e do botão "Varrer agora"."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import ScanResult

_LOGGER = logging.getLogger(__name__)

SENSOR_REFRESH = timedelta(minutes=15)


class Scheduler:
    """Roda no máximo uma varredura por vez.

    ``interval_hours = 0`` desativa o agendamento (só manual).
    """

    def __init__(
        self,
        run_scan: Callable[[], Awaitable[ScanResult]],
        interval_hours: int,
        scan_on_start: bool,
        on_status: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._run_scan = run_scan
        self._interval = timedelta(hours=interval_hours) if interval_hours > 0 else None
        self._scan_on_start = scan_on_start
        self._on_status = on_status
        self._lock = asyncio.Lock()
        self._trigger = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._current: asyncio.Task[ScanResult] | None = None
        self.next_run: datetime | None = None
        self.last_started: datetime | None = None
        self.last_result: ScanResult | None = None

    @property
    def running(self) -> bool:
        return self._lock.locked()

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "next_run": self.next_run.isoformat(timespec="seconds") if self.next_run else None,
            "last_started": self.last_started.isoformat(timespec="seconds") if self.last_started else None,
            "last_scan_id": self.last_result.scan_id if self.last_result else None,
            "interval_hours": int(self._interval.total_seconds() // 3600) if self._interval else 0,
        }

    def request_scan(self) -> bool:
        """Pede uma varredura imediata. Retorna False se já houver uma em andamento."""
        if self.running:
            return False
        self._trigger.set()
        return True

    def start(self) -> None:
        now = datetime.now(UTC)
        if self._scan_on_start:
            self.next_run = now
        elif self._interval:
            self.next_run = now + self._interval
        self._task = asyncio.create_task(self._loop(), name="auditor-scheduler")

    async def stop(self) -> None:
        for task in (self._current, self._task):
            if task and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

    async def _loop(self) -> None:
        while True:
            timeout = None
            if self.next_run is not None:
                timeout = max(0.0, (self.next_run - datetime.now(UTC)).total_seconds())
            try:
                await asyncio.wait_for(self._trigger.wait(), timeout=timeout)
                _LOGGER.info("Varredura manual solicitada")
            except TimeoutError:
                _LOGGER.info("Varredura agendada")
            self._trigger.clear()
            await self._execute()
            self.next_run = datetime.now(UTC) + self._interval if self._interval else None

    async def _execute(self) -> None:
        async with self._lock:
            self.last_started = datetime.now(UTC)
            await self._notify("varrendo")
            self._current = asyncio.create_task(self._run_scan(), name="auditor-scan")
            try:
                self.last_result = await self._current
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - o agendador sobrevive a qualquer falha
                _LOGGER.exception("Erro inesperado na varredura")
            finally:
                self._current = None
        await self._notify(self.last_result.status if self.last_result else "falhou")

    async def _notify(self, status: str) -> None:
        if self._on_status:
            try:
                await self._on_status(status)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Falha ao notificar status")
