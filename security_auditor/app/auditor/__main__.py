"""Ponto de entrada: ``python -m auditor``."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal

import aiohttp
from aiohttp import web

from . import __version__
from .config import load_options, load_paths
from .engine import ScanEngine
from .masking import MaskingFilter, masker
from .net import SafeHttpClient
from .publisher import SensorPublisher
from .scanners import default_scanners
from .scanners.traffic import TrafficCollector
from .scheduler import SENSOR_REFRESH, Scheduler
from .storage import Storage
from .supervisor import CoreStatesPublisher, SupervisorClient
from .web import create_app

_LOGGER = logging.getLogger("auditor")


def setup_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s", "%H:%M:%S"))
    # O filtro fica no handler: vale para qualquer logger, inclusive de bibliotecas.
    handler.addFilter(MaskingFilter(masker))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)


async def main() -> None:
    paths = load_paths()
    setup_logging("info")
    options = load_options(paths.data_dir)
    setup_logging(options.log_level)
    _LOGGER.info("HA Security Auditor %s", __version__)

    # Segredos conhecidos, só em memória, para nunca aparecerem em logs/relatórios.
    masker.add_known(os.environ.get("SUPERVISOR_TOKEN"), options.github_token, options.dns_password)
    loaded = masker.load_secrets_yaml(paths.config_dir / "secrets.yaml")
    _LOGGER.info("Mascaramento ativo (%d valores do secrets.yaml carregados em memória)", loaded)

    paths.cache_dir.mkdir(parents=True, exist_ok=True)
    storage = Storage(paths.db_path, paths.reports_dir)

    async with aiohttp.ClientSession() as internal_session, SafeHttpClient(github_token=options.github_token) as http:
        supervisor = SupervisorClient(internal_session)
        publisher = SensorPublisher(CoreStatesPublisher(internal_session))
        engine = ScanEngine(
            paths=paths,
            options=options,
            storage=storage,
            masker=masker,
            http=http,
            supervisor=supervisor if supervisor.available else None,
            scanners=default_scanners(),
        )
        status_holder = {"status": "ocioso"}

        async def on_status(status: str) -> None:
            status_holder["status"] = status
            latest = await asyncio.to_thread(storage.load_latest)
            await publisher.publish(latest, status)

        scheduler = Scheduler(engine.run, options.scan_interval_hours, options.scan_on_start, on_status)

        app = create_app(storage, scheduler, engine.progress)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        port = int(os.environ.get("AUDITOR_PORT", "8099"))
        site = web.TCPSite(runner, host=os.environ.get("AUDITOR_HOST", "0.0.0.0"), port=port)  # noqa: S104 - Ingress
        await site.start()
        _LOGGER.info("Interface disponível na porta %d (somente via Ingress)", port)

        await on_status("ocioso")
        scheduler.start()

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop.set)

        async def refresh_sensors() -> None:
            while True:
                await asyncio.sleep(SENSOR_REFRESH.total_seconds())
                if not scheduler.running:
                    await on_status(status_holder["status"])

        background = [asyncio.create_task(refresh_sensors(), name="auditor-sensores")]
        if supervisor.available and options.addons_scan:
            collector = TrafficCollector(storage, supervisor, options.stats_interval_minutes)
            background.append(asyncio.create_task(collector.run(), name="auditor-estatisticas"))
        await stop.wait()
        _LOGGER.info("Encerrando…")
        for task in background:
            task.cancel()
        await scheduler.stop()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
