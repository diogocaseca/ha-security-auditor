"""Ponto de entrada: ``python -m auditor``."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
from datetime import UTC, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import aiohttp
from aiohttp import web

from . import __version__
from .config import MODE_FIXED_TIME, load_options, load_paths
from .engine import ScanEngine
from .i18n import normalize
from .masking import MaskingFilter, masker
from .net import SafeHttpClient
from .publisher import SensorPublisher
from .resources import apply_low_priority, wants_low_priority
from .scanners import default_scanners
from .scanners.dns import check_servers
from .scanners.traffic import TrafficCollector
from .scheduler import SENSOR_REFRESH, Scheduler
from .storage import Storage
from .supervisor import CoreNotifier, CoreStatesPublisher, SupervisorClient
from .watcher import InstallWatcher
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
    _LOGGER.info("Modos de execução: %s", ", ".join(sorted(options.execution_modes)) or "nenhuma proteção")
    if wants_low_priority(options):
        # Antes de criar threads e subprocessos: tudo herda a prioridade baixa.
        applied = apply_low_priority()
        _LOGGER.info("Prioridade baixa aplicada: %s", ", ".join(applied) or "nada")

    # Segredos conhecidos, só em memória, para nunca aparecerem em logs/relatórios.
    masker.add_known(os.environ.get("SUPERVISOR_TOKEN"), options.github_token,
                     *(s.password for s in options.dns_servers))
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
            lang = await asyncio.to_thread(storage.get_setting, "idioma")
            await publisher.publish(latest, status, normalize(lang))

        # Verificação de instalações: a foto de referência acompanha as varreduras completas.
        watcher: InstallWatcher | None = None

        async def full_scan():
            snap = await watcher.snapshot() if watcher else None
            result = await engine.run()
            if watcher and snap is not None and result.status == "concluida":
                await asyncio.to_thread(watcher.set_base, snap)
            return result

        tz = await _timezone(supervisor)
        daily_at = options.scan_time_parts if options.has_mode(MODE_FIXED_TIME) else None
        if daily_at:
            _LOGGER.info("Varredura agendada todo dia às %02d:%02d (%s)", *daily_at, tz)
        scheduler = Scheduler(
            full_scan, options.scan_interval_hours, options.scan_on_start, on_status,
            daily_at=daily_at, tz=tz, modes=sorted(options.execution_modes),
        )

        # Teste de conexão com o AdGuard/Pi-hole: na inicialização e pelo botão da interface.
        dns_state: dict = {"configurado": bool(options.dns_servers), "testando": False, "resultados": []}

        async def check_dns() -> list[dict]:
            if not options.dns_servers:
                return []
            dns_state["testando"] = True
            try:
                dns_state["resultados"] = await check_servers(options.dns_servers, options.dns_verify_tls)
            finally:
                dns_state["testando"] = False
            return dns_state["resultados"]

        async def on_ignored_change() -> None:
            await on_status(status_holder["status"])

        app = create_app(storage, scheduler, engine.progress, config_allowlist=options.allowlist,
                         on_change=on_ignored_change, dns_state=dns_state, dns_check=check_dns,
                         blocklist_cache_dir=paths.cache_dir,
                         community_enabled=options.community_blocklist)
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
        if not options.dns_servers:
            _LOGGER.info("Nenhum servidor DNS configurado (AdGuard/Pi-hole): etapa de DNS desativada")
        if options.dns_servers:
            _LOGGER.info("Testando a conexão com %d servidor(es) DNS: %s", len(options.dns_servers),
                         ", ".join(s.label for s in options.dns_servers))
            background.append(asyncio.create_task(check_dns(), name="auditor-teste-dns"))
        if options.watch_installs:
            watcher = InstallWatcher(
                config_dir=paths.config_dir, storage=storage,
                supervisor=supervisor if supervisor.available else None,
                notifier=CoreNotifier(internal_session),
                run_job=lambda changes: scheduler.run_job(lambda: engine.run(changes)),
                is_busy=lambda: scheduler.running, min_level=options.alert_min_level,
                addons=options.addons_scan,
                # AUDITOR_DEV_WATCH_SECONDS: só para desenvolvimento (intervalo em segundos).
                interval=float(os.environ.get("AUDITOR_DEV_WATCH_SECONDS") or options.watch_interval_minutes * 60),
            )
            background.append(asyncio.create_task(watcher.run(), name="auditor-instalacoes"))
        else:
            _LOGGER.info("Verificação de instalações desligada (verificar_instalacoes: false)")
        if supervisor.available and options.addons_scan:
            collector = TrafficCollector(storage, supervisor, options.stats_interval_minutes)
            background.append(asyncio.create_task(collector.run(), name="auditor-estatisticas"))
        await stop.wait()
        _LOGGER.info("Encerrando…")
        for task in background:
            task.cancel()
        await scheduler.stop()
        await runner.cleanup()


async def _timezone(supervisor: SupervisorClient) -> tzinfo:
    """Fuso do HA: variável TZ do add-on, senão o do Supervisor, senão UTC."""
    names = [os.environ.get("TZ")]
    if supervisor.available:
        try:
            names.append((await supervisor.info()).get("timezone"))
        except Exception as err:  # noqa: BLE001 - sem fuso do Supervisor, cai para UTC
            _LOGGER.debug("Fuso do Supervisor indisponível: %s", type(err).__name__)
    for name in names:
        if name:
            try:
                return ZoneInfo(name)
            except (ZoneInfoNotFoundError, ValueError):
                _LOGGER.warning("Fuso horário desconhecido: %s", name)
    return UTC


if __name__ == "__main__":
    asyncio.run(main())
