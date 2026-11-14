"""Verificação de instalações e atualizações: varre só o componente que mudou e avisa no HA.

A cada ``intervalo_verificacao_minutos`` (padrão: ``CHECK_INTERVAL``) tira uma "foto" leve do que está instalado:
 - integrações (``custom_components/<nome>``) e cards (``www/community/<nome>``): nome, tamanho e
   data de cada arquivo (sem ler o conteúdo);
 - add-ons: versão de cada um (``GET /addons`` no Supervisor, só leitura).

Quando a foto muda e fica igual por uma verificação seguida (o HACS grava os arquivos aos
poucos), roda uma varredura parcial só com o que mudou e, se houver achados a partir do nível
configurado ou correspondência na lista negra, cria uma notificação no HA. Sempre dispara o
evento ``security_auditor_alerta`` (para automações, ex.: aviso no celular).

Também roda a verificação só de DNS (``intervalo_dns_minutos``, ``DnsWatcher``): relê o log do
AdGuard/Pi-hole, atualiza a parte de DNS do relatório e avisa sobre achados de DNS novos.

O auditor **não bloqueia** nada: a verificação acontece logo depois da instalação.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from .i18n import Translator, normalize
from .inventory import SKIP_DIRS, walk_files
from .models import ComponentType, ScanResult, Severity

_LOGGER = logging.getLogger(__name__)

CHECK_INTERVAL = 120  # segundos
SETTING_KEY = "inventario_instalado"
LEVELS = {"critica": Severity.CRITICAL, "alta": Severity.HIGH, "media": Severity.MEDIUM, "baixa": Severity.LOW}
_SEV_PT = {Severity.CRITICAL: "crítico(s)", Severity.HIGH: "alto(s)", Severity.MEDIUM: "médio(s)",
           Severity.LOW: "baixo(s)", Severity.INFO: "informativo(s)"}
_SEV_EN = {Severity.CRITICAL: "critical", Severity.HIGH: "high", Severity.MEDIUM: "medium",
           Severity.LOW: "low", Severity.INFO: "info"}
# (rótulo em português, rótulo em inglês, feminino em português)
_TYPE_LABELS = {ComponentType.INTEGRATION: ("A integração", "Integration", True),
                ComponentType.FRONTEND: ("O card", "Frontend card", False),
                ComponentType.ADDON: ("O add-on", "Add-on", False)}
_SAFE = re.compile(r"[^a-z0-9_]+")

Snapshot = dict[str, str]  # "tipo/nome" -> impressão digital (versão ou hash dos arquivos)


def _dir_fingerprint(path: Path) -> str:
    """Hash de nome, tamanho e data de cada arquivo (sem __pycache__ e .pyc, que o HA gera)."""
    h = hashlib.sha256()
    files, links = walk_files(path)
    for f in files:
        try:
            st = f.stat()
        except OSError:
            continue
        h.update(f"{f.relative_to(path)}\x1f{st.st_size}\x1f{st.st_mtime_ns}\n".encode())
    for link in links:
        h.update(f"L\x1f{link}\n".encode())
    return h.hexdigest()[:24]


def file_snapshot(config_dir: Path) -> Snapshot:
    """Integrações e cards do HACS. Os demais arquivos de www/ ficam de fora (mudam muito)."""
    out: Snapshot = {}
    for folder, ctype in ((config_dir / "custom_components", ComponentType.INTEGRATION),
                          (config_dir / "www" / "community", ComponentType.FRONTEND)):
        if not folder.is_dir() or folder.is_symlink():
            continue
        for d in sorted(folder.iterdir()):
            if d.is_dir() and not d.is_symlink() and d.name not in SKIP_DIRS and not d.name.startswith("."):
                out[f"{ctype}/{d.name}"] = _dir_fingerprint(d)
    return out


def diff(old: Snapshot, new: Snapshot) -> list[dict[str, str]]:
    """Mudanças entre duas fotos: [{tipo, nome, mudanca: novo|atualizado|removido}]."""
    changes = []
    for key in sorted(set(old) | set(new)):
        tipo, _, nome = key.partition("/")
        if key not in old:
            changes.append({"tipo": tipo, "nome": nome, "mudanca": "novo"})
        elif key not in new:
            changes.append({"tipo": tipo, "nome": nome, "mudanca": "removido"})
        elif old[key] != new[key]:
            changes.append({"tipo": tipo, "nome": nome, "mudanca": "atualizado"})
    return changes


def build_alert(result: ScanResult, change: dict[str, str], min_level: str, lang: str,
                ingress_url: str | None = None) -> tuple[dict[str, Any], tuple[str, str, str] | None]:
    """(dados do evento, notificação ou None). A notificação é (id, título, mensagem)."""
    key = (change["tipo"], change["nome"])
    findings = [f for f in result.findings if (f.component_type, f.component) == key and not f.suppressed]
    counts = {sev.key: sum(1 for f in findings if f.severity is sev) for sev in Severity}
    blocklisted = [f for f in findings if f.category == "lista_negra"]
    meta = next((c.metadata for c in result.components if (c.component_type, c.name) == key), {})
    threshold = LEVELS.get(min_level)
    serious = [f for f in findings if threshold is not None and f.severity >= threshold]
    alert = bool(threshold is not None and (serious or blocklisted))
    event = {"tipo": change["tipo"], "componente": change["nome"], "mudanca": change["mudanca"],
             "versao": meta.get("versao"), "achados": counts, "lista_negra": bool(blocklisted),
             "alerta": alert, "scan_id": result.scan_id}
    if not alert:
        return event, None

    en = lang == "en"
    tr = Translator(lang)
    label_pt, label_en, fem = _TYPE_LABELS.get(change["tipo"], (change["tipo"], change["tipo"], False))
    name = change["nome"]
    version = f" {meta['versao']}" if meta.get("versao") else ""
    names = _SEV_EN if en else _SEV_PT
    summary = ", ".join(f"{counts[s.key]} {names[s]}" for s in sorted(Severity, reverse=True) if counts[s.key])
    if en:
        what = {"novo": "was installed", "atualizado": "was updated"}.get(change["mudanca"], change["mudanca"])
        first = f"{label_en} **{name}**{version} {what} and was checked right away."
    else:
        end = "a" if fem else "o"
        what = {"novo": f"instalad{end}", "atualizado": f"atualizad{end}"}.get(change["mudanca"], change["mudanca"])
        first = f"{label_pt} **{name}**{version} foi {what} e verificad{end} logo em seguida."
    lines = [first, ""]
    if blocklisted:
        reason = (blocklisted[0].en or {}).get("title") if en else None
        lines.append(("- **Blocklist:** " if en else "- **Lista negra:** ") + (reason or blocklisted[0].title))
    if summary:
        lines.append(("- Findings: " if en else "- Achados: ") + summary)
    top = sorted(serious or findings, key=lambda f: -int(f.severity))[:3]
    for f in top:
        title = ((f.en or {}).get("title") if en else None) or f.title
        lines.append(f"- {tr.t(f.severity.label)}: {title}")
    lines.append("")
    if ingress_url:
        lines += [f"[{'Open Security Auditor' if en else 'Abrir o Security Auditor'}]({ingress_url})", ""]
    lines.append(_DISCLAIMER[1] if en else _DISCLAIMER[0])
    title = (f"Security Auditor: review {name}" if en else f"Security Auditor: revise {name}")
    notification_id = "security_auditor_" + _SAFE.sub("_", f"{change['tipo']}_{name}".lower())[:80]
    return event, (notification_id, title, "\n".join(lines))


_DISCLAIMER = ("O auditor aponta o que merece revisão; não decide sozinho que algo é malicioso.",
               ("The auditor points out what deserves review; it does not decide on its own that something "
                "is malicious."))
DNS_NOTIFICATION_ID = "security_auditor_rede_dns"


def build_dns_alert(result: ScanResult, min_level: str, lang: str, ingress_url: str | None = None
                    ) -> tuple[dict[str, Any] | None, tuple[str, str, str] | None]:
    """Verificação de DNS: (evento, notificação). Evento só se houver achado de DNS novo."""
    findings = [f for f in result.findings
                if (f.component_type, f.component) == (ComponentType.NETWORK, "dns") and f.is_new
                and not f.suppressed]
    if not findings:
        return None, None
    counts = {sev.key: sum(1 for f in findings if f.severity is sev) for sev in Severity}
    threshold = LEVELS.get(min_level)
    serious = [f for f in findings if threshold is not None and f.severity >= threshold]
    event = {"tipo": str(ComponentType.NETWORK), "componente": "dns", "mudanca": "verificacao_dns",
             "versao": None, "achados": counts, "lista_negra": False, "alerta": bool(serious),
             "scan_id": result.scan_id}
    if not serious:
        return event, None
    en = lang == "en"
    tr = Translator(lang)
    names = _SEV_EN if en else _SEV_PT
    summary = ", ".join(f"{counts[s.key]} {names[s]}" for s in sorted(Severity, reverse=True) if counts[s.key])
    lines = ["The DNS check found something new in the queries made by Home Assistant." if en else
             "A verificação de DNS encontrou algo novo nas consultas feitas pelo Home Assistant.", "",
             ("- New findings: " if en else "- Achados novos: ") + summary]
    for f in sorted(serious, key=lambda f: -int(f.severity))[:3]:
        title = ((f.en or {}).get("title") if en else None) or f.title
        lines.append(f"- {tr.t(f.severity.label)}: {title}")
    lines.append("")
    if ingress_url:
        lines += [f"[{'Open Security Auditor' if en else 'Abrir o Security Auditor'}]({ingress_url})", ""]
    lines.append(_DISCLAIMER[1] if en else _DISCLAIMER[0])
    title = "Security Auditor: review DNS queries" if en else "Security Auditor: revise as consultas DNS"
    return event, (DNS_NOTIFICATION_ID, title, "\n".join(lines))


async def _ingress_url(supervisor: Any | None) -> str | None:
    if supervisor is None:
        return None
    try:
        return await supervisor.self_page()
    except Exception:  # noqa: BLE001
        return None


async def _send(notifier: Any | None, event: dict[str, Any], note: tuple[str, str, str] | None,
                label: str) -> str:
    """Dispara o evento e cria a notificação. Devolve o complemento para o log."""
    if notifier is not None and notifier.available:
        try:
            await notifier.fire_alert(event)
            if note:
                await notifier.notify(*note)
                return " — notificação criada no HA"
        except Exception as err:  # noqa: BLE001 - aviso nunca derruba o vigia
            _LOGGER.warning("Não foi possível avisar no HA sobre %s: %s", label, err)
        return ""
    return " — merece aviso, mas sem acesso ao HA (SUPERVISOR_TOKEN)" if note else ""


def _every(seconds: float) -> str:
    return f"{int(seconds // 60)} min" if seconds >= 60 and seconds % 60 == 0 else f"{int(seconds)} s"


class InstallWatcher:
    def __init__(self, *, config_dir: Path, storage: Any, supervisor: Any | None, notifier: Any | None,
                 run_job: Callable[[list[dict[str, str]]], Awaitable[ScanResult | None]],
                 is_busy: Callable[[], bool], min_level: str, addons: bool = True,
                 interval: float = CHECK_INTERVAL) -> None:
        self._config_dir = config_dir
        self._storage = storage
        self._supervisor = supervisor
        self._notifier = notifier
        self._run_job = run_job
        self._is_busy = is_busy
        self._min_level = min_level
        self._addons = addons and supervisor is not None
        self._interval = interval
        self._base: Snapshot | None = None
        self._pending: Snapshot | None = None

    # --- Foto do que está instalado ------------------------------------------------------

    async def snapshot(self) -> Snapshot:
        snap = await asyncio.to_thread(file_snapshot, self._config_dir)
        if self._addons:
            try:
                own = await self._supervisor.self_slug()
                for item in await self._supervisor.addons():
                    slug = str(item.get("slug") or "")
                    if slug and slug != own:
                        snap[f"{ComponentType.ADDON}/{slug}"] = str(item.get("version") or "")
            except Exception as err:  # noqa: BLE001 - sem a lista, mantém os add-ons da foto anterior
                _LOGGER.debug("Lista de add-ons indisponível: %s", type(err).__name__)
                for key, value in (self._base or {}).items():
                    if key.startswith(f"{ComponentType.ADDON}/"):
                        snap[key] = value
        return snap

    def set_base(self, snap: Snapshot) -> None:
        """Nova referência (após uma varredura completa ou parcial)."""
        self._base = snap
        self._pending = None
        self._storage.set_setting(SETTING_KEY, json.dumps(snap, sort_keys=True))

    def _load_base(self) -> Snapshot | None:
        raw = self._storage.get_setting(SETTING_KEY)
        try:
            data = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    # --- Laço -----------------------------------------------------------------------------

    async def run(self) -> None:
        self._base = await asyncio.to_thread(self._load_base)
        if self._base is None:
            await asyncio.to_thread(self.set_base, await self.snapshot())
            _LOGGER.info("Verificação de instalações ativa (conferência a cada %s): referência criada com "
                         "%d componente(s)", _every(self._interval), len(self._base or {}))
        else:
            _LOGGER.info("Verificação de instalações ativa (conferência a cada %s)", _every(self._interval))
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self.check()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - o vigia nunca para por causa de uma falha
                _LOGGER.exception("Falha na verificação de instalações")

    async def check(self) -> ScanResult | None:
        """Uma rodada: detecta mudança, espera estabilizar e varre só o que mudou."""
        current = await self.snapshot()
        base = self._base or {}
        if current == base:
            self._pending = None
            return None
        if current != self._pending:
            # Primeira vez que vê esta foto: espera a próxima rodada para a instalação terminar.
            self._pending = current
            _LOGGER.info("Mudança detectada em %s; verificando assim que a instalação terminar",
                         ", ".join(f"{c['nome']} ({c['mudanca']})" for c in diff(base, current)))
            return None
        if self._is_busy():
            return None  # tenta de novo na próxima rodada
        changes = diff(base, current)
        result = await self._run_job(changes)
        if result is None:
            return None  # outra varredura começou ou o usuário cancelou: tenta de novo depois
        await asyncio.to_thread(self.set_base, current)
        if result.status == "concluida":
            await self.alert(result, [c for c in changes if c["mudanca"] != "removido"])
        else:
            _LOGGER.warning("Varredura de instalação terminou como %s", result.status)
        return result

    async def alert(self, result: ScanResult, changes: list[dict[str, str]]) -> None:
        if not changes:
            return
        lang = normalize(await asyncio.to_thread(self._storage.get_setting, "idioma"))
        ingress = await _ingress_url(self._supervisor)
        for change in changes:
            event, note = build_alert(result, change, self._min_level, lang, ingress)
            counts = ", ".join(f"{k}={v}" for k, v in event["achados"].items() if v) or "sem achados"
            sent = await _send(self._notifier, event, note, change["nome"])
            _LOGGER.info("Verificado após %s: %s %s (%s)%s", change["mudanca"], change["tipo"], change["nome"],
                         counts, sent)


BUSY_RETRY = 60  # segundos: outra varredura rodando, tenta de novo logo depois


class DnsWatcher:
    """Roda a verificação só de DNS a cada ``interval`` segundos e avisa sobre achados novos."""

    def __init__(self, *, storage: Any, supervisor: Any | None, notifier: Any | None,
                 run_job: Callable[[], Awaitable[ScanResult | None]], is_busy: Callable[[], bool],
                 min_level: str, interval: float, retry: float = BUSY_RETRY) -> None:
        self._storage = storage
        self._supervisor = supervisor
        self._notifier = notifier
        self._run_job = run_job
        self._is_busy = is_busy
        self._min_level = min_level
        self._interval = interval
        self._retry = min(retry, interval)

    async def run(self) -> None:
        _LOGGER.info("Verificação de DNS ativa (a cada %s)", _every(self._interval))
        wait = self._interval
        while True:
            await asyncio.sleep(wait)
            try:
                done = await self.check()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - o laço nunca para por causa de uma falha
                _LOGGER.exception("Falha na verificação de DNS")
                done = True
            wait = self._interval if done else self._retry

    async def check(self) -> bool:
        """Uma rodada. False = não rodou (outra varredura em andamento): tentar de novo em breve."""
        if self._is_busy():
            return False
        if await asyncio.to_thread(self._storage.latest_completed_id) is None:
            return True  # ainda sem relatório: a primeira varredura completa já traz o DNS
        result = await self._run_job()
        if result is None:
            return False  # outra varredura começou ou o usuário cancelou
        if result.status != "concluida":
            _LOGGER.warning("Verificação de DNS terminou como %s", result.status)
            return True
        await self.alert(result)
        return True

    async def alert(self, result: ScanResult) -> None:
        lang = normalize(await asyncio.to_thread(self._storage.get_setting, "idioma"))
        event, note = build_dns_alert(result, self._min_level, lang, await _ingress_url(self._supervisor))
        if event is None:
            return
        counts = ", ".join(f"{k}={v}" for k, v in event["achados"].items() if v)
        sent = await _send(self._notifier, event, note, "DNS")
        _LOGGER.info("Verificação de DNS: achados novos (%s)%s", counts, sent)
