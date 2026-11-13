"""Verificação de instalações/atualizações: varredura parcial e avisos no HA."""

from __future__ import annotations

import json
import os

import pytest

from auditor.config import Options
from auditor.models import ComponentType, Severity
from auditor.report import render_html
from auditor.supervisor import CoreNotifier, ForbiddenPathError
from auditor.watcher import InstallWatcher, build_alert, diff, file_snapshot

from .conftest import make_finding
from .test_engine_web import _engine

# --- Foto do que está instalado ------------------------------------------------------------


def _write(path, text="x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_snapshot_detects_new_updated_removed_and_ignores_pycache(tmp_path):
    _write(tmp_path / "custom_components/a/__init__.py")
    _write(tmp_path / "custom_components/b/__init__.py")
    _write(tmp_path / "www/community/card/card.js")
    _write(tmp_path / "www/foto.jpg")  # fora de community/: não entra
    base = file_snapshot(tmp_path)
    assert set(base) == {"integracao/a", "integracao/b", "frontend/card"}

    _write(tmp_path / "custom_components/a/__pycache__/x.cpython-312.pyc")  # o HA gera isto sozinho
    _write(tmp_path / "www/foto.jpg", "outra")
    assert file_snapshot(tmp_path) == base

    p = tmp_path / "custom_components/a/__init__.py"
    p.write_text("código novo")
    os.utime(p, ns=(1, 1))
    _write(tmp_path / "custom_components/c/__init__.py")
    (tmp_path / "custom_components/b/__init__.py").unlink()
    (tmp_path / "custom_components/b").rmdir()
    assert diff(base, file_snapshot(tmp_path)) == [
        {"tipo": "integracao", "nome": "a", "mudanca": "atualizado"},
        {"tipo": "integracao", "nome": "b", "mudanca": "removido"},
        {"tipo": "integracao", "nome": "c", "mudanca": "novo"},
    ]


# --- Varredura parcial ---------------------------------------------------------------------


class Scanner:
    """Registra componentes e devolve achados, respeitando a varredura parcial (ctx.wants)."""

    name = "falso"

    def __init__(self, components):
        self.components = components  # nome -> lista de achados

    async def scan(self, ctx):
        out = []
        for name, findings in self.components.items():
            if ctx.wants("integracao", name):
                ctx.register_component("integracao", name, versao="1.0")
                out += findings
        return out


def _f(component, **kw):
    return make_finding(component=component, file=f"custom_components/{component}/x.py",
                        snippet=f"eval({component})", **kw)


async def test_partial_scan_merges_with_latest_full(paths, storage, masker):
    full = await _engine(paths, storage, masker, Options(), [Scanner({
        "antiga": [_f("antiga", severity=Severity.HIGH)], "mudou": [], "saiu": [_f("saiu")]})]).run()
    assert full.kind == "completa"

    new_finding = _f("mudou", severity=Severity.CRITICAL, rule_id="auditor.novo")
    changes = [{"tipo": "integracao", "nome": "mudou", "mudanca": "atualizado"},
               {"tipo": "integracao", "nome": "saiu", "mudanca": "removido"}]
    scanner = Scanner({"antiga": [_f("antiga", severity=Severity.LOW, rule_id="nao.deve.rodar")],
                       "mudou": [new_finding]})
    part = await _engine(paths, storage, masker, Options(), [scanner]).run(changes)

    assert part.kind == "parcial" and part.targets == changes
    by_comp = {f.component: f for f in part.findings}
    # "antiga" não foi varrida de novo: o achado vem da completa, sem selo de novo.
    assert by_comp["antiga"].rule_id == "auditor.eval-dinamico" and not by_comp["antiga"].is_new
    assert by_comp["mudou"].is_new and by_comp["mudou"].severity is Severity.CRITICAL
    assert "saiu" not in by_comp and "saiu" not in {c.name for c in part.components}
    assert {c.name for c in part.components} == {"antiga", "mudou"}
    assert part.new_count == 1

    # Fica salvo como a mais recente e aparece no histórico como verificação de instalação.
    assert storage.load_latest().scan_id == part.scan_id
    (row, _) = storage.list_scans(2)
    assert row["kind"] == "parcial" and row["targets"][0]["nome"] == "mudou"
    html = render_html(part, status={}, history=storage.list_scans(5), csrf_token="t", lang="en",
                       history_page={"page": 1, "pages": 1, "total": 2, "scan": None})
    assert "Install/update:" in html and "mudou (updated)" in html and "install/update check" in html


async def test_partial_without_previous_report_becomes_full(paths, storage, masker):
    scanner = Scanner({"a": [], "b": []})
    result = await _engine(paths, storage, masker, Options(), [scanner]).run(
        [{"tipo": "integracao", "nome": "a", "mudanca": "novo"}])
    assert result.kind == "completa" and {c.name for c in result.components} == {"a", "b"}


# --- Avisos ------------------------------------------------------------------------------


async def _result_with(paths, storage, masker, findings):
    return await _engine(paths, storage, masker, Options(), [Scanner({"nova": findings})]).run()


NEW = {"tipo": "integracao", "nome": "nova", "mudanca": "novo"}


async def test_alert_levels_and_blocklist(paths, storage, masker):
    medium = await _result_with(paths, storage, masker, [_f("nova", severity=Severity.MEDIUM)])
    event, note = build_alert(medium, NEW, "alta", "pt")
    assert note is None and event["alerta"] is False and event["achados"]["medium"] == 1
    event, note = build_alert(medium, NEW, "media", "pt", "/hassio/ingress/abc_security_auditor")
    assert event["alerta"] is True and event["versao"] == "1.0"
    notification_id, title, message = note
    assert notification_id == "security_auditor_integracao_nova" and title == "Security Auditor: revise nova"
    assert "A integração **nova** 1.0 foi instalada e verificada logo em seguida." in message
    assert "1 médio(s)" in message
    assert "(/hassio/ingress/abc_security_auditor)" in message and "não decide sozinho" in message
    assert build_alert(medium, NEW, "desligado", "pt")[1] is None

    listed = await _result_with(paths, storage, masker, [_f(
        "nova", severity=Severity.LOW, category="lista_negra", rule_id="auditor.lista-negra.malicioso",
        title="Na lista negra: envia o token", en={"title": "Blocklisted: sends the token",
                                                   "explanation": "e", "recommendation": "r"})])
    event, note = build_alert(listed, NEW, "critica", "en")  # lista negra avisa em qualquer nível
    assert event["lista_negra"] and note[1] == "Security Auditor: review nova"
    assert "**Blocklist:** Blocklisted: sends the token" in note[2] and "**nova** 1.0 was installed" in note[2]


async def test_suppressed_findings_do_not_alert(paths, storage, masker):
    from auditor.config import AllowlistEntry

    opts = Options(allowlist=(AllowlistEntry(component="nova", rule="*", reason="meu"),))
    result = await _engine(paths, storage, masker, opts,
                           [Scanner({"nova": [_f("nova", severity=Severity.CRITICAL)]})]).run()
    assert build_alert(result, NEW, "baixa", "pt")[1] is None


class FakeNotifier:
    available = True

    def __init__(self):
        self.events, self.notes = [], []

    async def fire_alert(self, data):
        self.events.append(data)

    async def notify(self, *note):
        self.notes.append(note)


async def test_watcher_waits_for_install_to_finish_then_scans_and_alerts(tmp_path, paths, storage, masker):
    config = tmp_path / "cfg"
    _write(config / "custom_components/velha/__init__.py")
    jobs = []
    engine = _engine(paths, storage, masker, Options(), [Scanner({"nova": [_f("nova", severity=Severity.HIGH)],
                                                                  "velha": []})])
    await engine.run()  # relatório completo de referência

    async def run_job(changes):
        jobs.append(changes)
        return await engine.run(changes)

    notifier = FakeNotifier()
    watcher = InstallWatcher(config_dir=config, storage=storage, supervisor=None, notifier=notifier,
                             run_job=run_job, is_busy=lambda: False, min_level="alta")
    watcher.set_base(await watcher.snapshot())
    assert await watcher.check() is None and not jobs  # nada mudou

    _write(config / "custom_components/nova/__init__.py")
    assert await watcher.check() is None and not jobs  # mudou: espera a próxima rodada
    result = await watcher.check()  # igual à anterior: a instalação terminou
    assert jobs == [[NEW]] and result.kind == "parcial"
    assert notifier.events[0]["componente"] == "nova" and notifier.events[0]["alerta"] is True
    assert notifier.notes[0][0] == "security_auditor_integracao_nova"
    # A referência foi atualizada (e salva): a próxima rodada não varre de novo.
    assert json.loads(storage.get_setting("inventario_instalado")) == await watcher.snapshot()
    assert await watcher.check() is None and len(jobs) == 1


async def test_watcher_retries_when_busy(tmp_path, storage):
    config = tmp_path / "cfg"
    busy = {"v": True}
    calls = []

    async def run_job(changes):
        calls.append(changes)

    watcher = InstallWatcher(config_dir=config, storage=storage, supervisor=None, notifier=None,
                             run_job=run_job, is_busy=lambda: busy["v"], min_level="alta")
    watcher.set_base({})
    _write(config / "custom_components/nova/__init__.py")
    await watcher.check()
    await watcher.check()
    assert calls == []  # outra varredura rodando: espera
    busy["v"] = False
    await watcher.check()
    assert calls == [[NEW]]


async def test_notifier_only_allows_its_own_ids():
    notifier = CoreNotifier(session=None, token="t", base_url="http://supervisor")
    with pytest.raises(ForbiddenPathError):
        await notifier.notify("persistent_notification_do_usuario", "t", "m")


def test_options_defaults():
    opts = Options.from_dict({})
    assert opts.watch_installs is True and opts.alert_min_level == "alta"
    assert Options.from_dict({"aviso_nivel_minimo": "qualquer"}).alert_min_level == "alta"
    off = Options.from_dict({"verificar_instalacoes": False, "aviso_nivel_minimo": "desligado"})
    assert off.watch_installs is False and off.alert_min_level == "desligado"


def test_component_types_have_labels():
    from auditor.watcher import _TYPE_LABELS

    assert {ComponentType.INTEGRATION, ComponentType.FRONTEND, ComponentType.ADDON} <= set(_TYPE_LABELS)
