"""Verificação só de DNS (intervalo_dns_minutos): atualiza a parte de DNS do relatório e avisa."""

from __future__ import annotations

import itertools

import pytest

from auditor.config import Options
from auditor.models import ComponentType, Severity
from auditor.report import render_html
from auditor.watcher import DNS_NOTIFICATION_ID, DnsWatcher, build_dns_alert

from .conftest import make_finding
from .test_engine_web import _engine
from .test_instalacoes import FakeNotifier


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """Cada varredura com um horário diferente (o scan_id e as datas têm resolução de segundos)."""
    ticks = itertools.count()
    monkeypatch.setattr("auditor.engine.utcnow_iso", lambda: f"2026-11-13T10:{next(ticks):02d}:00+00:00")
    ids = itertools.count()
    monkeypatch.setattr("auditor.engine.new_scan_id", lambda: f"20261113T10{next(ids):04d}000000Z")


def _dns(rule="auditor.dns.mineracao", severity=Severity.HIGH, title="Consulta a pool de mineração"):
    return make_finding(component="dns", component_type=ComponentType.NETWORK, category="rede", rule_id=rule,
                        severity=severity, title=title, file=None, line=None, snippet=None, source="dns",
                        extra={"fingerprint_key": rule})


class Components:
    name = "componentes"

    def __init__(self):
        self.runs = 0

    async def scan(self, ctx):
        self.runs += 1
        ctx.register_component("integracao", "minha", versao="1.0")
        return [make_finding(component="minha", file="custom_components/minha/x.py")]


class Dns:
    name = "dns"

    def __init__(self, findings):
        self.findings = findings

    async def scan(self, ctx):
        if not ctx.wants("rede", "dns"):
            return []
        ctx.register_component("rede", "dns", dominios=[{"dominio": d.rule_id} for d in self.findings],
                               dominios_total=len(self.findings), clientes=["10.0.0.2"])
        return list(self.findings)


async def test_dns_check_updates_only_dns_and_keeps_one_history_entry(paths, storage, masker):
    comps, dns = Components(), Dns([_dns("auditor.dns.velho", Severity.LOW, "velho")])
    engine = _engine(paths, storage, masker, Options(), [comps, dns])
    assert await engine.run_dns() is None  # sem relatório completo ainda: não roda
    full = await engine.run()
    assert comps.runs == 1

    dns.findings = [_dns()]
    first = await engine.run_dns()
    assert first.kind == "dns" and comps.runs == 1  # os componentes não foram varridos de novo
    by_rule = {f.rule_id: f for f in first.findings}
    assert set(by_rule) == {"auditor.eval-dinamico", "auditor.dns.mineracao"}  # o velho saiu
    assert by_rule["auditor.dns.mineracao"].is_new and not by_rule["auditor.eval-dinamico"].is_new
    meta = {(c.component_type, c.name): c.metadata for c in first.components}
    assert meta[("rede", "dns")]["dominios"] == [{"dominio": "auditor.dns.mineracao"}]
    assert ("integracao", "minha") in meta

    # Segunda verificação seguida: substitui a anterior no histórico (não empurra a completa para fora).
    second = await engine.run_dns()
    assert [s["scan_id"] for s in storage.list_scans()] == [second.scan_id, full.scan_id]
    assert storage.load_scan(first.scan_id) is None
    assert not {f.rule_id: f for f in second.findings}["auditor.dns.mineracao"].is_new

    html = render_html(second, status={}, history=storage.list_scans(5), csrf_token="t", lang="en")
    assert "DNS check (only the DNS part was updated)" in html and " · DNS check" in html

    # Depois de uma completa, a próxima verificação de DNS vira uma entrada nova.
    await engine.run()
    await engine.run_dns()
    assert [s["kind"] for s in storage.list_scans()] == ["dns", "completa", "dns", "completa"]


async def test_install_scan_still_skips_dns(paths, storage, masker):
    dns = Dns([_dns()])
    engine = _engine(paths, storage, masker, Options(), [Components(), dns])
    await engine.run()
    dns.findings = [_dns("auditor.dns.outro")]
    part = await engine.run([{"tipo": "integracao", "nome": "minha", "mudanca": "atualizado"}])
    rules = {f.rule_id for f in part.findings}
    assert "auditor.dns.mineracao" in rules and "auditor.dns.outro" not in rules


async def _dns_result(paths, storage, masker, findings):
    engine = _engine(paths, storage, masker, Options(), [Dns([])])
    await engine.run()
    engine.scanners[0].findings = findings
    return await engine.run_dns()


async def test_dns_alert_levels(paths, storage, masker):
    result = await _dns_result(paths, storage, masker, [_dns(), _dns("auditor.dns.x", Severity.MEDIUM, "médio")])
    event, note = build_dns_alert(result, "alta", "pt", "/hassio/ingress/abc")
    assert event["alerta"] is True and event["achados"]["high"] == 1 and event["achados"]["medium"] == 1
    assert event["mudanca"] == "verificacao_dns" and event["componente"] == "dns"
    notification_id, title, message = note
    assert notification_id == DNS_NOTIFICATION_ID and title == "Security Auditor: revise as consultas DNS"
    assert "Consulta a pool de mineração" in message and "médio" not in message.split("Achados novos")[1][20:]
    assert "(/hassio/ingress/abc)" in message and "não decide sozinho" in message
    assert build_dns_alert(result, "critica", "en", None)[1] is None  # só alto: abaixo do nível
    assert build_dns_alert(result, "desligado", "en", None)[0]["alerta"] is False


async def test_dns_alert_only_for_new_findings(paths, storage, masker):
    engine = _engine(paths, storage, masker, Options(), [Dns([_dns()])])
    await engine.run()
    result = await engine.run_dns()  # o mesmo achado da completa: nada novo
    assert build_dns_alert(result, "baixa", "pt") == (None, None)


async def test_dns_watcher_check(paths, storage, masker):
    engine = _engine(paths, storage, masker, Options(), [Dns([])])
    busy = {"v": False}
    jobs = []

    async def run_job():
        jobs.append(1)
        return await engine.run_dns()

    notifier = FakeNotifier()
    watcher = DnsWatcher(storage=storage, supervisor=None, notifier=notifier, run_job=run_job,
                         is_busy=lambda: busy["v"], min_level="alta", interval=7200)
    assert await watcher.check() is True and not jobs  # sem relatório: espera o intervalo inteiro
    await engine.run()
    busy["v"] = True
    assert await watcher.check() is False and not jobs  # outra varredura rodando: tenta de novo em breve
    busy["v"] = False
    engine.scanners[0].findings = [_dns()]
    assert await watcher.check() is True and jobs == [1]
    assert notifier.events[0]["alerta"] is True and notifier.notes[0][0] == DNS_NOTIFICATION_ID
    assert await watcher.check() is True and len(notifier.events) == 1  # nada novo: sem aviso


def test_options_dns_interval():
    assert Options.from_dict({}).dns_interval_minutes == 120
    assert Options.from_dict({"intervalo_dns_minutos": 0}).dns_interval_minutes == 0
    assert Options.from_dict({"intervalo_dns_minutos": 30}).dns_interval_minutes == 30
    assert Options.from_dict({"intervalo_dns_minutos": 99999}).dns_interval_minutes == 1440


def test_config_yaml_dns_interval():
    from pathlib import Path

    import yaml

    addon = Path(__file__).parents[1] / "security_auditor"
    cfg = yaml.safe_load((addon / "config.yaml").read_text())
    keys = list(cfg["options"])
    assert keys.index("intervalo_dns_minutos") == keys.index("dns_verify_tls") + 1
    assert cfg["options"]["intervalo_dns_minutos"] == 120
    assert cfg["schema"]["intervalo_dns_minutos"] == "int(0,1440)"
    for lang in ("en", "pt-BR"):
        conf = yaml.safe_load((addon / "translations" / f"{lang}.yaml").read_text())["configuration"]
        assert conf["intervalo_dns_minutos"]["name"]


def test_dns_finding_identity_ignores_counts_and_times():
    """O trecho do achado de DNS traz contagens e horários; a identidade não pode depender deles."""
    from datetime import UTC, datetime

    from auditor.scanners.dns import DomainStats, analyze

    def rules(count, hour):
        stats = {d: DomainStats(domain=d, count=count, blocked=1, last=datetime(2026, 11, 13, hour, tzinfo=UTC))
                 for d in ("pool.supportxmr.com", "k8f2j9x7q1m4z6v3b5n0p2r8t4.example.org")}
        return {f.rule_id: (f.fingerprint, f.snippet) for f in analyze(stats, first_run=True)}

    before, after = rules(3, 10), rules(9, 12)
    assert set(before) == {"auditor.dns.mineracao", "auditor.dns.dominio-aleatorio", "auditor.dns.bloqueados"}
    for rule in before:
        assert before[rule][1] != after[rule][1] and before[rule][0] == after[rule][0]
