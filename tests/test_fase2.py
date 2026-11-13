"""Fase 2: outros add-ons (permissões, imagem, código-fonte, tráfego)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from auditor.addons import AddonInfo, collect
from auditor.config import Options, Paths
from auditor.masking import Masker
from auditor.models import Severity
from auditor.scanners import addon_image as image_mod
from auditor.scanners.addon_image import AddonImageScanner, findings_from_trivy, image_ref
from auditor.scanners.addon_perms import evaluate
from auditor.scanners.addon_source import AddonSourceScanner, find_addon_dir, parse_map
from auditor.scanners.base import ScanContext
from auditor.scanners.traffic import (
    MIN_SAMPLES,
    TrafficCollector,
    TrafficScanner,
    detect_spike,
    human_rate,
    rates,
)
from auditor.storage import Storage
from auditor.tools import ToolResult

from .conftest import FIXTURES
from .test_fase1 import RULES, FakeGitHub, _dir_files, _tar_of, needs_tools


# --- Supervisor falso --------------------------------------------------------------


class FakeSupervisor:
    def __init__(self, addons: list[dict], repos: list[dict] | None = None, own: str | None = None) -> None:
        self._addons = addons
        self._repos = repos or []
        self._own = own
        self.stats: dict[str, dict] = {}

    async def self_slug(self):
        return self._own

    async def addons(self):
        return [{"slug": a["slug"], "state": a.get("state", "started"), "repository": a.get("repository")}
                for a in self._addons]

    async def addon_info(self, slug):
        return next(a for a in self._addons if a["slug"] == slug)

    async def addon_stats(self, slug):
        return self.stats.get(slug, {})

    async def store_repositories(self):
        return self._repos


def _addon(**kw) -> dict:
    base = {"slug": "abc123_exemplo", "name": "Exemplo", "version": "1.2.0", "version_latest": "1.2.0",
            "repository": "abc123", "image": "ghcr.io/terceiro/amd64-addon-exemplo",
            "url": "https://github.com/terceiro/addons", "apparmor": "profile", "protected": True,
            "rating": 5, "state": "started"}
    base.update(kw)
    return base


def _ctx(tmp_path: Path, supervisor, http=None, options: Options | None = None) -> ScanContext:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (tmp_path / "work").mkdir(exist_ok=True)
    paths = Paths(config_dir=tmp_path / "config", data_dir=data, rules_dir=RULES)
    return ScanContext(
        paths=paths, options=options or Options(), http=http, supervisor=supervisor,
        storage=Storage(paths.db_path, paths.reports_dir), masker=Masker(), workdir=tmp_path / "work",
        scan_id="20261112T000000000000Z",
    )


# --- Coleta e permissões --------------------------------------------------------


async def test_collect_maps_repository_sources():
    sup = FakeSupervisor(
        [_addon(), _addon(slug="core_mosquitto", repository="core", url=None)],
        repos=[{"slug": "abc123", "source": "https://github.com/terceiro/addons"}],
    )
    addons = {a.slug: a for a in await collect(sup)}
    assert addons["abc123_exemplo"].inner_slug == "exemplo"
    assert addons["abc123_exemplo"].repository_source == "https://github.com/terceiro/addons"
    assert addons["core_mosquitto"].inner_slug == "mosquitto"
    assert addons["core_mosquitto"].github_candidates() == [("home-assistant", "addons")]


def _info(**kw) -> AddonInfo:
    data = _addon(**kw)
    return AddonInfo(slug=data["slug"], name=data["name"], version=data["version"],
                     version_latest=data["version_latest"], repository=data["repository"], info=data,
                     repository_source="https://github.com/terceiro/addons")


def test_permissions_dangerous_addon():
    addon = _info(full_access=True, docker_api=True, host_network=True, privileged=["NET_ADMIN", "SYS_ADMIN"],
                  protected=False, apparmor="disable", hassio_api=True, hassio_role="admin", rating=1,
                  update_available=True, version_latest="1.3.0", devices=["/dev/ttyUSB0"])
    by_rule = {f.rule_id: f for f in evaluate(addon)}
    assert by_rule["auditor.addon.docker-api"].severity is Severity.CRITICAL
    assert by_rule["auditor.addon.full-access"].severity is Severity.HIGH
    assert by_rule["auditor.addon.protecao-desativada"].severity is Severity.HIGH
    assert by_rule["auditor.addon.capacidades"].severity is Severity.HIGH
    assert "SYS_ADMIN" in by_rule["auditor.addon.capacidades"].explanation
    assert by_rule["auditor.addon.apparmor-desativado"].severity is Severity.HIGH
    assert by_rule["auditor.addon.role-admin"].severity is Severity.HIGH
    assert by_rule["auditor.addon.nota-seguranca"].severity is Severity.MEDIUM
    assert by_rule["auditor.addon.atualizacao-pendente"].snippet == "1.2.0 → 1.3.0"
    assert by_rule["auditor.addon.host-network"].severity is Severity.MEDIUM
    assert "auditor.addon.hardware" in by_rule and "auditor.addon.terceiro" in by_rule


def test_permissions_quiet_addon():
    findings = evaluate(_info(repository="core", slug="core_x"))
    assert [f for f in findings if f.severity > Severity.INFO] == []


def test_permissions_only_safe_caps():
    (cap,) = [f for f in evaluate(_info(privileged=["NET_ADMIN"])) if f.rule_id == "auditor.addon.capacidades"]
    assert cap.severity is Severity.LOW


# --- Imagens (Trivy) ---------------------------------------------------------------


def test_image_ref():
    assert image_ref(_info()) == "ghcr.io/terceiro/amd64-addon-exemplo:1.2.0"
    assert image_ref(_info(image=None)) is None
    assert image_ref(_info(repository="local", slug="local_x")) is None
    assert image_ref(_info(image="ghcr.io/x/y:fixa")) == "ghcr.io/x/y:fixa"


TRIVY_SAMPLE = {
    "Results": [
        {"Target": "alpine 3.19", "Class": "os-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.1.0",
             "FixedVersion": "3.1.5", "Severity": "CRITICAL"},
            {"VulnerabilityID": "CVE-2024-0002", "PkgName": "busybox", "InstalledVersion": "1.36",
             "Severity": "HIGH"},
            {"VulnerabilityID": "CVE-2024-0003", "PkgName": "zlib", "InstalledVersion": "1.3",
             "FixedVersion": "1.3.1", "Severity": "MEDIUM"},
        ]},
        {"Target": "/app/config.py", "Class": "secret", "Secrets": [
            {"RuleID": "github-pat", "Category": "GitHub", "Title": "GitHub Personal Access Token",
             "Severity": "CRITICAL", "StartLine": 3, "Match": "TOKEN = '****************'"},
        ]},
    ]
}


def test_findings_from_trivy():
    findings, counts = findings_from_trivy(_info(), "img:1", TRIVY_SAMPLE)
    by = {f.rule_id: f for f in findings}
    vul = by["trivy.vulnerabilidades"]
    assert vul.severity is Severity.HIGH  # crítica com correção disponível
    assert vul.snippet.splitlines()[0].startswith("CVE-2024-0001 [critical] openssl 3.1.0 → 3.1.5")
    assert counts["critical"] == 1 and counts["medium"] == 1
    sec = by["trivy.secret.github-pat"]
    assert sec.severity is Severity.HIGH and sec.file == "img:1:/app/config.py" and sec.line == 3


def test_trivy_without_fix_is_low():
    data = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1", "Severity": "CRITICAL"}]}]}
    (f,), _ = findings_from_trivy(_info(), "img:1", data)
    assert f.severity is Severity.LOW


async def test_image_scanner_flags_and_skips(tmp_path, monkeypatch):
    calls = []

    async def fake_run_tool(args, **kw):
        calls.append(args)
        return ToolResult(0, json.dumps(TRIVY_SAMPLE), "")

    monkeypatch.setattr(image_mod, "run_tool", fake_run_tool)
    sup = FakeSupervisor([
        _addon(),
        _addon(slug="local_meu", repository="local", image=None),
        _addon(slug="abc123_pulado", name="Pulado"),
    ])
    ctx = _ctx(tmp_path, sup, options=Options(image_scan_skip=("abc123_pulado",)))
    findings = await AddonImageScanner().scan(ctx)
    assert len(calls) == 1
    args = calls[0]
    for flag in ("--disable-telemetry", "--skip-version-check"):
        assert flag in args
    assert args[args.index("--image-src") + 1] == "remote"
    assert args[-1] == "ghcr.io/terceiro/amd64-addon-exemplo:1.2.0"
    local = [f for f in findings if f.component == "local_meu"]
    assert [f.rule_id for f in local] == ["trivy.nao-analisada"]
    assert ctx.components[("addon", "abc123_exemplo")]["cves"]["critical"] == 1


async def test_image_scan_disabled(tmp_path):
    ctx = _ctx(tmp_path, FakeSupervisor([_addon()]), options=Options(image_scan=False))
    assert await AddonImageScanner().scan(ctx) == []


async def test_addons_scan_disabled(tmp_path):
    ctx = _ctx(tmp_path, FakeSupervisor([_addon()]), options=Options(addons_scan=False))
    assert await ctx.addons() == []


# --- Código-fonte ------------------------------------------------------------------


def test_parse_map():
    assert parse_map(["config:rw", "ssl", {"type": "backup"}, {"type": "share", "read_only": False}]) == [
        ("config", False), ("ssl", True), ("backup", True), ("share", False)]


def test_find_addon_dir():
    found = find_addon_dir(FIXTURES / "addon_repo", "exemplo")
    assert found is not None and found[0].name == "exemplo" and found[1]["version"] == "1.3.0"
    assert find_addon_dir(FIXTURES / "addon_repo", "inexistente") is None


@needs_tools
async def test_addon_source_scanner(tmp_path):
    tarball = _tar_of("addons-main", _dir_files(FIXTURES / "addon_repo", "."))
    gh = FakeGitHub({"https://codeload.github.com/terceiro/addons/tar.gz/HEAD": tarball})
    sup = FakeSupervisor([_addon()], repos=[{"slug": "abc123", "source": "https://github.com/terceiro/addons"}])
    ctx = _ctx(tmp_path, sup, http=gh)
    findings = await AddonSourceScanner().scan(ctx)
    rules = {f.rule_id: f for f in findings}

    # Tags v1.2.0 e 1.2.0 não existem: caiu no HEAD, que declara outra versão.
    assert gh.calls[:2] == [
        "https://codeload.github.com/terceiro/addons/tar.gz/v1.2.0",
        "https://codeload.github.com/terceiro/addons/tar.gz/1.2.0",
    ]
    assert "auditor.addon.fonte-versao-diferente" in rules
    assert rules["auditor.addon.map-config-rw"].severity is Severity.HIGH
    assert rules["auditor.addon.map-backup-ro"].severity is Severity.MEDIUM
    assert rules["auditor.sh.baixa-e-executa"].file == "terceiro/addons@HEAD:exemplo/Dockerfile"
    assert "auditor.docker.add-de-url" in rules
    token = [f for f in findings if f.rule_id == "auditor.sh.token-supervisor-externo"]
    assert len(token) == 1 and "coleta.example.net" in token[0].snippet  # o http://supervisor não conta
    assert "auditor.sh.acesso-sensivel" in rules
    assert ctx.components[("addon", "abc123_exemplo")]["codigo_fonte"] == "terceiro/addons@HEAD"

    # Segunda varredura: tags inexistentes e o HEAD ficam em cache, nada é baixado.
    gh.calls.clear()
    ctx2 = _ctx(tmp_path, sup, http=gh)
    again = await AddonSourceScanner().scan(ctx2)
    assert gh.calls == []
    assert {f.fingerprint for f in again} == {f.fingerprint for f in findings}


async def test_addon_source_not_found(tmp_path):
    sup = FakeSupervisor([_addon()])
    findings = await AddonSourceScanner().scan(_ctx(tmp_path, sup, http=FakeGitHub({})))
    assert [f.rule_id for f in findings] == ["auditor.addon.codigo-nao-encontrado"]


# --- Tráfego -----------------------------------------------------------------------


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def test_rates_ignore_container_restart():
    t0 = datetime(2026, 11, 1, tzinfo=UTC)
    samples = [
        {"ts": _iso(t0), "network_tx": 1000},
        {"ts": _iso(t0 + timedelta(seconds=10)), "network_tx": 2000},
        {"ts": _iso(t0 + timedelta(seconds=20)), "network_tx": 100},  # reinício: contador zerou
        {"ts": _iso(t0 + timedelta(seconds=30)), "network_tx": 600},
    ]
    assert [r for _, r in rates(samples)] == [100.0, 50.0]


def test_detect_spike_thresholds():
    base = [10_000.0, 12_000.0, 11_000.0] * 5
    assert detect_spike(base, 2_000_000)[0]
    assert not detect_spike(base, 40_000)[0]  # acima da média mas abaixo do mínimo absoluto
    assert not detect_spike(base[: MIN_SAMPLES - 1], 2_000_000)[0]  # poucas amostras
    assert human_rate(512) == "512 B/s" and human_rate(2 * 1024 * 1024) == "2.0 MiB/s"


async def test_collector_detects_spike_and_scanner_reports_once(tmp_path):
    sup = FakeSupervisor([_addon(), _addon(slug="parado", state="stopped")])
    ctx = _ctx(tmp_path, sup)
    collector = TrafficCollector(ctx.storage, sup, interval_minutes=5)
    t = datetime.now(UTC) - timedelta(hours=3)
    tx = 0
    for i in range(30):
        tx += 300 * 10_000 if i < 29 else 300 * 3_000_000  # ~10 KB/s normal, ~3 MB/s no fim
        sup.stats["abc123_exemplo"] = {"cpu_percent": 1.5, "memory_usage": 50 * 1024 * 1024,
                                       "network_rx": i * 1000, "network_tx": tx}
        spikes = await collector.tick(now=t + timedelta(minutes=5 * i))
    assert spikes == 1  # só a última amostra é pico

    findings = await TrafficScanner().scan(ctx)
    (f,) = findings
    assert f.component == "abc123_exemplo" and f.rule_id == "auditor.addon.pico-trafego-saida"
    assert f.severity is Severity.HIGH  # 300x a média e acima de 1 MiB/s
    meta = ctx.components[("addon", "abc123_exemplo")]
    assert meta["envio_maximo"].endswith("MiB/s") and meta["cpu_media"] == "1.5%"
    # O add-on parado não gerou amostras.
    assert ctx.storage.addon_stats_since("parado", "2000") == []

    # Já reportado: a próxima varredura não repete.
    assert await TrafficScanner().scan(_ctx(tmp_path, sup)) == []


async def test_traffic_host_network_not_measured(tmp_path):
    ctx = _ctx(tmp_path, FakeSupervisor([_addon(host_network=True)]))
    await TrafficScanner().scan(ctx)
    assert "rede do host" in ctx.components[("addon", "abc123_exemplo")]["trafego"]


@pytest.mark.parametrize("interval", [0])
async def test_collector_disabled(tmp_path, interval):
    sup = FakeSupervisor([_addon()])
    ctx = _ctx(tmp_path, sup)
    await TrafficCollector(ctx.storage, sup, interval).run()  # retorna imediatamente


async def test_auditor_does_not_audit_itself(tmp_path):
    own = _addon(slug="9f8e7d6c_security_auditor", name="HA Security Auditor")
    sup = FakeSupervisor([_addon(), own], own="9f8e7d6c_security_auditor")
    assert [a.slug for a in await collect(sup)] == ["abc123_exemplo"]


async def test_collector_skips_itself(tmp_path):
    sup = FakeSupervisor([_addon(), _addon(slug="eu_security_auditor")], own="eu_security_auditor")
    ctx = _ctx(tmp_path, sup)
    for slug in ("abc123_exemplo", "eu_security_auditor"):
        sup.stats[slug] = {"cpu_percent": 1.0, "memory_usage": 1, "network_rx": 1, "network_tx": 1}
    await TrafficCollector(ctx.storage, sup, interval_minutes=5).tick()
    assert ctx.storage.addon_stats_since("eu_security_auditor", "2000-01-01T00:00:00+00:00") == []
    assert ctx.storage.addon_stats_since("abc123_exemplo", "2000-01-01T00:00:00+00:00")
