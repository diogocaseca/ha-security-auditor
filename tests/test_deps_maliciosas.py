"""Dependências maliciosas: pacotes catalogados na OSV (MAL-…) e typosquatting."""

from __future__ import annotations

import json

import pytest

from auditor.config import Paths
from auditor.models import Severity
from auditor.scanners.deps import DependencyScanner
from auditor.scanners.deps_malicious import OSV_BATCH, malicious_ids, typosquat_of

from .test_fase1 import RULES, _ctx


@pytest.mark.parametrize("name, popular", [
    ("reqeusts", "requests"),        # inversão
    ("requets", "requests"),         # falta uma letra
    ("aiohtttp", "aiohttp"),         # sobra uma letra
    ("crypt0graphy", "cryptography"),  # troca
    ("Pahho_MQT", None),             # duas diferenças (e normalização): não conta
    ("Paho_MQTT2", "paho-mqtt"),     # normaliza "_" e maiúsculas antes de comparar
    ("requests", None), ("pyaml", None), ("bleak", None), ("six", None),
])
def test_typosquat_of(name, popular):
    assert typosquat_of(name) == popular


class FakeOsv:
    def __init__(self, bad: dict[str, list[str]], fail=False):
        self.bad, self.fail, self.calls = bad, fail, []

    async def post_json(self, url, body, headers=None):
        self.calls.append((url, body))
        if self.fail:
            raise TimeoutError
        names = [q["package"]["name"] for q in body["queries"]]
        return {"results": [{"vulns": [{"id": i} for i in self.bad.get(n, [])]} for n in names]}


async def test_malicious_ids_only_sends_names():
    osv = FakeOsv({"0requests": ["MAL-2026-15859", "GHSA-xxxx"]})
    assert await malicious_ids(osv, ["0Requests", "requests"]) == {"0requests": ["MAL-2026-15859"]}
    (url, body), = osv.calls
    assert url == OSV_BATCH
    assert body == {"queries": [{"package": {"name": "0requests", "ecosystem": "PyPI"}},
                                {"package": {"name": "requests", "ecosystem": "PyPI"}}]}


def _paths(tmp_path, requirements):
    comp = tmp_path / "config/custom_components/minha"
    comp.mkdir(parents=True)
    (comp / "manifest.json").write_text(json.dumps({"domain": "minha", "requirements": requirements}))
    (tmp_path / "data").mkdir()
    return Paths(config_dir=tmp_path / "config", data_dir=tmp_path / "data", rules_dir=RULES)


async def test_scanner_reports_malicious_and_typosquat(tmp_path):
    # Sem versão exata: o pip-audit nem roda, só a checagem nova.
    paths = _paths(tmp_path, ["reqeusts>=2", "0requests", "aiohttp>=3"])
    osv = FakeOsv({"0requests": ["MAL-2026-15859"]})
    findings = await DependencyScanner().scan(_ctx(paths, tmp_path, http=osv))
    by = {f.rule_id: f for f in findings if f.rule_id.startswith(("auditor.deps.typo", "auditor.deps.pacote"))}
    assert set(by) == {"auditor.deps.typosquatting", "auditor.deps.pacote-malicioso"}
    assert by["auditor.deps.pacote-malicioso"].severity is Severity.CRITICAL
    assert "MAL-2026-15859" in by["auditor.deps.pacote-malicioso"].explanation
    assert by["auditor.deps.typosquatting"].snippet == "reqeusts>=2" and "requests" in by["auditor.deps.typosquatting"].title + by["auditor.deps.typosquatting"].explanation


async def test_osv_failure_does_not_break_the_scanner(tmp_path):
    paths = _paths(tmp_path, ["reqeusts>=2"])
    findings = await DependencyScanner().scan(_ctx(paths, tmp_path, http=FakeOsv({}, fail=True)))
    assert "auditor.deps.typosquatting" in {f.rule_id for f in findings}


NUM2WORDS = [{"package": {"name": "num2words", "ecosystem": "PyPI"}, "versions": ["0.5.15", "0.5.16"],
              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0.5.15"}, {"last_affected": "0.5.16"}]}]}]


class FakeOsvDetails(FakeOsv):
    def __init__(self, bad, details):
        super().__init__(bad)
        self.details, self.gets = details, []

    async def get_json(self, url, headers=None, **kw):
        self.gets.append(url)
        return {"id": url.rsplit("/", 1)[-1], "affected": self.details[url.rsplit("/", 1)[-1]]}


@pytest.mark.parametrize("requirement, rule, severity", [
    # sentient pede a 0.5.14; só a 0.5.15 e a 0.5.16 foram maliciosas (conta do autor invadida)
    ("num2words==0.5.14", "auditor.deps.pacote-malicioso-outra-versao", Severity.INFO),
    ("num2words==0.5.15", "auditor.deps.pacote-malicioso", Severity.CRITICAL),
    ("num2words>=0.5.10", "auditor.deps.pacote-malicioso-faixa", Severity.MEDIUM),
    ("num2words<0.5.15", "auditor.deps.pacote-malicioso-outra-versao", Severity.INFO),
])
async def test_malicious_check_compares_versions(tmp_path, requirement, rule, severity):
    paths = _paths(tmp_path, [requirement])
    osv = FakeOsvDetails({"num2words": ["MAL-2025-6794"]}, {"MAL-2025-6794": NUM2WORDS})
    findings = await DependencyScanner().scan(_ctx(paths, tmp_path, http=osv))
    (f,) = [f for f in findings if f.rule_id.startswith("auditor.deps.pacote")]
    assert (f.rule_id, f.severity) == (rule, severity)
    assert osv.gets == ["https://api.osv.dev/v1/vulns/MAL-2025-6794"]  # só o id vai
    assert severity is Severity.CRITICAL or "0.5.15, 0.5.16" in f.explanation


async def test_malicious_package_without_versions_is_always_critical(tmp_path):
    paths = _paths(tmp_path, ["0requests==1.0"])
    whole = [{"package": {"name": "0requests", "ecosystem": "PyPI"},
              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]
    osv = FakeOsvDetails({"0requests": ["MAL-2026-15859"]}, {"MAL-2026-15859": whole})
    findings = await DependencyScanner().scan(_ctx(paths, tmp_path, http=osv))
    (f,) = [f for f in findings if f.rule_id.startswith("auditor.deps.pacote")]
    assert f.rule_id == "auditor.deps.pacote-malicioso" and f.severity is Severity.CRITICAL
