"""DNS mais esperto: listas de ameaças e de DNS cifrado, quem usa cada domínio, túnel e ritmo regular."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta

from auditor import code_hosts, threat_intel
from auditor.config import Paths
from auditor.inventory import discover
from auditor.models import Severity
from auditor.scanners.code_threats import CodeThreatScanner
from auditor.scanners.dns import DnsIntel, DnsQuery, aggregate, analyze
from auditor.storage import Storage

from .test_fase1 import RULES, _ctx

NOW = datetime.now(UTC)


def _feed(cache_dir, name, lines):
    path = cache_dir / "listas" / f"{name}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Title: teste\n" + "\n".join(lines) + "\n")
    return path


def _stats(*queries):
    return aggregate([DnsQuery(ts, d, "1.2.3.4", blocked, qtype=qt) for ts, d, blocked, qt in queries], {"x"})


def _q(domain, minutes_ago=5, blocked=False, qtype="A"):
    return (NOW - timedelta(minutes=minutes_ago), domain, blocked, qtype)


def _by_rule(findings):
    return {f.rule_id.removeprefix("auditor.dns."): f for f in findings}


# --- Listas baixadas -------------------------------------------------------------------


async def test_lookup_matches_domain_and_subdomains_from_cache(tmp_path):
    _feed(tmp_path, "ameacas", ["malware-c2.example", "phish.test"])
    hits, ok = await threat_intel.lookup(None, tmp_path, "ameacas",
                                         {"a.b.malware-c2.example", "malware-c2.example", "github.com"})
    assert ok and hits == {"a.b.malware-c2.example": "malware-c2.example", "malware-c2.example": "malware-c2.example"}


async def test_without_list_threats_are_unavailable_but_doh_has_fallback(tmp_path):
    assert await threat_intel.lookup(None, tmp_path, "ameacas", {"x.com"}) == ({}, False)
    hits, ok = await threat_intel.lookup(None, tmp_path, "dns_cifrado", {"dns.google", "github.com"})
    assert ok and hits == {"dns.google": "dns.google"}


async def test_stale_list_is_downloaded_again(tmp_path):
    path = _feed(tmp_path, "ameacas", ["velho.example"])
    old = time.time() - threat_intel.FEED_TTL - 60
    os.utime(path, (old, old))

    class Http:
        urls: list = []  # noqa: RUF012 - só neste teste

        async def download(self, url, dest, max_bytes):
            Http.urls.append(url)
            dest.write_text("novo.example\n")
            return dest

    hits, _ = await threat_intel.lookup(Http(), tmp_path, "ameacas", {"novo.example", "velho.example"})
    assert Http.urls == [threat_intel.FEEDS["ameacas"][0]] and hits == {"novo.example": "novo.example"}


# --- Domínios citados no código --------------------------------------------------------


def _components(config):
    (config / "custom_components/minha").mkdir(parents=True)
    (config / "custom_components/minha/api.py").write_text(
        'URL = "https://api.minha-nuvem.com/v1"\nx = e.target\nwindow.location.app\nconsole.info("oi")\n'
        'CHAVE = "profile.name"\n')
    (config / "www/community/meu-card").mkdir(parents=True)
    (config / "www/community/meu-card/card.js").write_text('fetch("https://cdn.cardhost.io/x.js");t.length;')


def test_code_hosts_index_and_cache(tmp_path, monkeypatch):
    config, cache = tmp_path / "config", tmp_path / "cache"
    _components(config)
    index = code_hosts.build(discover(config), cache, RULES)
    assert index.users("api.minha-nuvem.com") == {"integracao/minha": "custom_components/minha/api.py"}
    assert "frontend/meu-card" in index.users("cdn.cardhost.io")
    # Só conta nome numa URL ou sozinho entre aspas: chamadas como console.info( e performance.now() ficam de
    # fora, mesmo terminando num TLD real (.info, .now).
    for junk in ("t.length", "e.target", "window.location.app", "console.info"):
        assert junk not in index.exact, junk
    assert "profile.name" in index.exact  # entre aspas: entra, mas não como URL
    assert index.in_url["integracao/minha"] == {"api.minha-nuvem.com"}
    # Segunda vez: nada mudou, nada é relido.
    reads = []
    monkeypatch.setattr(code_hosts, "_scan_component", lambda *a: reads.append(a) or {})
    code_hosts.build(discover(config), cache, RULES)
    assert reads == []


async def test_code_threat_scanner(tmp_path, storage):
    config = tmp_path / "config"
    _components(config)
    paths = Paths(config_dir=config, data_dir=tmp_path / "dados", rules_dir=RULES)
    _feed(paths.cache_dir, "ameacas", ["minha-nuvem.com", "profile.name", "console.info"])
    findings = await CodeThreatScanner().scan(_ctx(paths, tmp_path, http=None, storage=storage))
    by = {f.title.split(": ", 1)[1]: f for f in findings}
    assert set(by) == {"api.minha-nuvem.com", "profile.name"}  # console.info( é chamada de função
    f = by["api.minha-nuvem.com"]
    assert f.component == "minha" and f.severity is Severity.HIGH and f.category == "lista_ameacas"
    assert f.file == "custom_components/minha/api.py" and f.line == 1 and "api.minha-nuvem.com" in f.snippet
    assert by["profile.name"].severity is Severity.MEDIUM and "só entre aspas" in by["profile.name"].explanation


# --- Análise do DNS --------------------------------------------------------------------


def test_threat_and_encrypted_dns_findings_with_attribution():
    stats = _stats(_q("c2.malware.example"), _q("dns.google"), _q("bloqueado.example", blocked=True))
    intel = DnsIntel(threats={"c2.malware.example": "malware.example", "bloqueado.example": "bloqueado.example"},
                     encrypted_dns={"dns.google": "dns.google"},
                     users=lambda d: {"integracao/minha": "custom_components/minha/x.py"} if "malware" in d else {})
    by = {(f.rule_id, f.title): f for f in analyze(stats, first_run=False, intel=intel)}
    threat = next(f for (r, t), f in by.items() if "c2.malware.example" in t)
    assert threat.severity is Severity.HIGH and "citado no código de: minha (custom_components/minha/x.py)" in threat.snippet
    assert "mentioned in the code of: minha" in threat.en["snippet"]
    blocked = next(f for (r, t), f in by.items() if "bloqueado.example" in t and "ameaças" in t)
    assert blocked.severity is Severity.MEDIUM  # só tentou: o filtro bloqueou tudo
    doh = next(f for (r, t), f in by.items() if r == "auditor.dns.dns-cifrado")
    assert doh.severity is Severity.MEDIUM and "dns.google" in doh.title


def test_tunnel_by_many_names_and_txt():
    names = [_q(f"{'a' * 22}{i:04d}.exfil.example") for i in range(60)]
    txt = [_q("t.texto.example", qtype="TXT") for _ in range(25)]
    findings = analyze(_stats(*names, *txt), first_run=False)
    tunnels = {f.extra["fingerprint_key"]: f for f in findings if f.rule_id == "auditor.dns.tunel"}
    assert tunnels["exfil.example"].severity is Severity.MEDIUM and "60 nome(s)" in tunnels["exfil.example"].snippet
    assert tunnels["texto.example"].severity is Severity.LOW and "25 consulta(s) TXT" in tunnels["texto.example"].snippet


def test_regular_pace_only_for_recent_unknown_domains():
    regular = [_q("beacon.example", minutes_ago=5 * i) for i in range(1, 20)]  # a cada 300 s
    owned = [_q("nuvem.example", minutes_ago=5 * i) for i in range(1, 20)]
    irregular = [_q("solto.example", minutes_ago=m) for m in (1, 3, 9, 30, 31, 70, 140, 141, 300, 301, 600, 900)]
    stats = _stats(*regular, *owned, *irregular)
    intel = DnsIntel(users=lambda d: {"integracao/x": "x.py"} if d == "nuvem.example" else {})
    (f,) = [f for f in analyze(stats, first_run=False, intel=intel) if f.rule_id == "auditor.dns.batimento"]
    assert f.severity is Severity.LOW and f.snippet == "beacon.example: a cada ~300 s (19 consultas)"
    # Domínio conhecido há mais de 7 dias não entra.
    old = DnsIntel(users=intel.users, first_seen={"beacon.example": (NOW - timedelta(days=30)).isoformat()})
    assert not [f for f in analyze(stats, first_run=False, intel=old) if f.rule_id == "auditor.dns.batimento"]


def test_new_domain_right_after_an_update():
    stats = aggregate([DnsQuery(NOW - timedelta(minutes=50), "telemetria.example", "1.2.3.4", False)], {"antigo.com"})
    intel = DnsIntel(changes=[(NOW - timedelta(minutes=53), "meu-card", "atualizado")])
    (new,) = [f for f in analyze(stats, first_run=False, intel=intel) if f.rule_id == "auditor.dns.novos"]
    assert "primeira consulta 3 min depois de: meu-card (atualizado)" in new.snippet
    assert "first queried 3 min after: meu-card (updated)" in new.en["snippet"]


def test_recent_changes_from_partial_scans(tmp_path):
    storage = Storage(tmp_path / "db.sqlite", tmp_path / "reports")
    with storage._conn() as conn:
        conn.execute("INSERT INTO scans (scan_id, started_at, status, kind, targets_json) VALUES (?, ?, ?, ?, ?)",
                     ("p1", "2026-11-22T10:00:00+00:00", "concluida", "parcial",
                      json.dumps([{"tipo": "frontend", "nome": "meu-card", "mudanca": "atualizado"},
                                  {"tipo": "integracao", "nome": "velha", "mudanca": "removido"}])))
        conn.execute("INSERT INTO scans (scan_id, started_at, status, kind) VALUES ('c1', '2026-11-22T11:00:00+00:00', "
                     "'concluida', 'completa')")
    assert storage.recent_changes("2026-11-22T00:00:00+00:00") == [
        ("2026-11-22T10:00:00+00:00", "meu-card", "atualizado")]
    assert storage.recent_changes("2026-11-23T00:00:00+00:00") == []
