"""Idiomas: todo texto da interface tem tradução e a escolha do usuário fica guardada."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

from auditor import i18n
from auditor.i18n import EN, JS_KEYS, Translator
from auditor.models import Severity
from auditor.report import _DETAIL_KEYS, COMPONENT_TYPE_LABELS

WEB = Path(i18n.__file__).resolve().parent / "web"
_STR = r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\''


def _strings(pattern: str, text: str) -> set[str]:
    out = set()
    for m in re.finditer(pattern, text):
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        out.add(raw.replace('\\"', '"').replace("\\'", "'"))
    return out


def test_every_template_text_has_english():
    html = (WEB / "templates" / "report.html").read_text(encoding="utf-8")
    texts = _strings(r"\b_h?\(\s*(?:" + _STR + r")", html)
    assert len(texts) > 150  # sanidade: a extração achou os textos
    missing = sorted(t for t in texts if t not in EN)
    assert missing == [], f"sem tradução: {missing}"


def test_every_js_text_has_english_and_reaches_the_page():
    js = "\n".join(line for line in (WEB / "static" / "app.js").read_text(encoding="utf-8").splitlines()
                   if not line.strip().startswith("//"))
    texts = _strings(r"\bT\(\s*(?:" + _STR + r")", js)
    assert len(texts) > 25
    assert sorted(t for t in texts if t not in EN) == []
    assert sorted(t for t in texts if t not in JS_KEYS) == []  # senão não chega ao navegador


def test_dynamic_labels_have_english():
    dynamic = {s.label for s in Severity} | set(COMPONENT_TYPE_LABELS.values()) | {"pessoal", "comunitária"}
    dynamic |= {label for _, label in _DETAIL_KEYS if label}
    assert sorted(t for t in dynamic if t not in EN) == []


def test_translator():
    en, pt = Translator("en"), Translator("pt")
    assert en.t("Varrer agora") == "Scan now" and pt.t("Varrer agora") == "Varrer agora"
    assert en.t("({a} de {b})", a=2, b=4) == "(2 of 4)"
    assert en.t("texto que não existe") == "texto que não existe"  # sem tradução: mostra o original
    assert Translator("xx").lang == "en" and Translator(None).lang == "en"  # padrão: inglês
    # Variáveis em textos com HTML são escapadas.
    html = en.h("Varredura de {data}", data="<script>")
    assert "<script>" not in str(html) and "&lt;script&gt;" in str(html)
    assert pt.js_catalog() == {} and en.js_catalog()["Varrer agora"] == "Scan now"


@pytest.fixture
async def client(aiohttp_client, tmp_path):
    from auditor.scheduler import Scheduler
    from auditor.storage import Storage
    from auditor.web import CSRF_HEADER, create_app

    storage = Storage(tmp_path / "db.sqlite", tmp_path / "reports")
    app = create_app(storage, Scheduler(lambda: None, 0, False), {}, allowed_peers={ipaddress.ip_address("127.0.0.1")})
    c = await aiohttp_client(app)
    html = await (await c.get("/")).text()
    token = html.split('name="csrf-token" content="')[1].split('"')[0]
    return c, {CSRF_HEADER: token}, storage


async def test_language_default_and_saved(client):
    c, h, storage = client
    html = await (await c.get("/")).text()
    body = html.split("<body", 1)[1]
    assert '<html lang="en">' in html and "Scan now" in body and "Varrer agora" not in body
    assert 'data-lang-choice="en" aria-pressed="true"' in html
    assert '"Varrer agora": "Scan now"' in html  # catálogo do JavaScript na página

    assert (await c.post("/api/idioma", json={"idioma": "pt"})).status == 403  # sem CSRF
    assert (await c.post("/api/idioma", headers=h, json={"idioma": "fr"})).status == 400
    resp = await c.post("/api/idioma", headers=h, json={"idioma": "pt"})
    assert resp.status == 200 and storage.get_setting("idioma") == "pt"

    html = await (await c.get("/")).text()
    assert '<html lang="pt-BR">' in html and "Varrer agora" in html and "Scan now" not in html
    assert '<script type="application/json" id="i18n-js">{}</script>' in html


# --- Achados em inglês -------------------------------------------------------------------------


def test_every_finding_construction_has_english():
    import ast

    root = Path(i18n.__file__).resolve().parent
    missing = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Finding":
                if not any(k.arg == "en" for k in node.keywords):
                    missing.append(f"{path.relative_to(root)}:{node.lineno}")
    assert missing == [], f"Finding sem en=: {missing}"


def test_every_semgrep_rule_has_english():
    import yaml

    rules_dir = Path(i18n.__file__).resolve().parent.parent / "rules" / "semgrep"
    missing = []
    for path in sorted(rules_dir.rglob("*.yaml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
            meta = rule.get("metadata") or {}
            if not all(meta.get(k) for k in ("titulo_en", "explicacao_en", "recomendacao_en")):
                missing.append(rule["id"])
    assert missing == []


async def test_english_finding_text_is_shown_and_masked(paths, storage, masker):
    from auditor.models import en_text
    from auditor.report import render_html

    from .conftest import make_finding
    from .test_engine_web import FakeScanner, _engine

    secret = "token-ultra-secreto-999"
    masker.add_known(secret)
    finding = make_finding(en=en_text("English title", f"Leaks {secret} here", "Do this"))
    result = await _engine(paths, storage, masker, __import__("auditor.config").config.Options(),
                           [FakeScanner([finding])]).run()
    (f,) = result.findings
    assert secret not in f.en["explanation"] and "****" in f.en["explanation"]
    html_en = render_html(result, status={}, history=[], csrf_token="t", lang="en")
    html_pt = render_html(result, status={}, history=[], csrf_token="t", lang="pt")
    assert "English title" in html_en and "Do this" in html_en
    assert "English title" not in html_pt and f.title in html_pt
    saved = storage.load_scan(result.scan_id)
    assert saved.findings[0].en["title"] == "English title"  # sobrevive ao JSON salvo


def test_categories_steps_and_suppression_have_english():
    import ast

    import yaml

    from auditor.i18n import CATEGORY_LABELS, STEP_LABELS
    from auditor.scanners import default_scanners

    root = Path(i18n.__file__).resolve().parent
    used = set()
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.keyword) and node.arg == "category" and isinstance(node.value, ast.Constant):
                used.add(node.value.value)
    for path in (root.parent / "rules" / "semgrep").rglob("*.yaml"):
        used |= {r["metadata"]["categoria"] for r in yaml.safe_load(path.read_text())["rules"]}
    from auditor.scanners.static import _BANDIT_INFO

    used |= {v[0] for v in _BANDIT_INFO.values()}
    assert sorted(used - set(CATEGORY_LABELS)) == []
    assert {s.name for s in default_scanners()} <= set(STEP_LABELS)
    assert all(label in EN for label in STEP_LABELS.values() if label != "DNS")
    tr = Translator("en")
    assert tr.category("ofuscacao") == "obfuscation" and Translator("pt").category("ofuscacao") == "ofuscação"
    assert tr.suppression("revisado (lista de ignorados)") == "revisado (ignore list)"
    assert tr.source("integridade") == "integrity" and tr.source("semgrep") == "semgrep"
    from auditor.i18n import SOURCE_EN

    sources = set()
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.keyword) and node.arg == "source" and isinstance(node.value, ast.Constant):
                sources.add(node.value.value)
    pt_only = {s for s in sources if any(c in s for c in "_-") or s in ("integridade", "estatisticas")}
    assert sorted(pt_only - set(SOURCE_EN) - {"pip-audit", "zip_release"}) == []  # zip_release: tipo de pacote do HACS
    assert tr.meta({"x": "pt", "x_en": "en"}, "x") == "en" and Translator("pt").meta({"x": "pt", "x_en": "en"}, "x") == "pt"


def test_sensor_names_follow_language_but_ids_and_units_do_not():
    from auditor.publisher import build_states

    pt = build_states(None, "ocioso", "pt")
    en = build_states(None, "ocioso", "en")
    assert pt.keys() == en.keys()  # entity_id iguais
    assert en["sensor.security_auditor_alertas_altos"][1]["friendly_name"] == "Security Auditor High alerts"
    assert pt["sensor.security_auditor_alertas_altos"][1]["friendly_name"] == "Security Auditor Alertas altos"
    assert en["sensor.security_auditor_ultima_varredura"][1]["friendly_name"] == "Security Auditor Last scan"
    # Unidade e valor de estado não mudam (estatísticas e automações continuam funcionando).
    assert en["sensor.security_auditor_alertas_altos"][1]["unit_of_measurement"] == "achados"
    assert en["sensor.security_auditor_status"][0] == pt["sensor.security_auditor_status"][0] == "ocioso"
