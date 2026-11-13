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
