"""Botão "Perguntar à IA" na aba DNS: só o domínio sai, e só para o provedor escolhido."""

from __future__ import annotations

import ipaddress
import json

import pytest

from auditor import ai
from auditor.ai import AiError, ask_domain, check_domain
from auditor.config import Options
from auditor.net import HttpError

from .test_dns_ignorados import _result_with


class FakeHttp:
    """No lugar do SafeHttpClient: guarda o que seria enviado e devolve a resposta pronta."""

    calls: list = []  # noqa: RUF012 - zerada pela fixture a cada teste
    reply: object = None

    def __init__(self, allowed_hosts, timeout, session=None):
        self.allowed = allowed_hosts

    async def post_json(self, url, body, headers):
        FakeHttp.calls.append({"allowed": self.allowed, "url": url, "body": body, "headers": headers})
        if isinstance(FakeHttp.reply, Exception):
            raise FakeHttp.reply
        return FakeHttp.reply

    async def close(self):
        pass


@pytest.fixture
def http(monkeypatch):
    FakeHttp.calls = []
    monkeypatch.setattr(ai, "SafeHttpClient", FakeHttp)
    return FakeHttp


ANSWER = {"veredito": "malicioso", "explicacao": "Pool de mineração conhecida."}


def _claude(answer=ANSWER, stop="end_turn"):
    return {"stop_reason": stop, "content": [{"type": "thinking", "thinking": ""},
                                             {"type": "text", "text": json.dumps(answer)}]}


async def test_claude_sends_only_the_domain(http):
    http.reply = _claude()
    got = await ask_domain("claude", "sk-teste", None, "Pool.SupportXMR.com.", "pt")
    assert got == {**ANSWER, "provedor": "claude", "modelo": "claude-opus-5-5"}
    (call,) = http.calls
    assert call["allowed"] == frozenset({"api.anthropic.com"})
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"]["x-api-key"] == "sk-teste" and call["headers"]["anthropic-version"] == "2026-10-21"
    body = call["body"]
    assert body["messages"] == [{"role": "user", "content": "pool.supportxmr.com"}]  # só o domínio
    assert body["output_config"]["format"]["type"] == "json_schema" and body["fallbacks"] == "default"
    assert "Brazilian Portuguese" in body["system"]
    assert "temperature" not in body


async def test_gemini_request_and_thought_parts(http):
    http.reply = {"candidates": [{"content": {"parts": [
        {"text": "pensando…", "thought": True}, {"text": json.dumps(ANSWER)}]}}]}
    got = await ask_domain("gemini", "AIza-teste", "gemini-4-hydrogen", "pool.supportxmr.com", "en")
    assert got["veredito"] == "malicioso" and got["modelo"] == "gemini-4-hydrogen"
    (call,) = http.calls
    assert call["allowed"] == frozenset({"generativelanguage.googleapis.com"})
    assert call["url"].endswith("/v1beta/models/gemini-4-hydrogen:generateContent")
    assert call["headers"] == {"x-goog-api-key": "AIza-teste"}
    assert call["body"]["contents"] == [{"role": "user", "parts": [{"text": "pool.supportxmr.com"}]}]
    assert call["body"]["generationConfig"]["responseMimeType"] == "application/json"
    assert "English" in call["body"]["systemInstruction"]["parts"][0]["text"]


async def test_gemini_default_model(http):
    http.reply = {"candidates": [{"content": {"parts": [{"text": json.dumps(ANSWER)}]}}]}
    assert (await ask_domain("gemini", "k", "", "a.com", "pt"))["modelo"] == "gemini-3.5-flash-lite"


@pytest.mark.parametrize("reply, message", [
    (HttpError(401, "https://api.anthropic.com/v1/messages"), "recusou a chave"),
    (HttpError(404, "https://api.anthropic.com/v1/messages"), "Modelo não encontrado"),
    (HttpError(429, "https://api.anthropic.com/v1/messages"), "Limite de uso"),
    (_claude(stop="refusal"), "recusou responder"),
    (_claude(stop="max_tokens"), "cortada"),
    (_claude({"veredito": "talvez", "explicacao": "x"}), "resposta válida"),
    ({"stop_reason": "end_turn", "content": [{"type": "text", "text": "não é json"}]}, "resposta válida"),
    (TimeoutError(), "Não foi possível falar com o Claude"),
])
async def test_claude_errors(http, reply, message):
    http.reply = reply
    with pytest.raises(AiError) as err:
        await ask_domain("claude", "k", None, "a.com", "pt")
    assert message in err.value.args[0]


async def test_gemini_blocked(http):
    http.reply = {"candidates": []}
    with pytest.raises(AiError, match="não respondeu"):
        await ask_domain("gemini", "k", None, "a.com", "pt")


async def test_nothing_is_sent_when_misconfigured(http):
    with pytest.raises(AiError, match="Nenhuma IA"):
        await ask_domain("desligado", "k", None, "a.com", "pt")
    with pytest.raises(AiError, match="chave"):
        await ask_domain("claude", "", None, "a.com", "pt")
    with pytest.raises(AiError, match="modelo inválido"):
        await ask_domain("gemini", "k", "../../x?key=1", "a.com", "pt")
    with pytest.raises(ValueError):
        await ask_domain("claude", "k", None, "a.com/caminho", "pt")
    assert http.calls == []


@pytest.mark.parametrize("text", ["", "com", "a..b", "*.a.com", "a.com/x", "a b.com", "x" * 254 + ".com"])
def test_check_domain_rejects(text):
    with pytest.raises(ValueError):
        check_domain(text)


def test_options():
    opts = Options.from_dict({})
    assert opts.ai_provider == "desligado" and opts.ai_api_key is None and opts.ai_model is None
    opts = Options.from_dict({"ia_provedor": "Claude", "ia_chave_api": " sk ", "ia_modelo": ""})
    assert (opts.ai_provider, opts.ai_api_key, opts.ai_model) == ("claude", "sk", None)
    assert Options.from_dict({"ia_provedor": "openai"}).ai_provider == "desligado"


def test_config_yaml():
    from pathlib import Path

    import yaml

    addon = Path(__file__).parents[1] / "security_auditor"
    cfg = yaml.safe_load((addon / "config.yaml").read_text())
    keys = list(cfg["options"])
    start = keys.index("intervalo_dns_minutos") + 1
    assert keys[start:start + 3] == ["ia_provedor", "ia_chave_api", "ia_modelo"]
    assert cfg["options"]["ia_provedor"] == "desligado"
    assert cfg["schema"]["ia_provedor"] == "list(desligado|gemini|claude)"
    assert cfg["schema"]["ia_chave_api"] == "password?"
    for lang in ("en", "pt-BR"):
        conf = yaml.safe_load((addon / "translations" / f"{lang}.yaml").read_text())["configuration"]
        assert all(conf[k]["name"] for k in ("ia_provedor", "ia_chave_api", "ia_modelo"))


# --- Página e rota -------------------------------------------------------------------


def test_page_button_only_when_configured():
    from auditor.report import render_html

    result = _result_with(["pool.supportxmr.com", "outro.com"])
    off = render_html(result, status={}, history=[], csrf_token="t", lang="en")
    assert "data-dns-ai=" not in off and "dns-ai-dialog" not in off
    cached = {"pool.supportxmr.com": {"veredito": "malicioso", "explicacao": "x", "provedor": "claude",
                                      "modelo": "claude-opus-5-5", "idioma": "pt", "data": "2026-11-13"}}
    on = render_html(result, status={}, history=[], csrf_token="t", lang="en",
                     ai={"label": "Claude", "modelo": "claude-opus-5-5"}, dns_ai=cached)
    assert 'data-dns-ai="outro.com"' in on and "Ask the AI" in on
    assert 'class="badge sev-critical"' in on and "AI: Malicious" in on
    assert "Only the domain name is sent to Claude" in on


@pytest.fixture
async def client(aiohttp_client, tmp_path):
    from auditor.scheduler import Scheduler
    from auditor.storage import Storage
    from auditor.web import CSRF_HEADER, create_app

    storage = Storage(tmp_path / "db.sqlite", tmp_path / "reports")
    asked = []
    state = {"fail": False}

    async def ask(domain, lang):
        asked.append((domain, lang))
        if state["fail"]:
            raise AiError(ai.Bi("O Claude recusou a chave da API (HTTP 401)", "Claude rejected the API key (HTTP 401)"))
        return {**ANSWER, "provedor": "claude", "modelo": "claude-opus-5-5"}

    app = create_app(storage, Scheduler(lambda: None, 0, False), {}, allowed_peers={ipaddress.ip_address("127.0.0.1")},
                     ai={"label": "Claude", "modelo": "claude-opus-5-5", "ask": ask})
    c = await aiohttp_client(app)
    html = await (await c.get("/")).text()
    token = html.split('name="csrf-token" content="')[1].split('"')[0]
    return c, {CSRF_HEADER: token}, storage, asked, state


async def test_api_ask(client):
    c, h, storage, asked, state = client
    assert (await c.post("/api/dns/ia", json={"dominio": "pool.supportxmr.com"})).status == 403  # sem CSRF
    resp = await c.post("/api/dns/ia", headers=h, json={"dominio": "pool.supportxmr.com"})
    assert resp.status == 404 and not asked  # o auditor nunca viu esse domínio

    with storage._conn() as conn:
        conn.execute("INSERT INTO dns_domains (domain, first_seen) VALUES ('pool.supportxmr.com', '2026-11-13')")
    resp = await c.post("/api/dns/ia", headers=h, json={"dominio": "Pool.SupportXMR.com"})
    data = await resp.json()
    assert resp.status == 200 and data["veredito"] == "malicioso" and data["guardada"] is False
    assert asked == [("pool.supportxmr.com", "en")]
    # Segunda vez: resposta guardada, sem nova consulta (e sem custo).
    data = await (await c.post("/api/dns/ia", headers=h, json={"dominio": "pool.supportxmr.com"})).json()
    assert data["guardada"] is True and len(asked) == 1
    # "Perguntar de novo" consulta outra vez; um erro do provedor volta como 502 com a mensagem.
    state["fail"] = True
    resp = await c.post("/api/dns/ia", headers=h, json={"dominio": "pool.supportxmr.com", "refazer": True})
    assert resp.status == 502 and "rejected the API key" in (await resp.json())["error"] and len(asked) == 2
    assert storage.dns_ai()["pool.supportxmr.com"]["veredito"] == "malicioso"  # a anterior continua guardada
    assert (await c.post("/api/dns/ia", headers=h, json={"dominio": "a.com/x"})).status == 400


async def test_api_without_ai(aiohttp_client, tmp_path):
    from auditor.scheduler import Scheduler
    from auditor.storage import Storage
    from auditor.web import CSRF_HEADER, create_app

    storage = Storage(tmp_path / "db.sqlite", tmp_path / "reports")
    app = create_app(storage, Scheduler(lambda: None, 0, False), {}, allowed_peers={ipaddress.ip_address("127.0.0.1")})
    c = await aiohttp_client(app)
    html = await (await c.get("/")).text()
    token = html.split('name="csrf-token" content="')[1].split('"')[0]
    resp = await c.post("/api/dns/ia", headers={CSRF_HEADER: token}, json={"dominio": "a.com"})
    assert resp.status == 409
