// Testes do app.js sobre uma página gerada pelo template real (ver tests/test_interface_js.py).
// Rodar: pytest tests/test_interface_js.py  (o pytest gera a página e chama este arquivo).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { JSDOM, VirtualConsole } from "jsdom";

const HTML = readFileSync(process.env.UI_PAGE, "utf8");
const APP = readFileSync(process.env.UI_APP_JS, "utf8");
const DATA = JSON.parse(readFileSync(process.env.UI_DATA, "utf8"));

const tick = () => new Promise((r) => setTimeout(r, 0));
async function waitFor(cond, ms = 2000) {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("tempo esgotado esperando a condição");
    await new Promise((r) => setTimeout(r, 10));
  }
}

// Abre a página num "navegador" jsdom, com fetch, confirm e alert simulados, e roda o app.js.
function open(query = "", replies = {}) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => { if (!/Not implemented: navigation/.test(e.message)) errors.push(e.message); });
  const dom = new JSDOM(HTML, { url: "http://localhost/" + query, runScripts: "outside-only",
                                pretendToBeVisual: true, virtualConsole: vc });
  const w = dom.window;
  const calls = [];
  w.fetch = async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : undefined;
    calls.push({ url: String(url), method: opts.method || "GET", body });
    const r = (typeof replies[String(url)] === "function" ? replies[String(url)](body) : replies[String(url)])
      || { status: 200, json: {} };
    return { ok: r.status < 400, status: r.status, json: async () => r.json };
  };
  w.confirm = () => true;
  w.alert = (m) => calls.push({ alert: m });
  w.scrollTo = () => {};
  // O jsdom não implementa <dialog>: abre e fecha só mudando o atributo.
  for (const P of [w.HTMLElement.prototype, w.HTMLDialogElement?.prototype].filter(Boolean)) {
    P.showModal = function () { this.setAttribute("open", ""); };
    P.close = function () { this.removeAttribute("open"); this.dispatchEvent(new w.Event("close")); };
  }
  w.addEventListener("error", (e) => errors.push(e.message));
  w.eval(APP);
  const d = w.document;
  const $ = (sel) => d.querySelector(sel);
  const $$ = (sel) => Array.from(d.querySelectorAll(sel));
  const type = (el, text) => { el.value = text; el.dispatchEvent(new w.Event("input", { bubbles: true })); };
  const submit = (form) => form.dispatchEvent(new w.Event("submit", { bubbles: true, cancelable: true }));
  return { w, d, $, $$, calls, errors, type, submit };
}

const visibleRows = (p, sel) => p.$$(sel).filter((r) => !r.hidden && !r.classList.contains("search-hidden"));
const compNames = (p) => visibleRows(p, ".comp-row").map((r) => r.querySelector("[data-filter-component]").textContent.trim());

test("a página carrega sem erros de JavaScript", () => {
  for (const q of ["", "?ver=dns", "?ver=ignorados", "?componente=tuya_local"]) {
    const p = open(q);
    assert.deepEqual(p.errors, [], `erros em ${q || "resumo"}`);
  }
});

test("busca por nome na tabela de componentes (acha até os sem achados)", () => {
  const p = open("?ver=componentes");
  assert.deepEqual(compNames(p).sort(), ["luzes_sala", "tuya_local"]);  // sem achados escondido
  p.type(p.$("#filter-comp-name"), "LUZ");
  assert.deepEqual(compNames(p), ["luzes_sala"]);
  p.type(p.$("#filter-comp-name"), "limpa");
  assert.deepEqual(compNames(p), ["clima_limpa"]);
  p.type(p.$("#filter-comp-name"), "");
  assert.deepEqual(compNames(p).sort(), ["luzes_sala", "tuya_local"]);
});

test("realce da linha clicada: uma por vez, e botões não mexem nele", () => {
  const p = open("?ver=componentes");
  const [a, b] = visibleRows(p, ".comp-row");
  a.querySelector("td:nth-child(2)").click();
  assert.ok(a.classList.contains("row-selected"));
  b.querySelector("td:nth-child(2)").click();
  assert.ok(!a.classList.contains("row-selected") && b.classList.contains("row-selected"));
  b.querySelector("td:nth-child(2)").click();
  assert.ok(!b.classList.contains("row-selected"));
  b.querySelector("[data-ignore-component]").click();
  assert.ok(!b.classList.contains("row-selected"));
});

test("com Ignorados aberto, clicar num nível volta ao resumo filtrado", () => {
  const p = open("?ver=ignorados");
  assert.ok(p.d.body.classList.contains("view-ignored"));
  p.$('button.card[data-filter-sev="high"]').click();
  assert.ok(!p.d.body.classList.contains("view-ignored"));
  assert.equal(p.$("#toggle-ignored").getAttribute("aria-pressed"), "false");
  assert.equal(p.$('button.card[data-filter-sev="high"]').getAttribute("aria-pressed"), "true");
});

test("busca na lista de ignorados", () => {
  const p = open("?ver=ignorados");
  p.type(p.$('[data-table-search="ignored"]'), "integridade");
  const rows = visibleRows(p, '[data-search-body="ignored"] tr');
  assert.equal(rows.length, 1);
  assert.match(rows[0].textContent, /auditor\.integridade/);
});

test("DNS: selecionar só os visíveis e ignorar os selecionados", async () => {
  const p = open("?ver=dns", { "api/dns/ignorados": { status: 201, json: { ids: [9] } } });
  assert.equal(p.$$(".dns-select").length, 4);  // o domínio já ignorado não tem caixa
  assert.ok(p.$(".dns-ignore-selected").hidden);
  p.type(p.$('[data-table-search="dns-domains"]'), "pool");
  p.$(".dns-select-all").click();
  assert.deepEqual(p.$$(".dns-select").filter((b) => b.checked).map((b) => b.value), ["pool.supportxmr.com"]);
  assert.ok(!p.$(".dns-ignore-selected").hidden);
  assert.match(p.$(".dns-ignore-selected").textContent, /\(1\)/);
  p.$(".dns-ignore-selected").click();
  assert.ok(p.$("#dns-ignore-dialog").hasAttribute("open"));
  p.$("#dns-ignore-form").elements.reason.value = "conhecido";
  p.submit(p.$("#dns-ignore-form"));
  await waitFor(() => p.calls.some((c) => c.url === "api/dns/ignorados"));
  const call = p.calls.find((c) => c.url === "api/dns/ignorados");
  assert.deepEqual(call.body, { dominios: ["pool.supportxmr.com"], motivo: "conhecido" });
});

test("DNS: com 'Mostrar domínios ignorados', os botões em massa somem", () => {
  const p = open("?ver=dns");
  p.$$(".dns-select")[0].click();
  p.$$(".dns-select")[0].dispatchEvent(new p.w.Event("change", { bubbles: true }));
  assert.ok(!p.$(".dns-ignore-selected").hidden);
  p.$("#dns-show-ignored").click();
  for (const sel of [".dns-ignore-all", ".dns-ai-all", ".dns-ignore-selected"]) assert.ok(p.$(sel).hidden, sel);
  p.$("#dns-show-ignored").click();
  assert.ok(!p.$(".dns-ignore-all").hidden && !p.$(".dns-ai-all").hidden);
});

test("Perguntar à IA: envia só o host e mostra o veredito", async () => {
  const p = open("?ver=dns", { "api/dns/ia": { status: 200, json: {
    veredito: "malicioso", explicacao: "Pool de mineração.", modelo: "claude-opus-5-5", guardada: false, data: "2026-11-18",
    fatos: ["Registrado em 2026-11-19 (há 3 dias)", "Endereços: 203.0.113.7"] } } });
  p.$('[data-dns-ai="api.fabricante.com"]').click();
  await waitFor(() => !p.$("#dns-ai-result").hidden);
  assert.deepEqual(p.calls.find((c) => c.url === "api/dns/ia").body, { dominio: "api.fabricante.com", refazer: false });
  assert.equal(p.$("#dns-ai-verdict").textContent, "Malicioso");
  assert.equal(p.$("#dns-ai-explanation").textContent, "Pool de mineração.");
  // Os dados públicos que foram junto aparecem numa lista, como texto (nunca HTML).
  assert.ok(!p.$("#dns-ai-facts-box").hidden);
  assert.deepEqual(p.$$("#dns-ai-facts li").map((li) => li.textContent),
    ["Registrado em 2026-11-19 (há 3 dias)", "Endereços: 203.0.113.7"]);
});

test("Perguntar à IA sobre todos: só os visíveis sem resposta, um por vez", async () => {
  const asked = [];
  const p = open("?ver=dns", { "api/dns/ia": (body) => { asked.push(body.dominio);
    return { status: 200, json: { veredito: "desconhecido", explicacao: "-", modelo: "m", guardada: false } }; } });
  p.$(".dns-ai-all").click();
  await waitFor(() => asked.length === 3);
  // pool.supportxmr.com já tinha resposta e ja.ignorado.com está ignorado: ficam de fora.
  assert.deepEqual(asked, ["api.fabricante.com", "k8f2j9x7q1m4z6v3b5n0p2r8t4.example.org", "ads.rastreador.com"]);
});

test("achados: botão da IA por host e seleção para ignorar", async () => {
  const p = open("?componente=tuya_local", { "api/ignored": { status: 201, json: { id: 3 } } });
  assert.ok(p.$('[data-dns-ai="coleta.evil.xyz"]'), "botão da IA para o host da URL");
  assert.ok(!p.$$('[data-dns-ai]').some((b) => /token/.test(b.dataset.dnsAi)));
  const button = p.$("#findings-ignore-selected");
  assert.ok(button.hidden);
  p.$("#findings-select-all").click();
  assert.match(button.textContent, /\(3\)/);
  const box = p.$(`.finding-select[value="${DATA.fingerprints["auditor.shell"]}"]`);
  box.click();
  box.dispatchEvent(new p.w.Event("change", { bubbles: true }));
  assert.match(button.textContent, /\(2\)/);
  assert.ok(p.$("#findings-select-all").indeterminate);
  button.click();
  assert.ok(p.$("#ignore-dialog").hasAttribute("open"));
  p.$("#ignore-form").elements.reason.value = "revisados";
  p.submit(p.$("#ignore-form"));
  await waitFor(() => p.calls.some((c) => c.url === "api/ignored"));
  const body = p.calls.find((c) => c.url === "api/ignored").body;
  assert.equal(body.component, "tuya_local");
  assert.deepEqual(body.achados.sort(),
    [DATA.fingerprints["auditor.eval-dinamico"], DATA.fingerprints["auditor.rede"]].sort());
});

test("componente: Ignorar tira da varredura e Ignorar achados usa a foto dos atuais", async () => {
  const p = open("?ver=componentes", { "api/ignored": { status: 201, json: { id: 4 } } });
  p.$('[data-ignore-component="luzes_sala"]').click();
  assert.ok(p.$("#ignore-levels-field").hidden && !p.$("#ignore-skip-note").hidden);
  p.$("#ignore-form").elements.reason.value = "meu";
  p.submit(p.$("#ignore-form"));
  await waitFor(() => p.calls.some((c) => c.url === "api/ignored"));
  assert.deepEqual(p.calls.find((c) => c.url === "api/ignored").body,
    { component: "luzes_sala", rule: "*", reason: "meu", nao_analisar: true });

  const q = open("?ver=componentes", { "api/ignored": { status: 201, json: { id: 5 } } });
  q.$('[data-ignore-findings="tuya_local"]').click();
  assert.ok(!q.$("#ignore-levels-field").hidden);
  q.$('#ignore-form input[name="severity"][value="low"]').click();
  q.$("#ignore-form").elements.reason.value = "x";
  q.submit(q.$("#ignore-form"));
  await waitFor(() => q.calls.some((c) => c.url === "api/ignored"));
  const body = q.calls.find((c) => c.url === "api/ignored").body;
  assert.equal(body.achados_atuais, true);
  assert.deepEqual(body.severities, ["low"]);
});
