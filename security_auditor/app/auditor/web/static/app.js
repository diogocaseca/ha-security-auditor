// Interface do relatório: filtros no cliente, varredura/cancelamento e lista de ignorados.
(function () {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]').content;

  // --- Idioma: traduções vindas da página (vazio em português) ------------------------
  let STEPS = {};
  try { STEPS = JSON.parse(document.getElementById("i18n-steps")?.textContent || "{}"); } catch (e) { STEPS = {}; }
  let CATALOG = {};
  try { CATALOG = JSON.parse(document.getElementById("i18n-js")?.textContent || "{}"); } catch (e) { CATALOG = {}; }
  // T("Texto em português {x}", {x: 1}) -> texto no idioma escolhido, com as variáveis.
  function T(text, vars) {
    let out = CATALOG[text] || text;
    for (const [k, v] of Object.entries(vars || {})) out = out.split("{" + k + "}").join(String(v));
    return out;
  }
  const findings = Array.from(document.querySelectorAll(".finding"));
  const compRows = Array.from(document.querySelectorAll(".comp-row"));
  const sevLabels = {};
  document.querySelectorAll("button.card[data-filter-sev]").forEach((b) => {
    sevLabels[b.dataset.filterSev] = b.querySelector(".card-label")?.textContent.trim() || b.dataset.filterSev;
  });
  const SEV_KEYS = Object.keys(sevLabels);
  const state = { sev: new Set(), component: null, view: null, text: "", onlyNew: false, suppressed: false,
                  hideEmpty: true, type: "", onlyBlocklist: false, compName: "" };
  let afterApply = null; // ligado depois (seleção de achados), quando as variáveis dela já existem
  const onlyBlocklist = document.getElementById("only-blocklist");
  const typeSelect = document.getElementById("filter-type");
  const TYPES = typeSelect ? Array.from(typeSelect.options).map((o) => o.value).filter(Boolean) : [];
  // Preferência "Esconder componentes sem achados" (marcada por padrão), lembrada neste navegador.
  const HIDE_KEY = "auditor.esconderVazios";
  try { if (localStorage.getItem(HIDE_KEY) === "0") state.hideEmpty = false; } catch (e) { /* sem armazenamento */ }
  const VIEWS = ["ignorados", "historico", "listanegra", "dns"];
  const TAB_VIEWS = ["historico", "listanegra", "dns"]; // abas próprias; o resto pertence a "Início"

  // --- Estado na URL --------------------------------------------------------------
  // ?componente=X abre a tela de achados do componente; ?niveis=critical,high guarda os
  // níveis marcados. Assim "Voltar" (botão ou navegador) e recarregar mantêm a seleção.
  function readUrl() {
    const q = new URLSearchParams(window.location.search);
    state.component = q.get("componente") || null;
    state.view = state.component ? null : (VIEWS.includes(q.get("ver")) ? q.get("ver") : null);
    state.sev = new Set((q.get("niveis") || "").split(",").filter((k) => SEV_KEYS.includes(k)));
    state.type = TYPES.includes(q.get("tipo")) ? q.get("tipo") : "";
    state.onlyBlocklist = !!onlyBlocklist && q.get("lista") === "1";
    if (onlyBlocklist) onlyBlocklist.checked = state.onlyBlocklist;
    if (typeSelect) typeSelect.value = state.type;
  }

  function urlFor(component, view) {
    const q = new URLSearchParams(window.location.search);
    q.delete("componente");
    q.delete("ver");
    q.delete("niveis");
    q.delete("tipo");
    q.delete("lista");
    if (component) q.set("componente", component);
    else if (view) q.set("ver", view);
    if (view !== "historico") q.delete("pagina"); // a página só vale na aba de histórico
    if (state.sev.size) q.set("niveis", SEV_KEYS.filter((k) => state.sev.has(k)).join(","));
    if (state.type) q.set("tipo", state.type);
    if (state.onlyBlocklist) q.set("lista", "1");
    const qs = q.toString();
    return window.location.pathname + (qs ? "?" + qs : "");
  }

  function saveLevels() {
    // Atualiza a entrada atual do histórico (sem criar outra) quando os níveis mudam.
    try { history.replaceState(history.state, "", urlFor(state.component, state.view)); } catch (e) { /* sem histórico */ }
  }

  function compRowOf(name) {
    return compRows.find((r) => r.querySelector("[data-filter-component]")?.dataset.filterComponent === name) || null;
  }

  function apply() {
    const inComponent = !!state.component;
    document.body.classList.toggle("view-component", inComponent);
    document.body.classList.toggle("view-ignored", state.view === "ignorados");
    document.body.classList.toggle("view-history", state.view === "historico");
    document.body.classList.toggle("view-blocklist", state.view === "listanegra");
    document.body.classList.toggle("view-dns", state.view === "dns");
    const activeTab = TAB_VIEWS.includes(state.view) ? state.view : "inicio";
    document.querySelectorAll("[data-tab]").forEach((t) =>
      t.setAttribute("aria-selected", t.dataset.tab === activeTab ? "true" : "false"));
    // "Adicionar à lista negra…" só para integrações, frontend e add-ons.
    const blBtn = document.getElementById("bl-from-component");
    if (blBtn) {
      const row = inComponent ? compRowOf(state.component) : null;
      blBtn.hidden = !row || !["integracao", "frontend", "addon"].includes(row.dataset.type);
    }
    document.getElementById("toggle-ignored")?.setAttribute("aria-pressed", state.view === "ignorados" ? "true" : "false");
    let visible = 0;
    let total = 0;
    const perSev = {};
    for (const el of findings) {
      const mine = inComponent && el.dataset.component === state.component;
      if (mine) {
        total++;
        if (state.suppressed || el.dataset.suppressed !== "true") perSev[el.dataset.sev] = (perSev[el.dataset.sev] || 0) + 1;
      }
      const show =
        mine &&
        (state.sev.size === 0 || state.sev.has(el.dataset.sev)) &&
        (!state.onlyNew || el.dataset.new === "true") &&
        (state.suppressed || el.dataset.suppressed !== "true") &&
        (!state.text || el.textContent.toLowerCase().includes(state.text));
      el.hidden = !show;
      if (show) visible++;
    }
    if (inComponent) {
      document.getElementById("findings-component").textContent = state.component;
      document.getElementById("visible-count").textContent = T("({a} de {b})", { a: visible, b: total });
      const row = compRows.find((r) => r.querySelector("[data-filter-component]")?.dataset.filterComponent === state.component);
      const meta = [row?.children[1]?.textContent.trim(), row?.querySelector(".comp-meta")?.textContent.trim()];
      document.getElementById("findings-component-meta").textContent = meta.filter(Boolean).join(" · ");
      document.querySelectorAll("[data-chip-count]").forEach((c) => {
        const n = perSev[c.dataset.chipCount] || 0;
        c.textContent = n ? String(n) : "";
        c.parentElement.classList.toggle("chip-empty", !n);
      });
      document.title = `${state.component} · Security Auditor`;
    } else {
      document.title = "Security Auditor";
    }
    document.getElementById("component-empty")?.toggleAttribute("hidden", !inComponent || total > 0);
    document.getElementById("ignore-view-levels")?.toggleAttribute("hidden", !inComponent || total === 0);
    if (afterApply) afterApply();
    document.getElementById("no-match")?.toggleAttribute("hidden", !inComponent || total === 0 || visible > 0);
    // Tabela de componentes: com níveis selecionados, só os que têm achados em algum deles;
    // com "Esconder componentes sem achados", some quem não tem nenhum achado (fora os ignorados).
    // Busca por nome: acha o componente mesmo sem achados (ignora "Esconder componentes sem achados").
    let compVisible = 0;
    for (const row of compRows) {
      const sevs = row.dataset.sevs.split(" ").filter(Boolean);
      const name = (row.querySelector("[data-filter-component]")?.dataset.filterComponent || "").toLowerCase();
      const show = (state.sev.size === 0 || sevs.some((s) => state.sev.has(s))) &&
        (!state.hideEmpty || state.compName || sevs.length > 0) && (!state.type || row.dataset.type === state.type) &&
        (!state.onlyBlocklist || row.dataset.blocklist !== "") && (!state.compName || name.includes(state.compName));
      row.hidden = !show;
      if (show) compVisible++;
    }
    const compCount = document.getElementById("comp-count");
    if (compCount) compCount.textContent = compRows.length && compVisible < compRows.length ? T("({a} de {b})", { a: compVisible, b: compRows.length }) : "";
    const compNote = document.getElementById("comp-filter-note");
    if (compNote) {
      compNote.hidden = state.sev.size === 0;
      compNote.textContent = T("Com achados de nível: {niveis}",
        { niveis: Array.from(state.sev).map((k) => sevLabels[k] || k).join(", ") });
    }
    const compNone = document.getElementById("comp-no-match");
    if (compNone) compNone.hidden = compVisible > 0 || compRows.length === 0;
    const ignoreLevels = document.getElementById("ignore-levels");
    if (ignoreLevels) ignoreLevels.hidden = state.sev.size === 0;
    document.querySelectorAll("[data-filter-sev]").forEach((b) =>
      b.setAttribute("aria-pressed", state.sev.has(b.dataset.filterSev) ? "true" : "false"));
  }

  document.querySelectorAll("[data-filter-sev]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const key = btn.dataset.filterSev;
      // Com "Ignorados" aberto, clicar num nível fecha a lista e volta ao resumo filtrado por ele.
      if (state.view === "ignorados") {
        state.view = null;
        try { history.replaceState({}, "", urlFor(null, null)); } catch (e) { /* sem histórico */ }
        state.sev.clear();
      }
      state.sev.has(key) ? state.sev.delete(key) : state.sev.add(key);
      saveLevels();
      apply();
    }));

  // --- Realce da linha clicada (tabela de componentes e tabela de domínios do DNS) -------
  // Um clique realça a linha; outro clique nela tira o realce. Botões e links da linha seguem normais.
  document.querySelectorAll("#components tbody, [data-search-body]").forEach((body) =>
    body.addEventListener("click", (ev) => {
      const row = ev.target.closest("tr");
      if (!row || ev.target.closest("button, a, input, select, label")) return;
      const on = !row.classList.contains("row-selected");
      body.querySelectorAll("tr.row-selected").forEach((r) => r.classList.remove("row-selected"));
      row.classList.toggle("row-selected", on);
    }));

  // --- Busca nas tabelas (lista de ignorados, domínios do DNS e domínios ignorados) --------
  // Esconde as linhas sem o texto (classe própria: não mexe nas linhas escondidas por outro motivo).
  document.querySelectorAll("[data-table-search]").forEach((input) =>
    input.addEventListener("input", () => {
      const q = input.value.trim().toLowerCase();
      document.querySelectorAll(`[data-search-body="${input.dataset.tableSearch}"]`).forEach((body) => {
        body.querySelectorAll("tr").forEach((row) =>
          row.classList.toggle("search-hidden", !!q && !row.textContent.toLowerCase().includes(q)));
      });
    }));

  // --- Navegação entre o resumo e a tela de um componente --------------------------
  if ("scrollRestoration" in history) history.scrollRestoration = "manual";

  function openView(component, view) {
    // Guarda a posição do resumo para voltar ao mesmo ponto.
    try {
      if (component && TAB_VIEWS.includes(state.view)) {
        // Componente aberto a partir de uma aba (ex.: "Ver achados" na aba DNS): empilha,
        // para "Voltar" retornar à aba de origem.
        history.replaceState({ ...(history.state || {}), scroll: window.scrollY }, "", urlFor(null, state.view));
        history.pushState({ opened: true }, "", urlFor(component, null));
      } else if (state.component || state.view) {
        // Já fora do resumo: troca de tela sem empilhar, para "Voltar" sempre ir ao resumo.
        history.replaceState(history.state, "", urlFor(component, view));
      } else {
        history.replaceState({ ...(history.state || {}), scroll: window.scrollY }, "", urlFor(null, null));
        history.pushState({ opened: true }, "", urlFor(component, view));
      }
    } catch (e) { /* sem histórico: só troca a tela */ }
    state.component = component;
    state.view = view;
    apply();
    window.scrollTo(0, 0);
  }
  const openComponent = (name) => openView(name, null);

  function backToSummary() {
    if (history.state && history.state.opened) {
      history.back(); // volta pela entrada criada ao abrir o componente (popstate cuida do resto)
      return;
    }
    // Aberto direto pela URL (ex.: recarregou a página): substitui pela do resumo.
    try { history.replaceState({}, "", urlFor(null, null)); } catch (e) { /* sem histórico */ }
    state.component = null;
    state.view = null;
    apply();
    window.scrollTo(0, 0);
  }

  window.addEventListener("popstate", (ev) => {
    readUrl();
    apply();
    window.scrollTo(0, state.component || state.view ? 0 : (ev.state && ev.state.scroll) || 0);
  });

  document.querySelectorAll("[data-filter-component]").forEach((btn) =>
    btn.addEventListener("click", () => openComponent(btn.dataset.filterComponent)));
  document.getElementById("back-to-summary")?.addEventListener("click", backToSummary);
  document.getElementById("back-from-ignored")?.addEventListener("click", backToSummary);
  // Abas: "Início" volta ao resumo; "Histórico de verificações" abre a tabela de histórico.
  document.querySelectorAll("[data-tab]").forEach((t) => t.addEventListener("click", () => {
    if (TAB_VIEWS.includes(t.dataset.tab)) {
      if (state.view !== t.dataset.tab) openView(null, t.dataset.tab);
    } else if (state.component || state.view) {
      backToSummary();
    }
  }));
  // Quadrado "Ignorados": abre a aba da lista; clicar de novo volta ao resumo.
  document.getElementById("toggle-ignored")?.addEventListener("click", () =>
    state.view === "ignorados" ? backToSummary() : openView(null, "ignorados"));

  // "Só lista negra": só os componentes com o selo (fica na URL, como o tipo e os níveis).
  onlyBlocklist?.addEventListener("change", () => {
    state.onlyBlocklist = onlyBlocklist.checked;
    saveLevels();
    apply();
  });

  // Filtro de tipo (fica na URL, como os níveis, e volta selecionado ao retornar ao resumo).
  typeSelect?.addEventListener("change", () => {
    state.type = typeSelect.value;
    saveLevels();
    apply();
  });

  const compName = document.getElementById("filter-comp-name");
  compName?.addEventListener("input", () => { state.compName = compName.value.trim().toLowerCase(); apply(); });

  const hideEmpty = document.getElementById("hide-empty");
  if (hideEmpty) hideEmpty.checked = state.hideEmpty;
  hideEmpty?.addEventListener("change", () => {
    state.hideEmpty = hideEmpty.checked;
    try { localStorage.setItem(HIDE_KEY, hideEmpty.checked ? "1" : "0"); } catch (e) { /* sem armazenamento */ }
    apply();
  });

  const text = document.getElementById("filter-text");
  text?.addEventListener("input", () => { state.text = text.value.trim().toLowerCase(); apply(); });
  const onlyNew = document.getElementById("filter-new");
  onlyNew?.addEventListener("change", () => { state.onlyNew = onlyNew.checked; apply(); });
  const supp = document.getElementById("filter-suppressed");
  supp?.addEventListener("change", () => { state.suppressed = supp.checked; apply(); });
  document.getElementById("filter-clear")?.addEventListener("click", () => {
    state.sev.clear(); state.text = ""; state.onlyNew = false; state.suppressed = false;
    if (text) text.value = ""; if (onlyNew) onlyNew.checked = false; if (supp) supp.checked = false;
    saveLevels();
    apply();
  });

  // --- Idioma (guardado no add-on: vale em qualquer navegador) --------------------------
  document.querySelectorAll("[data-lang-choice]").forEach((b) => b.addEventListener("click", async () => {
    if (b.getAttribute("aria-pressed") === "true") return;
    try {
      const resp = await post("api/idioma", { idioma: b.dataset.langChoice });
      if (resp.ok) window.location.reload();
    } catch (e) { /* mantém o idioma atual */ }
  }));

  // --- Tema ---------------------------------------------------------------
  const themeButtons = document.querySelectorAll("[data-theme-choice]");
  function syncTheme() {
    const current = window.auditorTheme ? window.auditorTheme.get() : "system";
    themeButtons.forEach((b) => b.setAttribute("aria-pressed", b.dataset.themeChoice === current ? "true" : "false"));
  }
  themeButtons.forEach((b) => b.addEventListener("click", () => {
    if (window.auditorTheme) window.auditorTheme.set(b.dataset.themeChoice);
    syncTheme();
  }));
  syncTheme();

  // --- Varredura ---------------------------------------------------------
  const button = document.getElementById("scan-now");
  const cancelBtn = document.getElementById("scan-cancel");
  const statusEl = document.getElementById("scan-status");

  function post(url, body, method) {
    const headers = { "X-Auditor-CSRF": csrf };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(url, { method: method || "POST", headers, body: body === undefined ? undefined : JSON.stringify(body) });
  }

  async function poll() {
    try {
      const resp = await fetch("api/status", { cache: "no-store" });
      const data = await resp.json();
      if (data.running) {
        statusEl.textContent = data.cancelling ? T("Cancelando…") :
          T("Varrendo") + (data.progress && data.progress.step ? ": " + (STEPS[data.progress.step] || data.progress.step) : "") + "…";
        if (cancelBtn) {
          cancelBtn.hidden = false;
          if (data.cancelling) { cancelBtn.disabled = true; cancelBtn.textContent = T("Cancelando…"); }
        }
        setTimeout(poll, 2000);
      } else {
        window.location.href = "./";
      }
    } catch (e) {
      setTimeout(poll, 4000);
    }
  }

  button?.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = T("Varrendo…");
    try {
      const resp = await post("api/scan");
      if (resp.status !== 202 && resp.status !== 409) throw new Error("HTTP " + resp.status);
      if (cancelBtn) { cancelBtn.hidden = false; cancelBtn.disabled = false; }
      setTimeout(poll, 1000);
    } catch (e) {
      button.disabled = false;
      button.textContent = T("Varrer agora");
      statusEl.textContent = T("Não foi possível iniciar a varredura.");
    }
  });

  cancelBtn?.addEventListener("click", async () => {
    if (!window.confirm(T("Cancelar a varredura em andamento? O que já foi analisado fica salvo como relatório cancelado."))) return;
    cancelBtn.disabled = true;
    cancelBtn.textContent = T("Cancelando…");
    try {
      const resp = await post("api/scan/cancel");
      if (resp.status !== 202 && resp.status !== 409) throw new Error("HTTP " + resp.status);
      setTimeout(poll, 500);
    } catch (e) {
      cancelBtn.disabled = false;
      cancelBtn.textContent = T("Cancelar varredura");
      statusEl.textContent = T("Não foi possível cancelar a varredura.");
    }
  });

  if (document.body.dataset.running === "true") setTimeout(poll, 2000);

  // --- Lista de ignorados -----------------------------------------------------
  const dialog = document.getElementById("ignore-dialog");
  const form = document.getElementById("ignore-form");
  const errorEl = document.getElementById("ignore-error");
  // Modo do diálogo: achado, componente (linha da tabela), níveis (todos os componentes) ou manual.
  let mode = { kind: "manual" };
  const levelsField = document.getElementById("ignore-levels-field");
  const levelBoxes = Array.from(form ? form.querySelectorAll('input[name="severity"]') : []);
  const levelAll = document.getElementById("level-all");
  // "Todos os níveis" marca/desmarca todos; fica parcialmente marcado quando só alguns estão.
  function syncLevelAll() {
    if (!levelAll) return;
    const n = levelBoxes.filter((b) => b.checked).length;
    levelAll.checked = n === levelBoxes.length;
    levelAll.indeterminate = n > 0 && n < levelBoxes.length;
  }
  levelAll?.addEventListener("change", () => {
    levelBoxes.forEach((b) => { b.checked = levelAll.checked; });
    syncLevelAll();
  });
  levelBoxes.forEach((b) => b.addEventListener("change", syncLevelAll));
  const labelsOf = (keys) => keys.map((k) => sevLabels[k] || k).join(", ");

  function openDialog(next) {
    mode = next;
    form.reset();
    errorEl.hidden = true;
    const k = mode.kind;
    const titles = {
      finding: T("Ignorar achado"),
      levels: T("Ignorar níveis inteiros"),
      manual: T("Incluir na lista de ignorados"),
      skip: T("Ignorar componente"),
      findings: T("Ignorar achados do componente"),
      selected: T("Ignorar achados selecionados"),
    };
    document.getElementById("ignore-title").textContent = titles[k];
    document.getElementById("ignore-scope").hidden = k !== "finding";
    document.getElementById("ignore-manual").hidden = k !== "manual";
    levelsField.hidden = k === "finding" || k === "skip" || k === "selected";
    // Componente: deixa de ser analisado; o aviso fica visível antes de confirmar.
    document.getElementById("ignore-skip-note").hidden = k !== "skip";
    document.getElementById("ignore-levels-legend").textContent =
      k === "levels" ? T("Níveis a ignorar em todos os componentes") : T("Só estes níveis (nenhum marcado = todos)");
    form.elements.component.required = k === "manual";
    form.elements.rule.required = k === "manual";
    // Os níveis marcados nos cartões já vêm selecionados.
    levelBoxes.forEach((b) => { b.checked = k !== "manual" && k !== "finding" && state.sev.has(b.value); });
    // Ignorar todos os níveis em todos os componentes ignoraria tudo: a opção não aparece nesse modo.
    // "Todos os níveis" aparece também em "Ignorar estes níveis": só os achados de agora são ignorados.
    document.getElementById("level-all-wrap")?.toggleAttribute("hidden", false);
    syncLevelAll();
    const fileOpt = form.querySelector('input[value="file"]');
    if (fileOpt) fileOpt.parentElement.hidden = !(k === "finding" && mode.el.dataset.file);
    const subject = {
      finding: () => `${mode.el.dataset.title} — ${mode.el.dataset.component} · ${mode.el.dataset.rule}`,
      levels: () => T("Os achados atuais destes níveis, em todos os componentes. Achados novos continuam aparecendo."),
      manual: () => T("Use * como curinga (ex.: semgrep.* ou */vendor/*)."),
      skip: () => T("Componente {nome}.", { nome: mode.name }),
      findings: () => T("Componente {nome}: os achados atuais nos níveis marcados abaixo. Achados novos continuam aparecendo e o componente continua sendo analisado.", { nome: mode.name }),
      selected: () => T("{n} achado(s) selecionado(s) de {nome}. Achados iguais continuam escondidos; achados novos continuam aparecendo.", { n: mode.chosen.length, nome: mode.name }),
    };
    document.getElementById("ignore-subject").textContent = subject[k]();
    dialog.showModal();
    (k === "manual" ? form.elements.component : form.elements.reason).focus();
  }

  function entryFromForm() {
    const reason = form.elements.reason.value.trim();
    let severities = levelBoxes.filter((b) => b.checked).map((b) => b.value);
    if (severities.length === levelBoxes.length) severities = []; // todos = sem restrição de nível
    switch (mode.kind) {
      case "manual":
        return { component: form.elements.component.value.trim(), rule: form.elements.rule.value.trim(),
                 path: form.elements.path.value.trim() || null, reason, severities };
      // Níveis: só os achados de agora; achados novos (diferentes dos ignorados) continuam aparecendo.
      case "levels":
        return { component: "*", rule: "*", reason, severities, achados_atuais: true };
      case "skip":
        return { component: mode.name, rule: "*", reason, nao_analisar: true };
      // Achados do componente: só os de agora, nos níveis marcados (nenhum = todos).
      case "findings":
        return { component: mode.name, rule: "*", reason, severities, achados_atuais: true };
      case "selected":
        return { component: mode.name, rule: "*", reason, achados: mode.chosen };
      default: {
        const d = mode.el.dataset;
        const scope = form.elements.scope.value;
        const entry = { component: d.component, rule: d.rule, reason, title: d.title };
        if (scope === "finding") entry.fingerprint = d.fingerprint;
        if (scope === "file") entry.path = d.file;
        if (scope === "all") entry.component = "*";
        return entry;
      }
    }
  }

  form?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const entry = entryFromForm();
    if (mode.kind === "levels") {
      // Todos marcados viram "sem restrição" (lista vazia); nenhum marcado é erro.
      const ticked = levelBoxes.filter((b) => b.checked).map((b) => b.value);
      if (!ticked.length) {
        errorEl.textContent = T("Marque pelo menos um nível.");
        errorEl.hidden = false;
        return;
      }
      if (!window.confirm(T("Ignorar os achados atuais de nível {niveis} em todos os componentes? Achados novos continuam aparecendo.",
        { niveis: labelsOf(ticked) }))) return;
    }
    const submit = document.getElementById("ignore-submit");
    submit.disabled = true;
    try {
      const resp = await post("api/ignored", entry);
      if (resp.status === 201) { window.location.reload(); return; }
      const data = await resp.json().catch(() => ({}));
      errorEl.textContent = data.error || T("Não foi possível incluir (HTTP {status}).", { status: resp.status });
      errorEl.hidden = false;
    } catch (e) {
      errorEl.textContent = T("Não foi possível incluir.");
      errorEl.hidden = false;
    } finally {
      submit.disabled = false;
    }
  });
  document.getElementById("ignore-cancel")?.addEventListener("click", () => dialog.close());
  document.getElementById("ignore-add")?.addEventListener("click", () => openDialog({ kind: "manual" }));
  document.getElementById("ignore-levels")?.addEventListener("click", () => openDialog({ kind: "levels" }));
  document.querySelectorAll("[data-ignore]").forEach((b) =>
    b.addEventListener("click", () => openDialog({ kind: "finding", el: b.closest(".finding") })));
  // Seleção de achados na tela do componente: caixa por achado, "Selecionar todos" (os visíveis)
  // e "Ignorar selecionados".
  const selectAll = document.getElementById("findings-select-all");
  const ignoreSelected = document.getElementById("findings-ignore-selected");
  const findingBoxes = () => Array.from(document.querySelectorAll(".finding-select"))
    .filter((b) => b.closest(".finding").dataset.component === state.component);
  const visibleFinding = (b) => !b.closest(".finding").hidden;
  function syncFindingSelection() {
    const chosen = findingBoxes().filter((b) => b.checked);
    if (ignoreSelected) {
      ignoreSelected.hidden = chosen.length === 0;
      ignoreSelected.textContent = T("Ignorar selecionados ({n})…", { n: chosen.length });
    }
    const shown = findingBoxes().filter(visibleFinding);
    if (selectAll) {
      const n = shown.filter((b) => b.checked).length;
      selectAll.checked = shown.length > 0 && n === shown.length;
      selectAll.indeterminate = n > 0 && n < shown.length;
      document.getElementById("findings-select-all-wrap").hidden = shown.length === 0;
    }
  }
  selectAll?.addEventListener("change", () => {
    findingBoxes().filter(visibleFinding).forEach((b) => { b.checked = selectAll.checked; });
    syncFindingSelection();
  });
  document.getElementById("findings")?.addEventListener("change", (ev) => {
    if (ev.target.classList.contains("finding-select")) syncFindingSelection();
  });
  afterApply = syncFindingSelection;
  syncFindingSelection();
  ignoreSelected?.addEventListener("click", () => {
    const chosen = findingBoxes().filter((b) => b.checked).map((b) => b.value);
    if (chosen.length && state.component) openDialog({ kind: "selected", name: state.component, chosen });
  });

  // Tela de achados de um componente: botão único que ignora os achados atuais dele por nível.
  document.getElementById("ignore-view-levels")?.addEventListener("click", () => {
    if (state.component) openDialog({ kind: "findings", name: state.component });
  });
  document.querySelectorAll("[data-ignore-findings]").forEach((b) =>
    b.addEventListener("click", () => openDialog({ kind: "findings", name: b.dataset.ignoreFindings })));
  // "Ignorar…" do componente: ele deixa de ser analisado (fica na lista de ignorados).
  document.querySelectorAll("[data-ignore-component]").forEach((b) =>
    b.addEventListener("click", () => openDialog({ kind: "skip", name: b.dataset.ignoreComponent })));
  // "Excluir…": tira o componente da tabela até ele ser reinstalado ou atualizado.
  document.querySelectorAll("[data-exclude-component]").forEach((b) =>
    b.addEventListener("click", async () => {
      const nome = b.dataset.excludeComponent;
      if (!window.confirm(T("Excluir {nome} da tabela? Ele deixa de ser analisado e só volta se for reinstalado ou atualizado. Os arquivos não são apagados.", { nome }))) return;
      b.disabled = true;
      try {
        const resp = await post("api/componentes/excluidos", { tipo: b.dataset.excludeType, nome });
        if (resp.status === 201) { window.location.reload(); return; }
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.error || "HTTP " + resp.status);
      } catch (e) {
        b.disabled = false;
        window.alert(T("Não foi possível excluir: {erro}", { erro: e.message }));
      }
    }));
  document.querySelectorAll("[data-restore-component]").forEach((b) =>
    b.addEventListener("click", async () => {
      b.disabled = true;
      try {
        const url = "api/componentes/excluidos/" + encodeURIComponent(b.dataset.restoreType) + "/" +
          encodeURIComponent(b.dataset.restoreComponent);
        const resp = await post(url, undefined, "DELETE");
        if (resp.status === 204 || resp.status === 404) {
          window.alert(T("Restaurado: o componente volta à tabela na próxima varredura."));
          window.location.reload();
          return;
        }
        throw new Error("HTTP " + resp.status);
      } catch (e) {
        b.disabled = false;
        window.alert(T("Não foi possível restaurar."));
      }
    }));
  document.querySelectorAll("[data-unignore]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!window.confirm(T("Remover da lista de ignorados? Os achados voltam a contar nos totais."))) return;
      b.disabled = true;
      try {
        const resp = await post("api/ignored/" + encodeURIComponent(b.dataset.unignore), undefined, "DELETE");
        if (resp.status === 204 || resp.status === 404) { window.location.reload(); return; }
        throw new Error("HTTP " + resp.status);
      } catch (e) {
        b.disabled = false;
        window.alert(T("Não foi possível remover da lista."));
      }
    }));
  // Edição do motivo na tabela de ignorados (só itens incluídos pela interface).
  document.querySelectorAll("[data-edit-reason]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const row = btn.closest("tr");
      const cell = row.querySelector(".reason-cell");
      if (cell.querySelector("input")) return; // já em edição
      const original = cell.dataset.reason || "";
      const view = cell.querySelector(".reason-text");
      view.hidden = true;
      const box = document.createElement("div");
      box.className = "reason-edit";
      const input = document.createElement("input");
      input.type = "text";
      input.maxLength = 500;
      input.value = original;
      input.setAttribute("aria-label", T("Motivo"));
      const save = document.createElement("button");
      save.type = "button";
      save.className = "btn btn-primary btn-sm";
      save.textContent = T("Salvar");
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.className = "btn btn-ghost btn-sm";
      cancel.textContent = T("Cancelar");
      const err = document.createElement("p");
      err.className = "error small";
      err.hidden = true;
      box.append(input, save, cancel, err);
      cell.append(box);
      btn.disabled = true;
      input.focus();
      input.select();

      const close = () => { box.remove(); view.hidden = false; btn.disabled = false; };
      async function submit() {
        save.disabled = true;
        try {
          const resp = await post((btn.dataset.editUrl || "api/ignored/") + encodeURIComponent(btn.dataset.editReason),
                                  { reason: input.value }, "PATCH");
          if (resp.ok) { window.location.reload(); return; }
          const data = await resp.json().catch(() => ({}));
          err.textContent = data.error || T("Não foi possível salvar (HTTP {status}).", { status: resp.status });
          err.hidden = false;
        } catch (e) {
          err.textContent = T("Não foi possível salvar.");
          err.hidden = false;
        } finally {
          save.disabled = false;
        }
      }
      save.addEventListener("click", submit);
      cancel.addEventListener("click", close);
      input.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") { ev.preventDefault(); submit(); }
        if (ev.key === "Escape") { ev.preventDefault(); close(); }
      });
    }));

  // Teste de conexão com os servidores DNS (o resultado da inicialização já vem na página).
  const dnsBtn = document.getElementById("dns-check");
  dnsBtn?.addEventListener("click", async () => {
    dnsBtn.disabled = true;
    dnsBtn.textContent = T("Testando…");
    try {
      await post("api/dns/check");
    } catch (e) { /* o resultado (ou a falha) aparece ao recarregar */ }
    window.location.reload();
  });
  // Se o teste da inicialização ainda estiver rodando, atualiza quando terminar.
  if (dnsBtn && dnsBtn.disabled) {
    const waitDns = async () => {
      try {
        const data = await (await fetch("api/status", { cache: "no-store" })).json();
        if (data.dns && !data.dns.testando) { window.location.reload(); return; }
      } catch (e) { /* tenta de novo */ }
      setTimeout(waitDns, 2000);
    };
    setTimeout(waitDns, 2000);
  }

  // --- Domínios ignorados (aba DNS) ----------------------------------------------------
  const dnsDialog = document.getElementById("dns-ignore-dialog");
  const dnsForm = document.getElementById("dns-ignore-form");
  const dnsError = document.getElementById("dns-ignore-error");
  let dnsMany = null; // "Ignorar todos": lista de domínios da tabela
  function openDnsIgnore(domain, many, selected) {
    dnsForm.reset();
    dnsError.hidden = true;
    dnsMany = many || null;
    dnsForm.elements.domain.value = domain || "";
    dnsForm.elements.domain.required = !dnsMany;
    document.getElementById("dns-ignore-one").hidden = !!dnsMany;
    document.getElementById("dns-ignore-hint").hidden = !!dnsMany;
    const manyEl = document.getElementById("dns-ignore-many");
    manyEl.hidden = !dnsMany;
    document.getElementById("dns-ignore-many-warn").hidden = !dnsMany;
    const lista = dnsMany ? dnsMany.slice(0, 8).join(", ") + (dnsMany.length > 8 ? ", …" : "") : "";
    if (dnsMany) manyEl.textContent = selected
      ? T("Os {n} domínios selecionados: {lista}", { n: dnsMany.length, lista })
      : T("Todos os {n} domínios da tabela que ainda não estão ignorados: {lista}", { n: dnsMany.length, lista });
    document.getElementById("dns-ignore-title").textContent = dnsMany
      ? (selected ? T("Ignorar domínios selecionados") : T("Ignorar todos os domínios")) : T("Ignorar domínio");
    dnsDialog.showModal();
    (domain || dnsMany ? dnsForm.elements.reason : dnsForm.elements.domain).focus();
  }
  // Sem domínio para ignorar (todos já ignorados), o botão some.
  const syncDnsBulk = (showingIgnored) => {
    document.querySelectorAll(".dns-ignore-all").forEach((b) => {
      b.hidden = showingIgnored || !b.closest(".dns-domains").querySelector("[data-dns-ignore]");
    });
    // Com "Mostrar domínios ignorados", os botões em massa da tabela principal somem.
    document.querySelectorAll(".dns-ai-all").forEach((b) => { b.hidden = showingIgnored; });
    document.querySelectorAll(".dns-ignore-selected").forEach((b) => {
      b.hidden = showingIgnored || !b.closest(".dns-domains").querySelector(".dns-select:checked");
    });
  };
  syncDnsBulk(false);
  document.querySelectorAll(".dns-ignore-all").forEach((b) =>
    b.addEventListener("click", () => {
      const list = Array.from(b.closest(".dns-domains").querySelectorAll("[data-dns-ignore]"))
        .map((x) => x.dataset.dnsIgnore);
      if (list.length) openDnsIgnore("", list);
    }));
  // Seleção de domínios: caixa por linha, "selecionar todos" (só linhas visíveis) e "Ignorar selecionados".
  document.querySelectorAll(".dns-domains").forEach((table) => {
    const button = table.querySelector(".dns-ignore-selected");
    const all = table.querySelector(".dns-select-all");
    const boxes = () => Array.from(table.querySelectorAll(".dns-select"));
    const visible = (b) => !b.closest("tr").hidden && !b.closest("tr").classList.contains("search-hidden");
    const sync = () => {
      const chosen = boxes().filter((b) => b.checked);
      if (button) {
        button.hidden = chosen.length === 0 || !!document.getElementById("dns-show-ignored")?.checked;
        button.textContent = T("Ignorar selecionados ({n})…", { n: chosen.length });
      }
      const shown = boxes().filter(visible);
      if (all) {
        const n = shown.filter((b) => b.checked).length;
        all.checked = shown.length > 0 && n === shown.length;
        all.indeterminate = n > 0 && n < shown.length;
      }
    };
    all?.addEventListener("change", () => {
      boxes().filter(visible).forEach((b) => { b.checked = all.checked; });
      sync();
    });
    table.addEventListener("change", (ev) => { if (ev.target.classList.contains("dns-select")) sync(); });
    // A busca muda o que é "visível": atualiza o estado da caixa do cabeçalho.
    table.querySelectorAll("[data-table-search]").forEach((i) => i.addEventListener("input", sync));
    button?.addEventListener("click", () => {
      const chosen = boxes().filter((b) => b.checked).map((b) => b.value);
      if (chosen.length) openDnsIgnore("", chosen, true);
    });
    sync();
  });
  document.querySelectorAll(".dns-ignore-add").forEach((b) => b.addEventListener("click", () => openDnsIgnore("")));
  document.querySelectorAll("[data-dns-ignore]").forEach((b) =>
    b.addEventListener("click", () => openDnsIgnore(b.dataset.dnsIgnore)));
  document.getElementById("dns-ignore-cancel")?.addEventListener("click", () => dnsDialog.close());
  dnsForm?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const submit = document.getElementById("dns-ignore-submit");
    submit.disabled = true;
    try {
      const motivo = dnsForm.elements.reason.value;
      const resp = await post("api/dns/ignorados", dnsMany ? { dominios: dnsMany, motivo }
                                                           : { dominio: dnsForm.elements.domain.value, motivo });
      if (resp.status === 201) { window.location.reload(); return; }
      const data = await resp.json().catch(() => ({}));
      dnsError.textContent = data.error || T("Não foi possível incluir (HTTP {status}).", { status: resp.status });
      dnsError.hidden = false;
    } catch (e) {
      dnsError.textContent = T("Não foi possível incluir.");
      dnsError.hidden = false;
    } finally {
      submit.disabled = false;
    }
  });
  document.querySelectorAll("[data-dns-unignore]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!window.confirm(T("Remover da lista de domínios ignorados? Ele volta aos achados na próxima varredura."))) return;
      b.disabled = true;
      try {
        const resp = await post("api/dns/ignorados/" + encodeURIComponent(b.dataset.dnsUnignore), undefined, "DELETE");
        if (resp.status === 204 || resp.status === 404) { window.location.reload(); return; }
        throw new Error("HTTP " + resp.status);
      } catch (e) {
        b.disabled = false;
        window.alert(T("Não foi possível remover da lista."));
      }
    }));
  // "Mostrar domínios ignorados": troca a tabela de domínios consultados pela lista de ignorados.
  // A escolha fica guardada na aba do navegador (sobrevive ao recarregar depois de editar/remover).
  const showIgnored = document.getElementById("dns-show-ignored");
  function syncDnsView() {
    const on = showIgnored.checked;
    document.querySelectorAll(".dns-main-table").forEach((t) => { t.hidden = on; });
    syncDnsBulk(on);
    document.getElementById("dns-ignored").hidden = !on;
    try { sessionStorage.setItem("dnsIgnorados", on ? "1" : "0"); } catch (e) { /* sem armazenamento */ }
  }
  if (showIgnored) {
    try { showIgnored.checked = sessionStorage.getItem("dnsIgnorados") === "1"; } catch (e) { /* padrão */ }
    showIgnored.addEventListener("change", syncDnsView);
    syncDnsView();
  }

  // --- Perguntar à IA sobre um domínio (opção ia_provedor) ----------------------------
  const aiDialog = document.getElementById("dns-ai-dialog");
  const AI_VERDICTS = { malicioso: "Malicioso", suspeito: "Suspeito",
                        provavelmente_seguro: "Provavelmente seguro", desconhecido: "Desconhecido" };
  const AI_BADGE = { malicioso: "sev-critical", suspeito: "sev-medium" };
  let aiDomain = null;
  let aiChanged = false;
  async function askAi(domain, again) {
    aiDomain = domain;
    const status = document.getElementById("dns-ai-status");
    const result = document.getElementById("dns-ai-result");
    const error = document.getElementById("dns-ai-error");
    const againBtn = document.getElementById("dns-ai-again");
    document.getElementById("dns-ai-domain").textContent = domain;
    error.hidden = true;
    result.hidden = true;
    status.textContent = T("Consultando o {provedor}…", { provedor: aiDialog.dataset.provider });
    status.hidden = false;
    againBtn.disabled = true;
    if (!aiDialog.open) aiDialog.showModal();
    try {
      const resp = await post("api/dns/ia", { dominio: domain, refazer: !!again });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(data.error || T("Não foi possível consultar a IA (HTTP {status}).", { status: resp.status }));
      const badge = document.getElementById("dns-ai-verdict");
      badge.className = "badge " + (AI_BADGE[data.veredito] || "badge-muted");
      badge.textContent = T(AI_VERDICTS[data.veredito] || data.veredito);
      document.getElementById("dns-ai-explanation").textContent = data.explicacao;
      // Dados públicos que foram junto com o host (DNS e RDAP), para a pessoa conferir também.
      const factsBox = document.getElementById("dns-ai-facts-box");
      const factsList = document.getElementById("dns-ai-facts");
      if (factsBox && factsList) {
        factsList.replaceChildren(...(data.fatos || []).map((line) => {
          const li = document.createElement("li");
          li.textContent = line;
          return li;
        }));
        factsBox.hidden = !(data.fatos || []).length;
      }
      let when = data.data || "";
      try { when = new Date(data.data).toLocaleString(); } catch (e) { /* data como veio */ }
      document.getElementById("dns-ai-meta").textContent =
        T(data.guardada ? "Resposta guardada de {data} · {modelo}" : "Consultado agora · {modelo}",
          { data: when, modelo: data.modelo });
      result.hidden = false;
      if (!data.guardada) aiChanged = true;
    } catch (e) {
      error.textContent = e.message || T("Não foi possível consultar a IA.");
      error.hidden = false;
    } finally {
      status.hidden = true;
      againBtn.disabled = false;
    }
  }
  // "Perguntar à IA sobre todos": uma pergunta por vez, só domínios visíveis e ainda sem resposta.
  // Clicar de novo durante as perguntas para depois da atual.
  document.querySelectorAll(".dns-ai-all").forEach((all) => {
    const label = all.textContent;
    let running = false;
    let stop = false;
    all.addEventListener("click", async () => {
      if (running) { stop = true; all.textContent = T("Parando…"); return; }
      const table = all.closest(".dns-domains");
      const pending = Array.from(table.querySelectorAll("[data-dns-ai]"))
        .filter((b) => !b.dataset.aiSaved && !b.closest("tr").hidden && !b.closest("tr").classList.contains("search-hidden"))
        .map((b) => b.dataset.dnsAi);
      if (!pending.length) {
        window.alert(T("Todos os domínios visíveis já têm resposta da IA."));
        return;
      }
      if (!window.confirm(T("Perguntar ao {provedor} sobre {n} domínio(s)? Só o nome de cada domínio é enviado, uma pergunta por vez. O uso é cobrado pelo provedor, na sua conta.",
        { provedor: all.dataset.provider, n: pending.length }))) return;
      running = true;
      stop = false;
      let done = 0;
      let error = null;
      for (const dominio of pending) {
        if (stop) break;
        all.textContent = T("Perguntando {i} de {n}… (clique para parar)", { i: done + 1, n: pending.length });
        try {
          const resp = await post("api/dns/ia", { dominio });
          const data = await resp.json().catch(() => ({}));
          if (!resp.ok) { error = data.error || "HTTP " + resp.status; break; }
          done++;
        } catch (e) {
          error = e.message;
          break;
        }
      }
      running = false;
      all.textContent = label;
      if (error) window.alert(T("Parou depois de {n} resposta(s): {erro}", { n: done, erro: error }));
      if (done) window.location.reload();
    });
  });
  document.querySelectorAll("[data-dns-ai]").forEach((b) =>
    b.addEventListener("click", () => askAi(b.dataset.dnsAi, false)));
  document.getElementById("dns-ai-again")?.addEventListener("click", () => { if (aiDomain) askAi(aiDomain, true); });
  document.getElementById("dns-ai-close")?.addEventListener("click", () => aiDialog.close());
  // Resposta nova: recarrega para o selo "IA: …" aparecer na linha do domínio.
  aiDialog?.addEventListener("close", () => { if (aiChanged) window.location.reload(); });

  // --- Lista negra pessoal (aba "Lista negra") --------------------------------------
  const blDialog = document.getElementById("blocklist-dialog");
  const blForm = document.getElementById("bl-form");
  const blError = document.getElementById("bl-error");
  let blEditing = null; // id em edição; null = novo item

  function openBlocklist(values, editingId) {
    blEditing = editingId || null;
    blForm.reset();
    blError.hidden = true;
    document.getElementById("bl-title").textContent =
      editingId ? T("Editar item {id}", { id: editingId }) : T("Adicionar à lista negra pessoal");
    for (const [key, value] of Object.entries(values || {})) {
      const field = blForm.elements[key];
      if (!field) continue;
      field.value = Array.isArray(value) ? value.join("\n") : value;
    }
    blDialog.showModal();
    blForm.elements.motivo.focus();
  }

  document.getElementById("bl-add")?.addEventListener("click", () => openBlocklist({}, null));
  document.getElementById("bl-cancel")?.addEventListener("click", () => blDialog.close());
  document.getElementById("bl-from-component")?.addEventListener("click", () => {
    const row = compRowOf(state.component);
    if (!row) return;
    const github = row.dataset.github || "";
    const values = { tipo: row.dataset.type, nome: state.component };
    if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(github)) values.github = github; // add-ons trazem URL da loja
    if (row.dataset.type === "addon" && row.dataset.image) values.imagem = row.dataset.image;
    openBlocklist(values, null);
  });
  document.querySelectorAll("[data-bl-edit]").forEach((b) => b.addEventListener("click", () => {
    const item = JSON.parse(b.closest("tr").dataset.blItem || "{}");
    openBlocklist(item, b.dataset.blEdit);
  }));
  document.querySelectorAll("[data-bl-remove]").forEach((b) => b.addEventListener("click", async () => {
    if (!window.confirm(T("Remover o item {id} da lista negra pessoal?", { id: b.dataset.blRemove }))) return;
    b.disabled = true;
    try {
      const resp = await post("api/lista-negra/" + encodeURIComponent(b.dataset.blRemove), undefined, "DELETE");
      if (resp.status === 204 || resp.status === 404) { window.location.reload(); return; }
      throw new Error("HTTP " + resp.status);
    } catch (e) {
      b.disabled = false;
      window.alert(T("Não foi possível remover o item."));
    }
  }));
  blForm?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = blForm.elements;
    const body = {
      tipo: f.tipo.value, github: f.github.value, nome: f.nome.value, imagem: f.imagem.value,
      versoes: f.versoes.value, nivel: f.nivel.value, categoria: f.categoria.value, motivo: f.motivo.value,
      evidencias: f.evidencias.value.split("\n"),
    };
    const submit = document.getElementById("bl-submit");
    submit.disabled = true;
    try {
      const url = blEditing ? "api/lista-negra/" + encodeURIComponent(blEditing) : "api/lista-negra";
      const resp = await post(url, body, blEditing ? "PUT" : "POST");
      if (resp.ok) {
        // Depois de salvar, mostra a aba da lista (mesmo se veio da tela de um componente).
        try { history.replaceState({}, "", urlFor(null, "listanegra")); } catch (e) { /* sem histórico */ }
        window.location.reload();
        return;
      }
      const data = await resp.json().catch(() => ({}));
      blError.textContent = data.error || T("Não foi possível salvar (HTTP {status}).", { status: resp.status });
      blError.hidden = false;
    } catch (e) {
      blError.textContent = T("Não foi possível salvar.");
      blError.hidden = false;
    } finally {
      submit.disabled = false;
    }
  });

  readUrl();
  apply();
})();
