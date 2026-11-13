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
                  hideEmpty: true, type: "", onlyBlocklist: false };
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
    document.getElementById("no-match")?.toggleAttribute("hidden", !inComponent || total === 0 || visible > 0);
    // Tabela de componentes: com níveis selecionados, só os que têm achados em algum deles;
    // com "Esconder componentes sem achados", some quem não tem nenhum achado (fora os ignorados).
    let compVisible = 0;
    for (const row of compRows) {
      const sevs = row.dataset.sevs.split(" ").filter(Boolean);
      const show = (state.sev.size === 0 || sevs.some((s) => state.sev.has(s))) &&
        (!state.hideEmpty || sevs.length > 0) && (!state.type || row.dataset.type === state.type) &&
        (!state.onlyBlocklist || row.dataset.blocklist !== "");
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
      state.sev.has(key) ? state.sev.delete(key) : state.sev.add(key);
      saveLevels();
      apply();
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
    // Componente inteiro em todos os níveis = deixa de ser verificado: avisa antes de confirmar.
    const note = document.getElementById("ignore-skip-note");
    if (note) note.hidden = !(mode.kind === "component" && (n === 0 || n === levelBoxes.length));
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
      component: T("Ignorar achados do componente"),
      levels: T("Ignorar níveis inteiros"),
      manual: T("Incluir na lista de ignorados"),
    };
    document.getElementById("ignore-title").textContent = titles[k];
    document.getElementById("ignore-scope").hidden = k !== "finding";
    document.getElementById("ignore-manual").hidden = k !== "manual";
    levelsField.hidden = k === "finding";
    document.getElementById("ignore-levels-legend").textContent =
      k === "levels" ? T("Níveis a ignorar em todos os componentes") : T("Só estes níveis (nenhum marcado = todos)");
    form.elements.component.required = k === "manual";
    form.elements.rule.required = k === "manual";
    // Os níveis marcados nos cartões já vêm selecionados.
    levelBoxes.forEach((b) => { b.checked = k !== "manual" && k !== "finding" && state.sev.has(b.value); });
    // Ignorar todos os níveis em todos os componentes ignoraria tudo: a opção não aparece nesse modo.
    document.getElementById("level-all-wrap")?.toggleAttribute("hidden", k === "levels");
    syncLevelAll();
    const fileOpt = form.querySelector('input[value="file"]');
    if (fileOpt) fileOpt.parentElement.hidden = !(k === "finding" && mode.el.dataset.file);
    const subject = {
      finding: () => `${mode.el.dataset.title} — ${mode.el.dataset.component} · ${mode.el.dataset.rule}`,
      component: () => T("Componente {nome}: todas as regras, nos níveis marcados abaixo.", { nome: mode.name }),
      levels: () => T("Todos os componentes e regras. Os achados continuam visíveis com \"Mostrar suprimidos\"."),
      manual: () => T("Use * como curinga (ex.: semgrep.* ou */vendor/*)."),
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
      case "component":
        return { component: mode.name, rule: "*", reason, severities };
      case "levels":
        return { component: "*", rule: "*", reason, severities };
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
      if (!entry.severities.length) {
        errorEl.textContent = T("Marque pelo menos um nível.");
        errorEl.hidden = false;
        return;
      }
      if (!window.confirm(T("Ignorar todos os achados de nível {niveis} em todos os componentes?",
        { niveis: labelsOf(entry.severities) }))) return;
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
  document.querySelectorAll("[data-ignore-component]").forEach((b) =>
    b.addEventListener("click", () => openDialog({ kind: "component", name: b.dataset.ignoreComponent })));
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
          const resp = await post("api/ignored/" + encodeURIComponent(btn.dataset.editReason),
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
