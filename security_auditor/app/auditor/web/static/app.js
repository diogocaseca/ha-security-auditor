// Interface do relatório: filtros no cliente, varredura/cancelamento e lista de ignorados.
(function () {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const findings = Array.from(document.querySelectorAll(".finding"));
  const compRows = Array.from(document.querySelectorAll(".comp-row"));
  const sevLabels = {};
  document.querySelectorAll("[data-filter-sev]").forEach((b) => {
    sevLabels[b.dataset.filterSev] = b.querySelector(".card-label")?.textContent.trim() || b.dataset.filterSev;
  });
  const state = { sev: new Set(), component: null, text: "", onlyNew: false, suppressed: false };

  function apply() {
    let visible = 0;
    for (const el of findings) {
      const show =
        (state.sev.size === 0 || state.sev.has(el.dataset.sev)) &&
        (!state.component || el.dataset.component === state.component) &&
        (!state.onlyNew || el.dataset.new === "true") &&
        (state.suppressed || el.dataset.suppressed !== "true") &&
        (!state.text || el.textContent.toLowerCase().includes(state.text));
      el.hidden = !show;
      if (show) visible++;
    }
    const counter = document.getElementById("visible-count");
    if (counter) counter.textContent = findings.length ? `(${visible} de ${findings.length})` : "";
    const noMatch = document.getElementById("no-match");
    if (noMatch) noMatch.hidden = visible > 0 || findings.length === 0;
    // Tabela de componentes: com níveis selecionados, só os que têm achados em algum deles.
    let compVisible = 0;
    for (const row of compRows) {
      const sevs = row.dataset.sevs.split(" ").filter(Boolean);
      const show = state.sev.size === 0 || sevs.some((s) => state.sev.has(s));
      row.hidden = !show;
      if (show) compVisible++;
    }
    const compCount = document.getElementById("comp-count");
    if (compCount) compCount.textContent = state.sev.size && compRows.length ? `(${compVisible} de ${compRows.length})` : "";
    const compNote = document.getElementById("comp-filter-note");
    if (compNote) {
      compNote.hidden = state.sev.size === 0;
      compNote.textContent = "Com achados de nível: " + Array.from(state.sev).map((k) => sevLabels[k] || k).join(", ");
    }
    const compNone = document.getElementById("comp-no-match");
    if (compNone) compNone.hidden = compVisible > 0 || compRows.length === 0;
    document.querySelectorAll("[data-filter-sev]").forEach((b) =>
      b.setAttribute("aria-pressed", state.sev.has(b.dataset.filterSev) ? "true" : "false"));
    document.querySelectorAll("[data-filter-component]").forEach((b) =>
      b.classList.toggle("active", b.dataset.filterComponent === state.component));
  }

  document.querySelectorAll("[data-filter-sev]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const key = btn.dataset.filterSev;
      state.sev.has(key) ? state.sev.delete(key) : state.sev.add(key);
      apply();
    }));

  document.querySelectorAll("[data-filter-component]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const name = btn.dataset.filterComponent;
      state.component = state.component === name ? null : name;
      apply();
      document.getElementById("findings")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }));

  const text = document.getElementById("filter-text");
  text?.addEventListener("input", () => { state.text = text.value.trim().toLowerCase(); apply(); });
  const onlyNew = document.getElementById("filter-new");
  onlyNew?.addEventListener("change", () => { state.onlyNew = onlyNew.checked; apply(); });
  const supp = document.getElementById("filter-suppressed");
  supp?.addEventListener("change", () => { state.suppressed = supp.checked; apply(); });
  document.getElementById("filter-clear")?.addEventListener("click", () => {
    state.sev.clear(); state.component = null; state.text = ""; state.onlyNew = false; state.suppressed = false;
    if (text) text.value = ""; if (onlyNew) onlyNew.checked = false; if (supp) supp.checked = false;
    apply();
  });

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
        statusEl.textContent = data.cancelling ? "Cancelando…" :
          "Varrendo" + (data.progress && data.progress.step ? ": " + data.progress.step : "") + "…";
        if (cancelBtn) {
          cancelBtn.hidden = false;
          if (data.cancelling) { cancelBtn.disabled = true; cancelBtn.textContent = "Cancelando…"; }
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
    button.textContent = "Varrendo…";
    try {
      const resp = await post("api/scan");
      if (resp.status !== 202 && resp.status !== 409) throw new Error("HTTP " + resp.status);
      if (cancelBtn) { cancelBtn.hidden = false; cancelBtn.disabled = false; }
      setTimeout(poll, 1000);
    } catch (e) {
      button.disabled = false;
      button.textContent = "Varrer agora";
      statusEl.textContent = "Não foi possível iniciar a varredura.";
    }
  });

  cancelBtn?.addEventListener("click", async () => {
    if (!window.confirm("Cancelar a varredura em andamento? O que já foi analisado fica salvo como relatório cancelado.")) return;
    cancelBtn.disabled = true;
    cancelBtn.textContent = "Cancelando…";
    try {
      const resp = await post("api/scan/cancel");
      if (resp.status !== 202 && resp.status !== 409) throw new Error("HTTP " + resp.status);
      setTimeout(poll, 500);
    } catch (e) {
      cancelBtn.disabled = false;
      cancelBtn.textContent = "Cancelar varredura";
      statusEl.textContent = "Não foi possível cancelar a varredura.";
    }
  });

  if (document.body.dataset.running === "true") setTimeout(poll, 2000);

  // --- Lista de ignorados -----------------------------------------------------
  const dialog = document.getElementById("ignore-dialog");
  const form = document.getElementById("ignore-form");
  const errorEl = document.getElementById("ignore-error");
  let target = null; // achado escolhido; null = inclusão manual

  function openDialog(finding) {
    target = finding;
    form.reset();
    errorEl.hidden = true;
    document.getElementById("ignore-title").textContent = finding ? "Ignorar achado" : "Incluir na lista de ignorados";
    document.getElementById("ignore-scope").hidden = !finding;
    document.getElementById("ignore-manual").hidden = !!finding;
    form.elements.component.required = !finding;
    form.elements.rule.required = !finding;
    const fileOpt = form.querySelector('input[value="file"]');
    if (fileOpt) fileOpt.parentElement.hidden = !(finding && finding.dataset.file);
    document.getElementById("ignore-subject").textContent = finding
      ? `${finding.dataset.title} — ${finding.dataset.component} · ${finding.dataset.rule}`
      : "Use * como curinga (ex.: semgrep.* ou */vendor/*).";
    dialog.showModal();
    (finding ? form.elements.reason : form.elements.component).focus();
  }

  function entryFromForm() {
    const reason = form.elements.reason.value.trim();
    if (!target) {
      return { component: form.elements.component.value.trim(), rule: form.elements.rule.value.trim(),
               path: form.elements.path.value.trim() || null, reason };
    }
    const d = target.dataset;
    const scope = form.elements.scope.value;
    const entry = { component: d.component, rule: d.rule, reason, title: d.title };
    if (scope === "finding") entry.fingerprint = d.fingerprint;
    if (scope === "file") entry.path = d.file;
    if (scope === "all") entry.component = "*";
    return entry;
  }

  form?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const submit = document.getElementById("ignore-submit");
    submit.disabled = true;
    try {
      const resp = await post("api/ignored", entryFromForm());
      if (resp.status === 201) { window.location.reload(); return; }
      const data = await resp.json().catch(() => ({}));
      errorEl.textContent = data.error || "Não foi possível incluir (HTTP " + resp.status + ").";
      errorEl.hidden = false;
    } catch (e) {
      errorEl.textContent = "Não foi possível incluir.";
      errorEl.hidden = false;
    } finally {
      submit.disabled = false;
    }
  });
  document.getElementById("ignore-cancel")?.addEventListener("click", () => dialog.close());
  document.getElementById("ignore-add")?.addEventListener("click", () => openDialog(null));
  document.querySelectorAll("[data-ignore]").forEach((b) =>
    b.addEventListener("click", () => openDialog(b.closest(".finding"))));
  document.querySelectorAll("[data-unignore]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!window.confirm("Remover da lista de ignorados? Os achados voltam a contar nos totais.")) return;
      b.disabled = true;
      try {
        const resp = await post("api/ignored/" + encodeURIComponent(b.dataset.unignore), undefined, "DELETE");
        if (resp.status === 204 || resp.status === 404) { window.location.reload(); return; }
        throw new Error("HTTP " + resp.status);
      } catch (e) {
        b.disabled = false;
        window.alert("Não foi possível remover da lista.");
      }
    }));
  apply();
})();
