// Interface do relatório: filtros no cliente e botão "Varrer agora".
(function () {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const findings = Array.from(document.querySelectorAll(".finding"));
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

  // --- Varredura ---------------------------------------------------------
  const button = document.getElementById("scan-now");
  const statusEl = document.getElementById("scan-status");

  async function poll() {
    try {
      const resp = await fetch("api/status", { cache: "no-store" });
      const data = await resp.json();
      if (data.running) {
        statusEl.textContent = "Varrendo" + (data.progress && data.progress.step ? ": " + data.progress.step : "") + "…";
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
      const resp = await fetch("api/scan", { method: "POST", headers: { "X-Auditor-CSRF": csrf } });
      if (resp.status !== 202 && resp.status !== 409) throw new Error("HTTP " + resp.status);
      setTimeout(poll, 1000);
    } catch (e) {
      button.disabled = false;
      button.textContent = "Varrer agora";
      statusEl.textContent = "Não foi possível iniciar a varredura.";
    }
  });

  if (document.body.dataset.running === "true") setTimeout(poll, 2000);
  apply();
})();
