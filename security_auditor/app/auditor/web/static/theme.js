// Aplica o tema salvo antes da primeira pintura (carregado sem "defer").
// "system" (padrão) remove o atributo e deixa o prefers-color-scheme decidir.
(function () {
  "use strict";
  var KEY = "auditor-theme";
  var root = document.documentElement;

  function read() {
    try {
      var v = window.localStorage.getItem(KEY);
      return v === "light" || v === "dark" ? v : "system";
    } catch (e) {
      return "system";
    }
  }

  function apply(choice) {
    if (choice === "light" || choice === "dark") root.setAttribute("data-theme", choice);
    else root.removeAttribute("data-theme");
  }

  window.auditorTheme = {
    get: read,
    set: function (choice) {
      try {
        if (choice === "system") window.localStorage.removeItem(KEY);
        else window.localStorage.setItem(KEY, choice);
      } catch (e) {
        /* sem armazenamento: vale só nesta visita */
      }
      apply(choice);
    },
  };

  apply(read());
})();
