// Sin handlers inline: compatible con CSP script-src 'self'.

// 1) Mostrar/ocultar contraseña
document.addEventListener("click", function (event) {
  var toggle = event.target.closest("[data-toggle-password]");
  if (!toggle) return;
  var input = document.getElementById(toggle.getAttribute("data-toggle-password"));
  if (!input) return;
  var show = input.type === "password";
  input.type = show ? "text" : "password";
  toggle.textContent = show ? "Ocultar" : "Mostrar";
  toggle.setAttribute("aria-pressed", show ? "true" : "false");
});

// 2) Diálogos: <button commandfor="id" command="show-modal|close"> es nativo en navegadores
//    modernos; este respaldo cubre los que aún no lo soportan.
if (!("commandForElement" in HTMLButtonElement.prototype)) {
  document.addEventListener("click", function (event) {
    var button = event.target.closest("button[commandfor]");
    if (!button) return;
    var dialog = document.getElementById(button.getAttribute("commandfor"));
    if (!dialog || typeof dialog.showModal !== "function") return;
    var command = button.getAttribute("command");
    if (command === "show-modal") dialog.showModal();
    else if (command === "close") dialog.close();
  });
}

// 3) Cerrar un diálogo al hacer clic fuera de su contenido
document.addEventListener("click", function (event) {
  var dialog = event.target;
  if (dialog instanceof HTMLDialogElement && dialog.open) dialog.close();
});
// Menú hamburguesa (tres líneas) para la navegación principal.
(function () {
  "use strict";

  function setupToggle(buttonId, containerId, isGuest) {
    var button = document.getElementById(buttonId);
    var container = document.getElementById(containerId);
    if (!button || !container) return;

    function close() {
      container.classList.remove("open");
      if (isGuest) container.setAttribute("hidden", "");
      button.setAttribute("aria-expanded", "false");
    }

    function toggle() {
      var open = button.getAttribute("aria-expanded") === "true";
      if (open) {
        close();
      } else {
        container.classList.add("open");
        if (isGuest) container.removeAttribute("hidden");
        button.setAttribute("aria-expanded", "true");
      }
    }

    button.addEventListener("click", function (event) {
      event.stopPropagation();
      toggle();
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") close();
    });

    document.addEventListener("click", function (event) {
      if (button.getAttribute("aria-expanded") !== "true") return;
      if (container.contains(event.target) || button.contains(event.target)) return;
      close();
    });

    container.addEventListener("click", function (event) {
      var target = event.target;
      if (target && target.closest && target.closest("a, button")) {
        // cerrar tras navegar en móvil
        if (window.matchMedia("(max-width: 55.999rem)").matches) close();
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    setupToggle("menu-toggle", "app-rail", false);
    setupToggle("guest-menu-toggle", "guest-nav", true);
  });
})();
