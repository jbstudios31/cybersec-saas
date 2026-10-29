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
