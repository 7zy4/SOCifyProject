"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const button = document.querySelector("[data-workspace-focus]");
  if (!button) return;
  const update = () => {
    const focused = document.body.classList.contains("window-focused");
    button.setAttribute("aria-pressed", String(focused));
    button.textContent = SOCifyLocale.text(focused ? "استعادة توزيع النوافذ" : "توسيع مساحة العمل");
  };
  button.addEventListener("click", () => {
    document.body.classList.toggle("window-focused");
    update();
  });
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && document.body.classList.contains("window-focused") && !document.querySelector("dialog[open]")) {
      document.body.classList.remove("window-focused");
      update();
      button.focus();
    }
  });
  update();
});
