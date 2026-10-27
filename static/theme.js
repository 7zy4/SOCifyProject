"use strict";

// Runs in <head> before styles to resolve the first paint without a theme flash.
(() => {
  const key = "socify-interface-theme";
  const root = document.documentElement;
  const system = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = "system";
  try {
    const saved = localStorage.getItem(key);
    if (["light", "dark", "system"].includes(saved)) preference = saved;
  } catch (_) { /* Use the system preference when storage is unavailable. */ }

  function apply() {
    const resolved = preference === "system" ? (system.matches ? "dark" : "light") : preference;
    root.dataset.theme = resolved;
    root.dataset.themePreference = preference;
    root.style.colorScheme = resolved;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", resolved === "dark" ? "#0B1120" : "#DDE2E9");
  }

  apply();
  system.addEventListener("change", () => { if (preference === "system") apply(); });
  window.addEventListener("storage", (event) => {
    if (event.key !== key && event.key !== null) return;
    preference = ["light", "dark", "system"].includes(event.newValue) ? event.newValue : "system";
    apply();
    document.querySelectorAll("[data-theme-select]").forEach(select => { select.value = preference; });
  });

  function mount() {
    const t = window.SOCifyLocale.text;
    document.querySelectorAll("[data-theme-control]").forEach(container => {
      const label = document.createElement("label");
      label.className = "theme-control";
      const text = document.createElement("span");
      text.textContent = t("المظهر");
      const select = document.createElement("select");
      select.dataset.themeSelect = "";
      [["system", "حسب النظام"], ["light", "فاتح"], ["dark", "داكن"]].forEach(([value, copy]) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = t(copy);
        select.append(option);
      });
      select.value = preference;
      select.addEventListener("change", () => {
        preference = select.value;
        try { localStorage.setItem(key, preference); } catch (_) { /* Selection remains active for this page. */ }
        apply();
      });
      label.append(text, select);
      container.replaceChildren(label);
    });
  }
  document.addEventListener("DOMContentLoaded", mount, { once: true });
})();
