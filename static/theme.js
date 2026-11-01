"use strict";

// Resolve the saved appearance before first paint. The control animates independently of page content.
(() => {
  const key = "socify-interface-theme";
  const root = document.documentElement;
  const system = window.matchMedia("(prefers-color-scheme: dark)");
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  const options = ["light", "system", "dark"];
  const controls = [];
  let preference = "dark";
  try {
    const saved = localStorage.getItem(key);
    if (options.includes(saved)) preference = saved;
  } catch (_) { /* The control works without browser storage. */ }

  function apply() {
    const resolved = preference === "system" ? (system.matches ? "dark" : "light") : preference;
    root.dataset.theme = resolved;
    root.dataset.themePreference = preference;
    root.style.colorScheme = resolved;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", resolved === "dark" ? "#15191C" : "#E4DFD1");
    controls.forEach(control => control.update());
  }
  function choose(value) {
    preference = value;
    try { localStorage.setItem(key, preference); } catch (_) { /* Keep the in-memory choice. */ }
    apply();
  }
  apply();
  system.addEventListener("change", () => { if (preference === "system") apply(); });
  window.addEventListener("storage", event => {
    if (event.key !== key && event.key !== null) return;
    preference = options.includes(event.newValue) ? event.newValue : "system";
    apply();
  });

  function mount() {
    const t = window.SOCifyLocale.text;
    const icons = {
      light: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
      system: '<rect x="3" y="4" width="18" height="13" rx="1"/><path d="M8 21h8m-4-4v4"/>',
      dark: '<path d="M20.4 14.4A8.6 8.6 0 0 1 9.6 3.6 8.6 8.6 0 1 0 20.4 14.4Z"/>'
    };
    document.querySelectorAll("[data-theme-control]").forEach(container => {
      const group = document.createElement("div");
      group.className = "theme-switch";
      group.dataset.themeSwitch = "";
      group.setAttribute("role", "group");
      group.setAttribute("aria-label", t("المظهر"));
      group.dir = "ltr";
      const thumb = document.createElement("span");
      thumb.className = "theme-switch-thumb";
      thumb.setAttribute("aria-hidden", "true");
      group.append(thumb);
      let position = options.indexOf(preference) * 40, target = position, velocity = 0, frame = 0, previous = 0;
      const paint = () => { thumb.style.transform = `translateX(${position}px)`; };
      function tick(now) {
        const dt = Math.min((now - previous) / 1000 || 1 / 60, 0.032);
        previous = now;
        velocity += ((target - position) * 460 - velocity * 43) * dt;
        position += velocity * dt;
        if (Math.abs(target - position) < .05 && Math.abs(velocity) < .05) {
          position = target; velocity = 0; frame = 0; paint(); return;
        }
        paint(); frame = requestAnimationFrame(tick);
      }
      const buttons = options.map((value, index) => {
        const button = document.createElement("button");
        button.type = "button";
        button.dataset.themeOption = value;
        button.setAttribute("aria-label", t(["فاتح", "حسب النظام", "داكن"][index]));
        button.title = button.getAttribute("aria-label");
        button.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[value]}</svg>`;
        button.addEventListener("click", () => choose(value));
        group.append(button);
        return button;
      });
      const update = () => {
        buttons.forEach(button => button.setAttribute("aria-pressed", String(button.dataset.themeOption === preference)));
        target = options.indexOf(preference) * 40;
        if (reduced.matches) {
          cancelAnimationFrame(frame); frame = 0; velocity = 0; position = target; paint();
        } else if (!frame) { previous = performance.now(); frame = requestAnimationFrame(tick); }
      };
      reduced.addEventListener("change", update);
      controls.push({update});
      container.replaceChildren(group);
      paint(); update();
    });
  }
  document.addEventListener("DOMContentLoaded", mount, {once:true});
})();
