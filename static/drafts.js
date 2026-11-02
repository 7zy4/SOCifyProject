"use strict";

// Drafts stay in the current document, never in browser storage.
window.SOCifyDrafts = (() => {
  const forms = new Map();
  const snapshot = (form) => JSON.stringify([...form.querySelectorAll("input,textarea,select")]
    .filter(input => !["submit", "button", "hidden"].includes(input.type))
    .map(input => [input.name, input.type === "file" ? [...input.files].map(file => [file.name, file.size, file.lastModified]) : ["checkbox", "radio"].includes(input.type) ? input.checked : input.value]));
  const dirty = (scope = document, excludeSaving = false) => [...forms].filter(([form, initial]) =>
    form.isConnected && scope.contains(form) && !(excludeSaving && form.dataset.saving === "true") && snapshot(form) !== initial).map(([form]) => form);
  const saved = (form) => { if (forms.has(form)) forms.set(form, snapshot(form)); };
  const confirmDiscard = (scope = document, excludeSaving = false) => {
    const pending = dirty(scope, excludeSaving);
    if (!pending.length) return true;
    if (!window.confirm(SOCifyLocale.text("لديك تعديلات غير محفوظة. هل تريد مغادرتها؟"))) return false;
    pending.forEach(saved);
    return true;
  };
  window.addEventListener("beforeunload", (event) => {
    if (!dirty().length) return;
    event.preventDefault();
    event.returnValue = "";
  });
  return Object.freeze({
    track: (form) => { forms.set(form, snapshot(form)); queueMicrotask(() => saved(form)); return form; },
    saved,
    hasChanges: (scope = document) => dirty(scope).length > 0,
    confirmDiscard,
  });
})();
