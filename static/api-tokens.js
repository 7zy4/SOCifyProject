"use strict";

// API tokens on the Integrations page, for managers: the list with last use and revoke, and a dialog to create one
// (name, scopes, expiry). The full token is shown once, in a dialog, right after it is created.
window.SOCifyApiTokens = (() => {
  const t = (value) => SOCifyLocale.text(value);
  const scopeLabels = {
    "intake:write": () => t("استقبال التنبيهات"),
    "cases:read": () => t("قراءة القضايا"),
    "cases:write": () => t("إنشاء القضايا واستيراد السجلات"),
    "search:read": () => t("قراءة قوائم المراقبة"),
    "reports:read": () => t("قراءة التقارير وتنزيلها"),
    "audit:read": () => t("قراءة سجل التدقيق"),
  };
  const scopeLabel = (scope) => (scopeLabels[scope] ? scopeLabels[scope]() : scope);

  function status(item) {
    if (item.revoked_at) return t("ملغى");
    return item.active ? t("نشط") : t("منتهٍ");
  }

  function createDialog(scopes, done) {
    const name = node("input", { name: "name", required: true, minlength: 3, maxlength: 100 });
    const boxes = scopes.map((scope) => node("input", { type: "checkbox", name: "scopes", value: scope }));
    const expiry = node("select", { name: "expires_in_days" }, [30, 90, 180, 365].map((days) => node("option", { value: days, selected: days === 90, text: SOCifyLocale.template`${days} يومًا` })));
    const errors = node("p", { class: "notice span-2", role: "alert", hidden: true });
    const submit = node("button", { type: "submit", class: "button primary", text: t("إنشاء رمز") });
    const form = SOCifyDrafts.track(node("form", { class: "form-grid" }, [
      field(t("اسم الرمز"), name),
      field(t("مدة الصلاحية"), expiry),
      node("fieldset", { class: "span-2 check-grid token-scopes" }, [node("legend", { text: t("النطاقات") }), ...boxes.map((box) => field(scopeLabel(box.value), box))]),
      errors,
      node("div", { class: "action-row span-2" }, submit),
    ]));
    const dialog = autopsyModal(t("رمز API جديد"), form);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errors.hidden = true;
      const chosen = boxes.filter((box) => box.checked).map((box) => box.value);
      if (!chosen.length) { errors.textContent = t("اختر نطاقًا واحدًا على الأقل"); errors.hidden = false; return; }
      submit.disabled = true;
      try {
        const created = await api("/api/tokens", { method: "POST", body: { name: name.value.trim(), scopes: chosen, expires_in_days: Number(expiry.value) } });
        SOCifyDrafts.saved(form);
        dialog.close();
        autopsyModal(t("رمز API جديد"), node("div", { class: "form-grid" }, [
          field(t("الرمز"), node("input", { readonly: true, value: created.token, dir: "ltr", "data-api-token": "" }), true),
          node("p", { class: "field-hint span-2", text: t("يظهر الرمز مرة واحدة فقط.") }),
        ]));
        await done();
      } catch (error) { errors.textContent = error.message; errors.hidden = false; }
      finally { submit.disabled = false; }
    });
  }

  async function render(holder, create) {
    const data = await api("/api/tokens");
    create.onclick = () => createDialog(data.scopes, () => render(holder, create));
    holder.replaceChildren(data.items.length ? table([
      { label: t("الاسم"), value: (item) => node("span", { "data-user-content": "true", text: item.name }) },
      { label: t("البادئة"), value: (item) => node("bdi", { class: "mono", dir: "ltr", text: `${item.display_prefix}…` }) },
      { label: t("النطاقات"), value: (item) => node("div", { class: "tag-list" }, item.scopes.map((scope) => node("span", { class: "badge", text: scopeLabel(scope) }))) },
      { label: t("ينتهي"), value: (item) => formatTime(item.expires_at) },
      { label: t("آخر استخدام"), value: (item) => (item.last_used_at ? formatTime(item.last_used_at) : t("لم يُستخدم")) },
      { label: t("الحالة"), value: (item) => node("span", { class: "badge", text: status(item) }) },
      { label: t("إجراء"), value: (item) => (item.active ? button(t("إلغاء الرمز"), async () => {
        if (!window.confirm(t("إلغاء الرمز يوقف كل نظام يستخدمه فورًا. هل تريد المتابعة؟"))) return;
        try { await api(`/api/tokens/${item.id}`, { method: "DELETE" }); await render(holder, create); } catch (error) { handleError(error); }
      }) : "—") },
    ], data.items) : emptyState(t("لا توجد رموز API"), null));
  }

  // The panel for the Integrations page, or null for anyone who does not manage the team.
  async function panelFor() {
    if (!permission("integrations.manage")) return null;
    const holder = node("div", { class: "panel-body api-tokens" });
    const create = button(t("إنشاء رمز"), null, "primary");
    try { await render(holder, create); } catch (error) { holder.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message })); }
    return panel(t("رموز API"), holder, true, create);
  }

  return Object.freeze({ panel: panelFor });
})();
