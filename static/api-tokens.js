"use strict";

// API tokens on the team page, for managers: create (name, scopes, expiry), list with last use, revoke.
// The full token is shown once, in a dialog, right after it is created.
window.SOCifyApiTokens = (() => {
  const scopeLabels = {
    "intake:write": () => SOCifyLocale.text("استقبال التنبيهات"),
    "cases:read": () => SOCifyLocale.text("قراءة القضايا"),
    "cases:write": () => SOCifyLocale.text("إنشاء القضايا واستيراد السجلات"),
    "search:read": () => SOCifyLocale.text("قراءة قوائم المراقبة"),
    "reports:read": () => SOCifyLocale.text("قراءة التقارير وتنزيلها"),
    "audit:read": () => SOCifyLocale.text("قراءة سجل التدقيق"),
  };
  const scopeLabel = (scope) => (scopeLabels[scope] ? scopeLabels[scope]() : scope);

  function status(item) {
    if (item.revoked_at) return SOCifyLocale.text("ملغى");
    return item.active ? SOCifyLocale.text("نشط") : SOCifyLocale.text("منتهٍ");
  }

  async function render(holder) {
    const data = await api("/api/tokens");
    const name = node("input", { name: "name", required: true, minlength: 3, maxlength: 100 });
    const boxes = data.scopes.map((scope) => node("input", { type: "checkbox", name: "scopes", value: scope }));
    const expiry = node("select", { name: "expires_in_days" }, [30, 90, 180, 365].map((days) => node("option", { value: days, selected: days === 90, text: SOCifyLocale.template`${days} يومًا` })));
    const errors = node("p", { class: "notice", role: "alert", hidden: true });
    const form = node("form", { class: "form-grid" }, [
      field(SOCifyLocale.text("اسم الرمز"), name),
      field(SOCifyLocale.text("مدة الصلاحية"), expiry),
      node("fieldset", { class: "span-2 token-scopes" }, [node("legend", { text: SOCifyLocale.text("النطاقات") }), ...boxes.map((box) => field(scopeLabel(box.value), box))]),
      node("div", { class: "action-row span-2" }, node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("إنشاء رمز") })),
      errors,
    ]);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errors.hidden = true;
      const scopes = boxes.filter((box) => box.checked).map((box) => box.value);
      if (!scopes.length) { errors.textContent = SOCifyLocale.text("اختر نطاقًا واحدًا على الأقل"); errors.hidden = false; return; }
      try {
        const created = await api("/api/tokens", { method: "POST", body: { name: name.value.trim(), scopes, expires_in_days: Number(expiry.value) } });
        SOCifyDrafts.saved(form);
        autopsyModal(SOCifyLocale.text("رمز API جديد"), node("div", {}, [
          node("p", { text: SOCifyLocale.text("انسخ الرمز الآن واحفظه في مدير الأسرار؛ لن يظهر مرة أخرى.") }),
          field(SOCifyLocale.text("الرمز"), node("input", { readonly: true, value: created.token, dir: "ltr", "data-api-token": "" })),
        ]));
        await render(holder);
      } catch (error) { errors.textContent = error.message; errors.hidden = false; }
    });
    SOCifyDrafts.track(form);
    const list = data.items.length ? table([
      { label: SOCifyLocale.text("الاسم"), value: (item) => node("span", { "data-user-content": "true", text: item.name }) },
      { label: SOCifyLocale.text("البادئة"), value: (item) => node("bdi", { dir: "ltr", text: `${item.display_prefix}…` }) },
      { label: SOCifyLocale.text("النطاقات"), value: (item) => item.scopes.map(scopeLabel).join(" | ") },
      { label: SOCifyLocale.text("ينتهي"), value: (item) => formatTime(item.expires_at) },
      { label: SOCifyLocale.text("آخر استخدام"), value: (item) => (item.last_used_at ? formatTime(item.last_used_at) : SOCifyLocale.text("لم يُستخدم")) },
      { label: SOCifyLocale.text("الحالة"), value: status },
      { label: SOCifyLocale.text("إجراء"), value: (item) => (item.active ? button(SOCifyLocale.text("إلغاء الرمز"), async () => {
        if (!window.confirm(SOCifyLocale.text("إلغاء الرمز يوقف كل نظام يستخدمه فورًا. هل تريد المتابعة؟"))) return;
        await api(`/api/tokens/${item.id}`, { method: "DELETE" });
        await render(holder);
      }) : "—") },
    ], data.items) : emptyState(SOCifyLocale.text("لا توجد رموز API"), null);
    holder.replaceChildren(
      node("p", { text: SOCifyLocale.text("رموز تربط الأنظمة الأخرى بالمنصة دون جلسة متصفح. يعمل الرمز بصلاحيات من أنشأه وفي النطاقات المختارة فقط.") }),
      form,
      list,
    );
  }

  // The panel for the team page, or null for anyone who does not manage the team.
  async function panelFor() {
    if (!["soc_manager", "admin"].includes(state.user?.role)) return null;
    const holder = node("div", { class: "panel-body api-tokens" });
    try { await render(holder); } catch (error) { holder.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message })); }
    return panel(SOCifyLocale.text("رموز API"), holder, true);
  }

  return Object.freeze({ panel: panelFor });
})();
