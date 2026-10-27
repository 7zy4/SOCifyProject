"use strict";

function securityForm(fields, action, submitLabel) {
  const form = node("form", { class: "form-grid" });
  const controls = Object.create(null);
  for (const spec of fields) {
    const input = node("input", { name: spec.name, type: spec.type || "text", required: true, maxlength: spec.max || 128, minlength: spec.min || 1, autocomplete: spec.autocomplete || "off", inputmode: spec.inputmode });
    controls[spec.name] = input;
    form.append(field(spec.label, input));
  }
  const status = node("p", { role: "status", class: "span-2" });
  const submit = node("button", { type: "submit", class: "button primary", text: submitLabel });
  form.append(status, submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); submit.disabled = true; status.textContent = "";
    try { await action(Object.fromEntries(Object.entries(controls).map(([name, input]) => [name, input.value])), form); }
    catch (error) { status.textContent = error.message; }
    finally { submit.disabled = false; for (const input of Object.values(controls)) if (input.type === "password") input.value = ""; }
  });
  return form;
}

window.SOCifyAutopsy.profile = async () => {
  begin("profile");
  const [status, sessions] = await Promise.all([api("/api/auth/mfa/status"), api("/api/auth/sessions")]);
  const root = node("div", {}, pageHead(SOCifyLocale.text("أمان الحساب"), `${state.user.name} · ${autopsyLabel(state.user.role)}`));
  const mfa = node("div", { class: "panel-body" }, node("p", { text: status.enabled ? SOCifyLocale.template`المصادقة متعددة العوامل مفعّلة · رموز استرداد غير مستخدمة: ${status.recovery_codes_remaining}` : status.pending ? SOCifyLocale.text("إعداد المصادقة لم يكتمل. ابدأ إعدادًا جديدًا ثم أكد الرمز من تطبيقك المحلي.") : SOCifyLocale.text("المصادقة متعددة العوامل غير مفعّلة.") }));
  if (!status.enabled) {
    mfa.append(securityForm([{ name: "current_password", label: SOCifyLocale.text("كلمة المرور الحالية لبدء الإعداد"), type: "password", autocomplete: "current-password" }], async (body) => {
      const enrollment = await api("/api/auth/mfa/enroll", { method: "POST", body });
      let dialog;
      const secret = node("input", { readonly: true, value: enrollment.secret, dir: "ltr", autocomplete: "off", "aria-label": SOCifyLocale.text("مفتاح إعداد المصادقة") });
      const verify = securityForm([{ name: "code", label: SOCifyLocale.text("رمز التطبيق المحلي من ستة أرقام"), min: 6, max: 6, inputmode: "numeric", autocomplete: "one-time-code" }], async (payload) => {
        const enabled = await api("/api/auth/mfa/verify", { method: "POST", body: payload });
        dialog.close();
        const codes = node("textarea", { readonly: true, rows: 10, dir: "ltr", "aria-label": SOCifyLocale.text("رموز الاسترداد لمرة واحدة") }, enabled.backup_codes.join("\n"));
        const recovery = autopsyModal(SOCifyLocale.text("احفظ رموز الاسترداد في مكان آمن داخل الشركة؛ تظهر مرة واحدة"), node("div", {}, [node("p", { text: SOCifyLocale.text("كل رمز يستخدم مرة واحدة. لا تحفظها في ملاحظات قضية أو ترسلها في تقرير.") }), codes]));
        recovery.addEventListener("close", () => { codes.value = ""; window.SOCifyAutopsy.profile().catch(handleError); }, { once: true });
      }, SOCifyLocale.text("تأكيد وتفعيل المصادقة"));
      dialog = autopsyModal(SOCifyLocale.text("أدخل هذا المفتاح يدويًا في تطبيق مصادقة محلي ثم تحقق من الرمز"), node("div", {}, [node("p", { text: SOCifyLocale.text("المفتاح سري لحسابك. لا يرسل إلى أي خدمة خارجية ولا يحتاج إلى مولد QR خارجي.") }), secret, verify]));
      dialog.addEventListener("close", () => { secret.value = ""; }, { once: true });
    }, SOCifyLocale.text("بدء إعداد MFA")));
  } else {
    mfa.append(securityForm([{ name: "current_password", label: SOCifyLocale.text("كلمة المرور الحالية"), type: "password", autocomplete: "current-password" }, { name: "code", label: SOCifyLocale.text("رمز MFA أو رمز استرداد غير مستخدم"), max: 20, autocomplete: "one-time-code" }], async (body) => { await api("/api/auth/mfa", { method: "DELETE", body }); await window.SOCifyAutopsy.profile(); }, SOCifyLocale.text("إلغاء MFA بعد التحقق")));
  }
  root.append(panel(SOCifyLocale.text("المصادقة متعددة العوامل"), mfa, true));
  root.append(panel(SOCifyLocale.text("تغيير كلمة المرور"), node("div", { class: "panel-body" }, securityForm([{ name: "current_password", label: SOCifyLocale.text("كلمة المرور الحالية"), type: "password", autocomplete: "current-password" }, { name: "new_password", label: SOCifyLocale.text("كلمة مرور جديدة من 12 إلى 128 محرفًا وبحد 72 بايت"), type: "password", min: 12, autocomplete: "new-password" }, { name: "confirmation", label: SOCifyLocale.text("تأكيد كلمة المرور الجديدة"), type: "password", min: 12, autocomplete: "new-password" }], async (body) => {
    if (body.new_password !== body.confirmation) throw new Error(SOCifyLocale.text("تأكيد كلمة المرور غير مطابق"));
    await api("/api/profile/password", { method: "POST", body: { current_password: body.current_password, new_password: body.new_password } });
    await window.SOCifyAutopsy.profile();
  }, SOCifyLocale.text("حفظ كلمة المرور وإلغاء الجلسات الأخرى"))), true));
  root.append(panel(SOCifyLocale.text("جلساتي"), table([{ label: SOCifyLocale.text("الجلسة"), value: (item) => item.is_current ? SOCifyLocale.template`${item.id} · الحالية` : item.id }, { label: SOCifyLocale.text("بدأت"), value: (item) => formatTime(item.created_at) }, { label: SOCifyLocale.text("آخر نشاط"), value: (item) => formatTime(item.last_seen_at) }, { label: SOCifyLocale.text("تنتهي"), value: (item) => formatTime(item.expires_at) }, { label: SOCifyLocale.text("الحالة"), value: (item) => item.revoked_at ? SOCifyLocale.text("ملغاة") : SOCifyLocale.text("نشطة") }, { label: SOCifyLocale.text("إدارة"), value: (item) => !item.revoked_at ? button(SOCifyLocale.text("إلغاء الجلسة"), async () => { try { await api(`/api/auth/sessions/${item.id}`, { method: "DELETE" }); if (item.is_current) window.location.assign("/login"); else await window.SOCifyAutopsy.profile(); } catch (error) { handleError(error); } }) : "—" }], sessions.items), true));
  finish(root);
};
