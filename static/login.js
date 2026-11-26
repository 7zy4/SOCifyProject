"use strict";

// Signs in without reloading the page, so a second step (the MFA code) keeps the typed email and password.
// Without JavaScript, or when the request cannot be made, the form posts to the server as before.
(() => {
  const form = document.getElementById("auth-form");
  if (!form) return;
  const mfa = form.querySelector("details.auth-mfa");
  const codeField = document.getElementById("mfa_code");
  const submit = form.querySelector("button[type=submit]");
  const hintKey = "socify-login-mfa";
  const messages = {
    MFA_REQUIRED: "أدخل رمز المصادقة متعددة العوامل أو رمز الاسترداد الخاص بك.",
    INVALID_MFA_CODE: "رمز المصادقة غير صحيح. تحقق من الرمز وتوقيت جهازك.",
    LOGIN_RATE_LIMITED: "محاولات دخول كثيرة. انتظر انتهاء مدة الحماية ثم أعد المحاولة دون تكرار الطلب.",
  };
  const fallback = "تعذر تسجيل الدخول. تحقق من البريد وكلمة المرور.";

  function remembered() {
    try { return localStorage.getItem(hintKey) === "1"; } catch (_) { return false; }
  }
  function remember() {
    // Only the fact that this browser signs in with a code is kept, never the code or the account.
    try { localStorage.setItem(hintKey, "1"); } catch (_) { /* Storage may be blocked; the field still opens now. */ }
  }
  function show(text, error = true) {
    for (const old of form.querySelectorAll(".notice")) old.remove();
    const notice = document.createElement("div");
    notice.className = error ? "notice error" : "notice";
    notice.setAttribute("role", "alert");
    notice.dataset.loginMessage = "";
    notice.textContent = text;
    form.querySelector("label[for=email]").before(notice);
  }
  function target() {
    const next = form.elements.next?.value || "";
    return /^\/(?![/\\])[^\r\n\\]*$/.test(next) ? next : "/cases";
  }
  if (mfa && remembered()) mfa.open = true;

  let pending = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (pending) return;
    pending = true;
    submit.disabled = true;
    const data = new FormData(form);
    const body = { email: data.get("email"), password: data.get("password") };
    const code = String(data.get("mfa_code") || "").trim();
    if (code) body.mfa_code = code;
    let response;
    let payload = null;
    try {
      response = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json", "Content-Type": "application/json", "X-CSRFToken": String(data.get("csrf_token") || ""), "X-SOCify-Language": SOCifyLocale.language },
        body: JSON.stringify(body),
      });
      payload = await response.json();
    } catch (_) {
      form.submit();
      return;
    }
    if (response.ok) {
      window.location.assign(target());
      return;
    }
    const errorCode = payload?.error?.code;
    if (!errorCode || errorCode.startsWith("CSRF_")) {
      // The server's own form handling renews an expired page token and explains what happened.
      form.submit();
      return;
    }
    pending = false;
    submit.disabled = false;
    const wait = Number(payload.error.details?.retry_after);
    show(Number.isSafeInteger(wait) && wait > 0
      ? SOCifyLocale.template`محاولات دخول خاطئة كثيرة لهذا الحساب. أعد المحاولة بعد ${wait} ثانية.`
      : SOCifyLocale.error(errorCode, messages[errorCode] || fallback), errorCode !== "MFA_REQUIRED");
    if (errorCode === "MFA_REQUIRED" && mfa && codeField) {
      remember();
      mfa.open = true;
      codeField.focus();
    } else if (errorCode === "INVALID_MFA_CODE" && codeField) {
      codeField.select();
      codeField.focus();
    }
  });
})();
