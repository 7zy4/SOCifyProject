"use strict";

// Warns two minutes before the server ends a session for inactivity, and lets the person stay signed in.
// Requests the person makes count as activity (api() reports them); status polling is sent as background and does not.
window.SOCifySessionIdle = (() => {
  const seconds = Number(document.querySelector('meta[name="session-idle-seconds"]')?.content || 0);
  if (!Number.isFinite(seconds) || seconds <= 0) return Object.freeze({ activity() {} });
  const warnBefore = 120_000;
  // The server records activity at most once a minute, so its idle clock may run up to a minute ahead of this page's.
  const limit = seconds * 1000 - 60_000;
  let last = Date.now();
  let warningTimer = null;
  let endTimer = null;
  let dialog = null;

  function schedule() {
    clearTimeout(warningTimer);
    clearTimeout(endTimer);
    warningTimer = setTimeout(warn, Math.max(0, last + limit - warnBefore - Date.now()));
    endTimer = setTimeout(check, Math.max(0, last + limit - Date.now()));
  }

  function activity() {
    last = Date.now();
    dialog?.close();
    schedule();
  }

  async function check() {
    // Ask whether the server has ended the session, without counting the question as activity.
    // On 401 api() sends the person to sign in again, or offers to keep an unsaved draft.
    try {
      await api("/api/auth/me", { background: true });
      endTimer = setTimeout(check, 30_000);
    } catch (_) {
      dialog?.close();
    }
  }

  function warn() {
    if (dialog) return;
    const previous = document.activeElement;
    const errors = node("p", { role: "alert", class: "notice", hidden: true });
    const stay = button(SOCifyLocale.text("البقاء متصلًا"), async () => {
      stay.disabled = true;
      errors.hidden = true;
      try { await api("/api/auth/me"); }
      catch (error) { errors.textContent = error.message; errors.hidden = false; }
      finally { stay.disabled = false; }
    }, "primary");
    const signOut = button(SOCifyLocale.text("خروج"), () => {
      if (window.SOCifyDrafts && !SOCifyDrafts.confirmDiscard()) return;
      document.querySelector(".account-menu form[action$='/logout']")?.requestSubmit();
    });
    dialog = node("dialog", { id: "session-idle-warning", class: "autopsy-modal", "aria-labelledby": "session-idle-title", "aria-describedby": "session-idle-text" }, [
      node("h2", { id: "session-idle-title", text: SOCifyLocale.text("ستنتهي الجلسة قريبًا") }),
      node("p", { id: "session-idle-text", text: SOCifyLocale.text("ستنتهي جلستك بعد دقيقتين لعدم النشاط") }),
      node("div", { class: "action-row" }, [stay, signOut]),
      errors,
    ]);
    dialog.addEventListener("close", () => {
      dialog.remove();
      dialog = null;
      if (previous?.isConnected) previous.focus();
    });
    document.body.append(dialog);
    dialog.showModal();
    stay.focus();
  }

  schedule();
  return Object.freeze({ activity });
})();
