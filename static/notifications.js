"use strict";

// The bell: an unread count in the sidebar (and the mobile top bar) and a short list of what needs this person now.
// Each item says what happened and opens the place to act; opening it marks it read. The count refreshes once a
// minute as background activity, so it never keeps an idle session alive.
window.SOCifyNotifications = (() => {
  const t = (value) => SOCifyLocale.text(value);
  const POLL_MILLISECONDS = 60000;
  const bells = [];
  let panel = null;
  let unread = 0;
  let started = false;

  const icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 8 3 8H3s3-1 3-8"/><path d="M10.3 20a1.9 1.9 0 0 0 3.4 0"/></svg>';

  function sentence(item) {
    const ref = item.case?.reference || "";
    switch (item.kind) {
      case "case_assigned": return SOCifyLocale.template`أُسندت إليك القضية ${ref}`;
      case "case_member_added": return SOCifyLocale.template`أُضفت إلى القضية ${ref}`;
      case "batch_assigned": return SOCifyLocale.template`أُسندت إليك دفعة سجلات في ${ref}`;
      case "handoff": return SOCifyLocale.template`سُلّمت إليك القضية ${ref}`;
      case "review_requested": return SOCifyLocale.template`القضية ${ref} بانتظار المراجعة`;
      case "case_returned": return SOCifyLocale.template`أُعيدت القضية ${ref} للمتابعة`;
      case "report_approved": return SOCifyLocale.template`اعتُمد تقرير القضية ${ref}`;
      case "escalated": return SOCifyLocale.template`صُعّدت القضية ${ref} إلى المدير`;
      case "escalation_decided": return SOCifyLocale.template`قرر المدير في تصعيد ${ref}`;
      case "sla_warning": return SOCifyLocale.template`اقتربت مهلة القضية ${ref} من نهايتها`;
      case "sla_breached": return SOCifyLocale.template`تجاوزت القضية ${ref} مهلة الاستجابة`;
      case "intake_alert": return SOCifyLocale.template`تنبيه وارد بخطورة ${autopsyLabel(item.alert?.severity)}`;
      default: return t("إشعار");
    }
  }

  function target(item) {
    if (item.kind === "intake_alert") return "/monitoring?channel=intake";
    if (item.kind === "batch_assigned") return "/my-tasks";
    const base = `/cases/${item.case.id}`;
    if (["review_requested", "report_approved", "escalated", "escalation_decided"].includes(item.kind)) return `${base}?tab=reports`;
    if (["sla_warning", "sla_breached"].includes(item.kind)) return `${base}?tab=response`;
    return base;
  }

  function paint() {
    for (const bell of bells) {
      const count = bell.querySelector(".notification-count");
      count.textContent = unread > 99 ? "99+" : new Intl.NumberFormat(SOCifyLocale.locale).format(unread);
      count.hidden = unread === 0;
      bell.setAttribute("aria-label", unread ? SOCifyLocale.template`الإشعارات، ${unread} غير مقروءة` : t("الإشعارات"));
    }
  }

  async function refresh() {
    try {
      unread = (await api("/api/notifications/unread", { background: true })).unread;
      paint();
    } catch (_) { /* The next poll tries again; a signed-out session is handled by the page itself. */ }
  }

  function close() {
    if (!panel) return;
    panel.remove();
    panel = null;
    for (const bell of bells) { bell.setAttribute("aria-expanded", "false"); bell.removeAttribute("aria-controls"); }
  }

  async function open(bell) {
    if (panel) { close(); return; }
    const list = node("ul", { class: "notification-list" });
    const markAll = button(t("تحديد الكل كمقروء"), async () => {
      try { await api("/api/notifications/read-all", { method: "POST" }); close(); await open(bell); } catch (error) { handleError(error); }
    });
    panel = node("section", { class: "notification-panel", id: "notification-panel", "aria-label": t("الإشعارات") }, [
      node("header", { class: "notification-head" }, [node("h2", { text: t("الإشعارات") }), markAll]),
      list,
    ]);
    document.body.append(panel);
    // Open from the bell toward the workspace: the panel's near edge lines up with the bell, inside the window.
    const box = bell.getBoundingClientRect();
    const width = panel.getBoundingClientRect().width;
    panel.style.top = `${Math.round(box.bottom + 8)}px`;
    const left = document.documentElement.dir === "rtl" ? box.right - width : box.left;
    panel.style.left = `${Math.round(Math.min(Math.max(8, left), window.innerWidth - width - 8))}px`;
    bell.setAttribute("aria-expanded", "true");
    bell.setAttribute("aria-controls", "notification-panel");
    list.append(node("li", { class: "notification-empty", text: t("جارٍ التحميل…") }));
    try {
      const data = await api("/api/notifications");
      unread = data.unread;
      paint();
      markAll.disabled = !data.unread;
      list.replaceChildren(...(data.items.length ? data.items.map((item) => {
        const link = node("a", { href: target(item), class: item.read ? "" : "unread" }, [
          node("span", { class: "notification-text", text: sentence(item) }),
          item.case?.title || item.alert?.title ? node("span", { class: "notification-subject", "data-user-content": "true", text: item.case?.title || item.alert?.title }) : null,
          node("span", { class: "notification-meta" }, [item.actor_name ? node("span", { "data-user-content": "true", text: item.actor_name }) : null, node("time", { datetime: item.created_at, text: formatTime(item.created_at) })]),
        ]);
        link.addEventListener("click", async (event) => {
          if (item.read) return;
          event.preventDefault();
          try { await api(`/api/notifications/${item.id}/read`, { method: "POST" }); } catch (_) { /* Opening the place matters more than the mark. */ }
          window.location.assign(link.href);
        });
        return node("li", {}, link);
      }) : [node("li", { class: "notification-empty", text: t("لا توجد إشعارات") })]));
      list.querySelector("a")?.focus();
    } catch (error) { list.replaceChildren(node("li", { class: "notification-empty", role: "alert", text: error.message })); }
  }

  function mount(holder) {
    const bell = node("button", { type: "button", class: "icon-button notification-bell", "aria-expanded": "false", "aria-haspopup": "true" });
    bell.innerHTML = icon;
    bell.append(node("span", { class: "notification-count", hidden: true, "aria-hidden": "true" }));
    bell.addEventListener("click", (event) => { event.stopPropagation(); open(bell).catch(handleError); });
    holder.append(bell);
    bells.push(bell);
  }

  function start() {
    if (started || !state.user) return;
    started = true;
    document.querySelectorAll("[data-notifications]").forEach(mount);
    paint();
    refresh();
    window.setInterval(() => { if (!document.hidden) refresh(); }, POLL_MILLISECONDS);
    document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
    document.addEventListener("click", (event) => { if (panel && !panel.contains(event.target)) close(); });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && panel) {
        const owner = bells.find((bell) => bell.getAttribute("aria-expanded") === "true");
        close();
        owner?.focus();
      }
    });
  }

  document.addEventListener("socify:workspace-ready", start);
  return Object.freeze({ refresh });
})();
