"use strict";

// First-run checklist for a new team's manager, shown on the case list until every step is done or it is dismissed.
// Steps the server can see (an invitation, a case, an SLA, an intelligence import, a recent backup) tick themselves;
// any step can also be marked done by hand. Progress is stored per user on the server.
window.SOCifyOnboarding = (() => {
  const steps = {
    invite_team: {
      title: () => SOCifyLocale.text("ادعُ فريقك"),
      text: () => null,
      link: () => ["/team", SOCifyLocale.text("فتح الفريق")],
    },
    first_case: {
      title: () => SOCifyLocale.text("أنشئ أول قضية"),
      text: () => null,
      link: () => null,
    },
    sla_calendar: {
      title: () => SOCifyLocale.text("اضبط مهلة الاستجابة وتقويمها"),
      text: () => null,
      link: () => ["/team", SOCifyLocale.text("فتح الفريق")],
    },
    attack_catalogue: {
      title: () => SOCifyLocale.text("راجع كتالوج ATT&CK"),
      text: (data) => (data.attack_version ? SOCifyLocale.template`الإصدار المحلي ${data.attack_version}` : SOCifyLocale.text("لم يُحمّل بعد؛ راجع دليل التشغيل")),
      link: () => null,
    },
    threat_intel: {
      title: () => SOCifyLocale.text("استورد استخبارات التهديدات"),
      text: () => null,
      link: () => ["/analysis-library", SOCifyLocale.text("فتح مكتبة القواعد")],
    },
    backups: {
      title: () => SOCifyLocale.text("تأكد من النسخ الاحتياطي"),
      text: (data) => (data.last_backup_at ? SOCifyLocale.template`آخر نسخة ناجحة: ${formatTime(data.last_backup_at)}` : SOCifyLocale.text("لم تُسجَّل نسخة بعد")),
      link: () => null,
    },
  };

  function render(data, replace) {
    const list = node("ol", { class: "onboarding-steps" });
    for (const item of data.items) {
      const step = steps[item.id];
      if (!step) continue;
      const controls = [];
      const link = step.link(data);
      if (link && !item.done) controls.push(linkedButton(link[1], link[0]));
      if (!item.detected) {
        controls.push(button(item.marked ? SOCifyLocale.text("إلغاء التحديد") : SOCifyLocale.text("تحديد كمنجز"), async () => {
          const next = await api(`/api/onboarding/items/${item.id}`, { method: "PUT", body: { done: !item.marked } });
          if (!next.visible) showMessage(SOCifyLocale.text("اكتملت خطوات تجهيز الفريق"), "success");
          replace(next.visible ? render(next, replace) : null);
        }));
      }
      list.append(node("li", { class: item.done ? "done" : "" }, [
        node("span", { class: "badge onboarding-state", text: item.done ? SOCifyLocale.text("تم") : SOCifyLocale.text("لم يتم") }),
        node("div", { class: "onboarding-step" }, [node("strong", { text: step.title() }), step.text(data) ? node("p", { text: step.text(data) }) : null]),
        controls.length ? node("div", { class: "action-row" }, controls) : null,
      ]));
    }
    const hide = button(SOCifyLocale.text("إخفاء القائمة"), async () => {
      const next = await api("/api/onboarding/dismiss", { method: "POST", body: {} });
      replace(next.visible ? render(next, replace) : null);
    });
    const progress = node("progress", { max: data.total, value: data.completed, "aria-label": SOCifyLocale.text("تقدم خطوات البدء") });
    const body = node("div", { class: "panel-body" }, [
      node("div", { class: "onboarding-progress" }, [progress, node("span", { text: SOCifyLocale.template`${data.completed} من ${data.total}` })]),
      list,
    ]);
    const section = panel(SOCifyLocale.text("ابدأ مع SOCify"), body, true, hide);
    section.classList.add("onboarding-panel");
    return section;
  }

  // The panel for the case list, or null when this user has no checklist to show.
  async function panelFor() {
    if (!["soc_manager", "admin"].includes(state.user?.role)) return null;
    let data;
    try { data = await api("/api/onboarding"); } catch (_) { return null; }
    if (!data.visible) return null;
    let current = null;
    const replace = (next) => {
      if (next) current.replaceWith(next); else current.remove();
      current = next;
    };
    current = render(data, replace);
    return current;
  }

  return Object.freeze({ panel: panelFor });
})();
