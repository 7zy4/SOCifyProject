"use strict";

// The Intake channel on the alerts page: alerts received from a SIEM or EDR, before they become cases.
// Filters by status, severity and integration; a detail dialog shows the normalised fields, the entities and (with
// intake.triage) the raw payload, with actions to create a case, link to an existing case, or dismiss with a reason.
window.SOCifyIntake = (() => {
  const statusLabels = {
    open: () => SOCifyLocale.text("بانتظار الفرز"),
    new: () => SOCifyLocale.text("جديد"),
    triaging: () => SOCifyLocale.text("قيد الفرز"),
    linked: () => SOCifyLocale.text("مربوط بقضية"),
    dismissed: () => SOCifyLocale.text("مستبعد"),
    all: () => SOCifyLocale.text("الكل"),
  };
  const entityLabels = {
    hosts: () => SOCifyLocale.text("الأجهزة"),
    users: () => SOCifyLocale.text("المستخدمون"),
    ips: () => SOCifyLocale.text("عناوين IP"),
    domains: () => SOCifyLocale.text("النطاقات"),
    urls: () => SOCifyLocale.text("الروابط"),
    hashes: () => SOCifyLocale.text("البصمات"),
  };
  const severityLabel = (value) => (value === "info" ? SOCifyLocale.text("معلوماتي") : autopsyLabel(value));

  function details(alert, onDone) {
    const n = alert.normalized;
    const rows = [
      [SOCifyLocale.text("التكامل"), `${alert.integration_name} (${alert.integration_kind})`],
      [SOCifyLocale.text("القاعدة"), n.rule_name || n.rule_id || "—"],
      [SOCifyLocale.text("أول ظهور"), formatTime(alert.first_seen)],
      [SOCifyLocale.text("آخر ظهور"), formatTime(alert.last_seen)],
      [SOCifyLocale.text("مرات التكرار"), String(alert.occurrence_count)],
      ["MITRE ATT&CK", n.mitre.length ? n.mitre.join(" | ") : "—"],
      [SOCifyLocale.text("بصمة الحمولة SHA-256"), alert.raw_sha256],
    ];
    const content = node("div", { class: "intake-detail" }, [
      node("table", { class: "alert-property-table" }, node("tbody", {}, rows.map(([label, value]) => node("tr", {}, [node("th", { scope: "row", text: label }), node("td", { dir: "auto", text: value })])))),
      n.description ? node("p", { "data-user-content": "true", text: n.description }) : null,
      node("dl", { class: "intake-entities" }, Object.entries(n.entities).filter(([, values]) => values.length).flatMap(([kind, values]) => [
        node("dt", { text: entityLabels[kind]() }),
        node("dd", {}, values.map((value) => node("bdi", { class: "badge", dir: "ltr", text: value }))),
      ])),
    ]);
    if (alert.raw) content.append(node("details", {}, [node("summary", { text: SOCifyLocale.text("الحمولة الأصلية") }), node("pre", { dir: "ltr", text: JSON.stringify(alert.raw, null, 2) })]));
    if (alert.case_id) content.append(linkedButton(SOCifyLocale.text("فتح القضية"), `/cases/${alert.case_id}`));
    if (alert.dismissed_reason) content.append(node("p", { class: "notice", text: SOCifyLocale.template`سبب الاستبعاد: ${alert.dismissed_reason}` }));
    const open = ["new", "triaging"].includes(alert.status);
    if (open && alert.raw !== undefined) {
      const errors = node("p", { class: "notice", role: "alert", hidden: true });
      const fail = (error) => { errors.textContent = error.message; errors.hidden = false; };
      const title = node("input", { name: "title", value: alert.title, maxlength: 255 });
      const create = node("form", { class: "form-grid" }, [field(SOCifyLocale.text("عنوان القضية"), title, true), node("div", { class: "action-row span-2" }, node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("إنشاء قضية من التنبيه") }))]);
      create.addEventListener("submit", async (event) => {
        event.preventDefault();
        try { const made = await api(`/api/intake/alerts/${alert.id}/case`, { method: "POST", body: { title: title.value.trim() } }); window.location.assign(`/cases/${made.case_id}`); } catch (error) { fail(error); }
      });
      const caseChoice = node("select", { name: "case_id", required: true }, [node("option", { value: "", text: SOCifyLocale.text("اختر القضية") })]);
      api("/api/cases?page=1&page_size=50").then((cases) => cases.items.filter((item) => item.status !== "closed").forEach((item) => caseChoice.append(node("option", { value: item.id, text: `${item.reference} | ${item.title}` })))).catch(fail);
      const link = node("form", { class: "form-grid" }, [field(SOCifyLocale.text("ربط بقضية قائمة"), caseChoice, true), node("div", { class: "action-row span-2" }, node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("ربط التنبيه") }))]);
      link.addEventListener("submit", async (event) => {
        event.preventDefault();
        try { await api(`/api/intake/alerts/${alert.id}/link`, { method: "POST", body: { case_id: Number(caseChoice.value) } }); onDone(); } catch (error) { fail(error); }
      });
      const reason = node("input", { name: "reason", required: true, minlength: 5, maxlength: 500 });
      const dismiss = node("form", { class: "form-grid" }, [field(SOCifyLocale.text("سبب الاستبعاد"), reason, true), node("div", { class: "action-row span-2" }, node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("استبعاد التنبيه") }))]);
      dismiss.addEventListener("submit", async (event) => {
        event.preventDefault();
        try { await api(`/api/intake/alerts/${alert.id}/dismiss`, { method: "POST", body: { reason: reason.value.trim() } }); onDone(); } catch (error) { fail(error); }
      });
      content.append(create, link, dismiss, errors);
    }
    return content;
  }

  async function render(head, channels) {
    begin("monitoring");
    const params = new URLSearchParams(location.search);
    const filters = { status: params.get("status") || "open", severity: params.get("severity") || "", integration_id: params.get("integration_id") || "", page: params.get("page") || "1" };
    const query = new URLSearchParams(Object.entries(filters).filter(([, value]) => value));
    const [data, integrations] = await Promise.all([api("/api/intake/alerts?" + query), api("/api/intake/integrations")]);
    const root = node("div", { class: "monitoring-view intake-view" }, pageHead(...head));
    root.append(node("nav", { class: "channel-tabs", "aria-label": SOCifyLocale.text("قنوات التنبيهات") }, [
      ...channels.map(([value, label]) => { const target = new URL(location.href); target.search = new URLSearchParams({ channel: value }).toString(); return node("a", { class: "channel-tab", href: target.pathname + target.search }, node("span", { text: label })); }),
      node("a", { class: "channel-tab", href: "/monitoring?channel=intake", "aria-current": "page" }, [node("span", { text: SOCifyLocale.text("الوارد") }), node("span", { class: "channel-count", text: String(data.total) })]),
    ]));
    const status = node("select", { name: "status" }, Object.keys(statusLabels).map((value) => node("option", { value, selected: value === filters.status, text: statusLabels[value]() })));
    const severity = node("select", { name: "severity" }, [node("option", { value: "", text: SOCifyLocale.text("جميع الدرجات") }), ...["critical", "high", "medium", "low", "info"].map((value) => node("option", { value, selected: value === filters.severity, text: severityLabel(value) }))]);
    const integration = node("select", { name: "integration_id" }, [node("option", { value: "", text: SOCifyLocale.text("جميع التكاملات") }), ...integrations.items.map((item) => node("option", { value: item.id, selected: String(item.id) === filters.integration_id, text: item.name }))]);
    const form = node("form", { class: "filter-row", "aria-label": SOCifyLocale.text("تصفية التنبيهات الواردة") }, [field(SOCifyLocale.text("الحالة"), status), field(SOCifyLocale.text("الخطورة"), severity), field(SOCifyLocale.text("التكامل"), integration), node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("تطبيق") })]);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const next = new URLSearchParams({ channel: "intake", status: status.value });
      if (severity.value) next.set("severity", severity.value);
      if (integration.value) next.set("integration_id", integration.value);
      location.assign("/monitoring?" + next);
    });
    root.append(form);
    const reload = () => render(head, channels).catch(handleError);
    const open = async (alert) => {
      const full = await api(`/api/intake/alerts/${alert.id}`);
      const dialog = autopsyModal(full.title, details(full, () => { dialog.close(); reload(); }));
    };
    root.append(panel(SOCifyLocale.text("التنبيهات الواردة"), data.items.length ? table([
      { label: SOCifyLocale.text("الخطورة"), value: (item) => node("span", { class: `badge badge-severity ${item.severity === "info" ? "low" : item.severity}`, text: severityLabel(item.severity) }) },
      { label: SOCifyLocale.text("التنبيه"), value: (item) => node("span", { "data-user-content": "true", text: item.title }) },
      { label: SOCifyLocale.text("التكامل"), value: "integration_name" },
      { label: SOCifyLocale.text("آخر ظهور"), value: (item) => formatTime(item.last_seen) },
      { label: SOCifyLocale.text("التكرار"), value: (item) => String(item.occurrence_count) },
      { label: SOCifyLocale.text("الحالة"), value: (item) => node("span", { class: "badge", text: statusLabels[item.status]() }) },
      { label: SOCifyLocale.text("إجراء"), value: (item) => button(SOCifyLocale.text("عرض التنبيه"), () => open(item).catch(handleError)) },
    ], data.items) : emptyState(SOCifyLocale.text("لا توجد تنبيهات واردة بهذه المرشحات"), integrations.items.length ? null : SOCifyLocale.text("يضيف مدير الفريق تكاملات الاستقبال من صفحة الفريق.")), true));
    finish(root);
  }

  // Integrations on the team page, for managers: add one (kind, name, token or HMAC, automatic cases) and switch it on or off.
  async function integrationsPanel() {
    if (!["soc_manager", "admin"].includes(state.user?.role) || !permission("intake.read")) return null;
    const holder = node("div", { class: "panel-body" });
    const draw = async () => {
      const data = await api("/api/intake/integrations");
      const kind = node("select", { name: "kind" }, data.kinds.map((value) => node("option", { value, text: { wazuh: "Wazuh", elastic: "Elastic Security", splunk: "Splunk", sentinel: "Microsoft Sentinel", generic: SOCifyLocale.text("صيغة SOCify العامة") }[value] })));
      const name = node("input", { name: "name", required: true, minlength: 3, maxlength: 120 });
      const auth = node("select", { name: "auth_mode" }, [["hmac", SOCifyLocale.text("توقيع HMAC")], ["token", SOCifyLocale.text("رمز API بنطاق intake:write")]].map(([value, label]) => node("option", { value, text: label })));
      const minimum = node("select", { name: "min_severity" }, [node("option", { value: "", text: SOCifyLocale.text("لا تُنشأ قضايا تلقائيًا") }), ...["critical", "high", "medium"].map((value) => node("option", { value, text: SOCifyLocale.template`تلقائيًا من خطورة ${autopsyLabel(value)} فأعلى` }))]);
      const errors = node("p", { class: "notice", role: "alert", hidden: true });
      const form = node("form", { class: "form-grid" }, [field(SOCifyLocale.text("النوع"), kind), field(SOCifyLocale.text("الاسم"), name), field(SOCifyLocale.text("المصادقة"), auth), field(SOCifyLocale.text("إنشاء القضايا"), minimum), node("div", { class: "action-row span-2" }, node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("إضافة التكامل") })), errors]);
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          const created = await api("/api/intake/integrations", { method: "POST", body: { kind: kind.value, name: name.value.trim(), auth_mode: auth.value, auto_case: minimum.value ? { min_severity: minimum.value } : null } });
          SOCifyDrafts.saved(form);
          const endpoint = new URL(created.item.endpoint, window.location.origin).toString();
          autopsyModal(SOCifyLocale.text("تكامل استقبال جديد"), node("div", {}, [
            field(SOCifyLocale.text("عنوان الاستقبال"), node("input", { readonly: true, value: endpoint, dir: "ltr" })),
            created.hmac_secret ? node("p", { text: SOCifyLocale.text("سر التوقيع يظهر الآن فقط؛ احفظه في إعدادات نظام المراقبة.") }) : node("p", { text: SOCifyLocale.text("أنشئ رمز API بنطاق intake:write وأرسله في Authorization: Bearer.") }),
            created.hmac_secret ? field(SOCifyLocale.text("سر التوقيع"), node("input", { readonly: true, value: created.hmac_secret, dir: "ltr", "data-intake-secret": "" })) : null,
          ]));
          await draw();
        } catch (error) { errors.textContent = error.message; errors.hidden = false; }
      });
      SOCifyDrafts.track(form);
      const list = data.items.length ? table([
        { label: SOCifyLocale.text("الاسم"), value: (item) => node("span", { "data-user-content": "true", text: item.name }) },
        { label: SOCifyLocale.text("النوع"), value: "kind" },
        { label: SOCifyLocale.text("المصادقة"), value: (item) => (item.auth_mode === "hmac" ? "HMAC" : "API token") },
        { label: SOCifyLocale.text("العنوان"), value: (item) => node("bdi", { dir: "ltr", text: item.endpoint }) },
        { label: SOCifyLocale.text("الحالة"), value: (item) => node("span", { class: "badge", text: item.enabled ? SOCifyLocale.text("يعمل") : SOCifyLocale.text("موقوف") }) },
        { label: SOCifyLocale.text("إجراء"), value: (item) => button(item.enabled ? SOCifyLocale.text("إيقاف") : SOCifyLocale.text("تشغيل"), async () => { await api(`/api/intake/integrations/${item.id}`, { method: "PATCH", body: { enabled: !item.enabled } }); await draw(); }) },
      ], data.items) : emptyState(SOCifyLocale.text("لا توجد تكاملات استقبال"), null);
      holder.replaceChildren(node("p", { text: SOCifyLocale.text("استقبل تنبيهات SIEM وEDR في قناة الوارد بصفحة التنبيهات، ثم حوّلها إلى قضايا.") }), form, list);
    };
    try { await draw(); } catch (error) { holder.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message })); }
    return panel(SOCifyLocale.text("تكاملات الاستقبال"), holder, true);
  }

  return Object.freeze({ render, integrationsPanel });
})();
