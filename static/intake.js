"use strict";

// The Intake channel on the alerts page: alerts received from a SIEM or EDR, before they become cases. Built on the
// same surface as the other alert channels (filters, last update, rows that expand in place, pagination). An expanded
// row shows the normalised fields, the entities and (with intake.triage) the raw payload, and the triage actions:
// take the alert, create a case from it, link it to an open case, or dismiss it with a reason.
// The Integrations page (managers) lists the intake integrations next to the API tokens.
window.SOCifyIntake = (() => {
  const t = (value) => SOCifyLocale.text(value);
  const number = (value) => new Intl.NumberFormat(SOCifyLocale.locale).format(value);
  const statusLabels = {
    open: () => t("بانتظار الفرز"),
    new: () => t("جديد"),
    triaging: () => t("قيد الفرز"),
    linked: () => t("مربوط بقضية"),
    dismissed: () => t("مستبعد"),
    all: () => t("الكل"),
  };
  const entityLabels = {
    hosts: () => t("الأجهزة"),
    users: () => t("المستخدمون"),
    ips: () => t("عناوين IP"),
    domains: () => t("النطاقات"),
    urls: () => t("الروابط"),
    hashes: () => t("البصمات"),
  };
  const kindLabels = { wazuh: "Wazuh", elastic: "Elastic Security", splunk: "Splunk", sentinel: "Microsoft Sentinel", generic: () => t("صيغة SOCify العامة") };
  const kindLabel = (kind) => (typeof kindLabels[kind] === "function" ? kindLabels[kind]() : kindLabels[kind] || kind);
  const severityLabel = (value) => (value === "info" ? t("معلوماتي") : autopsyLabel(value));
  const severityBadge = (value) => node("span", { class: `badge badge-severity ${value === "info" ? "low" : value}`, text: severityLabel(value) });
  const columns = () => [t("التفاصيل"), t("الخطورة"), t("آخر ظهور"), t("التنبيه"), t("المصدر"), t("التكرار"), t("المسؤول"), t("الحالة")];

  function facts(alert) {
    const n = alert.normalized;
    const rows = [
      [t("التكامل"), `${alert.integration_name} | ${kindLabel(alert.integration_kind)}`],
      [t("القاعدة"), [n.rule_name, n.rule_id].filter(Boolean).join(" | ") || "—"],
      [t("معرف المصدر"), alert.external_id || "—"],
      [t("أول ظهور"), formatTime(alert.first_seen)],
      [t("آخر ظهور"), formatTime(alert.last_seen)],
      [t("مرات التكرار"), String(alert.occurrence_count)],
      ["MITRE ATT&CK", n.mitre.length ? n.mitre.join(" | ") : "—"],
      [t("بصمة الحمولة SHA-256"), alert.raw_sha256],
    ];
    const entities = Object.entries(n.entities).filter(([, values]) => values.length);
    return node("div", { class: "intake-facts" }, [
      node("table", { class: "alert-property-table" }, node("tbody", {}, rows.map(([label, value], index) => node("tr", {}, [
        node("th", { scope: "row", text: label }),
        index === rows.length - 1 ? node("td", { class: "mono", dir: "ltr", text: value }) : node("td", { dir: "auto", "data-user-content": "true", text: value }),
      ])))),
      n.description ? node("p", { class: "intake-description", "data-user-content": "true", text: n.description }) : null,
      entities.length ? node("dl", { class: "intake-entities" }, entities.flatMap(([kind, values]) => [
        node("dt", { text: entityLabels[kind]() }),
        node("dd", {}, values.map((value) => node("bdi", { class: "badge", dir: "ltr", "data-user-content": "true", text: value }))),
      ])) : null,
      alert.raw !== undefined ? node("details", { class: "intake-raw" }, [node("summary", { text: t("الحمولة الأصلية") }), node("pre", { dir: "ltr", "data-user-content": "true", text: JSON.stringify(alert.raw, null, 2) })]) : null,
    ]);
  }

  // Triage actions for an open alert. One short form shows at a time under the buttons; the list reloads after each action.
  function triage(alert, done) {
    const holder = node("div", { class: "intake-triage" });
    const errors = node("p", { class: "notice", role: "alert", hidden: true });
    const fail = (error) => { errors.textContent = error.message; errors.hidden = false; };
    const busy = (control, action) => async (event) => {
      event?.preventDefault();
      errors.hidden = true;
      control.disabled = true;
      try { await action(); } catch (error) { fail(error); } finally { control.disabled = false; }
    };
    const mine = alert.claimed_by === state.user?.id;
    const owner = alert.claimed_by_name
      ? node("p", { class: "intake-owner" }, [node("span", { text: t("يتولاه") }), personChip(alert.claimed_by_name), node("time", { class: "cell-meta", datetime: alert.claimed_at, text: formatTime(alert.claimed_at) })])
      : null;
    const take = button(mine ? t("إعادة إلى القائمة") : t("أتولى الفرز"), null);
    take.addEventListener("click", busy(take, async () => { await api(`/api/intake/alerts/${alert.id}/${mine ? "release" : "claim"}`, { method: "POST", body: {} }); done(); }));
    const slot = node("div", { class: "intake-action-form" });
    const reveal = (form) => { slot.replaceChildren(form); form.querySelector("input,select")?.focus(); };

    const create = button(t("إنشاء قضية"), null, "primary");
    create.addEventListener("click", busy(create, async () => {
      const made = await api(`/api/intake/alerts/${alert.id}/case`, { method: "POST", body: {} });
      window.location.assign(`/cases/${made.case_id}`);
    }));

    const caseChoice = node("select", { name: "case_id", required: true }, [node("option", { value: "", text: t("اختر القضية") })]);
    const linkSubmit = node("button", { type: "submit", class: "button", text: t("ربط التنبيه") });
    const linkForm = node("form", { class: "inline-action" }, [field(t("القضية"), caseChoice), linkSubmit]);
    linkForm.addEventListener("submit", busy(linkSubmit, async () => { await api(`/api/intake/alerts/${alert.id}/link`, { method: "POST", body: { case_id: Number(caseChoice.value) } }); done(); }));
    const link = button(t("ربط بقضية"), () => {
      reveal(linkForm);
      if (caseChoice.options.length > 1) return;
      api("/api/cases?page=1&page_size=50").then((cases) => cases.items.filter((item) => item.status !== "closed").forEach((item) => caseChoice.append(node("option", { value: item.id, text: `${item.reference} | ${item.title}` })))).catch(fail);
    });

    const reason = node("input", { name: "reason", required: true, minlength: 5, maxlength: 500, autocomplete: "off" });
    const dismissSubmit = node("button", { type: "submit", class: "button", text: t("استبعاد التنبيه") });
    const dismissForm = node("form", { class: "inline-action" }, [field(t("سبب الاستبعاد"), reason), dismissSubmit]);
    dismissForm.addEventListener("submit", busy(dismissSubmit, async () => { await api(`/api/intake/alerts/${alert.id}/dismiss`, { method: "POST", body: { reason: reason.value.trim() } }); done(); }));
    const dismiss = button(t("استبعاد"), () => reveal(dismissForm));

    holder.append(...[owner, node("div", { class: "action-row" }, [create, link, dismiss, take]), slot, errors].filter(Boolean));
    return holder;
  }

  function outcome(alert) {
    if (alert.case_id) return node("div", { class: "action-row" }, linkedButton(t("فتح القضية"), `/cases/${alert.case_id}`));
    if (alert.dismissed_reason) return node("p", { class: "notice", "data-user-content": "true", text: SOCifyLocale.template`سبب الاستبعاد: ${alert.dismissed_reason}` });
    return null;
  }

  async function render(head, channels) {
    const version = Symbol("intake");
    render.version = version;
    begin("monitoring");
    const params = new URLSearchParams(location.search);
    const filters = {
      q: params.get("q") || "",
      status: params.get("status") || "open",
      severity: params.get("severity") || "",
      integration_id: params.get("integration_id") || "",
      mine: params.get("mine") === "1" ? "1" : "",
      page: params.get("page") || "",
    };
    const query = new URLSearchParams(Object.entries(filters).filter(([, value]) => value));
    const [data, integrations, counts] = await Promise.all([
      api("/api/intake/alerts?" + query),
      api("/api/intake/integrations"),
      api("/api/soc/monitoring?page_size=1").then((answer) => answer.counts).catch(() => ({})),
    ]);
    if (render.version !== version) return;
    const reload = () => render(head, channels).catch(handleError);
    const root = node("div", { class: "monitoring-view intake-view" }, pageHead(...head));
    root.append(node("nav", { class: "channel-tabs", "aria-label": t("قنوات التنبيهات") }, [
      ...channels.map(([value, label]) => node("a", { class: "channel-tab", href: `/monitoring?channel=${value}` }, [node("span", { text: label }), node("span", { class: "channel-count", text: number(counts[value] ?? 0) })])),
      node("a", { class: "channel-tab", href: "/monitoring?channel=intake", "aria-current": "page" }, [node("span", { text: t("الوارد") }), node("span", { class: "channel-count", text: number(data.open) })]),
    ]));

    const search = node("input", { name: "q", type: "search", maxlength: 200, value: filters.q, autocomplete: "off", placeholder: t("بحث") });
    const severity = node("select", { name: "severity" }, [["", t("جميع الدرجات")], ...["critical", "high", "medium", "low", "info"].map((value) => [value, severityLabel(value)])].map(([value, label]) => node("option", { value, selected: value === filters.severity, text: label })));
    const status = node("select", { name: "status" }, Object.keys(statusLabels).map((value) => node("option", { value, selected: value === filters.status, text: statusLabels[value]() })));
    const integration = node("select", { name: "integration_id" }, [node("option", { value: "", text: t("جميع التكاملات") }), ...integrations.items.map((item) => node("option", { value: item.id, selected: String(item.id) === filters.integration_id, text: item.name }))]);
    const mine = node("select", { name: "mine" }, [["", t("جميع التنبيهات")], ["1", t("التي أتولاها")]].map(([value, label]) => node("option", { value, selected: value === filters.mine, text: label })));
    const form = node("form", { class: "monitoring-toolbar", "aria-label": t("مرشحات التنبيهات") }, [field(t("بحث"), search), field(t("الخطورة"), severity), field(t("الحالة"), status), field(t("المصدر"), integration), field(t("المسؤول"), mine), node("button", { type: "submit", class: "button", text: t("تطبيق") })]);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const next = new URLSearchParams({ channel: "intake" });
      for (const [key, control] of Object.entries({ q: search, severity, status, integration_id: integration, mine })) {
        const value = control.value.trim();
        if (value && !(key === "status" && value === "open")) next.set(key, value);
      }
      location.assign("/monitoring?" + next);
    });
    const surface = node("section", { class: "monitoring-surface", "aria-label": t("نتائج التنبيهات") }, [form, node("div", { class: "monitoring-caption" }, node("p", { text: t("آخر تحديث") + ": " + formatTime(data.fetched_at) }))]);

    if (!data.items.length) {
      const manage = !integrations.items.length && permission("integrations.manage") ? [linkedButton(t("إضافة تكامل"), "/integrations")] : [];
      surface.append(emptyState(t("لا توجد تنبيهات"), null, manage));
    } else {
      const labels = columns();
      const body = node("tbody");
      for (const item of data.items) {
        const detailId = `intake-details-${item.id}`;
        const content = node("div", { class: "intake-detail" });
        const detail = node("tr", { id: detailId, hidden: true }, node("td", { colspan: labels.length, class: "alert-detail-cell" }, content));
        let loaded = false;
        const expand = node("button", { type: "button", class: "row-expand", "aria-label": t("تفاصيل التنبيه") + " " + item.title, "aria-expanded": "false", "aria-controls": detailId });
        expand.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
        const titleToggle = node("button", { type: "button", class: "alert-name", "data-user-content": "true", "aria-expanded": "false", "aria-controls": detailId, text: item.title });
        const toggle = async () => {
          detail.hidden = !detail.hidden;
          for (const control of [expand, titleToggle]) control.setAttribute("aria-expanded", String(!detail.hidden));
          if (detail.hidden || loaded) return;
          expand.disabled = true;
          try {
            const full = await api(`/api/intake/alerts/${item.id}`);
            const open = ["new", "triaging"].includes(full.status);
            content.replaceChildren(facts(full), open && data.can_triage ? triage(full, reload) : outcome(full) || node("div"));
            loaded = true;
          } catch (error) { content.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message })); }
          finally { expand.disabled = false; }
        };
        expand.addEventListener("click", toggle);
        titleToggle.addEventListener("click", toggle);
        const rule = item.normalized.rule_name && item.normalized.rule_name !== item.title ? item.normalized.rule_name : item.external_id;
        const statusCell = item.case_id
          ? node("div", {}, [node("span", { class: "badge", text: statusLabels[item.status]() }), node("a", { class: "case-link cell-meta", href: `/cases/${item.case_id}`, text: t("فتح القضية") })])
          : node("span", { class: "badge", text: statusLabels[item.status]() });
        const cells = [
          expand,
          severityBadge(item.severity),
          node("time", { datetime: item.last_seen, text: formatTime(item.last_seen) }),
          node("div", { class: "rule-cell" }, [titleToggle, rule ? node("small", { dir: "auto", "data-user-content": "true", text: rule }) : null]),
          node("span", { "data-user-content": "true", text: item.integration_name }),
          node("span", { class: "numeric", text: number(item.occurrence_count) }),
          personChip(item.claimed_by_name),
          statusCell,
        ];
        body.append(node("tr", { "data-intake-row": item.id }, cells.map((value, index) => node("td", { "data-label": labels[index] }, value))), detail);
      }
      const headRow = node("thead", {}, node("tr", {}, labels.map((label) => node("th", { scope: "col", text: label }))));
      surface.append(node("div", { class: "table-wrap", role: "region", tabindex: 0, "aria-label": t("جدول التنبيهات") }, node("table", { class: "monitoring-table" }, [headRow, body])));
    }
    root.append(surface);
    if (data.total > data.page_size || data.page > 1) {
      const pages = node("nav", { class: "pagination monitoring-pagination", "aria-label": t("جدول التنبيهات") }, node("p", { text: t("الصفحة") + " " + number(data.page) + " / " + number(Math.max(1, Math.ceil(data.total / data.page_size))) }));
      for (const [label, page] of [[t("السابق"), data.page - 1], [t("التالي"), data.page + 1]]) {
        if (page < 1 || (page === data.page + 1 && data.page * data.page_size >= data.total)) continue;
        const target = new URL(location.href);
        target.searchParams.set("page", String(page));
        pages.append(linkedButton(label, target.pathname + target.search));
      }
      root.append(pages);
    }
    finish(root);
  }

  function ruleLabel(rules) {
    return rules.min_severity ? SOCifyLocale.template`من خطورة ${autopsyLabel(rules.min_severity)} فأعلى` : t("يدويًا");
  }

  // Intake integrations for managers: the list first, a dialog to add one, and the endpoint and secret shown once.
  async function integrationsPanel() {
    const holder = node("div", { class: "panel-body" });
    const add = button(t("إضافة تكامل"), null, "primary");
    const draw = async () => {
      const data = await api("/api/intake/integrations");
      add.onclick = () => {
        const kind = node("select", { name: "kind" }, data.kinds.map((value) => node("option", { value, text: kindLabel(value) })));
        const name = node("input", { name: "name", required: true, minlength: 3, maxlength: 120 });
        const auth = node("select", { name: "auth_mode" }, [["hmac", t("توقيع HMAC")], ["token", t("رمز API بنطاق intake:write")]].map(([value, label]) => node("option", { value, text: label })));
        const minimum = node("select", { name: "min_severity" }, [node("option", { value: "", text: t("يدويًا") }), ...["critical", "high", "medium"].map((value) => node("option", { value, text: SOCifyLocale.template`من خطورة ${autopsyLabel(value)} فأعلى` }))]);
        const errors = node("p", { class: "notice", role: "alert", hidden: true });
        const submit = node("button", { type: "submit", class: "button primary", text: t("إضافة التكامل") });
        const form = SOCifyDrafts.track(node("form", { class: "form-grid" }, [field(t("النوع"), kind), field(t("الاسم"), name), field(t("المصادقة"), auth), field(t("إنشاء القضايا"), minimum), node("div", { class: "action-row span-2" }, submit), errors]));
        const dialog = autopsyModal(t("تكامل استقبال جديد"), form);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          errors.hidden = true;
          submit.disabled = true;
          try {
            const created = await api("/api/intake/integrations", { method: "POST", body: { kind: kind.value, name: name.value.trim(), auth_mode: auth.value, auto_case: minimum.value ? { min_severity: minimum.value } : null } });
            SOCifyDrafts.saved(form);
            dialog.close();
            const endpoint = new URL(created.item.endpoint, window.location.origin).toString();
            autopsyModal(t("تكامل استقبال جديد"), node("div", { class: "form-grid" }, [
              field(t("عنوان الاستقبال"), node("input", { readonly: true, value: endpoint, dir: "ltr" }), true),
              created.hmac_secret
                ? field(t("سر التوقيع"), node("input", { readonly: true, value: created.hmac_secret, dir: "ltr", "data-intake-secret": "" }), true)
                : node("p", { class: "field-hint span-2", text: t("أرسل رمز API بنطاق intake:write في Authorization: Bearer.") }),
              created.hmac_secret ? node("p", { class: "field-hint span-2", text: t("يظهر السر مرة واحدة فقط.") }) : null,
            ]));
            await draw();
          } catch (error) { errors.textContent = error.message; errors.hidden = false; }
          finally { submit.disabled = false; }
        });
      };
      holder.replaceChildren(data.items.length ? table([
        { label: t("الاسم"), value: (item) => node("span", { "data-user-content": "true", text: item.name }) },
        { label: t("النوع"), value: (item) => kindLabel(item.kind) },
        { label: t("المصادقة"), value: (item) => (item.auth_mode === "hmac" ? "HMAC" : t("رمز API")) },
        { label: t("عنوان الاستقبال"), value: (item) => node("bdi", { class: "mono", dir: "ltr", text: new URL(item.endpoint, window.location.origin).toString() }) },
        { label: t("إنشاء القضايا"), value: (item) => ruleLabel(item.auto_case) },
        { label: t("الحالة"), value: (item) => node("span", { class: "badge", text: item.enabled ? t("يعمل") : t("موقوف") }) },
        { label: t("إجراء"), value: (item) => button(item.enabled ? t("إيقاف") : t("تشغيل"), async () => { try { await api(`/api/intake/integrations/${item.id}`, { method: "PATCH", body: { enabled: !item.enabled } }); await draw(); } catch (error) { handleError(error); } }) },
      ], data.items) : emptyState(t("لا توجد تكاملات استقبال"), null));
    };
    try { await draw(); } catch (error) { holder.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message })); }
    return panel(t("الاستقبال"), holder, true, add);
  }

  async function page() {
    begin("integrations");
    if (!permission("integrations.manage")) {
      finish(emptyState(t("هذا القسم غير متاح لدورك"), null));
      return;
    }
    const root = node("div", { class: "integrations-view" }, pageHead(t("التكاملات"), null));
    const [intake, tokens] = await Promise.all([integrationsPanel(), window.SOCifyApiTokens ? window.SOCifyApiTokens.panel() : Promise.resolve(null)]);
    root.append(intake);
    if (tokens) root.append(tokens);
    finish(root);
  }

  return Object.freeze({ render, page });
})();
