"use strict";

const teamPermissionLabels = {
  "alerts.read": "عرض التنبيهات", "alerts.triage": "فرز التنبيهات",
  "intake.read": "عرض التنبيهات الواردة", "intake.triage": "فرز التنبيهات الواردة",
  "audit.read": "عرض سجل التدقيق", "cases.create": "إنشاء القضايا",
  "cases.export": "تصدير القضايا", "cases.read": "عرض القضايا", "cases.update": "تعديل القضايا",
  "events.create": "استيراد السجلات", "events.read": "عرض السجلات",
  "evidence.add": "إضافة الأدلة", "evidence.download": "تنزيل الأدلة",
  "graph.read": "عرض علاقات الأدلة", "hunt.execute": "تنفيذ بحث التحقيق",
  "hunt.save": "حفظ بحث التحقيق", "hunt.share": "مشاركة بحث التحقيق",
  "notes.add": "إضافة الملاحظات", "playbooks.request": "طلب تشغيل إجراءات الاستجابة",
  "reports.approve": "اعتماد التقارير", "rules.read": "عرض قواعد الكشف", "sources.read": "عرض مصادر السجلات"
};

async function autopsyAssignmentQueue(mine = false) {
  const params = new URLSearchParams(window.location.search);
  const body = node("div", { class: "panel-body assignment-queue" });
  const query = node("input", { type: "search", name: "task_q", maxlength: 200, value: params.get("task_q") || "" });
  const labels = { "": "كل الحالات", pending: "لم تبدأ", in_progress: "جارٍ", completed: "مكتمل", reviewed: "تمت المراجعة" };
  const status = node("select", { name: "task_status" }, Object.entries(labels).map(([value, label]) => node("option", { value, selected: value === (params.get("task_status") || ""), text: SOCifyLocale.text(label) })));
  const notice = node("p", { role: "alert", class: "notice", hidden: true });
  const results = node("div", { class: "assignment-results", "aria-live": "polite" });
  let currentPage = Number(params.get("task_page")) || 1;
  let requestId = 0;
  const load = async (page = currentPage) => {
    const request = ++requestId;
    results.setAttribute("aria-busy", "true");
    const filters = { q: query.value.trim(), status: status.value };
    const options = new URLSearchParams({ scope: mine ? "me" : "team", ...filters, page: String(page) });
    try {
      const data = await api(`/api/team/assignments?${options}`);
      if (request !== requestId) return;
      if (data.total > 0 && !data.items.length && data.page > 1) return load(Math.ceil(data.total / data.page_size));
      currentPage = data.page;
      const url = new URL(window.location.href);
      for (const [key, value] of Object.entries({ task_q: filters.q, task_status: filters.status, task_page: currentPage > 1 ? String(currentPage) : "" })) value ? url.searchParams.set(key, value) : url.searchParams.delete(key);
      window.history.replaceState(null, "", url);
      const update = async (row, target, actions) => {
        notice.hidden = true;
        actions.querySelectorAll("button").forEach(control => { control.disabled = true; });
        try { await api(`/api/team/assignments/${row.id}`, { method: "PATCH", body: { status: target, expected_status: row.task_status } }); await load(); }
        catch (error) { notice.textContent = error.message; notice.hidden = false; }
        finally { actions.querySelectorAll("button").forEach(control => { control.disabled = false; }); }
      };
      const columns = [
        { label: SOCifyLocale.text("القضية"), value: row => node("div", {}, [linkedButton(row.reference, `/cases/${row.case_id}`), node("p", { text: row.case_title, "data-user-content": "true" })]) },
        { label: SOCifyLocale.text("الملف"), value: "filename" },
        { label: SOCifyLocale.text("التعليمات"), value: "instructions" },
        ...(!mine ? [{ label: SOCifyLocale.text("المسؤول"), value: (row) => personChip(row.assignee_name) }] : []),
        { label: SOCifyLocale.text("الحالة"), value: row => SOCifyLocale.text(labels[row.task_status] || row.task_status) },
        { label: SOCifyLocale.text("الإجراء"), value: row => {
          const actions = node("div", { class: "action-row" }, linkedButton(SOCifyLocale.text("فتح الدفعة"), `/cases/${row.case_id}?tab=logs&job_id=${row.job_id}`));
          if (row.can_update) {
            if (row.task_status === "pending") actions.append(button(SOCifyLocale.text("بدء التحليل"), () => update(row, "in_progress", actions)));
            if (["pending", "in_progress"].includes(row.task_status)) actions.append(button(SOCifyLocale.text("إكمال المهمة"), () => update(row, "completed", actions)));
            else actions.append(button(SOCifyLocale.text("إعادة فتح المهمة"), () => update(row, "in_progress", actions)));
          }
          return actions;
        } },
      ];
      const previous = button(SOCifyLocale.text("السابق"), () => load(currentPage - 1));
      previous.disabled = currentPage <= 1;
      const next = button(SOCifyLocale.text("التالي"), () => load(currentPage + 1));
      next.disabled = currentPage * data.page_size >= data.total;
      let content = emptyState(SOCifyLocale.text("لا مهام مطابقة"), null);
      if (data.items.length) {
        content = stackedTable(columns, data.items);
      }
      const pages = data.total > data.page_size || currentPage > 1 ? node("div", { class: "action-row" }, [previous, node("span", { text: SOCifyLocale.template`الصفحة ${currentPage} من ${Math.max(1, Math.ceil(data.total / data.page_size))}` }), next]) : null;
      results.replaceChildren(...[content, pages].filter(Boolean));
    } catch (error) { if (request === requestId) { notice.textContent = error.message; notice.hidden = false; } }
    finally { if (request === requestId) results.setAttribute("aria-busy", "false"); }
  };
  const form = node("form", { class: "filter-row" }, [field(SOCifyLocale.text("بحث المهام"), query), field(SOCifyLocale.text("الحالة"), status), node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("بحث") }), button(SOCifyLocale.text("تحديث القائمة"), () => { notice.hidden = true; return load(); })]);
  form.addEventListener("submit", event => { event.preventDefault(); notice.hidden = true; load(1); });
  body.append(form, notice, results);
  await load();
  return panel(SOCifyLocale.text(mine ? "مهامي داخل القضايا" : "دفعات الفريق"), body, true);
}

// The team's response-time policy: one budget per severity and the calendar it is counted in, applied to new cases.
async function teamSlaPanel() {
  const t = (value) => SOCifyLocale.text(value);
  const data = await api("/api/team/sla-policy");
  const severities = ["critical", "high", "medium", "low"];
  const policy = data.policy;
  const duration = (value) => (value % 60 === 0 ? SOCifyLocale.template`${value / 60} ساعة` : SOCifyLocale.template`${value} دقيقة`);
  const calendarText = (calendar) => (calendar.mode === "business"
    ? `${autopsyLabel(calendar.weekdays.includes(6) ? "sun_thu" : "mon_fri")} | ${calendar.start_hour}:00–${calendar.end_hour}:00 | ${calendar.timezone}`
    : `${autopsyLabel("24x7")} | ${calendar.timezone}`);
  const body = node("div", { class: "panel-body" });
  if (policy) {
    body.append(
      node("ul", { class: "sla-policy-grid" }, severities.map((severity) => node("li", {}, [autopsyBadge(severity), node("strong", { text: duration(policy.minutes[severity]) })]))),
      node("p", { class: "panel-caption" }, [node("span", { text: calendarText(policy.calendar) }), " | ", node("span", { text: SOCifyLocale.template`الإصدار ${policy.version}، للقضايا الجديدة` })]),
    );
  } else {
    body.append(node("p", { class: "panel-caption", text: t("لا توجد سياسة؛ تُحسب المهلة بساعات ثابتة حسب الأولوية") }));
  }
  if (!data.can_manage) return panel(t("مهلة الاستجابة"), body, true);

  const current = policy || { minutes: data.suggested_minutes, calendar: { mode: "24x7", timezone: "UTC" } };
  const hours = Object.fromEntries(severities.map((severity) => [severity, node("input", { name: `hours_${severity}`, type: "number", min: 0.25, max: 8760, step: 0.25, required: true, value: current.minutes[severity] / 60, dir: "ltr" })]));
  const mode = node("select", { name: "mode" }, ["24x7", "business"].map((value) => node("option", { value, selected: value === current.calendar.mode, text: autopsyLabel(value) })));
  const zone = autopsyChoice("timezone", autopsy.catalog.source_timezones || ["UTC"], current.calendar.timezone || "UTC", true);
  const weekdays = node("select", { name: "weekdays" }, ["sun_thu", "mon_fri"].map((value) => node("option", { value, selected: value === (current.calendar.weekdays?.includes(6) ? "sun_thu" : current.calendar.weekdays ? "mon_fri" : "sun_thu"), text: autopsyLabel(value) })));
  const start = node("input", { name: "start_hour", type: "number", min: 0, max: 23, required: true, value: current.calendar.start_hour ?? 8, dir: "ltr" });
  const end = node("input", { name: "end_hour", type: "number", min: 1, max: 24, required: true, value: current.calendar.end_hour ?? 16, dir: "ltr" });
  const holidays = node("input", { name: "holidays", maxlength: 1200, value: (current.calendar.holidays || []).join(", "), placeholder: "2026-12-18, 2027-02-22", dir: "ltr", autocomplete: "off" });
  const businessFields = [field(t("أيام العمل"), weekdays), field(t("ساعة بدء العمل"), start), field(t("ساعة انتهاء العمل"), end), field(t("أيام الإجازة"), holidays)];
  const errors = node("p", { class: "notice span-2", role: "alert", hidden: true });
  const submit = node("button", { type: "submit", class: "button primary", text: t("حفظ السياسة") });
  const form = SOCifyDrafts.track(node("form", { class: "form-grid", "aria-label": t("مهلة الاستجابة") }, [
    node("fieldset", { class: "span-2 sla-policy-hours" }, [node("legend", { text: t("المهلة بالساعات") }), ...severities.map((severity) => field(autopsyLabel(severity), hours[severity]))]),
    field(t("تقويم الاحتساب"), mode),
    field(t("المنطقة الزمنية"), zone.control),
    ...businessFields,
    errors,
    node("div", { class: "action-row span-2" }, submit),
  ]));
  const toggle = () => { for (const item of businessFields) { item.hidden = mode.value !== "business"; item.querySelector("input,select").required = !item.hidden && item.querySelector("[name=holidays]") === null; } };
  mode.addEventListener("change", toggle);
  toggle();
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errors.hidden = true;
    const calendar = { mode: mode.value, timezone: zone.input.autopsyValue() || "UTC" };
    if (mode.value === "business") {
      Object.assign(calendar, {
        weekdays: weekdays.value === "sun_thu" ? [6, 0, 1, 2, 3] : [0, 1, 2, 3, 4],
        start_hour: Number(start.value),
        end_hour: Number(end.value),
        holidays: holidays.value.split(/[\s,،]+/).map((value) => value.trim()).filter(Boolean),
      });
    }
    submit.disabled = true;
    try {
      await api("/api/team/sla-policy", { method: "PUT", body: { minutes: Object.fromEntries(severities.map((severity) => [severity, Math.round(Number(hours[severity].value) * 60)])), calendar } });
      SOCifyDrafts.saved(form);
      showMessage(t("حُفظت سياسة المهلة"), "success");
      await window.SOCifyAutopsy.team();
    } catch (error) { errors.textContent = error.message; errors.hidden = false; }
    finally { submit.disabled = false; }
  });
  body.append(policy ? node("details", { class: "sla-settings" }, [node("summary", { text: t("تعديل السياسة") }), form]) : form);
  return panel(t("مهلة الاستجابة"), body, true);
}

window.SOCifyAutopsy.team = async () => {
  begin("team");
  const data = await api("/api/team");
  autopsy.team = data;
  const root = node("div", {}, pageHead(SOCifyLocale.text("الفريق"), null));
  root.append(panel(SOCifyLocale.text("أعضاء الفريق"), table([{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("البريد"), value: "email" }, { label: SOCifyLocale.text("الدور"), value: (row) => autopsyLabel(row.role) }, { label: SOCifyLocale.text("الحالة"), value: (row) => row.is_active ? SOCifyLocale.text("نشط") : SOCifyLocale.text("موقوف") }, { label: SOCifyLocale.text("إدارة"), value: (row) => data.can_manage && row.is_active && row.role !== "admin" ? button(SOCifyLocale.text("إدارة العضو"), () => {
    const roleForm = autopsyForm({ role: { label: SOCifyLocale.text("الدور"), required: true, choices: data.roles.map((role) => role.role) } }, async (body) => { await api(`/api/team/members/${row.id}`, { method: "PATCH", body }); dialog.close(); await window.SOCifyAutopsy.team(); }, row);
    const handoff = autopsyForm({ handoff_to: { user: true }, reason: { required: true, max: 1000 } }, async (body) => { await api(`/api/team/members/${row.id}/deactivate`, { method: "POST", body }); dialog.close(); await window.SOCifyAutopsy.team(); });
    const dialog = autopsyModal(SOCifyLocale.template`إدارة ${row.name}`, node("div", {}, [panel(SOCifyLocale.text("تغيير الدور وسحب الجلسات الحالية"), roleForm, true), panel(SOCifyLocale.text("إيقاف الوصول وتسليم المسؤوليات"), handoff, true)]));
  }) : "—" }], data.members), true));
  if (permission("cases.read")) root.append(await teamSlaPanel());
  if (data.can_manage) {
    root.append(panel(SOCifyLocale.text("دعوة عضو جديد"), node("div", { class: "panel-body" }, autopsyForm({ email: { required: true, max: 254 }, role: { label: SOCifyLocale.text("الدور"), required: true, choices: data.roles.map((role) => role.role) } }, async (body) => {
      const invitation = await api("/api/team/invitations", { method: "POST", body });
      const url = new URL("/register", window.location.origin);
      url.hash = new URLSearchParams({ invitation_token: invitation.invitation_token }).toString();
      autopsyModal(SOCifyLocale.text("رابط دعوة سري؛ سلّمه داخليًا لصاحب البريد المحدد"), node("div", {}, [node("p", { text: SOCifyLocale.template`ينتهي: ${formatTime(invitation.expires_at)}` }), field(SOCifyLocale.text("رابط التسجيل بالدعوة"), node("input", { readonly: true, value: url.toString(), dir: "ltr" }))]));
    }, {}, { submitLabel: SOCifyLocale.text("إنشاء دعوة") })), true));
    const policies = node("div", { class: "panel-body" });
    for (const role of data.roles.filter((item) => item.role !== "soc_manager")) {
      const choices = node("div", { class: "check-grid" });
      const inputs = role.available.map((value) => {
        const input = node("input", { type: "checkbox", checked: role.permissions.includes(value), value });
        choices.append(field(SOCifyLocale.text(teamPermissionLabels[value] || value), input));
        return input;
      });
      policies.append(node("details", { class: "team-role-policy", "data-role": role.role }, [node("summary", { text: SOCifyLocale.template`صلاحيات ${autopsyLabel(role.role)}` }), node("div", { class: "panel-body" }, [choices, button(SOCifyLocale.text("حفظ حدود الدور"), async () => { try { await api(`/api/team/roles/${role.role}`, { method: "PUT", body: { permissions: inputs.filter((input) => input.checked).map((input) => input.value) } }); await window.SOCifyAutopsy.team(); } catch (error) { handleError(error); } })])]));
    }
    root.append(panel(SOCifyLocale.text("صلاحيات الأدوار"), policies, true));
    const cases = (await api("/api/cases?page_size=100")).items.filter((item) => item.status !== "closed" && (!window.SOCifyWorkspace?.selection.required || window.SOCifyWorkspace.selection.case_ids.includes(item.id)));
    const selected = autopsyChoice("case_id", cases.map((item) => ({ value: item.id, label: `${item.reference} | ${item.title}` })), "", true);
    // Until a case is chosen, the batch field holds its place beside it, disabled.
    const batchPlaceholder = () => field(SOCifyLocale.text("دفعة من القضية المحددة"), node("select", { disabled: true, "aria-disabled": "true" }, node("option", { text: SOCifyLocale.text("اختر القضية أولًا") })));
    const batchHolder = node("div", {}, batchPlaceholder());
    let batchChoice = null;
    let selectionRequest = 0;
    selected.input.addEventListener("input", () => { ++selectionRequest; batchChoice = null; batchHolder.replaceChildren(batchPlaceholder()); });
    selected.input.addEventListener("change", async () => {
      const request = ++selectionRequest;
      batchChoice = null;
      batchHolder.replaceChildren(batchPlaceholder());
      try { const caseId = selected.input.autopsyValue(); const imports = await api(`/api/cases/${caseId}/imports`); if (request !== selectionRequest) return; batchChoice = autopsyChoice("job_id", imports.items.filter((job) => ["completed", "completed_with_errors"].includes(job.status)).map((job) => ({ value: job.id, label: SOCifyLocale.template`${job.original_filename || job.filename} | ${job.accepted} سجل` })), "", true); batchHolder.replaceChildren(field(SOCifyLocale.text("دفعة من القضية المحددة"), batchChoice.control)); }
      catch (error) { if (request === selectionRequest) { batchChoice = null; batchHolder.replaceChildren(node("p", { text: error.message })); } }
    });
    const assignmentRoles = data.roles.filter(role => ["analyst", "l1_analyst", "l2_responder", "investigator", "soc_manager"].includes(role.role) && ["cases.read", "cases.update", "events.read"].every(permission => role.permissions.includes(permission))).map(role => role.role);
    const assignees = data.members.filter(member => member.is_active && assignmentRoles.includes(member.role)).map(member => ({ value: member.id, label: `${member.name} | ${autopsyLabel(member.role)}` }));
    const form = autopsyForm({ assignee: { required: true, choices: assignees }, instructions: { required: true, max: 2000 } }, async (body) => {
      if (!batchChoice) throw new Error(SOCifyLocale.text("اختر قضية ثم دفعة مكتملة منها"));
      await api("/api/team/assignments", { method: "POST", body: { ...body, case_id: selected.input.autopsyValue(), job_id: batchChoice.input.autopsyValue() } });
      await window.SOCifyAutopsy.team();
    }, {}, { submitLabel: SOCifyLocale.text("إسناد الدفعة") });
    form.prepend(field(SOCifyLocale.text("القضية"), selected.control), batchHolder);
    root.append(panel(SOCifyLocale.text("إسناد دفعة سجلات"), node("div", { class: "panel-body" }, form), true));
  }
  if (permission("cases.read")) root.append(await autopsyAssignmentQueue());
  finish(root);
};
