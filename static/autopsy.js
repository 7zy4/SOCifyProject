"use strict";

const autopsy = { catalog: null, team: null, current: null };
const autopsyLabels = {
  asset: "الأصول والأجهزة", indicator: "المؤشرات", timeline: "الخط الزمني", war_room: "غرفة التحقيق", hypothesis: "الفرضيات", response: "إجراءات الاستجابة", corrective: "الإجراءات التصحيحية", foothold: "أقدم اختراق مثبت", root_cause: "الأسباب الجذرية", escalation: "التصعيد", playbook: "إجراء القضية", reputation: "نتائج السمعة المستوردة", analysis: "نتائج التحليل",
  title: "العنوان", name: "الاسم", type: "النوع", role: "دور الأصل", address: "العنوان", owner: "مالك الأصل", operating_system: "نظام التشغيل", importance: "أهمية الأصل", assessment: "التقييم", details: "التفاصيل والأدلة", value: "القيمة", classification: "التصنيف", status: "الحالة", confidence: "الثقة من 0 إلى 100", source: "المصدر", expires_at: "تنتهي في", description: "الوصف", event_time: "وقت الحدث", category: "الفئة", tags: "الوسوم مفصولة بفاصلة", body: "الملاحظة أو القرار", visibility: "نطاق الملاحظة", statement: "الفرضية", phase: "المرحلة", performed_by: "من نفذ الإجراء", performed_at: "وقت التنفيذ", owner_id: "المسؤول", due_at: "الموعد المستهدف", validation: "التحقق من الفاعلية", asset_id: "الأصل المرتبط", first_observed_at: "أول نشاط مثبت", limitations: "حدود الأدلة والاستنتاج", conclusion: "استنتاج التحقيق", whys: "تحليل 5 Whys", evidence_id: "الدليل المرتبط", to_user: "مستقبل التصعيد", from_level: "من المستوى", to_level: "إلى المستوى", reason: "سبب فتح القضية", priority: "الأولوية", objective: "هدف التحقيق", attack_outcome: "نتيجة الهجوم", alert_verdict: "قرار صحة التنبيه",
  new: "مسودة", open: "فرز أولي", triaged: "تم الفرز", investigating: "قيد التحقيق", escalated: "مصعّدة", contained: "تم الاحتواء", remediated: "تمت المعالجة", recovered: "تم التعافي", awaiting_review: "بانتظار المراجعة", closed: "مغلقة", reopened: "أعيد فتحها", cancelled: "ملغاة",
  alert_review: "مراجعة تنبيه", suspicious_activity: "نشاط مشتبه به", threat_hunt: "صيد تهديد", user_report: "بلاغ مستخدم", forensic_review: "فحص أدلة رقمية", other: "أخرى", internal: "داخلي", confidential: "سري", restricted: "مقيد", successful: "ناجح", blocked: "فاشل أو محجوب", partial: "نجاح جزئي", unknown: "غير معروف", malicious: "خبيث مؤكد", benign: "نشاط حميد", false_positive: "إيجابي كاذب", undetermined: "غير محسوم",
  confirmed: "متأثر مؤكد", suspected: "مشتبه", checked_clear: "فُحص ضمن نطاق موثق", unexamined: "لم يُفحص", suspected_attacker: "مهاجم محتمل", defender: "مدافع أو هدف", affected: "متأثر", intermediary: "وسيط", web_server: "خادم ويب", application_server: "خادم تطبيق", database: "قاعدة بيانات", workstation: "جهاز مستخدم", router: "راوتر", switch: "محول شبكة", firewall: "جدار ناري", security_appliance: "جهاز أمني", container: "حاوية", cloud_asset: "أصل سحابي موثق", critical: "حرج", high: "عالٍ", medium: "متوسط", low: "منخفض", urgent: "عاجل",
  monitoring: "المراقبة", l1: "المستوى الأول", l2: "المستوى الثاني", investigation: "التحقيق", management: "الإدارة", raised: "أُرسل", acknowledged: "تم الاستلام", returned: "أعيد مع سبب", resolved: "تمت الاستجابة", planned: "مخطط", in_progress: "جارٍ", succeeded: "نجح", failed: "فشل", not_applicable: "غير منطبق", completed: "مكتمل", validated: "تم التحقق", containment: "الاحتواء", eradication: "الإزالة", recovery: "التعافي", acknowledgement: "إقرار الاستلام", triage: "الفرز", detection: "الرصد", team: "الفريق", private: "خاصة بالمؤلف والمدير", observed: "حدث مرصود", action: "إجراء", supported: "مؤيدة بأدلة", refuted: "دُحضت", observable: "قيمة مرصودة", ioc: "مؤشر اختراق مثبت", active: "نشط", expired: "منتهي", revoked: "مسحوب",
  compromised_credentials: "اعتماد مخترق", misconfiguration: "ضعف إعداد", exploited_vulnerability: "استغلال ثغرة", phishing: "تصيد أو هندسة اجتماعية", excessive_privileges: "صلاحيات زائدة", monitoring_gap: "فجوة مراقبة", supply_chain: "سلسلة توريد", l1_analyst: "محلل L1", l2_responder: "مستجيب L2", investigator: "محقق", reviewer: "مراجع", analyst: "محلل", auditor: "مدقق", soc_manager: "مدير الفريق", admin: "مسؤول المنصة"
};

function autopsyLabel(value) { return autopsyLabels[value] || value; }

autopsyLabels.reason = "السبب";
Object.assign(autopsyLabels, { handoff_to: "العضو البديل للمسؤوليات", assignee: "المحلل المسؤول", instructions: "المطلوب تحليله وتسليمه", email: "البريد الإلكتروني الداخلي" });

function autopsySelect(name, values, current = "") {
  return node("select", { name }, values.map((value) => node("option", { value, selected: value === current, text: autopsyLabel(value) })));
}

function autopsyChoice(name, values, current = "", required = false) {
  const id = `choice-${name}-${crypto.randomUUID()}`;
  const input = node("input", { name, list: id, required, autocomplete: "off", class: "search-choice" });
  const choices = values.map((entry) => typeof entry === "object" ? { ...entry, label: displayText(entry.label) } : { value: entry, label: displayText(autopsyLabel(entry)) });
  const selected = choices.find((entry) => String(entry.value) === String(current));
  input.value = selected?.label || "";
  const list = node("datalist", { id }, choices.map((entry) => node("option", { value: entry.label })));
  input.autopsyValue = () => {
    if (!input.value.trim() && !required) return null;
    const entry = choices.find((item) => item.label === input.value);
    if (!entry) throw new Error(`اختر قيمة معروفة للحقل ${autopsyLabel(name)}`);
    return entry.value;
  };
  return { control: node("span", {}, [input, list]), input };
}

function autopsyModal(title, content) {
  const previous = document.activeElement;
  const dialog = node("dialog", { class: "autopsy-modal", "aria-label": title }, [node("div", { class: "workspace-head" }, [node("h2", { text: title }), button("إغلاق", () => dialog.close())]), content]);
  document.body.append(dialog);
  dialog.addEventListener("close", () => { dialog.remove(); previous?.focus(); }, { once: true });
  dialog.showModal();
  return dialog;
}

function autopsyForm(schema, submit, initial = {}) {
  const form = node("form", { class: "form-grid" });
  const getters = {};
  for (const [key, spec] of Object.entries(schema)) {
    let control;
    if (spec.whys) {
      const rows = node("div");
      const add = (value = {}) => {
        const identifier = value.id || `why-${crypto.randomUUID()}`;
        const question = node("input", { value: value.question || "لماذا حدث ذلك؟", required: true, maxlength: 500 });
        const answer = node("textarea", { required: true, maxlength: 2000 }, value.answer || "");
        const assessment = autopsySelect("why_assessment", ["unverified", "hypothesis", "supported", "refuted"], value.assessment || (value.evidence_id ? "supported" : "unverified"));
        const evidence = autopsyChoice("evidence_id", (autopsy.current?.evidence || []).map((item) => ({ value: item.id, label: `${item.title} · ${item.id}` })), value.evidence_id);
        const parent = node("select", { name: "why_parent" });
        const row = node("fieldset", { class: "why-step" }, [node("legend", { text: "سبب مرتبط بدليل أو فرضية معلنة" }), field("السؤال", question), field("الإجابة", answer), field("التقييم", assessment), field("الدليل", evidence.control), field("السبب السابق في الشجرة", parent)]);
        row.whyId = identifier;
        row.whyParent = parent;
        const refresh = () => [...rows.children].forEach((item) => {
          const selected = item.whyParent.value || item.whyInitialParent || "";
          item.whyParent.replaceChildren(node("option", { value: "", text: "جذر مستقل" }), ...[...rows.children].filter((other) => other !== item).map((other, index) => node("option", { value: other.whyId, text: `السبب ${index + 1} · ${other.whyId}`, selected: other.whyId === selected })));
        });
        row.whyInitialParent = value.parent_id;
        parent.addEventListener("change", () => { row.whyInitialParent = parent.value; });
        row.autopsyValue = () => ({ id: identifier, question: question.value, answer: answer.value, assessment: assessment.value, ...(parent.value ? { parent_id: parent.value } : {}), ...(evidence.input.autopsyValue() ? { evidence_id: evidence.input.autopsyValue() } : {}) });
        row.append(button("حذف الخطوة", () => { row.remove(); refresh(); }));
        rows.append(row);
        refresh();
      };
      (initial[key] || []).forEach(add);
      control = node("fieldset", { class: "span-2" }, [node("legend", { text: autopsyLabel(key) }), rows, button("إضافة سؤال لماذا", () => { if (rows.children.length < 10) add(); })]);
      getters[key] = () => [...rows.children].map((row) => row.autopsyValue());
      form.append(control);
      continue;
    }
    let choices = spec.choices;
    if (spec.user) choices = autopsy.team.members.filter((member) => member.is_active && (!(spec.case_member || key === "owner_id") || ["admin", "soc_manager"].includes(member.role) || autopsy.current?.members.some((item) => item.user_id === member.id))).map((member) => ({ value: member.id, label: `${member.name} · ${autopsyLabel(member.role)}` }));
    if (spec.evidence) choices = (autopsy.current?.evidence || []).map((evidence) => ({ value: evidence.id, label: `${evidence.title} · ${evidence.id}` }));
    if (spec.asset) choices = (autopsy.assets || []).map((record) => ({ value: record.id, label: `${record.payload.name} · ${record.id}` }));
    if (choices) {
      const choice = autopsyChoice(key, choices, initial[key], spec.required);
      control = choice.control;
      getters[key] = choice.input.autopsyValue;
    } else if (spec.timestamp) {
      const input = node("input", { name: key, type: "datetime-local", required: spec.required });
      if (initial[key]) {
        const date = new Date(initial[key]);
        input.value = new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
      }
      control = input;
      getters[key] = () => input.value ? new Date(input.value).toISOString() : null;
    } else {
      const long = !spec.integer && (spec.max || 0) > 1000;
      const input = long ? node("textarea", { name: key, maxlength: spec.max, required: spec.required }, initial[key] || "") : node("input", { name: key, type: spec.integer ? "number" : "text", min: spec.min, max: spec.integer ? spec.max : null, maxlength: !spec.integer ? spec.max : null, required: spec.required, value: spec.list ? (initial[key] || []).join(", ") : initial[key] ?? "" });
      control = input;
      getters[key] = () => !input.value ? null : spec.integer ? Number(input.value) : spec.list ? input.value.split(",").map((value) => value.trim()).filter(Boolean) : input.value;
    }
    form.append(field(`${autopsyLabel(key)}${spec.required ? " *" : ""}${spec.timestamp ? " · وقت المتصفح" : ""}`, control, (spec.max || 0) > 1000));
  }
  const errors = node("p", { class: "notice span-2", role: "alert", hidden: true });
  const save = node("button", { type: "submit", class: "button primary", text: "حفظ" });
  form.append(errors, node("div", { class: "action-row span-2" }, save));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      const values = Object.fromEntries(Object.entries(getters).map(([key, getter]) => [key, getter()]).filter(([, value]) => value !== null));
      await submit(values);
    } catch (error) { errors.hidden = false; errors.textContent = error.message; }
    finally { save.disabled = false; }
  });
  return form;
}

function autopsyNewCase() {
  const form = autopsyForm({ title: { required: true, max: 255 }, reason: { required: true, choices: autopsy.catalog.reasons }, objective: { required: true, max: 2000 }, classification: { required: true, choices: autopsy.catalog.classifications } }, async (body) => {
    const created = await api("/api/cases", { method: "POST", body });
    window.location.assign(`/cases/${created.id}`);
  }, { classification: "confidential" });
  autopsyModal("إنشاء قضية: الاسم والسبب والهدف", form);
}

async function autopsyCases(page = 1, query = "") {
  begin("cases");
  document.getElementById("section-title").textContent = "قضايا الفريق";
  document.getElementById("section-kicker").textContent = "SOCIFY DIGITAL AUTOPSY";
  const data = await api(`/api/cases?page=${page}&page_size=25&q=${encodeURIComponent(query)}`);
  const search = node("input", { name: "q", type: "search", value: query, maxlength: 200, placeholder: "الاسم أو مرجع القضية" });
  const filters = node("form", { class: "filter-row", "aria-label": "بحث القضايا" }, [field("بحث", search), node("button", { type: "submit", class: "button ghost", text: "بحث" })]);
  filters.addEventListener("submit", (event) => { event.preventDefault(); autopsyCases(1, search.value).catch(handleError); });
  const root = node("div", {}, [pageHead("ابدأ بقضية واضحة الهدف", "تجتمع الأدلة والتحليل والمسؤوليات والقرارات والتقرير داخل القضية نفسها.", permission("cases.create") ? [button("إنشاء قضية", autopsyNewCase, "primary")] : []), filters]);
  root.append(data.items.length ? table([{ label: "المرجع", value: (row) => node("bdi", { text: row.reference }) }, { label: "القضية", value: "title" }, { label: "الحالة", value: (row) => autopsyLabel(row.status) }, { label: "الخطورة", value: (row) => autopsyLabel(row.severity) }, { label: "الأدلة", value: "evidence_count" }, { label: "المسؤول", value: "assignee_name" }, { label: "فتح", value: (row) => linkedButton("فتح القضية", `/cases/${row.id}`) }], data.items) : emptyState("لا توجد قضايا في النطاق المصرح", "أنشئ القضية باسم وسبب وهدف، ثم أضف الأدلة إلى مساحة التحقيق."));
  const pages = node("div", { class: "action-row" }, node("p", { text: `${data.total} قضية · الصفحة ${page}` }));
  if (page > 1) pages.append(button("السابق", () => autopsyCases(page - 1, query).catch(handleError)));
  if (page * 25 < data.total) pages.append(button("التالي", () => autopsyCases(page + 1, query).catch(handleError)));
  root.append(pages);
  finish(root);
}

function autopsyRecordCard(record) {
  const values = node("dl");
  Object.entries(record.payload).forEach(([key, value]) => {
    if (value === null || value === "") return;
    let display = Array.isArray(value) ? value.map((item) => typeof item === "object" && item !== null ? (item.question ? `${item.question}: ${item.answer || ""} · ${item.assessment || ""}${item.evidence_id ? ` · دليل ${item.evidence_id}` : ""}${item.parent_id ? ` · فرع ${item.parent_id}` : ""}` : JSON.stringify(item)) : item).join("\n") : typeof value === "object" ? JSON.stringify(value) : autopsyLabel(value);
    if (key.endsWith("_at") || key === "event_time") display = formatTime(value);
    values.append(node("dt", { text: autopsyLabel(key) }), node("dd", { text: display }));
  });
  const card = node("article", { class: "card record-card" }, [node("h3", { text: record.payload.title || record.payload.name || autopsyLabel(record.kind) }), values, node("small", { text: `الإصدار ${record.version} · ${formatTime(record.updated_at)}` })]);
  if (autopsy.current.can_update && autopsy.catalog.record_schemas[record.kind]) card.append(button("تعديل", () => autopsyEditRecord(record.kind, record)));
  if (record.kind === "analysis" && record.payload.analysis_type === "local_detection" && record.payload.next_after_id && autopsy.current.can_update && autopsy.current.status !== "closed") card.append(autopsyAction("استكمال فحص الدفعة التالية", async () => { await api(`/api/cases/${autopsy.current.id}/detection`, { method: "POST", body: { version: autopsy.current.version, mode: record.payload.mode, after_id: record.payload.next_after_id } }); await autopsyCase(autopsy.current.id); }));
  return card;
}

async function autopsyEditRecord(kind, record = null) {
  const schema = { ...autopsy.catalog.record_schemas[kind], evidence_id: { evidence: true } };
  if (kind === "corrective") {
    let causes = (await api(`/api/cases/${autopsy.current.id}/records?kind=root_cause&limit=100`)).items;
    if (record?.payload.root_cause_id && !causes.some((item) => item.id === record.payload.root_cause_id)) {
      const selected = (await api(`/api/cases/${autopsy.current.id}/records?kind=root_cause&limit=1&before=${record.payload.root_cause_id + 1}`)).items;
      if (selected[0]?.id === record.payload.root_cause_id) causes = [...causes, selected[0]];
    }
    schema.root_cause_id = { choices: causes.map((item) => ({ value: item.id, label: `${item.id} · ${item.payload.conclusion.slice(0, 80)}` })) };
    schema.why_id = { choices: causes.flatMap((item) => (item.payload.whys || []).map((why) => ({ value: why.id, label: `${item.id} · ${why.question.slice(0, 80)} · ${why.id}` }))) };
  }
  let dialog;
  const form = autopsyForm(schema, async (payload) => {
    await api(`/api/cases/${autopsy.current.id}/records/${record ? record.id : kind}`, { method: record ? "PATCH" : "POST", body: record ? { version: record.version, payload } : payload });
    dialog.close();
    await autopsyCase(autopsy.current.id);
  }, record?.payload || {});
  dialog = autopsyModal(`${record ? "تعديل" : "إضافة"} ${autopsyLabel(kind)}`, form);
}

async function autopsyRecordPanel(kind) {
  const data = await api(`/api/cases/${autopsy.current.id}/records?kind=${kind}&limit=100`);
  const content = data.items.length ? node("div", { class: "record-grid" }, data.items.map(autopsyRecordCard)) : emptyState("لا سجلات بعد", "أضف نتيجة موثقة من أدلة القضية، وميّز الحقائق عن الفرضيات.");
  return panel(autopsyLabel(kind), node("div", { class: "panel-body" }, [autopsy.current.can_update ? button(`إضافة ${autopsyLabel(kind)}`, () => autopsyEditRecord(kind).catch(handleError), "primary") : null, content]), true);
}

async function autopsyCase(caseId) {
  begin("case");
  let selected = new URLSearchParams(window.location.search).get("tab") || "summary";
  autopsy.current = await api(`/api/cases/${caseId}`);
  const current = autopsy.current;
  document.getElementById("section-title").textContent = displayText(current.title);
  document.getElementById("section-kicker").textContent = current.reference;
  document.title = `${current.reference} | SOCify Digital Autopsy`;
  const restricted = current.full_case_access === false;
  if (restricted && !["summary", "logs"].includes(selected)) selected = "logs";
  const assetData = restricted ? { items: [] } : await api(`/api/cases/${caseId}/records?kind=asset&limit=100`);
  autopsy.assets = assetData.items;
  const root = node("div", {}, [pageHead(current.title, `${current.reference} · ${autopsyLabel(current.status)} · ${autopsyLabel(current.severity)}`, [linkedButton("جميع القضايا", "/cases")])]);
  let tabs = [["summary", "الملخص والمسؤوليات"], ["logs", "السجلات والأدلة"], ["analysis", "الأصول والمؤشرات"], ["investigation", "التحقيق والخط الزمني"], ["response", "الاستجابة والتصعيد"], ["activity", "الحيازة والنشاط"]];
  if (restricted) {
    tabs = tabs.slice(0, 2);
    root.append(node("p", { class: "notice", text: "نطاق دفعات محدد: تظهر السجلات المصرح بها فقط. يتطلب سياق التحقيق والتقارير الوصول إلى جميع دفعات القضية." }));
  }
  root.append(node("nav", { class: "case-tabs", "aria-label": "أقسام القضية" }, tabs.map(([id, label]) => node("a", { class: "button ghost", href: `/cases/${caseId}?tab=${id}`, "aria-current": selected === id ? "page" : null, text: label }))));
  const content = node("div", { class: "case-content" });
  if (selected === "summary") {
    const transitions = autopsy.catalog.case_transitions[current.status] || [];
    if (current.can_update && transitions.length) content.append(panel("حالة القضية", node("div", { class: "panel-body" }, autopsyForm({ status: { required: true, choices: transitions.filter((value) => value !== "closed" || permission("cases.close")) }, reason: { required: true, max: 2000 } }, async (body) => { await api(`/api/cases/${caseId}/transitions`, { method: "POST", body: { ...body, version: current.version } }); await autopsyCase(caseId); })), true));
    const schema = { reason: { required: true, max: 500 }, objective: { required: true, max: 2000 }, classification: { choices: autopsy.catalog.classifications, required: true }, attack_outcome: { choices: autopsy.catalog.outcomes, required: true }, alert_verdict: { choices: autopsy.catalog.verdicts, required: true } };
    if (current.can_update && current.status !== "closed") content.append(panel("سبب القضية وهدفها ونتيجتها", node("div", { class: "panel-body" }, autopsyForm(schema, async (body) => { await api(`/api/cases/${caseId}/context`, { method: "PATCH", body: { ...body, version: current.version } }); await autopsyCase(caseId); }, current.context || { classification: "confidential", attack_outcome: "unknown", alert_verdict: "undetermined" })), true));
    else content.append(panel("ملخص القضية", node("div", { class: "panel-body" }, [node("p", { text: current.context?.reason || "قضية موروثة؛ يتطلب ملخصها مراجعة" }), node("p", { text: current.context?.objective || "—" })]), true));
    content.append(panel("فريق القضية", table([{ label: "الاسم", value: "name" }, { label: "الدور", value: (row) => autopsyLabel(row.role) }, { label: "المسؤولية", value: (row) => autopsyLabel(row.responsibility) }, { label: "أُسندت", value: (row) => formatTime(row.assigned_at) }], current.members)));
    if (current.can_manage) {
      content.append(panel("تحديد مسؤولية عضو", node("div", { class: "panel-body" }, autopsyForm({ user_id: { required: true, user: true }, responsibility: { required: true, choices: ["monitoring", "l1", "l2", "investigator", "reviewer", "owner"] } }, async (body) => { await api(`/api/cases/${caseId}/members`, { method: "POST", body }); await autopsyCase(caseId); }))));
    }
    content.append(panel("مهام القضية", current.tasks.length ? table([{ label: "المهمة", value: "title" }, { label: "الحالة", value: "status" }, { label: "إكمال", value: (row) => current.can_update && row.status !== "completed" ? button("إكمال المهمة", async () => { try { await api(`/api/incidents/${caseId}/tasks/${row.id}`, { method: "PATCH", body: { status: "completed" } }); await autopsyCase(caseId); } catch (error) { handleError(error); } }) : "—" }], current.tasks) : emptyState("لا مهام", "تظهر هنا المهام المرتبطة بالقضية.")));
  } else if (selected === "logs") {
    if (window.SOCifyAutopsy.logs) content.append(await window.SOCifyAutopsy.logs(caseId));
    content.append(panel("أدلة القضية", current.evidence.length ? table([{ label: "الدليل", value: "title" }, { label: "النوع", value: "evidence_type" }, { label: "SHA-256", value: (row) => node("bdi", { text: row.sha256 }) }, { label: "أضيف", value: (row) => formatTime(row.added_at) }], current.evidence) : emptyState("لا أدلة مرتبطة", "احتفظ بالأصل ومصدره واربطه بالقضية قبل استخلاص النتائج."), true));
  } else if (selected === "analysis") {
    for (const kind of ["asset", "indicator", "hypothesis", "foothold"]) content.append(await autopsyRecordPanel(kind));
    if (window.SOCifyAutopsy.analysis) content.append(await window.SOCifyAutopsy.analysis(caseId));
    if (window.SOCifyAutopsy.localDetection) content.append(await window.SOCifyAutopsy.localDetection(caseId));
  } else if (selected === "investigation") {
    if (window.SOCifyAutopsy.investigation) content.append(await window.SOCifyAutopsy.investigation(caseId));
    for (const kind of ["timeline", "root_cause", "war_room"]) content.append(await autopsyRecordPanel(kind));
  } else if (selected === "response") {
    for (const kind of ["escalation", "response", "corrective"]) content.append(await autopsyRecordPanel(kind));
    if (window.SOCifyAutopsy.procedures) content.append(await window.SOCifyAutopsy.procedures(caseId));
    if (window.SOCifyAutopsy.workflow) content.append(await window.SOCifyAutopsy.workflow(caseId));
  } else if (selected === "reports" && window.SOCifyAutopsy.reports) content.append(await window.SOCifyAutopsy.reports(caseId));
  else {
    const data = await api(`/api/cases/${caseId}/custody`);
    content.append(panel("سلسلة حيازة الأدلة", node("div", { class: "panel-body" }, [node("p", { text: `${data.integrity_valid ? "سلسلة البصمات متسقة" : "تحذير: عدم اتساق في السلسلة"} · ${data.total} حركة` }), table([{ label: "الإجراء", value: "action" }, { label: "الوقت", value: (row) => formatTime(row.created_at) }, { label: "بصمة الحركة", value: (row) => node("bdi", { text: row.entry_hash }) }], data.items)]), true));
    content.append(panel("نشاط القضية", table([{ label: "الحدث", value: "action" }, { label: "الفاعل", value: "actor_name" }, { label: "الوقت", value: (row) => formatTime(row.created_at) }], current.history), true));
  }
  if (!restricted && selected === "reports" && window.SOCifyAutopsy.capsules) content.append(await window.SOCifyAutopsy.capsules(caseId));
  if (!restricted && window.SOCifyAutopsy.reports && !tabs.some(([id]) => id === "reports")) root.querySelector(".case-tabs").append(linkedButton("التقارير والمراجعة", `/cases/${caseId}?tab=reports`));
  root.append(content);
  finish(root);
}

async function autopsyStart() {
  [autopsy.catalog, autopsy.team] = await Promise.all([api("/api/autopsy/catalog"), api("/api/team")]);
  const caseId = document.querySelector('meta[name="case-id"]')?.content;
  if (caseId) return autopsyCase(Number(caseId));
  if (state.section === "profile" && window.SOCifyAutopsy.profile) return window.SOCifyAutopsy.profile();
  if (state.section === "analysis-library" && window.SOCifyAutopsy.library) return window.SOCifyAutopsy.library();
  if (state.section === "playbooks" && window.SOCifyAutopsy.procedureLibrary) return window.SOCifyAutopsy.procedureLibrary();
  if (state.section === "team") return window.SOCifyAutopsy.team();
  if (state.section === "my-tasks") {
    begin("my-tasks");
    finish(panel("مهامي داخل القضايا", autopsy.team.assignments.length ? table([{ label: "القضية", value: (row) => linkedButton(row.case_title, `/cases/${row.case_id}`) }, { label: "المهمة", value: "instructions" }, { label: "الحالة", value: "task_status" }], autopsy.team.assignments) : emptyState("لا دفعات مسندة", "تظهر مهام تحليل السجلات التي يسندها مدير الفريق إليك هنا."), true));
    return;
  }
  if (state.section === "profile") {
    const data = await api("/api/auth/sessions");
    finish(panel("أمان الحساب والجلسات", node("div", { class: "panel-body" }, [node("p", { text: `${state.user.name} · ${autopsyLabel(state.user.role)}` }), table([{ label: "الجلسة", value: "id" }, { label: "بدأت", value: (row) => formatTime(row.created_at) }, { label: "تنتهي", value: (row) => formatTime(row.expires_at) }], data.items)]), true));
    return;
  }
  await autopsyCases();
}

window.SOCifyAutopsy = { start: autopsyStart };
