"use strict";

const autopsy = { catalog: null, team: null, current: null };
const autopsyLabels = {
  asset: SOCifyLocale.text("الأصول والأجهزة"), indicator: SOCifyLocale.text("المؤشرات"), timeline: SOCifyLocale.text("الخط الزمني"), war_room: SOCifyLocale.text("غرفة التحقيق"), hypothesis: SOCifyLocale.text("الفرضيات"), response: SOCifyLocale.text("إجراءات الاستجابة"), corrective: SOCifyLocale.text("الإجراءات التصحيحية"), foothold: SOCifyLocale.text("أقدم اختراق مثبت"), root_cause: SOCifyLocale.text("الأسباب الجذرية"), escalation: SOCifyLocale.text("التصعيد"), playbook: SOCifyLocale.text("إجراء القضية"), reputation: SOCifyLocale.text("نتائج السمعة المستوردة"), analysis: SOCifyLocale.text("نتائج التحليل"),
  title: SOCifyLocale.text("العنوان"), name: SOCifyLocale.text("الاسم"), type: SOCifyLocale.text("النوع"), role: SOCifyLocale.text("دور الأصل"), address: SOCifyLocale.text("العنوان"), owner: SOCifyLocale.text("مالك الأصل"), operating_system: SOCifyLocale.text("نظام التشغيل"), importance: SOCifyLocale.text("أهمية الأصل"), assessment: SOCifyLocale.text("التقييم"), details: SOCifyLocale.text("التفاصيل والأدلة"), value: SOCifyLocale.text("القيمة"), classification: SOCifyLocale.text("التصنيف"), status: SOCifyLocale.text("الحالة"), confidence: SOCifyLocale.text("الثقة من 0 إلى 100"), source: SOCifyLocale.text("المصدر"), expires_at: SOCifyLocale.text("تنتهي في"), description: SOCifyLocale.text("الوصف"), event_time: SOCifyLocale.text("وقت الحدث"), category: SOCifyLocale.text("الفئة"), tags: SOCifyLocale.text("الوسوم مفصولة بفاصلة"), body: SOCifyLocale.text("الملاحظة أو القرار"), visibility: SOCifyLocale.text("نطاق الملاحظة"), statement: SOCifyLocale.text("الفرضية"), phase: SOCifyLocale.text("المرحلة"), performed_by: SOCifyLocale.text("من نفذ الإجراء"), performed_at: SOCifyLocale.text("وقت التنفيذ"), owner_id: SOCifyLocale.text("المسؤول"), due_at: SOCifyLocale.text("الموعد المستهدف"), validation: SOCifyLocale.text("التحقق من الفاعلية"), asset_id: SOCifyLocale.text("الأصل المرتبط"), first_observed_at: SOCifyLocale.text("أول نشاط مثبت"), limitations: SOCifyLocale.text("حدود الأدلة والاستنتاج"), conclusion: SOCifyLocale.text("استنتاج التحقيق"), whys: SOCifyLocale.text("تحليل 5 Whys"), evidence_id: SOCifyLocale.text("الدليل المرتبط"), to_user: SOCifyLocale.text("مستقبل التصعيد"), from_level: SOCifyLocale.text("من المستوى"), to_level: SOCifyLocale.text("إلى المستوى"), reason: SOCifyLocale.text("سبب فتح القضية"), priority: SOCifyLocale.text("الأولوية"), objective: SOCifyLocale.text("هدف التحقيق"), attack_outcome: SOCifyLocale.text("نتيجة الهجوم"), alert_verdict: SOCifyLocale.text("قرار صحة التنبيه"),
  new: SOCifyLocale.text("مسودة"), open: SOCifyLocale.text("فرز أولي"), triaged: SOCifyLocale.text("تم الفرز"), investigating: SOCifyLocale.text("قيد التحقيق"), escalated: SOCifyLocale.text("مصعّدة"), contained: SOCifyLocale.text("تم الاحتواء"), remediated: SOCifyLocale.text("تمت المعالجة"), recovered: SOCifyLocale.text("تم التعافي"), awaiting_review: SOCifyLocale.text("بانتظار المراجعة"), closed: SOCifyLocale.text("مغلقة"), reopened: SOCifyLocale.text("أعيد فتحها"), cancelled: SOCifyLocale.text("ملغاة"),
  alert_review: SOCifyLocale.text("مراجعة تنبيه"), suspicious_activity: SOCifyLocale.text("نشاط مشتبه به"), threat_hunt: SOCifyLocale.text("صيد تهديد"), user_report: SOCifyLocale.text("بلاغ مستخدم"), forensic_review: SOCifyLocale.text("فحص أدلة رقمية"), other: SOCifyLocale.text("أخرى"), internal: SOCifyLocale.text("داخلي"), confidential: SOCifyLocale.text("سري"), restricted: SOCifyLocale.text("مقيد"), successful: SOCifyLocale.text("ناجح"), blocked: SOCifyLocale.text("فاشل أو محجوب"), partial: SOCifyLocale.text("نجاح جزئي"), unknown: SOCifyLocale.text("غير معروف"), malicious: SOCifyLocale.text("خبيث مؤكد"), benign: SOCifyLocale.text("نشاط حميد"), false_positive: SOCifyLocale.text("إيجابي كاذب"), undetermined: SOCifyLocale.text("غير محسوم"),
  confirmed: SOCifyLocale.text("متأثر مؤكد"), suspected: SOCifyLocale.text("مشتبه"), checked_clear: SOCifyLocale.text("فُحص ضمن نطاق موثق"), unexamined: SOCifyLocale.text("لم يُفحص"), suspected_attacker: SOCifyLocale.text("مهاجم محتمل"), defender: SOCifyLocale.text("مدافع أو هدف"), affected: SOCifyLocale.text("متأثر"), intermediary: SOCifyLocale.text("وسيط"), web_server: SOCifyLocale.text("خادم ويب"), application_server: SOCifyLocale.text("خادم تطبيق"), database: SOCifyLocale.text("قاعدة بيانات"), workstation: SOCifyLocale.text("جهاز مستخدم"), router: SOCifyLocale.text("راوتر"), switch: SOCifyLocale.text("محول شبكة"), firewall: SOCifyLocale.text("جدار ناري"), security_appliance: SOCifyLocale.text("جهاز أمني"), container: SOCifyLocale.text("حاوية"), cloud_asset: SOCifyLocale.text("أصل سحابي موثق"), critical: SOCifyLocale.text("حرج"), high: SOCifyLocale.text("عالٍ"), medium: SOCifyLocale.text("متوسط"), low: SOCifyLocale.text("منخفض"), urgent: SOCifyLocale.text("عاجل"),
  monitoring: SOCifyLocale.text("المراقبة"), l1: SOCifyLocale.text("المستوى الأول"), l2: SOCifyLocale.text("المستوى الثاني"), investigation: SOCifyLocale.text("التحقيق"), management: SOCifyLocale.text("الإدارة"), raised: SOCifyLocale.text("أُرسل"), acknowledged: SOCifyLocale.text("تم الاستلام"), returned: SOCifyLocale.text("أعيد مع سبب"), resolved: SOCifyLocale.text("تمت الاستجابة"), planned: SOCifyLocale.text("مخطط"), in_progress: SOCifyLocale.text("جارٍ"), succeeded: SOCifyLocale.text("نجح"), failed: SOCifyLocale.text("فشل"), not_applicable: SOCifyLocale.text("غير منطبق"), completed: SOCifyLocale.text("مكتمل"), validated: SOCifyLocale.text("تم التحقق"), containment: SOCifyLocale.text("الاحتواء"), eradication: SOCifyLocale.text("الإزالة"), recovery: SOCifyLocale.text("التعافي"), acknowledgement: SOCifyLocale.text("إقرار الاستلام"), triage: SOCifyLocale.text("الفرز"), detection: SOCifyLocale.text("الرصد"), team: SOCifyLocale.text("الفريق"), private: SOCifyLocale.text("خاصة بالمؤلف والمدير"), observed: SOCifyLocale.text("حدث مرصود"), action: SOCifyLocale.text("إجراء"), supported: SOCifyLocale.text("مؤيدة بأدلة"), refuted: SOCifyLocale.text("دُحضت"), observable: SOCifyLocale.text("قيمة مرصودة"), ioc: SOCifyLocale.text("مؤشر اختراق مثبت"), active: SOCifyLocale.text("نشط"), expired: SOCifyLocale.text("منتهي"), revoked: SOCifyLocale.text("مسحوب"),
  compromised_credentials: SOCifyLocale.text("اعتماد مخترق"), misconfiguration: SOCifyLocale.text("ضعف إعداد"), exploited_vulnerability: SOCifyLocale.text("استغلال ثغرة"), phishing: SOCifyLocale.text("تصيد أو هندسة اجتماعية"), excessive_privileges: SOCifyLocale.text("صلاحيات زائدة"), monitoring_gap: SOCifyLocale.text("فجوة مراقبة"), supply_chain: SOCifyLocale.text("سلسلة توريد"), l1_analyst: SOCifyLocale.text("محلل L1"), l2_responder: SOCifyLocale.text("مستجيب L2"), investigator: SOCifyLocale.text("محقق"), reviewer: SOCifyLocale.text("مراجع"), analyst: SOCifyLocale.text("محلل"), auditor: SOCifyLocale.text("مدقق"), soc_manager: SOCifyLocale.text("مدير الفريق"), admin: SOCifyLocale.text("مسؤول المنصة")
};

function autopsyLabel(value) { return autopsyLabels[value] || value; }

function autopsyEditPanel(title, content, wide = false) {
  return panel(title, node("details", { class: "context-editor" }, [
    node("summary", { text: SOCifyLocale.text("تعديل التفاصيل") }), content
  ]), wide);
}

function autopsyBadge(value) {
  return node("span", { class: `badge ${String(value || "unknown").replace(/[^a-z_]/g, "")}`, text: autopsyLabel(value) || "—" });
}

Object.assign(autopsyLabels, { identity_provider: SOCifyLocale.text("مزود الهوية"), email_gateway: SOCifyLocale.text("بوابة البريد"), mobile_device: SOCifyLocale.text("جهاز محمول"), storage: SOCifyLocale.text("نظام تخزين"), virtual_machine: SOCifyLocale.text("آلة افتراضية"), industrial_device: SOCifyLocale.text("جهاز صناعي"), unpatched_software: SOCifyLocale.text("برمجيات غير محدثة"), weak_authentication: SOCifyLocale.text("مصادقة ضعيفة"), insecure_remote_access: SOCifyLocale.text("وصول بعيد غير آمن"), insufficient_segmentation: SOCifyLocale.text("تقسيم شبكي غير كاف"), data_exposure: SOCifyLocale.text("انكشاف بيانات"), process_gap: SOCifyLocale.text("فجوة في الإجراءات") });
autopsyLabels.reason = SOCifyLocale.text("السبب");
Object.assign(autopsyLabels, { handoff_to: SOCifyLocale.text("العضو البديل للمسؤوليات"), assignee: SOCifyLocale.text("المحلل المسؤول"), instructions: SOCifyLocale.text("المطلوب تحليله وتسليمه"), email: SOCifyLocale.text("البريد الإلكتروني الداخلي"), task_id: SOCifyLocale.text("المهمة المرتبطة"), decision: SOCifyLocale.text("القرار الموثق") });

function autopsySelect(name, values, current = "") {
  return node("select", { name }, values.map((value) => node("option", { value, selected: value === current, text: autopsyLabel(value) })));
}

function autopsyCaseURL(caseId, changes = {}) {
  const path = `/cases/${caseId}`;
  const target = new URL(path, window.location.origin);
  if (window.location.pathname === path) target.search = window.location.search;
  for (const [key, value] of Object.entries(changes)) {
    if (value === null || value === "") target.searchParams.delete(key);
    else target.searchParams.set(key, String(value));
  }
  return target.pathname + target.search;
}

function autopsyCaseListURL() {
  const current = new URLSearchParams(window.location.search);
  const target = new URL("/cases", window.location.origin);
  if (current.get("list_q")) target.searchParams.set("q", current.get("list_q"));
  if (current.get("list_page")) target.searchParams.set("page", current.get("list_page"));
  return target.pathname + target.search;
}

function autopsyChoice(name, values, current = "", required = false) {
  const id = `choice-${name}-${crypto.randomUUID()}`;
  const input = node("input", { name, list: id, required, autocomplete: "off", class: "search-choice" });
  const choices = values.map((entry) => typeof entry === "object" ? { ...entry, label: displayText(entry.label) } : { value: entry, label: displayText(autopsyLabel(entry)) });
  const labelCounts = new Map();
  for (const entry of choices) labelCounts.set(entry.label, (labelCounts.get(entry.label) || 0) + 1);
  for (const entry of choices) if (labelCounts.get(entry.label) > 1) entry.label = `${entry.label} · ${entry.value}`;
  const selected = choices.find((entry) => String(entry.value) === String(current));
  input.value = selected?.label || "";
  const list = node("datalist", { id }, choices.map((entry) => node("option", { value: entry.label })));
  input.autopsyValue = () => {
    if (!input.value.trim() && !required) return null;
    const entry = choices.find((item) => item.label === input.value);
    if (!entry) throw new Error(SOCifyLocale.template`اختر قيمة معروفة للحقل ${autopsyLabel(name)}`);
    return entry.value;
  };
  let highlighted = -1;
  const menuId = `${id}-menu`;
  const menu = node("div", { id: menuId, role: "listbox", class: "choice-menu", hidden: true, "aria-label": autopsyLabel(name) });
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-controls", menuId);
  input.setAttribute("aria-expanded", "false");
  input.setAttribute("aria-autocomplete", "list");
  const expanded = (open) => {
    menu.hidden = !open;
    if (!open) highlighted = -1;
    input.setAttribute("aria-expanded", String(open));
    toggle.setAttribute("aria-expanded", String(open));
    // Keep the datalist contract for consumers, while one branded popup owns interaction.
    for (const option of list.options) option.disabled = open;
  };
  const close = () => expanded(false);
  const show = (all = false) => {
    const query = all ? "" : input.value.trim().toLocaleLowerCase();
    const matches = choices.filter((entry) => entry.label.toLocaleLowerCase().includes(query)).slice(0, 100);
    menu.replaceChildren(...matches.map((entry, index) => {
      const option = node("button", { type: "button", tabindex: "-1", role: "option", id: `${menuId}-${index}`, "aria-selected": String(input.value === entry.label), text: entry.label });
      option.addEventListener("focus", () => { highlighted = index; });
      option.addEventListener("mousedown", (event) => event.preventDefault());
      option.addEventListener("click", () => { input.value = entry.label; input.dispatchEvent(new Event("input", { bubbles: true })); close(); input.focus(); });
      return option;
    }));
    expanded(matches.length > 0);
  };
  input.addEventListener("input", () => { if (choices.some((entry) => entry.label === input.value)) close(); else show(); });
  input.addEventListener("keydown", (event) => {
    if (["ArrowDown", "ArrowUp"].includes(event.key)) {
      event.preventDefault();
      show(!input.value.trim() || choices.some((entry) => entry.label === input.value));
      const options = [...menu.children];
      (event.key === "ArrowDown" ? options[0] : options.at(-1))?.focus();
    } else if (event.key === "Enter" && !menu.hidden && highlighted >= 0) { event.preventDefault(); menu.children[highlighted]?.click(); }
    else if (event.key === "Escape") { event.preventDefault(); close(); }
  });
  menu.addEventListener("keydown", (event) => {
    const options = [...menu.children];
    const index = options.indexOf(document.activeElement);
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      const next = event.key === "Home" ? 0 : event.key === "End" ? options.length - 1 : (index + (event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length;
      options[next]?.focus();
    } else if (event.key === "Escape") { event.preventDefault(); close(); input.focus(); }
    else if (event.key === "Tab") close();
  });
  input.addEventListener("blur", (event) => { if (!menu.contains(event.relatedTarget)) close(); });
  const toggle = node("button", { type: "button", class: "choice-toggle", "aria-label": SOCifyLocale.text("عرض الخيارات"), "aria-controls": menuId, "aria-expanded": "false", text: "⌄" });
  toggle.addEventListener("mousedown", (event) => event.preventDefault());
  toggle.addEventListener("click", () => { if (menu.hidden) { input.focus(); show(true); } else close(); });
  const control = node("span", { class: "choice-control" }, [input, toggle, list, menu]);
  control.addEventListener("focusout", (event) => { if (!control.contains(event.relatedTarget)) close(); });
  return { control, input };
}

function autopsyModal(title, content) {
  const previous = document.activeElement;
  const dialog = node("dialog", { class: "autopsy-modal", "aria-label": title }, [node("div", { class: "workspace-head" }, [node("h2", { text: title }), button(SOCifyLocale.text("إغلاق"), () => dialog.close())]), content]);
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
        const question = node("input", { value: value.question || SOCifyLocale.text("لماذا حدث ذلك؟"), required: true, maxlength: 500 });
        const answer = node("textarea", { id: `why-answer-${crypto.randomUUID()}`, required: true, maxlength: 2000 }, value.answer || "");
        const answerTopics = [SOCifyLocale.text("اختر محور الإجابة"), SOCifyLocale.text("بيانات اعتماد مخترقة"), SOCifyLocale.text("إعداد غير آمن"), SOCifyLocale.text("ثغرة غير معالجة"), SOCifyLocale.text("رسالة تصيد"), SOCifyLocale.text("صلاحيات زائدة"), SOCifyLocale.text("فجوة في المراقبة"), SOCifyLocale.text("إجراء تشغيلي غير مكتمل"), SOCifyLocale.text("اعتماد من سلسلة التوريد"), SOCifyLocale.text("خطأ بشري"), SOCifyLocale.text("الأدلة غير كافية"), SOCifyLocale.text("سبب آخر موثق")];
        const answerChoice = node("select", { "aria-label": SOCifyLocale.text("محور الإجابة") }, answerTopics.map((text, index) => node("option", { value: index ? text : "", text })));
        const validateAnswer = () => answer.setCustomValidity(answerTopics.slice(1).some((topic) => answer.value.trim() === `${topic}:`) ? SOCifyLocale.text("وثق الإجابة والأدلة بعد محور الإجابة") : "");
        answer.addEventListener("input", validateAnswer);
        answerChoice.addEventListener("change", () => { if (answerChoice.value && !answer.value.trim()) { answer.value = `${answerChoice.value}: `; answer.focus(); } validateAnswer(); });
        const answerLabel = field(SOCifyLocale.text("الإجابة"), answer);
        answerLabel.setAttribute("for", answer.id);
        const answerField = node("div", { class: "answer-control" }, [field(SOCifyLocale.text("محور الإجابة"), answerChoice), node("small", { text: SOCifyLocale.text("اختر محورًا ثم وثق الإجابة والأدلة. الاختيار وحده لا يثبت السبب.") }), answerLabel]);
        const assessment = autopsySelect("why_assessment", ["unverified", "hypothesis", "supported", "refuted"], value.assessment || (value.evidence_id ? "supported" : "unverified"));
        const evidence = autopsyChoice("evidence_id", (autopsy.current?.evidence || []).map((item) => ({ value: item.id, label: `${item.title} · ${item.id}` })), value.evidence_id);
        const parent = node("select", { name: "why_parent" });
        const row = node("fieldset", { class: "why-step" }, [node("legend", { text: SOCifyLocale.text("سبب مرتبط بدليل أو فرضية معلنة") }), field(SOCifyLocale.text("السؤال"), question), answerField, field(SOCifyLocale.text("التقييم"), assessment), field(SOCifyLocale.text("الدليل"), evidence.control), field(SOCifyLocale.text("السبب السابق في الشجرة"), parent)]);
        row.whyId = identifier;
        row.whyParent = parent;
        const refresh = () => [...rows.children].forEach((item) => {
          const selected = item.whyParent.value || item.whyInitialParent || "";
          item.whyParent.replaceChildren(node("option", { value: "", text: SOCifyLocale.text("جذر مستقل") }), ...[...rows.children].filter((other) => other !== item).map((other, index) => node("option", { value: other.whyId, text: SOCifyLocale.template`السبب ${index + 1} · ${other.whyId}`, selected: other.whyId === selected })));
        });
        row.whyInitialParent = value.parent_id;
        parent.addEventListener("change", () => { row.whyInitialParent = parent.value; });
        row.autopsyValue = () => ({ id: identifier, question: question.value, answer: answer.value, assessment: assessment.value, ...(parent.value ? { parent_id: parent.value } : {}), ...(evidence.input.autopsyValue() ? { evidence_id: evidence.input.autopsyValue() } : {}) });
        row.append(button(SOCifyLocale.text("حذف الخطوة"), () => { row.remove(); refresh(); }));
        rows.append(row);
        refresh();
      };
      (initial[key] || []).forEach(add);
      control = node("fieldset", { class: "span-2" }, [node("legend", { text: autopsyLabel(key) }), rows, button(SOCifyLocale.text("إضافة سؤال لماذا"), () => { if (rows.children.length < 10) add(); })]);
      getters[key] = () => [...rows.children].map((row) => row.autopsyValue());
      form.append(control);
      continue;
    }
    let choices = spec.choices;
    if (spec.user) choices = autopsy.team.members.filter((member) => member.is_active && (!(spec.case_member || key === "owner_id") || ["admin", "soc_manager"].includes(member.role) || autopsy.current?.members.some((item) => item.user_id === member.id))).map((member) => ({ value: member.id, label: `${member.name} · ${autopsyLabel(member.role)}` }));
    if (spec.evidence) choices = (autopsy.current?.evidence || []).map((evidence) => ({ value: evidence.id, label: `${evidence.title} · ${evidence.id}` }));
    if (spec.asset) choices = (autopsy.assets || []).map((record) => ({ value: record.id, label: `${record.payload.name} · ${record.id}` }));
    if (spec.task) choices = (autopsy.current?.tasks || []).map((task) => ({ value: task.id, label: `${task.title} · ${task.id}` }));
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
    form.append(field(`${autopsyLabel(key)}${spec.required ? " *" : ""}${spec.timestamp ? SOCifyLocale.text(" · وقت المتصفح") : ""}`, control, (spec.max || 0) > 1000));
  }
  const errors = node("p", { class: "notice span-2", role: "alert", hidden: true });
  const save = node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("حفظ") });
  form.append(errors, node("div", { class: "action-row span-2" }, save));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    save.setAttribute("aria-busy", "true");
    save.textContent = SOCifyLocale.text("جارٍ الحفظ…");
    try {
      const values = Object.fromEntries(Object.entries(getters).map(([key, getter]) => [key, getter()]).filter(([, value]) => value !== null));
      await submit(values);
    } catch (error) { errors.hidden = false; errors.textContent = error.message; }
    finally { save.disabled = false; save.removeAttribute("aria-busy"); save.textContent = SOCifyLocale.text("حفظ"); }
  });
  return form;
}

function autopsyNewCase() {
  const form = autopsyForm({ title: { required: true, max: 255 }, reason: { required: true, choices: autopsy.catalog.reasons }, objective: { required: true, max: 2000 }, classification: { required: true, choices: autopsy.catalog.classifications } }, async (body) => {
    const created = await api("/api/cases", { method: "POST", body });
    window.location.assign(`/cases/${created.id}`);
  }, { classification: "confidential" });
  autopsyModal(SOCifyLocale.text("إنشاء قضية: الاسم والسبب والهدف"), form);
}

async function autopsyCases(page = null, query = null) {
  const location = new URL(window.location.href);
  page = page ?? Number(location.searchParams.get("page") || 1);
  if (!Number.isSafeInteger(page) || page < 1 || page > 1000000) page = 1;
  query = query ?? location.searchParams.get("q") ?? "";
  if (page > 1) location.searchParams.set("page", String(page)); else location.searchParams.delete("page");
  if (query) location.searchParams.set("q", query); else location.searchParams.delete("q");
  window.history.replaceState(null, "", location.pathname + location.search);
  begin("cases");
  document.getElementById("section-title").textContent = SOCifyLocale.text("مركز العمليات");
  document.getElementById("section-kicker").textContent = "SOCIFY DIGITAL AUTOPSY";
  const data = await api(`/api/cases?page=${page}&page_size=25&q=${encodeURIComponent(query)}`);
  const search = node("input", { name: "q", type: "search", value: query, maxlength: 200, placeholder: SOCifyLocale.text("الاسم أو مرجع القضية") });
  const filters = node("form", { class: "filter-row", "aria-label": SOCifyLocale.text("بحث القضايا") }, [field(SOCifyLocale.text("بحث"), search), node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("بحث") })]);
  filters.addEventListener("submit", (event) => { event.preventDefault(); autopsyCases(1, search.value).catch(handleError); });
  const root = node("div", { class: "cases-view" }, [pageHead(SOCifyLocale.text("قضايا الفريق"), SOCifyLocale.text("تجتمع الأدلة والتحليل والمسؤوليات والقرارات والتقرير داخل القضية نفسها."), permission("cases.create") ? [button(SOCifyLocale.text("إنشاء قضية"), autopsyNewCase, "primary")] : []), filters]);
  root.append(data.items.length ? table([{ label: SOCifyLocale.text("المرجع"), value: (row) => node("bdi", { class: "case-reference", text: row.reference }) }, { label: SOCifyLocale.text("القضية"), value: (row) => node("a", { class: "case-link", href: autopsyCaseURL(row.id, { list_q: query, list_page: page }), text: row.title }) }, { label: SOCifyLocale.text("الحالة"), value: (row) => autopsyBadge(row.status) }, { label: SOCifyLocale.text("الخطورة"), value: (row) => autopsyBadge(row.severity) }, { label: SOCifyLocale.text("الأدلة"), value: "evidence_count" }, { label: SOCifyLocale.text("المسؤول"), value: "assignee_name" }, { label: SOCifyLocale.text("فتح"), value: (row) => linkedButton(SOCifyLocale.text("فتح القضية"), autopsyCaseURL(row.id, { list_q: query, list_page: page })) }], data.items) : emptyState(SOCifyLocale.text("لا توجد قضايا في النطاق المصرح"), SOCifyLocale.text("أنشئ القضية باسم وسبب وهدف، ثم أضف الأدلة إلى مساحة التحقيق.")));
  root.querySelector(".table-wrap")?.classList.add("case-table");
  if (data.items.length) {
    const folders = node("div", { class: "case-folder-grid" });
    for (const row of data.items) {
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      for (const [key, value] of Object.entries({ width: 52, height: 44, viewBox: "0 0 48 40", "aria-hidden": "true" })) svg.setAttribute(key, String(value));
      const path = document.createElementNS(svg.namespaceURI, "path");
      path.setAttribute("d", "M2 7h15l5 5h24v26H2Z M2 7V3h15l5 4");
      path.setAttribute("fill", "currentColor");
      svg.append(path);
      folders.append(node("a", { class: "case-folder", href: autopsyCaseURL(row.id, { list_q: query, list_page: page }) }, [svg, node("bdi", { text: row.reference }), node("strong", { text: row.title }), node("small", { text: autopsyLabel(row.status) })]));
    }
    const tableView = root.querySelector(".case-table");
    let selectedView = document.body.classList.contains("window-focused") || innerWidth < 1100 ? "table" : "folders";
    try { const storedView = sessionStorage.getItem("socify-case-view"); if (["folders", "table"].includes(storedView)) selectedView = storedView; } catch (_) {}
    const controls = node("div", { class: "case-view-controls", role: "group", "aria-label": SOCifyLocale.text("طريقة عرض القضايا") });
    const updateView = view => {
      selectedView = view;
      folders.hidden = view !== "folders";
      tableView.hidden = view !== "table";
      controls.querySelectorAll("button").forEach(control => control.setAttribute("aria-pressed", String(control.dataset.view === view)));
    };
    for (const [view, title] of [["folders", SOCifyLocale.text("عرض المجلدات")], ["table", SOCifyLocale.text("عرض الجدول")]]) {
      const control = button(title, () => { updateView(view); try { sessionStorage.setItem("socify-case-view", view); } catch (_) {} }, "ghost compact");
      control.dataset.view = view;
      controls.append(control);
    }
    root.insertBefore(controls, tableView);
    root.insertBefore(folders, tableView);
    updateView(selectedView);
  }
  const pages = node("div", { class: "action-row pagination" }, node("p", { text: SOCifyLocale.template`${data.total} قضية · الصفحة ${page}` }));
  if (page > 1) pages.append(button(SOCifyLocale.text("السابق"), () => autopsyCases(page - 1, query).catch(handleError)));
  if (page * 25 < data.total) pages.append(button(SOCifyLocale.text("التالي"), () => autopsyCases(page + 1, query).catch(handleError)));
  root.append(pages);
  finish(root);
}

function autopsyRecordCard(record) {
  const values = node("dl");
  Object.entries(record.payload).forEach(([key, value]) => {
    if (value === null || value === "") return;
    let display = Array.isArray(value) ? value.map((item) => typeof item === "object" && item !== null ? (item.question ? `${item.question}: ${item.answer || ""} · ${item.assessment || ""}${item.evidence_id ? SOCifyLocale.template` · دليل ${item.evidence_id}` : ""}${item.parent_id ? SOCifyLocale.template` · فرع ${item.parent_id}` : ""}` : JSON.stringify(item)) : item).join("\n") : typeof value === "object" ? JSON.stringify(value) : autopsyLabel(value);
    if (key.endsWith("_at") || key === "event_time") display = formatTime(value);
    values.append(node("dt", { text: autopsyLabel(key) }), node("dd", { text: display }));
  });
  const card = node("article", { class: "card record-card" }, [node("h3", { text: record.payload.title || record.payload.name || autopsyLabel(record.kind) }), values, node("small", { text: SOCifyLocale.template`الإصدار ${record.version} · ${formatTime(record.updated_at)}` })]);
  if (autopsy.current.can_update && autopsy.catalog.record_schemas[record.kind]) card.append(button(SOCifyLocale.text("تعديل"), () => autopsyEditRecord(record.kind, record)));
  if (record.kind === "analysis" && record.payload.analysis_type === "local_detection" && record.payload.next_after_id && autopsy.current.can_update && autopsy.current.status !== "closed") card.append(autopsyAction(SOCifyLocale.text("استكمال فحص الدفعة التالية"), async () => { await api(`/api/cases/${autopsy.current.id}/detection`, { method: "POST", body: { version: autopsy.current.version, mode: record.payload.mode, after_id: record.payload.next_after_id } }); await autopsyCase(autopsy.current.id); }));
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
  dialog = autopsyModal(`${record ? SOCifyLocale.text("تعديل") : SOCifyLocale.text("إضافة")} ${autopsyLabel(kind)}`, form);
}

async function autopsyRecordPanel(kind) {
  const data = await api(`/api/cases/${autopsy.current.id}/records?kind=${kind}&limit=100`);
  const content = data.items.length ? node("div", { class: "record-grid" }, data.items.map(autopsyRecordCard)) : emptyState(SOCifyLocale.text("لا سجلات بعد"), SOCifyLocale.text("أضف نتيجة موثقة من أدلة القضية، وميّز الحقائق عن الفرضيات."));
  return panel(autopsyLabel(kind), node("div", { class: "panel-body" }, [autopsy.current.can_update ? button(SOCifyLocale.template`إضافة ${autopsyLabel(kind)}`, () => autopsyEditRecord(kind).catch(handleError), "primary") : null, content]), true);
}

async function autopsyCase(caseId) {
  begin("case");
  let selected = new URLSearchParams(window.location.search).get("tab") || "summary";
  autopsy.current = await api(`/api/cases/${caseId}`);
  const current = autopsy.current;
  document.getElementById("section-title").textContent = current.reference;
  document.getElementById("section-kicker").textContent = current.reference;
  document.title = `${current.reference} | SOCify Digital Autopsy`;
  const restricted = current.full_case_access === false;
  if (restricted && !["summary", "logs"].includes(selected)) selected = "logs";
  const assetData = restricted ? { items: [] } : await api(`/api/cases/${caseId}/records?kind=asset&limit=100`);
  autopsy.assets = assetData.items;
  const root = node("div", {}, [pageHead(current.title, SOCifyLocale.text("تجتمع الأدلة والتحليل والمسؤوليات والقرارات والتقرير داخل القضية نفسها."), [linkedButton(SOCifyLocale.text("جميع القضايا"), autopsyCaseListURL())])]);
  root.append(node("div", { class: "case-context-bar" }, [node("bdi", { class: "case-reference", text: current.reference }), autopsyBadge(current.status), autopsyBadge(current.severity)]));
  if (selected === "summary" && !restricted) {
    const fact = (label, value) => node("div", {}, [node("dt", { text: label }), node("dd", { text: value || "—" })]);
    root.append(node("section", { class: "case-overview", "aria-label": SOCifyLocale.text("نظرة على القضية") }, [
      node("h3", { text: SOCifyLocale.text("هدف التحقيق") }), node("p", { text: current.context?.objective || "—" }),
      node("dl", { class: "case-facts" }, [fact(SOCifyLocale.text("سبب فتح القضية"), autopsyLabel(current.context?.reason)), fact(SOCifyLocale.text("التصنيف الأمني"), autopsyLabel(current.context?.classification)), fact(SOCifyLocale.text("قرار صحة التنبيه"), autopsyLabel(current.context?.alert_verdict))])
    ]));
  }
  let tabs = [["summary", SOCifyLocale.text("الملخص والمسؤوليات")], ["logs", SOCifyLocale.text("السجلات والأدلة")], ["analysis", SOCifyLocale.text("الأصول والمؤشرات")], ["investigation", SOCifyLocale.text("التحقيق والخط الزمني")], ["response", SOCifyLocale.text("الاستجابة والتصعيد")], ["activity", SOCifyLocale.text("الحيازة والنشاط")]];
  if (restricted) {
    tabs = tabs.slice(0, 2);
    root.append(node("p", { class: "notice", text: SOCifyLocale.text("نطاق دفعات محدد: تظهر السجلات المصرح بها فقط. يتطلب سياق التحقيق والتقارير الوصول إلى جميع دفعات القضية.") }));
  }
  root.append(node("nav", { class: "case-tabs", "aria-label": SOCifyLocale.text("أقسام القضية") }, tabs.map(([id, label]) => node("a", { class: "button ghost", href: autopsyCaseURL(caseId, { tab: id }), "aria-current": selected === id ? "page" : null, text: label }))));
  const content = node("div", { class: "case-content" });
  if (selected === "summary") {
    const transitions = autopsy.catalog.case_transitions[current.status] || [];
    if (current.can_update && transitions.length) content.append(panel(SOCifyLocale.text("حالة القضية"), node("div", { class: "panel-body" }, autopsyForm({ status: { required: true, choices: transitions.filter((value) => value !== "closed" || permission("cases.close")) }, reason: { required: true, max: 2000 } }, async (body) => { await api(`/api/cases/${caseId}/transitions`, { method: "POST", body: { ...body, version: current.version } }); await autopsyCase(caseId); })), true));
    const schema = { reason: { required: true, max: 500 }, objective: { required: true, max: 2000 }, classification: { choices: autopsy.catalog.classifications, required: true }, attack_outcome: { choices: autopsy.catalog.outcomes, required: true }, alert_verdict: { choices: autopsy.catalog.verdicts, required: true } };
    if (current.can_update && current.status !== "closed") content.append(autopsyEditPanel(SOCifyLocale.text("سبب القضية وهدفها ونتيجتها"), node("div", { class: "panel-body" }, autopsyForm(schema, async (body) => { await api(`/api/cases/${caseId}/context`, { method: "PATCH", body: { ...body, version: current.version } }); await autopsyCase(caseId); }, current.context || { classification: "confidential", attack_outcome: "unknown", alert_verdict: "undetermined" })), true));
    else content.append(panel(SOCifyLocale.text("ملخص القضية"), node("div", { class: "panel-body" }, [node("p", { text: current.context?.reason || SOCifyLocale.text("قضية موروثة؛ يتطلب ملخصها مراجعة") }), node("p", { text: current.context?.objective || "—" })]), true));
    content.append(panel(SOCifyLocale.text("فريق القضية"), table([{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("الدور"), value: (row) => autopsyLabel(row.role) }, { label: SOCifyLocale.text("المسؤولية"), value: (row) => autopsyLabel(row.responsibility) }, { label: SOCifyLocale.text("أُسندت"), value: (row) => formatTime(row.assigned_at) }], current.members)));
    if (current.can_manage) {
      content.append(autopsyEditPanel(SOCifyLocale.text("تحديد مسؤولية عضو"), node("div", { class: "panel-body" }, autopsyForm({ user_id: { required: true, user: true }, responsibility: { required: true, choices: ["monitoring", "l1", "l2", "investigator", "reviewer", "owner"] } }, async (body) => { await api(`/api/cases/${caseId}/members`, { method: "POST", body }); await autopsyCase(caseId); }))));
      if (current.status !== "closed") content.append(autopsyEditPanel(SOCifyLocale.text("تسليم المناوبة"), node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("ينقل المسؤوليات والمهام المفتوحة والتصعيد والإسناد مع حفظ تاريخ المسؤول السابق. يبقى حسابه ووصوله الحالي فعالين؛ سحب الوصول يتم من إدارة الفريق.") }), autopsyForm({ from_user: { required: true, user: true, case_member: true }, to_user: { required: true, user: true }, reason: { required: true, max: 1000 } }, async (body) => { await api(`/api/cases/${caseId}/handoff`, { method: "POST", body: { ...body, version: current.version } }); await autopsyCase(caseId); })])));
    }
    content.append(panel(SOCifyLocale.text("مهام القضية"), current.tasks.length ? table([{ label: SOCifyLocale.text("المهمة"), value: "title" }, { label: SOCifyLocale.text("الحالة"), value: "status" }, { label: SOCifyLocale.text("إكمال"), value: (row) => current.can_update && row.status !== "completed" ? button(SOCifyLocale.text("إكمال المهمة"), async () => { try { await api(`/api/incidents/${caseId}/tasks/${row.id}`, { method: "PATCH", body: { status: "completed" } }); await autopsyCase(caseId); } catch (error) { handleError(error); } }) : "—" }], current.tasks) : emptyState(SOCifyLocale.text("لا مهام"), SOCifyLocale.text("تظهر هنا المهام المرتبطة بالقضية."))));
  } else if (selected === "logs") {
    if (window.SOCifyAutopsy.logs) content.append(await window.SOCifyAutopsy.logs(caseId));
    content.append(panel(SOCifyLocale.text("أدلة القضية"), current.evidence.length ? table([{ label: SOCifyLocale.text("الدليل"), value: "title" }, { label: SOCifyLocale.text("النوع"), value: "evidence_type" }, { label: "SHA-256", value: (row) => node("bdi", { text: row.sha256 }) }, { label: SOCifyLocale.text("أضيف"), value: (row) => formatTime(row.added_at) }], current.evidence) : emptyState(SOCifyLocale.text("لا أدلة مرتبطة"), SOCifyLocale.text("احتفظ بالأصل ومصدره واربطه بالقضية قبل استخلاص النتائج.")), true));
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
    content.append(panel(SOCifyLocale.text("سلسلة حيازة الأدلة"), node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.template`${data.integrity_valid ? SOCifyLocale.text("سلسلة البصمات متسقة") : SOCifyLocale.text("تحذير: عدم اتساق في السلسلة")} · ${data.total} حركة` }), table([{ label: SOCifyLocale.text("الإجراء"), value: "action" }, { label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.created_at) }, { label: SOCifyLocale.text("بصمة الحركة"), value: (row) => node("bdi", { text: row.entry_hash }) }], data.items)]), true));
    content.append(panel(SOCifyLocale.text("نشاط القضية"), table([{ label: SOCifyLocale.text("الحدث"), value: "action" }, { label: SOCifyLocale.text("الفاعل"), value: "actor_name" }, { label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.created_at) }], current.history), true));
  }
  if (!restricted && selected === "reports" && window.SOCifyAutopsy.capsules) content.append(await window.SOCifyAutopsy.capsules(caseId));
  if (!restricted && window.SOCifyAutopsy.reports && !tabs.some(([id]) => id === "reports")) {
    const reportsLink = linkedButton(SOCifyLocale.text("التقارير والمراجعة"), autopsyCaseURL(caseId, { tab: "reports" }));
    if (selected === "reports") reportsLink.setAttribute("aria-current", "page");
    root.querySelector(".case-tabs").append(reportsLink);
  }
  root.append(content);
  finish(root);
}

async function autopsyStart() {
  const role = document.querySelector("[data-user-role]");
  if (role) role.textContent = autopsyLabel(state.user.role);
  [autopsy.catalog, autopsy.team] = await Promise.all([api("/api/autopsy/catalog"), api("/api/team")]);
  const caseId = document.querySelector('meta[name="case-id"]')?.content;
  if (caseId) return autopsyCase(Number(caseId));
  if (state.section === "profile" && window.SOCifyAutopsy.profile) return window.SOCifyAutopsy.profile();
  if (state.section === "analysis-library" && window.SOCifyAutopsy.library) return window.SOCifyAutopsy.library();
  if (state.section === "playbooks" && window.SOCifyAutopsy.procedureLibrary) return window.SOCifyAutopsy.procedureLibrary();
  if (state.section === "team") return window.SOCifyAutopsy.team();
  if (state.section === "my-tasks") {
    begin("my-tasks");
    finish(panel(SOCifyLocale.text("مهامي داخل القضايا"), autopsy.team.assignments.length ? table([{ label: SOCifyLocale.text("القضية"), value: (row) => linkedButton(row.case_title, `/cases/${row.case_id}`) }, { label: SOCifyLocale.text("المهمة"), value: "instructions" }, { label: SOCifyLocale.text("الحالة"), value: "task_status" }], autopsy.team.assignments) : emptyState(SOCifyLocale.text("لا دفعات مسندة"), SOCifyLocale.text("تظهر مهام تحليل السجلات التي يسندها مدير الفريق إليك هنا.")), true));
    return;
  }
  if (state.section === "profile") {
    const data = await api("/api/auth/sessions");
    finish(panel(SOCifyLocale.text("أمان الحساب والجلسات"), node("div", { class: "panel-body" }, [node("p", { text: `${state.user.name} · ${autopsyLabel(state.user.role)}` }), table([{ label: SOCifyLocale.text("الجلسة"), value: "id" }, { label: SOCifyLocale.text("بدأت"), value: (row) => formatTime(row.created_at) }, { label: SOCifyLocale.text("تنتهي"), value: (row) => formatTime(row.expires_at) }], data.items)]), true));
    return;
  }
  await autopsyCases();
}

window.SOCifyAutopsy = { start: autopsyStart };
