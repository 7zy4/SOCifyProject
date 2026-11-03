"use strict";

const autopsy = { catalog: null, team: null, current: null };
window.addEventListener("hashchange", () => autopsy.taskNavigation?.());
const autopsyLabels = {
  pending: SOCifyLocale.text("لم تبدأ"), reviewed: SOCifyLocale.text("تمت المراجعة"),
  asset: SOCifyLocale.text("الأصول والأجهزة"), indicator: SOCifyLocale.text("المؤشرات"), timeline: SOCifyLocale.text("الخط الزمني"), war_room: SOCifyLocale.text("غرفة التحقيق"), hypothesis: SOCifyLocale.text("الفرضيات"), response: SOCifyLocale.text("إجراءات الاستجابة"), corrective: SOCifyLocale.text("الإجراءات التصحيحية"), foothold: SOCifyLocale.text("أقدم اختراق مثبت"), root_cause: SOCifyLocale.text("الأسباب الجذرية"), escalation: SOCifyLocale.text("التصعيد"), playbook: SOCifyLocale.text("إجراء القضية"), reputation: SOCifyLocale.text("نتائج السمعة المستوردة"), analysis: SOCifyLocale.text("نتائج التحليل"),
  title: SOCifyLocale.text("العنوان"), name: SOCifyLocale.text("الاسم"), type: SOCifyLocale.text("النوع"), role: SOCifyLocale.text("دور الأصل"), address: SOCifyLocale.text("العنوان"), owner: SOCifyLocale.text("مالك الأصل"), operating_system: SOCifyLocale.text("نظام التشغيل"), importance: SOCifyLocale.text("أهمية الأصل"), assessment: SOCifyLocale.text("التقييم"), details: SOCifyLocale.text("التفاصيل والأدلة"), value: SOCifyLocale.text("القيمة"), classification: SOCifyLocale.text("التصنيف"), status: SOCifyLocale.text("الحالة"), confidence: SOCifyLocale.text("الثقة من 0 إلى 100"), source: SOCifyLocale.text("المصدر"), expires_at: SOCifyLocale.text("تنتهي في"), description: SOCifyLocale.text("الوصف"), event_time: SOCifyLocale.text("وقت الحدث"), category: SOCifyLocale.text("الفئة"), tags: SOCifyLocale.text("الوسوم مفصولة بفاصلة"), body: SOCifyLocale.text("الملاحظة أو القرار"), visibility: SOCifyLocale.text("نطاق الملاحظة"), statement: SOCifyLocale.text("الفرضية"), phase: SOCifyLocale.text("المرحلة"), performed_by: SOCifyLocale.text("من نفذ الإجراء"), performed_at: SOCifyLocale.text("وقت التنفيذ"), owner_id: SOCifyLocale.text("المسؤول"), due_at: SOCifyLocale.text("الموعد المستهدف"), validation: SOCifyLocale.text("التحقق من الفاعلية"), asset_id: SOCifyLocale.text("الأصل المرتبط"), first_observed_at: SOCifyLocale.text("أول نشاط مثبت"), limitations: SOCifyLocale.text("حدود الأدلة والاستنتاج"), conclusion: SOCifyLocale.text("استنتاج التحقيق"), whys: SOCifyLocale.text("تحليل 5 Whys"), evidence_id: SOCifyLocale.text("الدليل المرتبط"), to_user: SOCifyLocale.text("مستقبل التصعيد"), from_level: SOCifyLocale.text("من المستوى"), to_level: SOCifyLocale.text("إلى المستوى"), reason: SOCifyLocale.text("سبب فتح القضية"), priority: SOCifyLocale.text("الأولوية"), objective: SOCifyLocale.text("هدف التحقيق"), attack_outcome: SOCifyLocale.text("نتيجة الهجوم"), alert_verdict: SOCifyLocale.text("قرار صحة التنبيه"),
  new: SOCifyLocale.text("مسودة"), open: SOCifyLocale.text("فرز أولي"), triaged: SOCifyLocale.text("تم الفرز"), investigating: SOCifyLocale.text("قيد التحقيق"), escalated: SOCifyLocale.text("مصعّدة"), contained: SOCifyLocale.text("تم الاحتواء"), remediated: SOCifyLocale.text("تمت المعالجة"), recovered: SOCifyLocale.text("تم التعافي"), awaiting_review: SOCifyLocale.text("بانتظار المراجعة"), closed: SOCifyLocale.text("مغلقة"), reopened: SOCifyLocale.text("أعيد فتحها"), cancelled: SOCifyLocale.text("ملغاة"),
  alert_review: SOCifyLocale.text("مراجعة تنبيه"), suspicious_activity: SOCifyLocale.text("نشاط مشتبه به"), threat_hunt: SOCifyLocale.text("صيد تهديد"), user_report: SOCifyLocale.text("بلاغ مستخدم"), forensic_review: SOCifyLocale.text("فحص أدلة رقمية"), other: SOCifyLocale.text("أخرى"), internal: SOCifyLocale.text("داخلي"), confidential: SOCifyLocale.text("سري"), restricted: SOCifyLocale.text("مقيد"), successful: SOCifyLocale.text("ناجح"), blocked: SOCifyLocale.text("فاشل أو محجوب"), partial: SOCifyLocale.text("نجاح جزئي"), unknown: SOCifyLocale.text("غير معروف"), malicious: SOCifyLocale.text("خبيث مؤكد"), benign: SOCifyLocale.text("نشاط حميد"), false_positive: SOCifyLocale.text("إيجابي كاذب"), undetermined: SOCifyLocale.text("غير محسوم"),
  confirmed: SOCifyLocale.text("متأثر مؤكد"), suspected: SOCifyLocale.text("مشتبه"), checked_clear: SOCifyLocale.text("فُحص ضمن نطاق موثق"), unexamined: SOCifyLocale.text("لم يُفحص"), suspected_attacker: SOCifyLocale.text("مهاجم محتمل"), defender: SOCifyLocale.text("مدافع أو هدف"), affected: SOCifyLocale.text("متأثر"), intermediary: SOCifyLocale.text("وسيط"), web_server: SOCifyLocale.text("خادم ويب"), application_server: SOCifyLocale.text("خادم تطبيق"), database: SOCifyLocale.text("قاعدة بيانات"), workstation: SOCifyLocale.text("جهاز مستخدم"), router: SOCifyLocale.text("راوتر"), switch: SOCifyLocale.text("محول شبكة"), firewall: SOCifyLocale.text("جدار ناري"), security_appliance: SOCifyLocale.text("جهاز أمني"), container: SOCifyLocale.text("حاوية"), cloud_asset: SOCifyLocale.text("أصل سحابي موثق"), critical: SOCifyLocale.text("حرج"), high: SOCifyLocale.text("عالٍ"), medium: SOCifyLocale.text("متوسط"), low: SOCifyLocale.text("منخفض"), urgent: SOCifyLocale.text("عاجل"),
  monitoring: SOCifyLocale.text("المراقبة"), l1: SOCifyLocale.text("المستوى الأول"), l2: SOCifyLocale.text("المستوى الثاني"), investigation: SOCifyLocale.text("التحقيق"), management: SOCifyLocale.text("الإدارة"), raised: SOCifyLocale.text("أُرسل"), acknowledged: SOCifyLocale.text("تم الاستلام"), returned: SOCifyLocale.text("أعيد مع سبب"), resolved: SOCifyLocale.text("تمت الاستجابة"), planned: SOCifyLocale.text("مخطط"), in_progress: SOCifyLocale.text("جارٍ"), succeeded: SOCifyLocale.text("نجح"), failed: SOCifyLocale.text("فشل"), not_applicable: SOCifyLocale.text("غير منطبق"), completed: SOCifyLocale.text("مكتمل"), validated: SOCifyLocale.text("تم التحقق"), containment: SOCifyLocale.text("الاحتواء"), eradication: SOCifyLocale.text("الإزالة"), recovery: SOCifyLocale.text("التعافي"), acknowledgement: SOCifyLocale.text("إقرار الاستلام"), triage: SOCifyLocale.text("الفرز"), detection: SOCifyLocale.text("الرصد"), team: SOCifyLocale.text("الفريق"), private: SOCifyLocale.text("خاصة بالمؤلف والمدير"), observed: SOCifyLocale.text("حدث مرصود"), action: SOCifyLocale.text("إجراء"), supported: SOCifyLocale.text("مؤيدة بأدلة"), refuted: SOCifyLocale.text("دُحضت"), observable: SOCifyLocale.text("قيمة مرصودة"), ioc: SOCifyLocale.text("مؤشر اختراق مثبت"), active: SOCifyLocale.text("نشط"), expired: SOCifyLocale.text("منتهي"), revoked: SOCifyLocale.text("مسحوب"),
  compromised_credentials: SOCifyLocale.text("اعتماد مخترق"), misconfiguration: SOCifyLocale.text("ضعف إعداد"), exploited_vulnerability: SOCifyLocale.text("استغلال ثغرة"), phishing: SOCifyLocale.text("تصيد أو هندسة اجتماعية"), excessive_privileges: SOCifyLocale.text("صلاحيات زائدة"), monitoring_gap: SOCifyLocale.text("فجوة مراقبة"), supply_chain: SOCifyLocale.text("سلسلة توريد"), l1_analyst: SOCifyLocale.text("محلل L1"), l2_responder: SOCifyLocale.text("مستجيب L2"), investigator: SOCifyLocale.text("محقق"), reviewer: SOCifyLocale.text("مراجع"), analyst: SOCifyLocale.text("محلل"), auditor: SOCifyLocale.text("مدقق"), soc_manager: SOCifyLocale.text("مدير الفريق"), admin: SOCifyLocale.text("مسؤول المنصة")
};

function autopsyLabel(value) { return autopsyLabels[value] || value; }
function caseResponsibilityLabel(value) { return value === "owner" ? SOCifyLocale.text("مسؤول القضية") : autopsyLabel(value); }

function autopsyEditPanel(title, content, wide = false) {
  return panel(title, node("details", { class: "context-editor" }, [
    node("summary", { text: SOCifyLocale.text("تعديل التفاصيل") }), content
  ]), wide);
}

function autopsyBadge(value, context = "") {
  const label = context === "case" && value === "resolved" ? SOCifyLocale.text("بانتظار الإغلاق") : autopsyLabel(value);
  return node("span", { class: `badge ${String(value || "unknown").replace(/[^a-z_]/g, "")}`, text: label || "—" });
}

Object.assign(autopsyLabels, { identity_provider: SOCifyLocale.text("مزود الهوية"), email_gateway: SOCifyLocale.text("بوابة البريد"), mobile_device: SOCifyLocale.text("جهاز محمول"), storage: SOCifyLocale.text("نظام تخزين"), virtual_machine: SOCifyLocale.text("آلة افتراضية"), industrial_device: SOCifyLocale.text("جهاز صناعي"), unpatched_software: SOCifyLocale.text("برمجيات غير محدثة"), weak_authentication: SOCifyLocale.text("مصادقة ضعيفة"), insecure_remote_access: SOCifyLocale.text("وصول بعيد غير آمن"), insufficient_segmentation: SOCifyLocale.text("تقسيم شبكي غير كاف"), data_exposure: SOCifyLocale.text("انكشاف بيانات"), process_gap: SOCifyLocale.text("فجوة في الإجراءات") });
autopsyLabels.reason = SOCifyLocale.text("السبب");
autopsyLabels.address = SOCifyLocale.text("عنوان الشبكة");
Object.assign(autopsyLabels, { handoff_to: SOCifyLocale.text("العضو البديل للمسؤوليات"), assignee: SOCifyLocale.text("المحلل المسؤول"), instructions: SOCifyLocale.text("المطلوب تحليله وتسليمه"), email: SOCifyLocale.text("البريد الإلكتروني الداخلي"), task_id: SOCifyLocale.text("المهمة المرتبطة"), decision: SOCifyLocale.text("القرار الموثق") });
Object.assign(autopsyLabels, { previous_shift: SOCifyLocale.text("المناوبة السابقة"), responsibility: SOCifyLocale.text("مسؤولية العضو") });
Object.assign(autopsyLabels, { member_access_revoked: SOCifyLocale.text("سحب وصول عضو"), member_assigned: SOCifyLocale.text("إسناد مسؤولية عضو"), shift_handed_off: SOCifyLocale.text("تسليم المناوبة") });
Object.assign(autopsyLabels, { root_cause_id: SOCifyLocale.text("السبب الجذري المرتبط"), why_id: SOCifyLocale.text("فرع السبب المرتبط") });

function autopsySelect(name, values, current = "") {
  return node("select", { name }, values.map((value) => node("option", { value, selected: value === current, text: autopsyLabel(value) })));
}

function autopsyCaseURL(caseId, changes = {}) {
  const tool = window.SOCifyWorkspace?.selection.required ? {logs:"log-management",reports:"reports"}[changes.tab] : null;
  const path = tool ? `/${tool}` : `/cases/${caseId}`;
  if(tool) changes = {...changes,case_id:caseId,tab:null};
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
      option.addEventListener("click", () => { input.value = entry.label; input.dispatchEvent(new Event("input", { bubbles: true })); input.dispatchEvent(new Event("change", { bubbles: true })); close(); input.focus(); });
      return option;
    }));
    expanded(matches.length > 0);
  };
  input.addEventListener("input", () => { if (!input.value.trim() || choices.some((entry) => entry.label === input.value)) close(); else show(); });
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
  const saving = () => Boolean(dialog.querySelector('form[data-saving="true"]'));
  const closeButton = button(SOCifyLocale.text("إغلاق"), () => { if (!saving() && SOCifyDrafts.confirmDiscard(dialog)) dialog.close(); });
  const dialog = node("dialog", { class: "autopsy-modal", "aria-label": title }, [node("div", { class: "workspace-head" }, [node("h2", { text: title }), closeButton]), content]);
  document.body.append(dialog);
  const observer = new MutationObserver(() => { closeButton.disabled = saving(); });
  observer.observe(dialog, { subtree: true, attributes: true, attributeFilter: ["data-saving"] });
  dialog.addEventListener("cancel", event => { if (saving() || !SOCifyDrafts.confirmDiscard(dialog)) event.preventDefault(); });
  dialog.addEventListener("close", () => { observer.disconnect(); dialog.remove(); previous?.focus(); }, { once: true });
  dialog.showModal();
  return dialog;
}

function autopsyReferenceChoice(name, source, required = false) {
  const id = `reference-${crypto.randomUUID()}`;
  const entry = item => ({ value: item.id, label: `${source.kind === "task" ? item.display_title : source.kind === "event" ? item.title : item.payload.conclusion.slice(0, 160)} · ${item.id}`, record: item });
  let chosen = source.initial ? entry(source.initial) : null, options = [], cursor = null, requestId = 0, timer;
  let lastQuery = "", retryAction;
  const input = node("input", { name, required, autocomplete: "off", class: "search-choice", value: chosen?.label || "", role: "combobox", "aria-controls": id, "aria-expanded": "false", "aria-autocomplete": "list" });
  const list = node("div", { id, role: "listbox", "aria-label": autopsyLabel(name) });
  const message = node("p", { role: "status", class: "notice", hidden: true });
  const failure = node("p", { role: "alert", class: "notice", hidden: true });
  const retry = button(SOCifyLocale.text("إعادة المحاولة"), () => retryAction?.()); retry.hidden = true;
  const more = button(SOCifyLocale.text("عرض المزيد"), () => load(lastQuery, cursor, true)); more.hidden = true;
  const popup = node("div", { class: "choice-menu", hidden: true }, [list, message, failure, retry, more]);
  const close = () => { clearTimeout(timer); popup.hidden = true; input.setAttribute("aria-expanded", "false"); };
  const open = () => { popup.hidden = false; input.setAttribute("aria-expanded", "true"); };
  const select = value => {
    chosen = value;
    input.value = value.label;
    source.onSelect?.(value.record);
    close(); input.focus();
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };
  function render() {
    list.replaceChildren(...options.map(value => {
      const option = node("button", { type: "button", tabindex: "-1", role: "option", "aria-selected": String(chosen?.value === value.value), text: value.label });
      option.addEventListener("mousedown", event => event.preventDefault());
      option.addEventListener("click", () => select(value));
      return option;
    }));
  }
  async function load(query, next = null, append = false, focusFirst = false) {
    clearTimeout(timer);
    const request = ++requestId;
    lastQuery = query;
    failure.hidden = retry.hidden = more.hidden = true;
    message.textContent = SOCifyLocale.text("جارٍ التحميل…"); message.hidden = false;
    list.setAttribute("aria-busy", "true"); open();
    if (!append) { options = []; render(); }
    retryAction = () => load(query, next, append, focusFirst);
    try {
      const path = source.kind === "event"
        ? `/api/cases/${source.caseId}/timeline?${new URLSearchParams({ q: query, page: String(next || 1), limit: "25" })}`
        : source.kind === "task"
        ? `/api/cases/${source.caseId}/tasks?${new URLSearchParams({ q: query, page: String(next || 1) })}`
        : `/api/cases/${source.caseId}/records?${new URLSearchParams({ kind: source.kind, q: query, limit: "25", ...(next ? { before: next } : {}) })}`;
      const data = await api(path);
      if (request !== requestId) return;
      const incoming = data.items.map(entry);
      options = append ? [...options, ...incoming.filter(value => !options.some(existing => existing.value === value.value))] : incoming;
      cursor = source.kind === "event" ? data.has_next ? data.page + 1 : null : source.kind === "task" ? data.page * data.page_size < data.total ? data.page + 1 : null : data.next_before;
      render(); more.hidden = !cursor;
      message.textContent = SOCifyLocale.text("لا نتائج مطابقة"); message.hidden = options.length > 0;
      if (focusFirst && !popup.hidden) list.querySelector("[role=option]")?.focus();
    } catch (error) {
      if (request !== requestId) return;
      failure.textContent = error.message; failure.hidden = retry.hidden = false; message.hidden = true;
    } finally { if (request === requestId) list.setAttribute("aria-busy", "false"); }
  }
  input.autopsyValue = () => {
    if (!input.value.trim() && !required) return null;
    const found = chosen?.label === input.value ? chosen : options.find(value => value.label === input.value);
    if (!found) throw new Error(SOCifyLocale.template`اختر قيمة معروفة للحقل ${autopsyLabel(name)}`);
    return found.value;
  };
  input.addEventListener("input", () => {
    requestId++; chosen = null; source.onSelect?.(null);
    options = []; render(); more.hidden = true;
    clearTimeout(timer);
    if (input.value.trim()) timer = setTimeout(() => load(input.value.trim()), 200);
    else close();
  });
  input.addEventListener("keydown", event => {
    if (["ArrowDown", "ArrowUp"].includes(event.key)) {
      event.preventDefault(); load(chosen?.label === input.value ? "" : input.value.trim(), null, false, true);
    } else if (event.key === "Escape") { event.preventDefault(); close(); }
  });
  list.addEventListener("keydown", event => {
    const controls = [...list.querySelectorAll("[role=option]")], index = controls.indexOf(document.activeElement);
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      const next = event.key === "Home" ? 0 : event.key === "End" ? controls.length - 1 : (index + (event.key === "ArrowDown" ? 1 : -1) + controls.length) % controls.length;
      controls[next]?.focus();
    } else if (event.key === "Escape") { event.preventDefault(); close(); input.focus(); }
  });
  const toggle = button("⌄", () => { if (popup.hidden) { input.focus(); load(""); } else close(); });
  toggle.className = "choice-toggle"; toggle.setAttribute("aria-label", SOCifyLocale.text("عرض الخيارات"));
  toggle.addEventListener("mousedown", event => event.preventDefault());
  const control = node("span", { class: "choice-control" }, [input, toggle, popup]);
  control.addEventListener("focusout", event => { if (!control.contains(event.relatedTarget)) close(); });
  return { control, input };
}

function autopsyForm(schema, submit, initial = {}, { submitLabel = SOCifyLocale.text("حفظ") } = {}) {
  const form = node("form", { class: "form-grid" });
  const getters = {};
  const choiceFields = new Map();
  form.choiceValue = key => {
    try { return getters[key]?.(); } catch (_) { return null; }
  };
  form.replaceChoice = (key, choices, selected = "") => {
    const previous = choiceFields.get(key);
    if (!previous) return;
    const replacement = autopsyChoice(key, choices, selected, schema[key].required);
    previous.control.replaceWith(replacement.control);
    choiceFields.set(key, replacement); getters[key] = replacement.input.autopsyValue;
  };
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
          item.whyParent.replaceChildren(node("option", { value: "", text: SOCifyLocale.text("جذر مستقل") }), ...[...rows.children].flatMap((other, index) => other === item ? [] : [node("option", { value: other.whyId, text: SOCifyLocale.template`السؤال ${index + 1}`, selected: other.whyId === selected })]));
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
    if (spec.reference || spec.task) {
      const choice = autopsyReferenceChoice(key, { kind: "task", caseId: autopsy.current.id, ...spec.reference }, spec.required);
      control = choice.control;
      getters[key] = choice.input.autopsyValue;
    } else if (choices) {
      const choice = autopsyChoice(key, choices, initial[key], spec.required);
      choiceFields.set(key, choice);
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
    form.append(field(`${spec.label || autopsyLabel(key)}${spec.required ? " *" : ""}${spec.timestamp ? SOCifyLocale.text(" · وقت المتصفح") : ""}`, control, (spec.max || 0) > 1000));
  }
  const errors = node("p", { class: "notice span-2", role: "alert", hidden: true });
  const save = node("button", { type: "submit", class: "button primary", text: submitLabel });
  form.append(errors, node("div", { class: "action-row span-2" }, save));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    save.setAttribute("aria-busy", "true");
    save.textContent = SOCifyLocale.text("جارٍ الحفظ…");
    form.dataset.saving = "true";
    const frozen = form.dataset.libraryForm || form.dataset.caseForm ? [...form.querySelectorAll("input,textarea,select,button")].filter(control => !control.disabled) : [];
    try {
      const values = Object.fromEntries(Object.entries(getters).map(([key, getter]) => [key, getter()]).filter(([, value]) => value !== null));
      frozen.forEach(control => { control.disabled = true; });
      await submit(values);
      errors.hidden = true;
      errors.textContent = "";
      SOCifyDrafts.saved(form);
    } catch (error) { errors.hidden = false; errors.textContent = error.message; }
    finally { if (!form.dataset.caseCommitted) frozen.forEach(control => { control.disabled = false; }); delete form.dataset.saving; save.disabled = Boolean(form.dataset.caseNeedsReview || form.dataset.caseUnavailable); save.removeAttribute("aria-busy"); save.textContent = form.dataset.caseCommitted ? SOCifyLocale.text("تحديث القضية") : submitLabel; }
  });
  return SOCifyDrafts.track(form);
}

// Retain operation metadata and payload digests only; never persist draft contents.
const autopsyWriteIntents = new Map();
async function autopsyWriteIntent(scope, body, { preserveBaseVersion = true } = {}) {
  const { version: selectedVersion, ...withoutVersion } = body;
  const version = preserveBaseVersion ? selectedVersion : undefined;
  const content = preserveBaseVersion ? withoutVersion : body;
  const canonical = JSON.stringify(content, (_, value) => value && typeof value === "object" && !Array.isArray(value)
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])) : value);
  const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)))].map(byte => byte.toString(16).padStart(2, "0")).join("");
  const storageKey = `socify:${scope}:${state.user.workspace_id}:${state.user.id}:${digest}`;
  let intent = autopsyWriteIntents.get(storageKey);
  if (!intent) {
    try { intent = JSON.parse(sessionStorage.getItem(storageKey)); } catch (_) { /* In-memory recovery remains available. */ }
    if (!intent || !/^[a-f0-9-]{36}$/.test(intent.key) || (version !== undefined && !Number.isSafeInteger(intent.version))) intent = { key: crypto.randomUUID(), version };
    autopsyWriteIntents.set(storageKey, intent);
    try { sessionStorage.setItem(storageKey, JSON.stringify(intent)); } catch (_) { /* Storage may be disabled. */ }
  }
  return { key: intent.key, body: { ...content, ...(version !== undefined ? { version: intent.version } : {}) }, received: id => {
    intent.result_id = id;
    try { sessionStorage.setItem(storageKey, JSON.stringify(intent)); } catch (_) { /* Retained in memory until navigation. */ }
  }, acknowledged: () => {
    autopsyWriteIntents.delete(storageKey);
    try { sessionStorage.removeItem(storageKey); } catch (_) { /* No draft data was stored. */ }
  } };
}

function autopsyAcknowledgeCaseIntake(ids) {
  const visible = new Set(ids);
  const prefix = `socify:case-create:${state.user.workspace_id}:${state.user.id}:`;
  const keys = new Set(autopsyWriteIntents.keys());
  try { Object.keys(sessionStorage).forEach(key => keys.add(key)); } catch (_) { /* Storage may be disabled. */ }
  for (const key of keys) {
    if (!key.startsWith(prefix)) continue;
    let intent = autopsyWriteIntents.get(key);
    try { intent ||= JSON.parse(sessionStorage.getItem(key)); } catch (_) { /* Ignore invalid metadata. */ }
    if (!visible.has(intent?.result_id)) continue;
    autopsyWriteIntents.delete(key);
    try { sessionStorage.removeItem(key); } catch (_) { /* The document has acknowledged its result. */ }
  }
}

function autopsyNewCase(unassigned = false, destination = "overview") {
  const form = autopsyForm({ title: { required: true, max: 255 }, reason: { required: true, choices: autopsy.catalog.reasons }, objective: { required: true, max: 2000 }, classification: { required: true, choices: autopsy.catalog.classifications } }, async (body) => {
    const controls = [...form.querySelectorAll("input,textarea,select,button")].filter(control => !control.disabled);
    controls.forEach(control => { control.disabled = true; });
    try {
      const payload = unassigned ? { ...body, assignee: null } : body;
      const intent = await autopsyWriteIntent("case-create", payload);
      const created = await api("/api/cases", { method: "POST", headers: { "Idempotency-Key": intent.key }, body: intent.body });
      intent.received(created.id);
      SOCifyDrafts.saved(form);
      window.location.assign(unassigned ? "/cases" : `/cases/${created.id}${destination === "logs" ? "?tab=logs" : ""}`);
    } finally { controls.forEach(control => { control.disabled = false; }); }
  }, { reason: "alert_review", objective: SOCifyLocale.text("التحقيق الأولي السريع وتحديد المؤشرات والإجراء المناسب"), classification: "confidential" });
  autopsyModal(unassigned ? SOCifyLocale.text("إيداع قضية مفتوحة في طابور الفريق") : SOCifyLocale.text("إنشاء قضية سريعة وبدء التحقيق"), form);
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
  document.getElementById("section-title").textContent = SOCifyLocale.text("إدارة القضايا");
  document.getElementById("section-kicker").textContent = "SOCIFY TACTICAL WORKBENCH";
  const [data, claimable] = await Promise.all([
    api(`/api/cases?page=${page}&page_size=25&q=${encodeURIComponent(query)}`),
    permission("cases.update") ? api("/api/cases/claimable").catch(() => ({ items: [] })) : Promise.resolve({ items: [] })
  ]);
  const search = node("input", { name: "q", type: "search", value: query, maxlength: 200, placeholder: SOCifyLocale.text("الاسم أو مرجع القضية") });
  const filters = node("form", { class: "filter-row", "aria-label": SOCifyLocale.text("بحث القضايا") }, [field(SOCifyLocale.text("بحث"), search), node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("بحث") })]);
  filters.addEventListener("submit", (event) => { event.preventDefault(); autopsyCases(1, search.value).catch(handleError); });
  const headActions = permission("cases.create")
    ? [
        button(SOCifyLocale.text("إنشاء قضية"), () => autopsyNewCase(false), "primary"),
        button(SOCifyLocale.text("إيداع في طابور الفريق"), () => autopsyNewCase(true))
      ]
    : [];
  const root = node("div", { class: "cases-view" }, [pageHead(SOCifyLocale.text("قضايا الفريق"), null, headActions), filters]);
  if (claimable.items?.length) {
    root.append(panel(SOCifyLocale.text("قضايا متاحة لاستلام الملكية"), table([
      { label: SOCifyLocale.text("المرجع"), value: (row) => node("bdi", { class: "case-reference", text: row.reference }) },
      { label: SOCifyLocale.text("القضية"), value: "title" },
      { label: SOCifyLocale.text("الخطورة"), value: (row) => autopsyBadge(row.severity) },
      { label: SOCifyLocale.text("أنشأها"), value: (row) => row.creator_name || "—" },
      { label: SOCifyLocale.text("إجراء"), value: (row) => button(SOCifyLocale.text("استلام الملكية"), async () => {
        await api(`/api/cases/${row.id}/claim`, { method: "POST", body: {} });
        window.location.assign(`/cases/${row.id}`);
      }, "primary") }
    ], claimable.items), true));
  }
  if (window.SOCifyWorkspace?.selection.required) root.append(window.SOCifyWorkspace.chooser(data.items));
  if (!window.SOCifyWorkspace?.selection.required) root.append(data.items.length ? table([{ label: SOCifyLocale.text("المرجع"), value: (row) => node("bdi", { class: "case-reference", text: row.reference }) }, { label: SOCifyLocale.text("القضية"), value: (row) => node("a", { class: "case-link", href: autopsyCaseURL(row.id, { list_q: query, list_page: page }), text: row.title }) }, { label: SOCifyLocale.text("الحالة"), value: (row) => autopsyBadge(row.status, "case") }, { label: SOCifyLocale.text("الخطورة"), value: (row) => autopsyBadge(row.severity) }, { label: SOCifyLocale.text("الأدلة"), value: "evidence_count" }, { label: SOCifyLocale.text("المسؤول"), value: "assignee_name" }, { label: SOCifyLocale.text("فتح"), value: (row) => linkedButton(SOCifyLocale.text("فتح القضية"), autopsyCaseURL(row.id, { list_q: query, list_page: page })) }], data.items) : emptyState(SOCifyLocale.text("لا توجد قضايا في النطاق المصرح"),null));
  root.querySelector(".table-wrap")?.classList.add("case-table");
  const pages = node("div", { class: "action-row pagination" }, node("p", { text: SOCifyLocale.template`${data.total} قضية · الصفحة ${page}` }));
  if (page > 1) pages.append(button(SOCifyLocale.text("السابق"), () => autopsyCases(page - 1, query).catch(handleError)));
  if (page * 25 < data.total) pages.append(button(SOCifyLocale.text("التالي"), () => autopsyCases(page + 1, query).catch(handleError)));
  root.append(pages);
  finish(root);
  autopsyAcknowledgeCaseIntake([...data.items, ...(claimable.items || [])].map(item => item.id));
}

function autopsyRecordCard(record) {
  if(record.kind === "analysis" && record.payload.analysis_type === "local_detection") {
    return node("article", { class: "card record-card" }, [node("h3", { text: SOCifyLocale.text("نتيجة فحص السجلات") }), autopsyDetectionResult(record, autopsy.current.id), node("p", { text: formatTime(record.updated_at) })]);
  }
  if(record.kind==="analysis"&&(record.payload.method==="quick_static_triage"||record.payload.engine==="SOCify local static analysis/1")) {
    return node("article",{class:"card record-card sample-record"},[node("h3",{text:record.payload.filename||SOCifyLocale.text("نتيجة الفحص")}),autopsySampleView(record.payload),node("p",{text:formatTime(record.updated_at)})]);
  }
  if (record.kind === "analysis" && (/^(email_static_triage|eml_static_v1|v[0-9]+_email_static_triage)$/.test(record.payload.method))) {
    return node("article", { class: "card record-card email-record" }, [node("h3", { text: record.payload.title }), autopsyEmailView(record.payload), node("p", { text: formatTime(record.updated_at) })]);
  }
  const rows = node("tbody");
  const values = node("table", { class: "alert-property-table", "aria-label": record.payload.title || record.payload.name || autopsyLabel(record.kind) }, rows);
  Object.entries(record.payload).forEach(([key, value]) => {
    if (value === null || value === "") return;
    let display = Array.isArray(value) ? value.map((item, index) => {
      if (typeof item !== "object" || item === null) return item;
      if (!item.question) return JSON.stringify(item);
      const parent = value.findIndex(other => other?.id === item.parent_id);
      const assessment = item.assessment === "hypothesis" ? SOCifyLocale.text("الفرضية") : autopsyLabel(item.assessment);
      return `${index + 1}. ${item.question}: ${item.answer || ""} · ${assessment || ""}${item.evidence_id ? SOCifyLocale.template` · دليل ${item.evidence_id}` : ""}${item.parent_id && parent >= 0 ? SOCifyLocale.template` · مرتبط بالسؤال ${parent + 1}` : ""}`;
    }).join("\n") : typeof value === "object" ? JSON.stringify(value) : autopsyLabel(value);
    if (key.endsWith("_at") || key === "event_time") display = formatTime(value);
    if (record.kind === "corrective" && key === "status" && value === "open") display = SOCifyLocale.text("مفتوح");
    let content = node("td", {}, node("span", { dir: "auto", text: display }));
    if (autopsy.catalog.record_schemas[record.kind]?.[key]?.user) content = node("td", { "data-user-content": true, text: autopsy.team.members.find(member => member.id === value)?.name || SOCifyLocale.text("المستخدم غير متاح") });
    if (key === "task_id") content = node("td", {}, [node("a", { href: `/cases/${autopsy.current.id}?tab=summary#case-task-${value}`, text: SOCifyLocale.text("فتح المهمة") })]);
    if (key === "root_cause_id" || key === "why_id") {
      const caseId = autopsy.current.id;
      content = node("td", {}, [autopsyAction(SOCifyLocale.text(key === "why_id" ? "عرض فرع السبب" : "عرض السبب الجذري"), async () => {
        const linked = (await api(`/api/cases/${caseId}/records?kind=root_cause&focus=${record.payload.root_cause_id}`)).items[0];
        const branches = linked.payload.whys || [];
        const selected = key === "why_id" ? branches.filter(item => item.id === value) : branches;
        if (key === "why_id" && !selected.length) throw new Error(SOCifyLocale.text("فرع السبب المرتبط غير متاح"));
        const details = node("div", {}, [node("p", { dir: "auto", text: linked.payload.conclusion }), ...selected.map(item => node("section", {}, [
          node("h3", { dir: "auto", text: item.question }), node("p", { dir: "auto", text: item.answer }), node("p", { text: autopsyLabel(item.assessment || "unverified") }),
        ]))]);
        autopsyModal(SOCifyLocale.text(key === "why_id" ? "فرع السبب المرتبط" : "السبب الجذري المرتبط"), details);
      })]);
    }
    rows.append(node("tr", {}, [node("th", { scope: "row", text: autopsyLabel(key) }), content]));
  });
  const card = node("article", { class: "card record-card" }, [node("h3", { text: record.payload.title || record.payload.name || autopsyLabel(record.kind) }), values, node("p", { text: formatTime(record.updated_at) })]);
  if (autopsy.current.can_update && (autopsy.current.status !== "closed" || record.kind === "corrective") && autopsy.catalog.record_schemas[record.kind]) card.append(button(SOCifyLocale.text("تعديل"), () => autopsyEditRecord(record.kind, record)));
  return card;
}

async function autopsyEditRecord(kind, record = null) {
  const schema = { ...autopsy.catalog.record_schemas[kind], evidence_id: { evidence: true } };
  let cause = null;
  try {
    if (record?.payload.task_id) {
      const data = await api(`/api/cases/${autopsy.current.id}/tasks?focus=${record.payload.task_id}`);
      schema.task_id = { ...schema.task_id, reference: { initial: data.items.find(item => item.id === record.payload.task_id) } };
    }
    if (kind === "corrective" && record?.payload.root_cause_id) {
      cause = (await api(`/api/cases/${autopsy.current.id}/records?kind=root_cause&focus=${record.payload.root_cause_id}`)).items[0];
    }
  } catch (error) {
    let recovery;
    const retry = button(SOCifyLocale.text("إعادة المحاولة"), () => { recovery.close(); autopsyEditRecord(kind, record).catch(handleError); });
    recovery = autopsyModal(SOCifyLocale.text("تعذر تحميل المرجع المرتبط"), node("div", {}, [node("p", { role: "alert", class: "notice", text: error.message }), retry]));
    return;
  }
  let form;
  if (kind === "corrective") {
    const branches = item => {
      const choices = (item?.payload.whys || []).map((why, index) => ({ value: why.id, label: `${index + 1}. ${why.question}` }));
      const previous = record?.payload;
      if (item && item.id === previous?.root_cause_id && previous.why_id && !choices.some(choice => choice.value === previous.why_id)) {
        choices.push({ value: previous.why_id, label: SOCifyLocale.text("فرع السبب المرتبط غير متاح") });
      }
      return choices;
    };
    let selectedCause = cause?.id;
    const selectedBranches = new Map(cause ? [[cause.id, record.payload.why_id || ""]] : []);
    schema.root_cause_id = { reference: { kind: "root_cause", initial: cause, onSelect: item => {
      if (selectedCause) selectedBranches.set(selectedCause, form.choiceValue("why_id") || "");
      selectedCause = item?.id;
      form.replaceChoice("why_id", branches(item), selectedBranches.get(selectedCause) || "");
    } } };
    schema.why_id = { choices: branches(cause) };
    schema.status = { ...schema.status, choices: schema.status.choices.map(value => ({ value, label: value === "open" ? SOCifyLocale.text("مفتوح") : autopsyLabel(value) })) };
  }
  let dialog;
  form = autopsyForm(schema, async (payload) => {
    await api(`/api/cases/${autopsy.current.id}/records/${record ? record.id : kind}`, { method: record ? "PATCH" : "POST", body: record ? { version: record.version, payload } : payload });
    dialog.close();
    await autopsyCase(autopsy.current.id);
  }, record?.payload || {});
  dialog = autopsyModal(`${record ? SOCifyLocale.text("تعديل") : SOCifyLocale.text("إضافة")} ${autopsyLabel(kind)}`, form);
}

async function autopsyRecordPanel(kind) {
  const base = `/api/cases/${autopsy.current.id}/records?kind=${kind}&limit=25`;
  const data = await api(base);
  const content = data.items.length ? node("div", { class: "record-grid" }, data.items.map(autopsyRecordCard)) : node("p", { class: "record-empty", text: SOCifyLocale.text("لا عناصر بعد") });
  let cursor = data.next_before;
  const more = button(SOCifyLocale.text("عرض المزيد"), async () => {
    more.disabled = true;
    try { const next = await api(`${base}&before=${cursor}`); content.append(...next.items.map(autopsyRecordCard)); cursor = next.next_before; more.hidden = !cursor; }
    catch (error) { handleError(error); } finally { more.disabled = false; }
  });
  more.hidden = !cursor;
  return panel(autopsyLabel(kind), node("div", { class: "panel-body" }, [autopsy.current.can_update && (autopsy.current.status !== "closed" || kind === "corrective") ? button(SOCifyLocale.template`إضافة ${autopsyLabel(kind)}`, () => autopsyEditRecord(kind).catch(handleError), "primary") : null, content, more]), true);
}

async function autopsyCaseTasks(current) {
  const params = new URLSearchParams(location.search);
  let focus = location.hash.startsWith("#case-task-") ? location.hash.slice("#case-task-".length) : null;
  let page = params.get("case_task_page") || "1", requestId = 0;
  let requestedPage = page, requestedFocus = focus;
  const body = node("div", { class: "panel-body case-task-queue" });
  const query = node("input", { name: "case_task_q", type: "search", maxlength: 200, value: focus ? "" : params.get("case_task_q") || "" });
  const status = autopsySelect("case_task_status", ["", "pending", "in_progress", "completed", "reviewed"], focus ? "" : params.get("case_task_status") || "");
  status.options[0].textContent = SOCifyLocale.text("كل الحالات");
  const notice = node("p", { role: "alert", class: "notice", hidden: true });
  const results = node("div", { class: "case-task-results", "aria-live": "polite" });
  const retry = button(SOCifyLocale.text("إعادة المحاولة"), () => load(requestedPage, requestedFocus));
  const reset = button(SOCifyLocale.text("عرض مهام القضية"), () => { query.value = ""; status.value = ""; return load(1, null); });
  const recovery = node("div", { class: "action-row", hidden: true }, [retry, reset]);
  async function load(nextPage = page, target = focus) {
    const request = ++requestId;
    requestedPage = nextPage; requestedFocus = target;
    notice.hidden = recovery.hidden = true;
    results.setAttribute("aria-busy", "true");
    const filters = { q: query.value.trim(), status: status.value };
    const options = new URLSearchParams({ ...filters, page: String(nextPage), ...(target ? { focus: target } : {}) });
    try {
      const data = await api(`/api/cases/${current.id}/tasks?${options}`);
      if (request !== requestId || location.pathname !== `/cases/${current.id}`) return;
      page = data.page; focus = data.focus ? String(data.focus) : null;
      const url = new URL(location.href);
      for (const [key, value] of Object.entries({ case_task_q: filters.q, case_task_status: filters.status, case_task_page: page > 1 ? String(page) : "" })) value ? url.searchParams.set(key, value) : url.searchParams.delete(key);
      url.hash = focus ? `case-task-${focus}` : "";
      history.replaceState(null, "", url);
      const update = async (row, control) => {
        control.disabled = true;
        notice.hidden = true;
        try {
          const updated = await api(`/api/incidents/${current.id}/tasks/${row.id}`, { method: "PATCH", body: { status: "completed", expected_status: row.status } });
          if (current.version === updated.case_version_before) current.version = updated.case_version;
          await load(page, focus);
        } catch (error) { notice.textContent = error.message; notice.hidden = false; }
        finally { control.disabled = false; }
      };
      let content = emptyState(SOCifyLocale.text("لا مهام مطابقة"), null);
      if (data.items.length) {
        content = stackedTable([
          { label: SOCifyLocale.text("المهمة"), value: "display_title" }, { label: SOCifyLocale.text("المسؤول"), value: "assignee_name" },
          { label: SOCifyLocale.text("الحالة"), value: row => autopsyLabel(row.status) },
          { label: SOCifyLocale.text("إكمال"), value: row => {
            if (!row.can_update || ["completed", "reviewed"].includes(row.status)) return "—";
            const control = button(SOCifyLocale.text("إكمال المهمة"), () => update(row, control));
            return control;
          } },
        ], data.items);
        content.querySelectorAll("tbody tr").forEach((row, index) => { row.id = `case-task-${data.items[index].id}`; row.tabIndex = -1; });
      }
      const previous = button(SOCifyLocale.text("السابق"), () => load(page - 1, null)); previous.disabled = page <= 1;
      const next = button(SOCifyLocale.text("التالي"), () => load(page + 1, null)); next.disabled = page * data.page_size >= data.total;
      results.replaceChildren(content);
      if (data.total > data.page_size) results.append(node("nav", { class: "pagination", "aria-label": SOCifyLocale.text("مهام القضية") }, [previous, node("span", { text: SOCifyLocale.template`الصفحة ${page} من ${Math.max(1, Math.ceil(data.total / data.page_size))}` }), next]));
      if (body.isConnected && focus) {
        const targetRow = document.getElementById(`case-task-${focus}`);
        if (targetRow) { targetRow.focus({ preventScroll: true }); targetRow.scrollIntoView({ block: "center", behavior: "instant" }); }
      }
    } catch (error) {
      if (request !== requestId) return;
      results.replaceChildren();
      notice.textContent = error.message; notice.hidden = recovery.hidden = false;
    } finally { if (request === requestId) results.setAttribute("aria-busy", "false"); }
  }
  const form = node("form", { class: "filter-row" }, [field(SOCifyLocale.text("بحث مهام القضية"), query), field(SOCifyLocale.text("الحالة"), status), node("button", { type: "submit", class: "button", text: SOCifyLocale.text("بحث") }), button(SOCifyLocale.text("تحديث القائمة"), () => load(page, focus))]);
  form.addEventListener("submit", event => { event.preventDefault(); load(1, null); });
  body.append(form, notice, recovery, results);
  autopsy.taskNavigation = () => {
    if (!body.isConnected || location.pathname !== `/cases/${current.id}`) return;
    const target = location.hash.startsWith("#case-task-") ? location.hash.slice("#case-task-".length) : null;
    if (target) { query.value = ""; status.value = ""; }
    load(target ? 1 : page, target);
  };
  await load();
  return panel(SOCifyLocale.text("مهام القضية"), body);
}

let autopsySummaryRefresh = Promise.resolve();
function autopsyRefreshSummary(caseId, savedForm) {
  const next = autopsySummaryRefresh.catch(() => {}).then(() => autopsyCase(caseId, { refresh: true, savedForm }));
  autopsySummaryRefresh = next;
  return next;
}

function autopsySummaryForm(kind, schema, current, operation, initial = {}, afterRefresh = null, options = {}) {
  const form = autopsyForm(schema, async body => {
    if (form.dataset.caseNeedsReview || form.dataset.caseUnavailable) throw new Error(SOCifyLocale.text("راجع تحديثات القضية قبل متابعة الحفظ"));
    if (!form.dataset.caseCommitted) {
      try { await operation(body, form.caseVersion); }
      catch (error) {
        if (["CASE_VERSION_CONFLICT", "VERSION_CONFLICT"].includes(error.code)) {
          form.dataset.caseConflict = "true";
          try {
            const latest = await autopsyRefreshSummary(current.id, null);
            if (latest && options.reviewReplacement && form.isConnected) autopsyRetainSummaryDraft(form, options.reviewReplacement(latest), latest);
          } catch (_) { /* Keep the draft and original conflict if refresh is unavailable. */ }
          delete form.dataset.caseConflict;
          if (form.dataset.caseNeedsReview) error.message = SOCifyLocale.text("راجع تحديثات القضية قبل متابعة الحفظ");
        }
        throw error;
      }
      form.dataset.caseCommitted = "true";
      SOCifyDrafts.saved(form);
    }
    try { await autopsyRefreshSummary(current.id, form); }
    catch (_) { throw new Error(SOCifyLocale.text("حُفظ الإجراء. تعذر تحديث القضية؛ أعد المحاولة.")); }
    if (afterRefresh) afterRefresh();
  }, initial, options);
  form.dataset.caseForm = kind;
  form.caseVersion = current.version;
  form.caseContext = JSON.stringify(current.context);
  return form;
}

function autopsyRetainSummaryDraft(form, replacement, current) {
  const oldReview = form.querySelector(".case-form-review");
  oldReview?.remove();
  if (!replacement) {
    form.dataset.caseUnavailable = "true";
    form.querySelector('button[type="submit"]').disabled = true;
    form.append(node("p", { class: "notice case-form-review span-2", role: "status", text: SOCifyLocale.text("مسودتك باقية؛ هذا الإجراء غير متاح في الحالة الحالية للقضية.") }));
    return;
  }
  delete form.dataset.caseUnavailable;
  if (form.dataset.caseForm === "context" && form.caseContext === JSON.stringify(current.context)) form.caseVersion = current.version;
  if (form.caseVersion === current.version) {
    delete form.dataset.caseNeedsReview;
    if (form.dataset.saving !== "true") form.querySelector('button[type="submit"]').disabled = false;
    return;
  }
  if (form.dataset.caseCommitted || (form.dataset.saving === "true" && !form.dataset.caseConflict)) return;
  form.dataset.caseNeedsReview = "true";
  form.querySelector('button[type="submit"]').disabled = true;
  const facts = form.dataset.caseForm === "context"
    ? Object.entries(current.context || {}).filter(([key]) => ["reason", "objective", "classification", "attack_outcome", "alert_verdict"].includes(key)).map(([key, value]) => ({ label: autopsyLabel(key), value: autopsyLabel(value) }))
    : [{ label: SOCifyLocale.text("الحالة"), value: autopsyLabel(current.status) }, ...(current.members || []).map(member => ({ label: member.name, value: caseResponsibilityLabel(member.responsibility) }))];
  const accept = button(SOCifyLocale.text("متابعة بعد المراجعة"), () => {
    // Copy the visible draft into fresh controls, retaining current choices and
    // an optimistic version from the reviewed response. Nothing is saved here.
    for (const input of form.querySelectorAll("input[name],textarea[name],select[name]")) {
      const target = [...replacement.querySelectorAll("input[name],textarea[name],select[name]")].find(item => item.name === input.name);
      if (!target || input.type === "file") continue;
      if (["checkbox", "radio"].includes(input.type)) target.checked = input.checked;
      else target.value = input.value;
    }
    form.replaceWith(replacement);
    replacement.querySelector("input,textarea,select")?.focus({ preventScroll: true });
  });
  form.append(node("details", { class: "case-form-review span-2" }, [node("summary", { text: SOCifyLocale.text("مراجعة تحديثات القضية") }), stackedTable([{ label: SOCifyLocale.text("الحقل"), value: "label" }, { label: SOCifyLocale.text("القيمة الحالية"), value: "value" }], facts), accept]));
}

async function autopsyCase(caseId, { refresh = false, savedForm = null } = {}) {
  if (!refresh && !SOCifyDrafts.confirmDiscard(workspace, true)) return;
  if (window.SOCifyWorkbench?.sections.includes(state.section)) { await window.SOCifyWorkbench.start(state.section); return; }
  if (!refresh) begin("case");
  let selected = new URLSearchParams(window.location.search).get("tab") || "summary";
  autopsy.current = await api(`/api/cases/${caseId}`);
  const current = autopsy.current;
  if (window.SOCifyWorkspace?.intake(current)) { autopsyAcknowledgeCaseIntake([current.id]); return; }
  document.getElementById("section-title").textContent = current.reference;
  document.getElementById("section-kicker").textContent = current.reference;
  document.title = `${current.reference} | SOCify Tactical Workbench`;
  const restricted = current.full_case_access === false;
  if (restricted && !["summary", "logs"].includes(selected)) selected = "logs";
  const assetData = restricted ? { items: [] } : await api(`/api/cases/${caseId}/records?kind=asset&limit=100`);
  autopsy.assets = assetData.items;
  const root = node("div", { class: "case-view" }, [pageHead(current.title, null, [linkedButton(SOCifyLocale.text("جميع القضايا"), autopsyCaseListURL()), ...(selected === "summary" ? [button(SOCifyLocale.text("تحديث القضية"), () => autopsyRefreshSummary(caseId, null).catch(handleError))] : []), ...(!restricted && window.SOCifyWorkbench ? [window.SOCifyWorkbench.reportButton(current)] : [])])]);
  root.append(node("div", { class: "case-context-bar" }, [node("bdi", { class: "case-reference", text: current.reference }), autopsyBadge(current.status, "case"), autopsyBadge(current.severity)]));
  if (selected === "summary" && !restricted) {
    const fact = (label, value) => node("div", {}, [node("dt", { text: label }), node("dd", { text: value || "—" })]);
    root.append(node("section", { class: "case-overview", "aria-label": SOCifyLocale.text("نظرة على القضية") }, [
      node("h3", { text: SOCifyLocale.text("هدف التحقيق") }), node("p", { text: current.context?.objective || "—" }),
      node("dl", { class: "case-facts" }, [fact(SOCifyLocale.text("سبب فتح القضية"), autopsyLabel(current.context?.reason)), fact(SOCifyLocale.text("التصنيف الأمني"), autopsyLabel(current.context?.classification)), fact(SOCifyLocale.text("قرار صحة التنبيه"), autopsyLabel(current.context?.alert_verdict))])
    ]));
  }
  let tabs = [["summary", SOCifyLocale.text("الملخص والمسؤوليات")], ["investigation", SOCifyLocale.text("التحقيق والخط الزمني")], ["response", SOCifyLocale.text("الاستجابة والتصعيد")], ["activity", SOCifyLocale.text("الحيازة والنشاط")]];
  if (!window.SOCifyWorkspace?.selection.required) tabs.splice(1, 0, ["logs", SOCifyLocale.text("السجلات والأدلة")], ["analysis", SOCifyLocale.language === "ar" ? "التحليل" : "Analysis"]);
  if (restricted) {
    tabs = [["summary", SOCifyLocale.text("الملخص والمسؤوليات")], ...(!window.SOCifyWorkspace?.selection.required ? [["logs", SOCifyLocale.text("السجلات والأدلة")]] : [])];
    root.append(node("p", { class: "notice", text: SOCifyLocale.text("نطاق دفعات محدد: تظهر السجلات المصرح بها فقط. يتطلب سياق التحقيق والتقارير الوصول إلى جميع دفعات القضية.") }));
  }
  root.append(node("nav", { class: "case-tabs", "aria-label": SOCifyLocale.text("أقسام القضية") }, tabs.map(([id, label]) => node("a", { class: "button ghost", href: autopsyCaseURL(caseId, { tab: id }), "aria-current": selected === id ? "page" : null, text: label }))));
  const content = node("div", { class: "case-content" });
  if (selected === "summary") {
    const relationship = window.SOCifyWorkspace?.relationship(current);
    if (relationship) relationship.querySelector("form").dataset.caseForm = "relationship";
    if (relationship) content.append(relationship);
    const transitions = autopsy.catalog.case_transitions[current.status] || [];
    if (current.can_update && transitions.length) content.append(panel(SOCifyLocale.text("حالة القضية"), node("div", { class: "panel-body" }, autopsySummaryForm("status", { status: { required: true, choices: transitions.filter((value) => value !== "closed" || permission("cases.close")) }, reason: { required: true, max: 2000 } }, current, (body, version) => api(`/api/cases/${caseId}/transitions`, { method: "POST", body: { ...body, version } }))), true));
    const schema = { reason: { required: true, max: 500 }, objective: { required: true, max: 2000 }, classification: { choices: autopsy.catalog.classifications, required: true }, attack_outcome: { choices: autopsy.catalog.outcomes, required: true }, alert_verdict: { choices: autopsy.catalog.verdicts, required: true } };
    if (current.can_update && current.status !== "closed") content.append(autopsyEditPanel(SOCifyLocale.text("سبب القضية وهدفها ونتيجتها"), node("div", { class: "panel-body" }, autopsySummaryForm("context", schema, current, (body, version) => api(`/api/cases/${caseId}/context`, { method: "PATCH", body: { ...body, version } }), current.context || { classification: "confidential", attack_outcome: "unknown", alert_verdict: "undetermined" })), true));
    else content.append(panel(SOCifyLocale.text("ملخص القضية"), node("div", { class: "panel-body" }, [node("p", { text: current.context?.reason || SOCifyLocale.text("قضية موروثة؛ يتطلب ملخصها مراجعة") }), node("p", { text: current.context?.objective || "—" })]), true));
    const memberColumns = [{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("الدور"), value: (row) => autopsyLabel(row.role) }, { label: SOCifyLocale.text("المسؤولية"), value: (row) => caseResponsibilityLabel(row.responsibility) }, { label: SOCifyLocale.text("أُسندت"), value: (row) => formatTime(row.assigned_at) }];
    if (current.can_manage && permission("cases.assign")) memberColumns.push({ label: SOCifyLocale.text("الإجراء"), value: row => ["admin", "soc_manager"].includes(row.role) ? "—" : button(SOCifyLocale.text("سحب الوصول"), () => {
      const buildForm = latest => latest.can_manage && permission("cases.assign") && latest.members.some(member => member.user_id === row.user_id)
        ? autopsySummaryForm(`remove-${row.user_id}`, { reason: { required: true, max: 1000 } }, latest, (body, version) => api(`/api/cases/${caseId}/members/${row.user_id}`, { method: "DELETE", body: { ...body, version } }), {}, () => dialog.close(), { submitLabel: SOCifyLocale.text("سحب الوصول"), reviewReplacement: buildForm })
        : null;
      const form = buildForm(current);
      const dialog = autopsyModal(SOCifyLocale.text("سحب الوصول إلى القضية"), node("div", {}, [node("p", { text: `${row.name} · ${current.reference}`, "data-user-content": "true" }), form]));
    }) });
    content.append(panel(SOCifyLocale.text("فريق القضية"), stackedTable(memberColumns, current.members)));
    if (current.can_manage && permission("cases.assign")) {
      content.append(autopsyEditPanel(SOCifyLocale.text("تحديد مسؤولية عضو"), node("div", { class: "panel-body" }, autopsySummaryForm("members", { user_id: { required: true, user: true }, responsibility: { required: true, choices: ["monitoring", "l1", "l2", "investigator", "reviewer", "owner"].map(value => ({ value, label: caseResponsibilityLabel(value) })) } }, current, (body, version) => api(`/api/cases/${caseId}/members`, { method: "POST", body: { ...body, version } })))));
      if (current.status !== "closed" && permission("cases.update")) content.append(autopsyEditPanel(SOCifyLocale.text("تسليم المناوبة"), node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("التسليم ينقل العمل المفتوح ويبقي وصول العضو. لسحب وصوله، استخدم فريق القضية بعد التسليم.") }), autopsySummaryForm("handoff", { from_user: { label: SOCifyLocale.text("مسلّم المناوبة"), required: true, user: true, case_member: true }, to_user: { label: SOCifyLocale.text("مستلم المناوبة"), required: true, user: true }, reason: { required: true, max: 1000 } }, current, (body, version) => api(`/api/cases/${caseId}/handoff`, { method: "POST", body: { ...body, version } }))])));
    }
    if (!restricted) content.append(await autopsyCaseTasks(current));
  } else if (selected === "logs") {
    if (window.SOCifyAutopsy.logs) content.append(await window.SOCifyAutopsy.logs(caseId));
    content.append(panel(SOCifyLocale.text("أدلة القضية"), current.evidence.length ? table([{ label: SOCifyLocale.text("الدليل"), value: "title" }, { label: SOCifyLocale.text("النوع"), value: "evidence_type" }, { label: "SHA-256", value: (row) => node("bdi", { text: row.sha256 }) }, { label: SOCifyLocale.text("أضيف"), value: (row) => formatTime(row.added_at) }], current.evidence) : emptyState(SOCifyLocale.text("لا أدلة مرتبطة"),null), true));
  } else if (selected === "analysis") {
    if (window.SOCifyAutopsy.analysisWorkspace) content.append(await window.SOCifyAutopsy.analysisWorkspace(caseId));
  } else if (selected === "investigation") {
    if (window.SOCifyAutopsy.investigation) content.append(await window.SOCifyAutopsy.investigation(caseId));
    for (const kind of ["timeline", "root_cause", "war_room", "hypothesis", "foothold"]) content.append(await autopsyRecordPanel(kind));
  } else if (selected === "response") {
    for (const kind of ["escalation", "response", "corrective"]) content.append(await autopsyRecordPanel(kind));
    if (window.SOCifyAutopsy.procedures) content.append(await window.SOCifyAutopsy.procedures(caseId));
    if (window.SOCifyAutopsy.workflow) content.append(await window.SOCifyAutopsy.workflow(caseId));
  } else if (selected === "reports" && window.SOCifyAutopsy.reports) content.append(await window.SOCifyAutopsy.reports(caseId));
  else {
    const data = await api(`/api/cases/${caseId}/custody`);
    content.append(panel(SOCifyLocale.text("سلسلة حيازة الأدلة"), node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.template`${data.integrity_valid ? SOCifyLocale.text("سلسلة البصمات متسقة") : SOCifyLocale.text("تحذير: عدم اتساق في السلسلة")} · ${data.total} حركة` }), table([{ label: SOCifyLocale.text("الإجراء"), value: (row) => autopsyLabel(row.action) }, { label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.created_at) }, { label: SOCifyLocale.text("بصمة الحركة"), value: (row) => node("bdi", { text: row.entry_hash }) }], data.items)]), true));
    content.append(panel(SOCifyLocale.text("نشاط القضية"), table([{ label: SOCifyLocale.text("الحدث"), value: (row) => autopsyLabel(row.action) }, { label: SOCifyLocale.text("الفاعل"), value: "actor_name" }, { label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.created_at) }], current.history), true));
  }
  if (!restricted && selected === "reports" && window.SOCifyAutopsy.capsules) content.append(await window.SOCifyAutopsy.capsules(caseId));
  if (!window.SOCifyWorkspace?.selection.required && !restricted && window.SOCifyAutopsy.reports && !tabs.some(([id]) => id === "reports")) {
    const reportsLink = linkedButton(SOCifyLocale.text("التقارير والمراجعة"), autopsyCaseURL(caseId, { tab: "reports" }));
    if (selected === "reports") reportsLink.setAttribute("aria-current", "page");
    root.querySelector(".case-tabs").append(reportsLink);
  }
  root.append(content);
  window.SOCifyWorkbench?.bindCase(current);
  const active = document.activeElement;
  let retainedFocus = false;
  if (refresh && selected === "summary") {
    for (const form of workspace.querySelectorAll("form[data-case-form]")) {
      if (form === savedForm || (!SOCifyDrafts.hasChanges(form) && form.dataset.saving !== "true")) continue;
      const replacement = root.querySelector(`form[data-case-form="${form.dataset.caseForm}"]`);
      retainedFocus ||= form.contains(active);
      const details = form.closest("details");
      const expanded = details ? details.open : form.dataset.caseExpanded === "true";
      form.dataset.caseExpanded = String(expanded);
      if (form.dataset.caseForm !== "relationship") autopsyRetainSummaryDraft(form, replacement, current);
      if (replacement) { if (expanded) replacement.closest("details")?.setAttribute("open", ""); replacement.replaceWith(form); }
      else content.append(panel(SOCifyLocale.text("مسودة غير محفوظة"), form));
    }
  }
  finish(root);
  if (retainedFocus && active?.isConnected) active.focus({ preventScroll: true });
  autopsyAcknowledgeCaseIntake([current.id]);
  if (selected === "summary" && /^#case-task-\d+$/.test(location.hash)) {
    const task = document.getElementById(location.hash.slice(1));
    if (task) { task.focus({ preventScroll: true }); task.scrollIntoView({ block: "center", behavior: "instant" }); }
  }
  return current;
}

async function autopsyStart() {
  const role = document.querySelector("[data-user-role]");
  if (role) role.textContent = autopsyLabel(state.user.role);
  window.SOCifyWorkbench?.navigation();
  if (["audit", "admin"].includes(state.section)) {
    const allowed = permission(state.section === "audit" ? "audit.read" : "users.read");
    if (!allowed) {
      begin(state.section);
      finish(emptyState(SOCifyLocale.text("هذا القسم غير متاح لدورك"),null, [linkedButton(SOCifyLocale.text("الملف والأمان"), "/profile")]));
      return;
    }
    return state.section === "audit" ? renderAudit() : renderAdmin();
  }
  if (state.section === "profile" && window.SOCifyAutopsy.profile) {
    if(permission("cases.read")) await window.SOCifyWorkspace?.initialize();
    return window.SOCifyAutopsy.profile();
  }
  if (!permission("cases.read") && !["profile", "team"].includes(state.section)) {
    finish(emptyState(SOCifyLocale.text("هذا القسم غير متاح لدورك"),null, [linkedButton(SOCifyLocale.text("الملف والأمان"), "/profile")])); return;
  }
  [autopsy.catalog, autopsy.team] = await Promise.all([permission("cases.read") ? api("/api/autopsy/catalog") : Promise.resolve({}), api("/api/team")]);
  if (permission("cases.read")) await window.SOCifyWorkspace?.initialize();
  window.SOCifyWorkbench?.navigation();
  const caseId = document.querySelector('meta[name="case-id"]')?.content;
  if (state.section === "performance") return window.SOCifyInsights.performance();
  if (caseId) return autopsyCase(Number(caseId));
  if (window.SOCifyWorkbench?.sections.includes(state.section)) return window.SOCifyWorkbench.start(state.section);
  if (state.section === "profile" && window.SOCifyAutopsy.profile) return window.SOCifyAutopsy.profile();
  if (state.section === "analysis-library" && window.SOCifyAutopsy.library) return window.SOCifyAutopsy.library();
  if (state.section === "playbooks" && window.SOCifyAutopsy.procedureLibrary) return window.SOCifyAutopsy.procedureLibrary();
  if (state.section === "team") return window.SOCifyAutopsy.team();
  if (state.section === "my-tasks") {
    begin("my-tasks");
    if(window.SOCifyWorkspace?.selection.required && !window.SOCifyWorkspace.selection.case_ids.length) {
      finish(emptyState(SOCifyLocale.text("اختر قضية لبدء العمل"),null,[linkedButton(SOCifyLocale.text("اختيار نطاق التحقيق"),"/cases")])); return;
    }
    finish(await autopsyAssignmentQueue(true));
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
