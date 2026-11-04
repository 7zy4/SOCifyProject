"use strict";

let autopsyReportTimer = null;
const autopsyReportProfiles = new Map();
const autopsyReportViews = new Map();

function autopsySavedReportProfile(key) {
  if (autopsyReportProfiles.has(key)) return autopsyReportProfiles.get(key);
  try { return localStorage.getItem(`socify-report-profile:${key}`); } catch (_) { return null; }
}

function autopsyRememberReportProfile(key, value) {
  autopsyReportProfiles.set(key, value);
  try { localStorage.setItem(`socify-report-profile:${key}`, value); } catch (_) { /* Keep this page's choice. */ }
}

function autopsyReportSharingLabel(profile) {
  return SOCifyLocale.text(profile === "full" ? "كامل للاستخدام الداخلي المصرح" : "منقح: بيانات إحصائية وحالة فقط");
}

const autopsyReportLabels = {
  evidenced_timeline: SOCifyLocale.text("السجل الزمني للأدلة"),
  legacy_closure: SOCifyLocale.text("قرارات الإغلاق السابقة"),
  shared_notes: SOCifyLocale.text("الملاحظات المشتركة"),
  content_inspection: SOCifyLocale.language === "ar" ? "فحص المحتوى والترميزات" : "Content and encoding inspection",
  investigation_assessment: SOCifyLocale.text("قرارات التحقيق"),
  summary: SOCifyLocale.text("الملخص التنفيذي"),
  case: SOCifyLocale.text("بيانات القضية ونطاق التحقيق"),
  context: SOCifyLocale.text("الهدف وقرار التنبيه ونتيجة الهجوم"),
  metrics: SOCifyLocale.text("قياسات مراحل الاستجابة"),
  scope: SOCifyLocale.text("نطاق الفحص وحدود الاستنتاج"),
  members: SOCifyLocale.text("المسؤوليات"),
  alerts: SOCifyLocale.text("التنبيهات"),
  records: SOCifyLocale.text("سجلات التحقيق"),
  tasks: SOCifyLocale.text("المهام"),
  evidence: SOCifyLocale.text("فهرس الأدلة وبصماتها"),
  imports: SOCifyLocale.text("الأصول المستوردة وإصدارات المعالجة"),
  custody: SOCifyLocale.text("سلامة سلسلة الحيازة"),
  history: SOCifyLocale.text("تاريخ حالات القضية"),
  limitations: SOCifyLocale.text("حدود التقرير والتحليل"),
  chronology: SOCifyLocale.text("الخط الزمني المشترك"),
  observables: SOCifyLocale.text("الإثراء المحلي"),
  workflow: SOCifyLocale.text("دورة التحقيق"),
  techniques: SOCifyLocale.text("تقنيات MITRE ATT&CK"),
  payload: SOCifyLocale.text("البيانات المسجلة"),
  id: SOCifyLocale.text("المعرف"),
  created_at: SOCifyLocale.text("وقت الإنشاء"),
  created_by: SOCifyLocale.text("معرف المؤلف"),
  created_by_name: SOCifyLocale.language === "ar" ? "المؤلف" : "Author",
  updated_by_name: SOCifyLocale.language === "ar" ? "آخر محرر" : "Last editor",
  updated_at: SOCifyLocale.text("آخر تعديل"),
  reference: SOCifyLocale.text("مرجع القضية"),
  source_version: SOCifyLocale.text("إصدار القضية"),
  revision: SOCifyLocale.text("إصدار التقرير"),
  profile: SOCifyLocale.text("سياسة المشاركة"),
  generated_at: SOCifyLocale.text("وقت إعداد النسخة"),
  entries: SOCifyLocale.text("عدد حركات الحيازة"),
  name: SOCifyLocale.text("الاسم"),
  role: SOCifyLocale.text("الدور"),
  responsibility: SOCifyLocale.text("المسؤولية"),
  title: SOCifyLocale.text("العنوان"),
  status: SOCifyLocale.text("الحالة"),
  classification: SOCifyLocale.text("تصنيف السرية"),
  attack_outcome: SOCifyLocale.text("نتيجة الهجوم"),
  alert_verdict: SOCifyLocale.text("قرار التنبيه"),
  sha256: SOCifyLocale.text("بصمة SHA-256"),
  version: SOCifyLocale.text("الإصدار"),
  objective: SOCifyLocale.text("الهدف"),
  reason: SOCifyLocale.text("السبب"),
  severity: SOCifyLocale.text("درجة الخطورة"),
  priority: SOCifyLocale.text("الأولوية"),
  source: SOCifyLocale.text("المصدر"),
  conclusion: SOCifyLocale.text("الاستنتاج"),
  evidence_id: SOCifyLocale.text("مرجع الدليل"),
  event_time: SOCifyLocale.text("وقت الحدث"),
  performed_at: SOCifyLocale.text("وقت التنفيذ"),
  details: SOCifyLocale.text("تفاصيل التحقيق"),
  counts: SOCifyLocale.text("موجز الأدلة المتاحة"),
  evidence_type: SOCifyLocale.text("نوع الدليل"),
  original_filename: SOCifyLocale.text("اسم الأصل"),
  parser_version: SOCifyLocale.text("إصدار المحلل"),
  accepted: SOCifyLocale.text("السجلات المقبولة"),
  rejected: SOCifyLocale.text("السجلات المرفوضة"),
  head_sha256: SOCifyLocale.text("بصمة رأس سلسلة الحيازة"),
  basis: SOCifyLocale.text("أساس حساب القياسات وحدودها"),
  integrity_valid: SOCifyLocale.text("سلامة سلسلة الحيازة"),
  normalized_logs: SOCifyLocale.text("السجلات المطبعّة"),
  status_at_preparation: SOCifyLocale.text("حالة القضية عند إعداد النسخة"),
  closed_at: SOCifyLocale.text("وقت الإغلاق"),
  legal_hold: SOCifyLocale.text("الحجز القانوني"),
  retention_until: SOCifyLocale.text("الاحتفاظ حتى")
};

function autopsyReportHasContent(value) {
  if (value === null || value === undefined || value === "") return false;
  if (typeof value === "object") return Object.values(value).some(autopsyReportHasContent);
  return true;
}

function autopsyReportFieldLabel(key) {
  return autopsyReportLabels[key] || (autopsy.catalog.report_labels?.[key] ? SOCifyLocale.text(autopsy.catalog.report_labels[key]) : autopsyLabel(key));
}

function autopsyReportPreview(value, depth = 0, fieldKey = "", view = null, path = [], recordContext = "") {
  if (value === null || typeof value !== "object") {
    let text = value === null ? "—" : String(value);
    if (fieldKey === "basis" && typeof value === "string") {
      const translated = SOCifyLocale.text(value);
      if (typeof translated === "string") text = translated;
    }
    if (["phase", "status"].includes(fieldKey) && typeof value === "string" && Object.prototype.hasOwnProperty.call(autopsyLabels, value)) text = autopsyLabel(value);
    if (fieldKey === "profile") text = value === "full" ? SOCifyLocale.text("كامل للاستخدام الداخلي المصرح") : value === "metadata_only_v1" ? SOCifyLocale.text("منقح: بيانات إحصائية وحالة فقط") : text;
    if (["created_at", "updated_at", "generated_at", "event_time", "performed_at", "closed_at"].includes(fieldKey) && typeof value === "string" && Number.isFinite(Date.parse(value))) text = formatTime(value);
    return node("span", { "data-user-content": "true", text });
  }
  if (depth >= 8) return node("p", { text: SOCifyLocale.text("تفاصيل إضافية متاحة في ملف JSON الكامل.") });
  const entries = (Array.isArray(value) ? value.map((item, index) => {
    let source = item;
    let identity = item && typeof item === "object" && ["question", "reference", "title", "name", "original_filename"].find(key => item[key] !== null && item[key] !== undefined && item[key] !== "");
    if (!identity && item?.payload && typeof item.payload === "object") {
      identity = ["title", "name"].find(key => typeof item.payload[key] === "string" && item.payload[key].trim());
      if (identity) source = item.payload;
    }
    if (!identity && item && typeof item === "object" && item.id !== null && item.id !== undefined && item.id !== "") identity = "id";
    return [identity ? `${autopsyReportFieldLabel(identity)}: ${source[identity]}` : `${SOCifyLocale.text("العنصر")} ${index + 1}`, item];
  }) : Object.entries(value).filter(([key]) => !["schema", "revision", "version", "source_version", "parser_version"].includes(key)
    && !(recordContext === "record" && ["id", "kind", "created_by", "updated_by"].includes(key)))).filter(([, item]) => autopsyReportHasContent(item));
  if (!entries.length) return node("p", { text: SOCifyLocale.text("لا توجد عناصر مسجلة") });
  const body = node("dl", { class: "report-data" });
  for (const [index, [key, item]] of entries.slice(0, 100).entries()) {
    const label = Array.isArray(value) ? key : autopsyReportFieldLabel(key);
    body.append(node("dt", { text: label }));
    const detail = node("dd");
    if (item !== null && typeof item === "object") {
      const entryPath = [...path, index], identity = JSON.stringify(entryPath);
      const childRecordContext = fieldKey === "records" ? "records" : Array.isArray(value) && recordContext === "records" ? "record" : "";
      const expand = node("details", { open: view?.has(identity) || false }, node("summary", { text: Array.isArray(item) ? SOCifyLocale.template`عناصر مسجلة: ${item.length}` : SOCifyLocale.text("عرض التفاصيل") }));
      const populate = () => { if (expand.open && expand.children.length === 1) expand.append(autopsyReportPreview(item, depth + 1, key, view, entryPath, childRecordContext)); };
      expand.addEventListener("toggle", () => { if (view && expand.isConnected) { if (expand.open) view.add(identity); else view.delete(identity); } populate(); });
      populate();
      detail.append(expand);
    } else detail.append(autopsyReportPreview(item, depth + 1, key));
    body.append(detail);
  }
  if (entries.length > 100) body.append(node("dd", { text: SOCifyLocale.text("تُعرض أول 100 نتيجة؛ الملف الكامل متاح للتنزيل.") }));
  return body;
}

function autopsyQuickChoiceLabel(value) {
  const parts = String(value).match(/^(.*)\s+\(([^()]*)\)$/u);
  return parts ? (SOCifyLocale.language === "ar" ? parts[1] : parts[2]) : SOCifyLocale.text(value);
}

function autopsyQuickReportLabel(value) {
  return SOCifyLocale.text({ draft: "مسودة", escalated: "أُحيل للمراجعة", acknowledged: "تمت المراجعة", approved: "معتمد", needs_followup: "يتطلب متابعة", closed: "مغلقة" }[value] || "—");
}

function autopsyReportProcessingLabel(value) {
  return SOCifyLocale.text({ queued: "بانتظار المعالجة", processing: "تجري المعالجة", completed: "جاهز للتنزيل", failed: "تعذرت المعالجة", cancelled: "أُلغيت المعالجة" }[value] || "غير متاحة");
}

function autopsyReportIssue(job) {
  if (!job.error_code || ["completed", "cancelled"].includes(job.state)) return null;
  const retrying = job.state === "queued";
  const messages = {
    ANALYSIS_UNAVAILABLE: retrying ? "إعداد التقرير متوقف مؤقتًا. ستتم إعادة المحاولة تلقائيًا." : "تعذر إعداد التقرير حاليًا. بيانات التحقيق محفوظة.",
    RESOURCE_LIMIT: "تجاوز إعداد التقرير الوقت المتاح. بيانات التحقيق محفوظة.",
    ACCESS_REVOKED: "تغيرت صلاحيات صاحب طلب التقرير. راجع صلاحياته أو أعد إعداد التقرير.",
    LEASE_EXPIRED: retrying ? "توقفت المعالجة قبل الاكتمال. ستتم إعادة المحاولة تلقائيًا." : "توقفت المعالجة قبل الاكتمال. بيانات التحقيق محفوظة.",
  };
  const notice = node("div", { class: "notice report-issue", role: "status" }, node("p", { text: SOCifyLocale.text(messages[job.error_code] || "تعذر إكمال إعداد التقرير. بيانات التحقيق محفوظة.") }));
  if (job.state === "failed" && job.attempts >= 3) notice.append(node("p", { text: SOCifyLocale.text("انتهت محاولات الإعداد. يمكنك طلب تقرير جديد لاحقًا.") }));
  return notice;
}

const autopsyReportSignature = report => JSON.stringify([report.state, report.job.state, report.job.error_code, report.job.attempts, report.formats]);

async function autopsyQuickDropdownReportPanel(caseId) {
  const data = await api(`/api/cases/${caseId}/quick-report`);
  const savedAnswers = data.report?.answers || data.default_answers || {};
  const selects = Object.create(null);
  const label = autopsyQuickChoiceLabel;
  const grid = node("form", { class: "form-grid", "aria-label": SOCifyLocale.text("قرارات التحقيق") });

  const sum = data.auto_summary;
  grid.append(node("p", {
    class: "span-2",
    text: SOCifyLocale.template`${sum.logs_count} سجل · ${sum.alerts_count} تنبيه · ${sum.static_triage_items.length} فحص`,
  }));

  for (const q of data.questions) {
    const sel = node(
      "select",
      { name: q.id, required:true, disabled: !autopsy.current.can_update || autopsy.current.status === "closed" },
      [node("option", {value:"", selected:!savedAnswers[q.id], disabled:true, text:SOCifyLocale.text("اختر الإجابة")}), ...q.options.map((opt) => node("option", { value: opt.value, selected: opt.value === savedAnswers[q.id], text: label(opt.label) }))],
    );
    selects[q.id] = sel;
    grid.append(field(label(q.label), sel));
  }

  const noteInput = node("input", {
    name: "executive_note",
    maxlength: 280,
    value: data.report?.executive_note || "",
    disabled: !autopsy.current.can_update || autopsy.current.status === "closed",
    placeholder: SOCifyLocale.text("اختياري: سطر واحد فقط عند الحاجة (بحد أقصى 280 حرفًا)…"),
  });
  grid.append(field(SOCifyLocale.text("ملاحظة مختصرة (اختيارية)"), noteInput));

  const collectPayload = () => ({
    answers: Object.fromEntries(Object.entries(selects).map(([k, el]) => [k, el.value])),
    executive_note: noteInput.value.trim(),
    case_version: data.case_version,
  });

  const statusNotice = node("div", { class: "span-2", "aria-live": "polite" });
  if (data.report) {
    statusNotice.append(node("p", {
      text: `${SOCifyLocale.text("الحالة")}: ${autopsyQuickReportLabel(data.report.status)}`,
    }));
  }

  const printLink = linkedButton(SOCifyLocale.text("فتح التقرير"), data.print_url);
  printLink.target = "_blank";
  printLink.rel = "noopener";

  const actions = node("div", { class: "action-row span-2" }, data.report ? [printLink] : []);
  if (autopsy.current.can_update && autopsy.current.status !== "closed") {
    const saveBtn = node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("حفظ إجابات التقرير") });
    const escalateBtn = button(SOCifyLocale.text("حفظ وتصعيد مباشر للمدير"), async () => {
      if (!grid.reportValidity()) return;
      escalateBtn.disabled = true;
      try {
        await api(`/api/cases/${caseId}/quick-report/escalate`, { method: "POST", body: collectPayload() });
        SOCifyDrafts.saved(grid);
        await autopsyCase(caseId);
      } catch (error) {
        statusNotice.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message }));
      } finally {
        escalateBtn.disabled = false;
      }
    }, "primary");
    actions.prepend(saveBtn, escalateBtn);
  }
  grid.append(actions, statusNotice);

  grid.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api(`/api/cases/${caseId}/quick-report`, { method: "PUT", body: collectPayload() });
      SOCifyDrafts.saved(grid);
      await autopsyCase(caseId);
    } catch (error) {
      statusNotice.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message }));
    }
  });

  SOCifyDrafts.track(grid);
  const container = node("div", { class: "panel-body" }, [grid]);
  if (data.report?.manager_decision) {
    container.prepend(node("div", { class: "notice review-decision", role: "status" }, [
      node("strong", { text: `${SOCifyLocale.text("قرار المدير")}: ${autopsyQuickReportLabel(data.report.manager_decision)}` }),
      data.report.manager_comment ? node("p", { "data-user-content": "true", text: data.report.manager_comment }) : null,
    ]));
  }
  if (data.closure && !data.closure.closed) {
    const requirements = node("details", { class: "closure-requirements" }, [
      node("summary", { text: SOCifyLocale.text("متطلبات الإغلاق") }),
    ]);
    if (data.closure.ready) requirements.append(node("p", { text: SOCifyLocale.text("القضية جاهزة للإغلاق") }));
    else requirements.append(node("ul", {}, data.closure.missing.map(item => node("li", {}, [
      node("a", { href: autopsyCaseURL(caseId, { tab: item.tab }), text: SOCifyLocale.text(item.label) }),
    ]))));
    container.append(requirements);
  }
  if (data.can_acknowledge_as_manager && data.report) {
    const decSelect = node("select", { name: "decision" }, [
      ["approved", SOCifyLocale.text("اعتماد التقرير والإجراءات (Approved)")],
      ["needs_followup", SOCifyLocale.text("طلب استكمال تحقيق إضافي (Needs Follow-up)")],
      ...(data.closure?.can_close ? [["closed", SOCifyLocale.text("اعتماد وإغلاق القضية")]] : []),
    ].map(([v, l]) => node("option", { value: v, selected: v === (data.report.manager_decision || "approved"), text: l })));
    const mgrComment = node("input", { name: "comment", maxlength: 500, value: data.report.manager_comment || "", placeholder: SOCifyLocale.text("توجيه أو تعليق مدير مركز العمليات…") });
    const mgrForm = node("form", { class: "filter-row" }, [
      field(SOCifyLocale.text("قرار مدير مركز العمليات"), decSelect),
      field(SOCifyLocale.text("تعليق المدير"), mgrComment),
      node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("اعتماد قرار المدير") }),
    ]);
    mgrForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await api(`/api/cases/${caseId}/quick-report/acknowledge`, { method: "POST", body: { decision: decSelect.value, comment: mgrComment.value.trim(), case_version: data.case_version } });
        SOCifyDrafts.saved(mgrForm);
        await autopsyCase(caseId);
      } catch (error) {
        statusNotice.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message }));
        if (error.code === "CASE_CLOSURE_INCOMPLETE") {
          const requirements = container.querySelector(".closure-requirements");
          if (requirements) { requirements.open = true; requirements.scrollIntoView({ block: "center" }); }
        }
      }
    });
    container.append(SOCifyDrafts.track(mgrForm));
  }
  return panel(SOCifyLocale.text("قرارات التحقيق"), container, true);
}

window.SOCifyAutopsy.reports = async (caseId) => {
  clearTimeout(autopsyReportTimer);
  const rootWrap = node("div", { class: "case-content" });
  try {
    rootWrap.append(await autopsyQuickDropdownReportPanel(caseId));
  } catch (error) {
    handleError(error);
  }
  const current = autopsy.current;
  const body = node("div", { class: "panel-body" });
  const profiles = permission("evidence.download") ? [{ value: "full", label: SOCifyLocale.text("كامل للاستخدام الداخلي المصرح") }, { value: "metadata_only_v1", label: SOCifyLocale.text("منقح: بيانات إحصائية وحالة فقط") }] : [{ value: "metadata_only_v1", label: SOCifyLocale.text("منقح: بيانات إحصائية وحالة فقط") }];
  const profileKey = `${state.user.id}:${caseId}`;
  const retainedProfile = autopsySavedReportProfile(profileKey);
  const choice = autopsyChoice("profile", profiles, profiles.some(item => item.value === retainedProfile) ? retainedProfile : profiles[0].value, true);
  choice.input.addEventListener("input", () => {
    const selected = profiles.find(item => item.label === choice.input.value);
    if (selected) autopsyRememberReportProfile(profileKey, selected.value);
  });
  const createError = node("div", { class: "report-create-error" });
  const create = button(SOCifyLocale.text("إعداد تقرير جديد"), async () => {
    if (!SOCifyDrafts.confirmDiscard(workspace)) return;
    create.disabled = true;
    createError.replaceChildren();
    try { await api(`/api/cases/${caseId}/reports`, { method: "POST", body: { version: current.version, profile: choice.input.autopsyValue() } }); await autopsyCase(caseId); }
    catch (error) { createError.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message })); create.disabled = false; }
  }, "primary");
  body.append(field(SOCifyLocale.text("سياسة مشاركة التقرير"), choice.control), create, button(SOCifyLocale.text("تحديث حالة التقارير"), () => autopsyCase(caseId).catch(handleError)), createError);
  let pending = false;
  const reportStates = new Map();
  if (current.archived_reports?.length) body.append(panel(SOCifyLocale.text("أرشيف التقارير"), table([{ label: SOCifyLocale.text("الإصدار"), value: "revision" }, { label: SOCifyLocale.text("الصيغة"), value: "format" }, { label: SOCifyLocale.text("البصمة"), value: "sha256" }, { label: SOCifyLocale.text("الملف"), value: (item) => permission("evidence.download") ? linkedButton(SOCifyLocale.text("تنزيل النسخة المؤرشفة"), `/api/incidents/${caseId}/report?format=${item.format}&revision=${item.revision}`) : SOCifyLocale.text("التنزيل يتطلب صلاحية مستقلة") }], current.archived_reports)));
  for (const item of current.reports) {
    const report = await api(`/api/cases/${caseId}/reports/${item.id}`);
    reportStates.set(report.id, autopsyReportSignature(report));
    const stale = report.source_version !== current.version;
    const viewKey = `${profileKey}:${report.id}`;
    if (!autopsyReportViews.has(viewKey)) autopsyReportViews.set(viewKey, new Set());
    const view = autopsyReportViews.get(viewKey);
    const card = node("article", { class: "card report-revision" }, [
      node("h3", { text: SOCifyLocale.template`تقرير ${report.revision}` }),
      node("p", { class: "report-sharing", text: autopsyReportSharingLabel(report.profile) }),
      node("p", { class: "report-status", text: `${autopsyQuickReportLabel(report.state)} · ${autopsyReportProcessingLabel(report.job.state)}` }),
      node("p", { text: SOCifyLocale.text(stale ? "تغيرت القضية بعد إعداد هذا التقرير" : "يتضمن أحدث بيانات القضية") }),
      node("p", { text: SOCifyLocale.template`أُعد: ${formatTime(report.created_at)}${report.approved_at ? SOCifyLocale.template` · اعتُمد: ${formatTime(report.approved_at)}` : ""}` }),
      node("details", {}, [node("summary", { text: SOCifyLocale.text("بصمة الملف") }), node("bdi", { text: `SHA-256: ${report.sha256}` })]),
    ]);
    const links = node("div", { class: "action-row report-downloads" });
    const available = report.formats.filter(format => ["json", "html", "pdf", "md", "docx"].includes(format));
    if (available.length) {
      const paths = new Map(available.map(format => [format, `/api/cases/${caseId}/reports/${report.id}/files/${encodeURIComponent(format)}`]));
      const formats = node("select", { "aria-label": SOCifyLocale.text("صيغة التقرير") }, available.map((format) => node("option", { value: format, selected: format === "pdf", text: format.toUpperCase() })));
      const download = linkedButton(SOCifyLocale.text("تنزيل الصيغة المختارة"), paths.get(formats.value));
      formats.addEventListener("change", () => { const path = paths.get(formats.value); if (path) download.href = path; });
      card.append(node("div", { class: "report-downloads action-row" }, [field(SOCifyLocale.text("صيغة التقرير"), formats), download]));
    }
    for (const format of available) links.append(linkedButton(SOCifyLocale.template`تنزيل ${format.toUpperCase()}`, `/api/cases/${caseId}/reports/${report.id}/files/${format}`));
    card.append(links);
    if (report.payload) {
      const preview = node("details", { open: view.has("preview") }, [node("summary", { text: SOCifyLocale.text("عرض بيانات النسخة للمراجعة") }), node("div", { class: "report-preview" }, autopsyReportPreview(report.payload, 0, "", view))]);
      preview.addEventListener("toggle", () => { if (preview.isConnected) { if (preview.open) view.add("preview"); else view.delete("preview"); } });
      card.append(preview);
    }
    const issue = autopsyReportIssue(report.job);
    if (issue) card.append(issue);
    if (["queued", "processing"].includes(report.job.state)) {
      pending = true;
      if (report.created_by === state.user.id || current.can_manage) card.append(button(SOCifyLocale.text("إلغاء المعالجة"), async () => { try { await api(`/api/cases/${caseId}/jobs/${report.job.id}/cancel`, { method: "POST", body: {} }); await autopsyCase(caseId); } catch (error) { handleError(error); } }));
    } else if (["failed", "cancelled"].includes(report.job.state) && report.job.attempts < 3 && (report.created_by === state.user.id || current.can_manage)) card.append(button(SOCifyLocale.text("إعادة المحاولة"), async () => { try { await api(`/api/cases/${caseId}/jobs/${report.job.id}/retry`, { method: "POST", body: {} }); await autopsyCase(caseId); } catch (error) { handleError(error); } }));
    if (current.can_approve && report.state === "draft" && !stale && report.formats.length === 5 && report.payload?.profile === "full") card.append(button(SOCifyLocale.text("مراجعة واعتماد النسخة"), () => {
      let dialog;
      const form = autopsyForm({ override_reason: { max: 1000 } }, async (payload) => { await api(`/api/cases/${caseId}/reports/${report.id}/approve`, { method: "POST", body: { ...payload, version: current.version } }); dialog.close(); await autopsyCase(caseId); });
      dialog = autopsyModal(SOCifyLocale.text("اعتماد نسخة ثابتة؛ اعتماد المؤلف نفسه يتطلب استثناء مدير مسبب"), form);
    }, "primary"));
    body.append(card);
  }
  if (pending) {
    let updates = 0;
    const poll = async () => {
      if (!body.isConnected || ++updates > 40) return;
      if (SOCifyDrafts.hasChanges(workspace) || !profiles.some(item => item.label === choice.input.value)) { autopsyReportTimer = setTimeout(poll, 2500); return; }
      try {
        const latest = await api(`/api/cases/${caseId}`);
        if (!body.isConnected) return;
        if (latest.full_case_access === false || latest.version !== current.version) { await autopsyCase(caseId); return; }
        const statuses = await Promise.all(latest.reports.slice(0, 20).map((item) => api(`/api/cases/${caseId}/reports/${item.id}`)));
        if (!body.isConnected) return;
        if (statuses.some(item => reportStates.get(item.id) !== autopsyReportSignature(item)) || !statuses.some(item => ["queued", "processing"].includes(item.job.state))) {
          if (SOCifyDrafts.hasChanges(workspace) || !profiles.some(item => item.label === choice.input.value)) { autopsyReportTimer = setTimeout(poll, 2500); return; }
          const selectedProfile = choice.input.value;
          autopsy.current = latest;
          const replacement = await window.SOCifyAutopsy.reports(caseId);
          if (!rootWrap.isConnected) return;
          if (SOCifyDrafts.hasChanges(workspace) || choice.input.value !== selectedProfile) { autopsyReportTimer = setTimeout(poll, 2500); return; }
          const position = { top: window.scrollY, left: window.scrollX, behavior: "instant" };
          rootWrap.replaceWith(replacement);
          window.scrollTo(position);
          return;
        }
        autopsyReportTimer = setTimeout(poll, 2500);
      } catch (error) { handleError(error); }
    };
    autopsyReportTimer = setTimeout(poll, 2500);
  }
  rootWrap.append(panel(SOCifyLocale.text("التقارير والمراجعة"), body, true));
  return rootWrap;
};
