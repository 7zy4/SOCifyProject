"use strict";

let autopsyReportTimer = null;

const autopsyReportLabels = {
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

function autopsyReportPreview(value, depth = 0) {
  if (value === null || typeof value !== "object") return node("span", { "data-user-content": "true", text: value === null ? "—" : String(value) });
  if (depth >= 8) return node("p", { text: SOCifyLocale.text("تفاصيل إضافية متاحة في ملف JSON الكامل.") });
  const entries = Array.isArray(value) ? value.map((item, index) => [String(index + 1), item]) : Object.entries(value);
  if (!entries.length) return node("p", { text: SOCifyLocale.text("لا توجد عناصر مسجلة") });
  const body = node("dl", { class: "report-data" });
  for (const [key, item] of entries.slice(0, 100)) {
    const label = autopsyReportLabels[key] || autopsyLabel(key);
    body.append(node("dt", { text: label }));
    const detail = node("dd");
    if (item !== null && typeof item === "object") {
      const expand = node("details", {}, node("summary", { text: Array.isArray(item) ? SOCifyLocale.template`عناصر مسجلة: ${item.length}` : SOCifyLocale.text("عرض التفاصيل") }));
      expand.addEventListener("toggle", () => { if (expand.open && expand.children.length === 1) expand.append(autopsyReportPreview(item, depth + 1)); });
      detail.append(expand);
    } else detail.append(autopsyReportPreview(item, depth + 1));
    body.append(detail);
  }
  if (entries.length > 100) body.append(node("dd", { text: SOCifyLocale.text("تُعرض أول 100 نتيجة؛ الملف الكامل متاح للتنزيل.") }));
  return body;
}

window.SOCifyAutopsy.reports = async (caseId) => {
  clearTimeout(autopsyReportTimer);
  const current = autopsy.current;
  const body = node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("إصدارات ثابتة تجمع نتائج التحقيق والأدلة والإجراءات. الملاحظات الخاصة مستبعدة. لا يعني إنشاء التقرير اعتماده أو إغلاق القضية.") }), node("p", { text: SOCifyLocale.text("يتطلب الإغلاق: أدلة، تحليل سبب جذري أو سبب عدم تحديده، تحقق من الاستجابة، إكمال المهام والخطوات الإلزامية، وتقرير كامل معتمد يطابق آخر إصدار للقضية.") })]);
  const profiles = permission("evidence.download") ? [{ value: "full", label: SOCifyLocale.text("كامل للاستخدام الداخلي المصرح") }, { value: "metadata_only_v1", label: SOCifyLocale.text("منقح: بيانات إحصائية وحالة فقط") }] : [{ value: "metadata_only_v1", label: SOCifyLocale.text("منقح: بيانات إحصائية وحالة فقط") }];
  const choice = autopsyChoice("profile", profiles, profiles[0].value, true);
  const create = button(SOCifyLocale.text("إعداد تقرير جديد"), async () => {
    create.disabled = true;
    try { await api(`/api/cases/${caseId}/reports`, { method: "POST", body: { version: current.version, profile: choice.input.autopsyValue() } }); await autopsyCase(caseId); }
    catch (error) { handleError(error); create.disabled = false; }
  }, "primary");
  body.append(field(SOCifyLocale.text("سياسة مشاركة التقرير"), choice.control), create, button(SOCifyLocale.text("تحديث حالة التقارير"), () => autopsyCase(caseId).catch(handleError)));
  let pending = false;
  if (current.archived_reports?.length) body.append(panel(SOCifyLocale.text("أرشيف تقارير V2 · النسخ الأصلية محفوظة دون إعادة توليد"), table([{ label: SOCifyLocale.text("الإصدار"), value: "revision" }, { label: SOCifyLocale.text("الصيغة"), value: "format" }, { label: SOCifyLocale.text("البصمة"), value: "sha256" }, { label: SOCifyLocale.text("الملف"), value: (item) => permission("evidence.download") ? linkedButton(SOCifyLocale.text("تنزيل النسخة المؤرشفة"), `/api/incidents/${caseId}/report?format=${item.format}&revision=${item.revision}`) : SOCifyLocale.text("التنزيل يتطلب صلاحية مستقلة") }], current.archived_reports)));
  for (const item of current.reports) {
    const report = await api(`/api/cases/${caseId}/reports/${item.id}`);
    const stale = report.source_version !== current.version;
    const card = node("article", { class: "card report-revision" }, [node("h3", { text: SOCifyLocale.template`تقرير الإصدار ${report.revision}` }), node("p", { text: SOCifyLocale.template`الحالة: ${report.state} · المعالجة: ${report.job.state || SOCifyLocale.text("غير متاحة")} · بيانات القضية: ${report.source_version}${stale ? SOCifyLocale.text(" · نسخة تاريخية؛ تغيرت القضية بعدها") : SOCifyLocale.text(" · مطابق للإصدار الحالي")}` }), node("p", { text: SOCifyLocale.template`أُعد: ${formatTime(report.created_at)}${report.approved_at ? SOCifyLocale.template` · اعتُمد: ${formatTime(report.approved_at)}` : ""}` }), node("p", { text: `SHA-256: ${report.sha256}` })]);
    const links = node("div", { class: "action-row report-downloads" });
    if (report.formats.length) {
      const formats = node("select", { "aria-label": SOCifyLocale.text("صيغة التقرير") }, report.formats.map((format) => node("option", { value: format, selected: format === "pdf", text: format.toUpperCase() })));
      const download = linkedButton(SOCifyLocale.text("تنزيل الصيغة المختارة"), `/api/cases/${caseId}/reports/${report.id}/files/${formats.value}`);
      formats.addEventListener("change", () => { download.href = `/api/cases/${caseId}/reports/${report.id}/files/${formats.value}`; });
      card.append(node("div", { class: "report-downloads action-row" }, [field(SOCifyLocale.text("صيغة التقرير"), formats), download]));
    }
    for (const format of report.formats) links.append(linkedButton(SOCifyLocale.template`تنزيل ${format.toUpperCase()}`, `/api/cases/${caseId}/reports/${report.id}/files/${format}`));
    card.append(links);
    if (report.payload) {
      const preview = node("details", {}, [node("summary", { text: SOCifyLocale.text("عرض بيانات النسخة للمراجعة") }), node("div", { class: "report-preview" }, autopsyReportPreview(report.payload))]);
      card.append(preview);
    }
    if (report.job.error_code) card.append(node("p", { class: "notice", role: "status", text: SOCifyLocale.template`تعذر المعالجة: ${report.job.error_code}. راجع عامل المعالجة المحلي وحدود الموارد دون تغيير الدليل.` }));
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
      try {
        const latest = await api(`/api/cases/${caseId}`);
        const statuses = await Promise.all(latest.reports.slice(0, 20).map((item) => api(`/api/cases/${caseId}/reports/${item.id}`)));
        if (statuses.some((item) => !["queued", "processing"].includes(item.job.state) && !current.reports.some((old) => old.id === item.id && old.state === item.state))) return autopsyCase(caseId);
        if (!statuses.some((item) => ["queued", "processing"].includes(item.job.state))) return autopsyCase(caseId);
        autopsyReportTimer = setTimeout(poll, 2500);
      } catch (error) { handleError(error); }
    };
    autopsyReportTimer = setTimeout(poll, 2500);
  }
  return panel(SOCifyLocale.text("التقارير والمراجعة"), body, true);
};
