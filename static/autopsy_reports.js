"use strict";

let autopsyReportTimer = null;

window.SOCifyAutopsy.reports = async (caseId) => {
  clearTimeout(autopsyReportTimer);
  const current = autopsy.current;
  const body = node("div", { class: "panel-body" }, [node("p", { text: "إصدارات ثابتة تجمع نتائج التحقيق والأدلة والإجراءات. الملاحظات الخاصة مستبعدة. لا يعني إنشاء التقرير اعتماده أو إغلاق القضية." }), node("p", { text: "يتطلب الإغلاق: أدلة، تحليل سبب جذري أو سبب عدم تحديده، تحقق من الاستجابة، إكمال المهام والخطوات الإلزامية، وتقرير كامل معتمد يطابق آخر إصدار للقضية." })]);
  const profiles = permission("evidence.download") ? [{ value: "full", label: "كامل للاستخدام الداخلي المصرح" }, { value: "metadata_only_v1", label: "منقح: بيانات إحصائية وحالة فقط" }] : [{ value: "metadata_only_v1", label: "منقح: بيانات إحصائية وحالة فقط" }];
  const choice = autopsyChoice("profile", profiles, profiles[0].value, true);
  const create = button("إعداد تقرير جديد", async () => {
    create.disabled = true;
    try { await api(`/api/cases/${caseId}/reports`, { method: "POST", body: { version: current.version, profile: choice.input.autopsyValue() } }); await autopsyCase(caseId); }
    catch (error) { handleError(error); create.disabled = false; }
  }, "primary");
  body.append(field("سياسة مشاركة التقرير", choice.control), create, button("تحديث حالة التقارير", () => autopsyCase(caseId).catch(handleError)));
  let pending = false;
  for (const item of current.reports) {
    const report = await api(`/api/cases/${caseId}/reports/${item.id}`);
    const stale = report.source_version !== current.version;
    const card = node("article", { class: "card report-revision" }, [node("h3", { text: `تقرير الإصدار ${report.revision}` }), node("p", { text: `الحالة: ${report.state} · المعالجة: ${report.job.state || "غير متاحة"} · بيانات القضية: ${report.source_version}${stale ? " · نسخة تاريخية؛ تغيرت القضية بعدها" : " · مطابق للإصدار الحالي"}` }), node("p", { text: `أُعد: ${formatTime(report.created_at)}${report.approved_at ? ` · اعتُمد: ${formatTime(report.approved_at)}` : ""}` }), node("p", { text: `SHA-256: ${report.sha256}` })]);
    const links = node("div", { class: "action-row" });
    for (const format of report.formats) links.append(linkedButton(`تنزيل ${format.toUpperCase()}`, `/api/cases/${caseId}/reports/${report.id}/files/${format}`));
    card.append(links);
    if (report.payload) {
      const preview = node("details", {}, [node("summary", { text: "عرض بيانات النسخة للمراجعة" }), node("pre", { text: JSON.stringify(report.payload, null, 2) })]);
      card.append(preview);
    }
    if (report.job.error_code) card.append(node("p", { class: "notice", role: "status", text: `تعذر المعالجة: ${report.job.error_code}. راجع عامل المعالجة المحلي وحدود الموارد دون تغيير الدليل.` }));
    if (["queued", "processing"].includes(report.job.state)) {
      pending = true;
      if (report.created_by === state.user.id || current.can_manage) card.append(button("إلغاء المعالجة", async () => { try { await api(`/api/cases/${caseId}/jobs/${report.job.id}/cancel`, { method: "POST", body: {} }); await autopsyCase(caseId); } catch (error) { handleError(error); } }));
    } else if (["failed", "cancelled"].includes(report.job.state) && report.job.attempts < 3 && (report.created_by === state.user.id || current.can_manage)) card.append(button("إعادة المحاولة", async () => { try { await api(`/api/cases/${caseId}/jobs/${report.job.id}/retry`, { method: "POST", body: {} }); await autopsyCase(caseId); } catch (error) { handleError(error); } }));
    if (current.can_approve && report.state === "draft" && !stale && report.formats.length === 5 && report.payload?.profile === "full") card.append(button("مراجعة واعتماد النسخة", () => {
      let dialog;
      const form = autopsyForm({ override_reason: { max: 1000 } }, async (payload) => { await api(`/api/cases/${caseId}/reports/${report.id}/approve`, { method: "POST", body: { ...payload, version: current.version } }); dialog.close(); await autopsyCase(caseId); });
      dialog = autopsyModal("اعتماد نسخة ثابتة؛ اعتماد المؤلف نفسه يتطلب استثناء مدير مسبب", form);
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
  return panel("التقارير والمراجعة", body, true);
};
