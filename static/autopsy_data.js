"use strict";

autopsyLabels.event_id = SOCifyLocale.text("السجل المعتمد كدليل");

function autopsyImportForm(caseId) {
  const file = node("input", { type: "file", name: "file", required: true, accept: ".csv,.json,.jsonl,.ndjson,.txt,.log,.xml,.evtx,.pcap,.pcapng" });
  const source = node("input", { name: "source_label", maxlength: 100, value: "file-import", required: true });
  const format = autopsySelect("format", autopsy.catalog.import_formats, "auto");
  const zone = autopsyChoice("source_timezone", autopsy.catalog.source_timezones, "UTC", true);
  const encoding = autopsySelect("encoding", ["utf-8-sig", "utf-8", "utf-16", "latin-1"], "utf-8-sig");
  const delimiter = node("select", { name: "delimiter" }, [[",", SOCifyLocale.text("فاصلة ,")], [";", SOCifyLocale.text("فاصلة منقوطة ;")], ["\t", "Tab"], ["|", SOCifyLocale.text("فاصل |")]].map(([value, label]) => node("option", { value, text: label })));
  const form = node("form", { class: "form-grid", "aria-label": SOCifyLocale.text("استيراد أدلة القضية") }, [field(SOCifyLocale.text("ملف السجلات أو الأدلة الشبكية"), file, true), field(SOCifyLocale.text("مصدر جمع السجلات"), source), field(SOCifyLocale.text("الصيغة"), format), field(SOCifyLocale.text("المنطقة الزمنية للمصدر"), zone.control), field(SOCifyLocale.text("الترميز"), encoding), field(SOCifyLocale.text("فاصل CSV"), delimiter)]);
  const preview = node("div", { class: "span-2", "aria-live": "polite" });
  const mappingView = node("div", { class: "span-2" });
  const mapping = Object.create(null);
  let confirmed = null;
  const identity = () => JSON.stringify([file.files[0]?.name, file.files[0]?.size, file.files[0]?.lastModified, source.value, format.value, zone.input.value, encoding.value, delimiter.value, mapping]);
  const commit = node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("اعتماد الاستيراد"), disabled: true });
  const body = () => {
    if (!file.files[0]) throw new Error(SOCifyLocale.text("اختر ملفًا أولًا"));
    const data = new FormData();
    data.set("file", file.files[0]);
    data.set("source_label", source.value);
    data.set("format", format.value);
    data.set("source_timezone", zone.input.autopsyValue());
    data.set("encoding", encoding.value);
    data.set("delimiter", delimiter.value);
    data.set("mapping", JSON.stringify(mapping));
    return data;
  };
  const markChanged = () => { if (identity() !== confirmed) commit.disabled = true; };
  form.addEventListener("input", markChanged);
  form.addEventListener("change", markChanged);
  const previewButton = button(SOCifyLocale.text("معاينة السجلات والبصمة"), async () => {
    previewButton.disabled = true;
    try {
      const result = await api(`/api/cases/${caseId}/imports/preview`, { method: "POST", body: body() });
      preview.replaceChildren(node("p", { text: SOCifyLocale.template`الصيغة: ${result.format} · SHA-256: ${result.content_hash}` }), node("pre", { text: JSON.stringify(result.preview, null, 2) }));
      const header = result.preview.find((record) => record.raw_payload)?.raw_payload;
      if (header && typeof header === "object" && !mappingView.children.length) {
        const from = autopsyChoice("mapping_from", Object.keys(header), "", true);
        const to = autopsyChoice("mapping_to", autopsy.catalog.mapping_fields, "", true);
        const list = node("div", { "aria-live": "polite" });
        mappingView.append(node("fieldset", {}, [node("legend", { text: SOCifyLocale.text("ربط حقول المصدر بالحقول الموحّدة") }), field(SOCifyLocale.text("حقل المصدر"), from.control), field(SOCifyLocale.text("الحقل الموحّد"), to.control), button(SOCifyLocale.text("إضافة ربط حقل"), () => {
          try {
            mapping[from.input.autopsyValue()] = to.input.autopsyValue();
            list.replaceChildren(...Object.entries(mapping).map(([sourceField, target]) => node("p", {}, [node("bdi", { text: `${sourceField} → ${target}` }), button(SOCifyLocale.text("إزالة الربط"), () => { delete mapping[sourceField]; list.replaceChildren(); markChanged(); })])));
            markChanged();
          } catch (error) { handleError(error); }
        }), list]));
        from.input.required = false;
        to.input.required = false;
      }
      confirmed = identity();
      commit.disabled = false;
    } catch (error) { preview.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message })); commit.disabled = true; }
    finally { previewButton.disabled = false; }
  }, "ghost");
  form.append(node("div", { class: "action-row span-2" }, [previewButton, commit]), mappingView, preview);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (confirmed !== identity()) return;
    commit.disabled = true;
    try { await api(`/api/cases/${caseId}/imports`, { method: "POST", body: body() }); await autopsyCase(caseId); }
    catch (error) { preview.replaceChildren(node("p", { class: "notice", role: "alert", text: error.message })); commit.disabled = false; }
  });
  return form;
}

async function autopsyLogsPanel(caseId) {
  const query = new URLSearchParams(window.location.search).get("q") || "";
  const page = Math.max(1, Number(new URLSearchParams(window.location.search).get("page")) || 1);
  const selectedJob = new URLSearchParams(window.location.search).get("job_id") || "";
  const jobFilter = selectedJob ? `&job_id=${encodeURIComponent(selectedJob)}` : "";
  const [data, imports] = await Promise.all([api(`/api/cases/${caseId}/logs?q=${encodeURIComponent(query)}&page=${page}${jobFilter}`), api(`/api/cases/${caseId}/imports`)]);
  const root = node("div", { class: "case-content" });
  if (autopsy.current.can_update && autopsy.current.status !== "closed") root.append(panel(SOCifyLocale.text("استيراد مرتبط بالقضية"), node("div", { class: "panel-body" }, autopsyImportForm(caseId)), true));
  const jobColumns = [{ label: SOCifyLocale.text("الملف"), value: (job) => job.original_filename || job.filename }, { label: SOCifyLocale.text("الحالة"), value: "status" }, { label: SOCifyLocale.text("مقبول"), value: "accepted" }, { label: SOCifyLocale.text("مرفوض"), value: "rejected" }, { label: SOCifyLocale.text("متكرر"), value: "skipped" }, { label: SOCifyLocale.text("الأصل"), value: (job) => permission("evidence.download") ? linkedButton(SOCifyLocale.text("تنزيل الأصل"), `/api/cases/${caseId}/imports/${job.id}/original`) : "—" }, { label: SOCifyLocale.text("التفاصيل"), value: (job) => button(SOCifyLocale.text("حالة الاستيراد"), async () => {
    try {
      const result = await api(`/api/cases/${caseId}/imports/${job.id}`);
      const content = node("div", {}, [node("p", { text: SOCifyLocale.template`الحالة ${result.status} · ${result.accepted} مقبول · ${result.rejected} مرفوض` }), node("p", { text: `SHA-256: ${result.content_hash}` }), node("pre", { text: JSON.stringify(result.errors, null, 2) })]);
      if (autopsy.current.can_update && ["queued", "processing", "interrupted"].includes(result.status)) content.append(button(SOCifyLocale.text("إلغاء الاستيراد"), async () => { try { await api(`/api/cases/${caseId}/imports/${job.id}/cancel`, { method: "POST", body: {} }); await autopsyCase(caseId); } catch (error) { handleError(error); } }));
      if (autopsy.current.can_update && ["failed", "interrupted", "cancelled"].includes(result.status)) content.append(button(SOCifyLocale.text("استئناف الاستيراد"), async () => { try { await api(`/api/cases/${caseId}/imports/${job.id}/resume`, { method: "POST", body: {} }); await autopsyCase(caseId); } catch (error) { handleError(error); } }));
      autopsyModal(SOCifyLocale.text("حالة الأصل ومهمة المعالجة"), content);
    } catch (error) { handleError(error); }
  }) }];
  jobColumns.push({ label: SOCifyLocale.text("الإصدار المشتق"), value: (job) => `${job.active_version ? SOCifyLocale.text("فعال") : SOCifyLocale.text("تاريخي")}${job.restricted ? SOCifyLocale.text(" · وصول مقيد") : ""}` }, { label: SOCifyLocale.text("النطاق"), value: (job) => linkedButton(SOCifyLocale.text("سجلات هذه النسخة"), autopsyCaseURL(caseId, { tab: "logs", job_id: job.id, page: null })) });
  if (autopsy.current.can_manage) jobColumns.push({ label: SOCifyLocale.text("إدارة النسخة والدفعة"), value: (job) => autopsyAction(SOCifyLocale.text("إدارة الدفعة"), async () => {
    const members = node("select", { multiple: true, "aria-label": SOCifyLocale.text("أعضاء الدفعة") }, autopsy.team.members.filter((member) => member.is_active).map((member) => node("option", { value: member.id, selected: job.batch_members?.includes(member.id), text: `${member.name} · ${autopsyLabel(member.role)}` })));
    const content = node("div");
    const form = autopsyForm({ scope: { required: true, choices: ["team", "restricted"] }, reason: { required: true, max: 1000 } }, async (body) => { await api(`/api/cases/${caseId}/imports/${job.id}/access`, { method: "PUT", body: { restricted: body.scope === "restricted", members: [...members.selectedOptions].map((option) => Number(option.value)), reason: body.reason } }); await autopsyCase(caseId); }, { scope: job.restricted ? "restricted" : "team" });
    form.prepend(field(SOCifyLocale.text("أعضاء مخولون عند تقييد الدفعة؛ يبقى مالك الأصل والمدير مخولين"), members)); content.append(form);
    if (!job.active_version && ["completed", "completed_with_errors"].includes(job.status) && job.accepted > 0) content.append(autopsyForm({ reason: { required: true, max: 1000 } }, async (body) => { await api(`/api/cases/${caseId}/imports/${job.id}/activate`, { method: "POST", body: { ...body, version: autopsy.current.version } }); await autopsyCase(caseId); }));
    autopsyModal(SOCifyLocale.text("نطاق الدفعة وتفعيل النسخة؛ أعد فحص القواعد بعد التفعيل"), content);
  }) });
  if (selectedJob) root.append(node("p", { text: SOCifyLocale.text("تعرض سجلات نسخة محددة، وقد تكون تاريخية.") }), linkedButton(SOCifyLocale.text("عرض النسخ الفعالة"), autopsyCaseURL(caseId, { tab: "logs", job_id: null, page: null })));
  root.append(panel(SOCifyLocale.text("أصول الاستيراد والمعالجة"), imports.items.length ? table(jobColumns, imports.items) : emptyState(SOCifyLocale.text("لا استيرادات بعد"), SOCifyLocale.text("الأصل وبصمته ومصدره محفوظة منفصلة عن السجلات المطبّعة.")), true));
  const search = node("input", { type: "search", name: "q", value: query, maxlength: 200 });
  const form = node("form", { class: "filter-row", "aria-label": SOCifyLocale.text("بحث سجلات القضية") }, [field(SOCifyLocale.text("عنوان أو عنوان شبكة أو مستخدم أو مضيف"), search), node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("بحث السجلات") })]);
  form.addEventListener("submit", (event) => { event.preventDefault(); window.location.assign(autopsyCaseURL(caseId, { tab: "logs", q: search.value, page: null })); });
  const exports = node("div", { class: "action-row" });
  if (permission("cases.export")) for (const format of ["csv", "json", "jsonl"]) {
    exports.append(linkedButton(SOCifyLocale.template`${format.toUpperCase()} · بيانات وصفية محجوبة`, `/api/cases/${caseId}/logs/export?format=${format}&redacted=1&q=${encodeURIComponent(query)}${jobFilter}`));
    if (permission("evidence.download")) exports.append(linkedButton(SOCifyLocale.template`${format.toUpperCase()} · غير منقّح`, `/api/cases/${caseId}/logs/export?format=${format}&redacted=0&q=${encodeURIComponent(query)}${jobFilter}`));
  }
  const columns = [{ label: SOCifyLocale.text("وقت الحدث"), value: (row) => row.normalized_fields.event_time_known === false ? SOCifyLocale.text("غير متوفر؛ محفوظ وقت الإدخال") : formatTime(row.event_time) }, { label: SOCifyLocale.text("العنوان"), value: "title" }, { label: SOCifyLocale.text("المصدر"), value: "source" }, { label: SOCifyLocale.text("الخطورة"), value: (row) => autopsyLabel(row.severity) }, { label: SOCifyLocale.text("فحص"), value: (row) => button(SOCifyLocale.text("تفاصيل السجل"), async () => { try { const detail = await api(`/api/cases/${caseId}/logs/${row.id}`); autopsyModal(SOCifyLocale.text("السجل الخام والمطبع"), node("pre", { text: JSON.stringify(detail, null, 2) })); } catch (error) { handleError(error); } }) }];
  const tableContent = node("div", { class: "panel-body" }, [form, exports, node("p", { text: SOCifyLocale.template`${data.total_relation === "gte" ? SOCifyLocale.text("على الأقل ") : ""}${data.total} سجل في نطاق البحث${data.total_relation === "gte" ? SOCifyLocale.text(" · الحد الأدنى للعدد يحافظ على سرعة البحث؛ تستمر الصفحات التالية") : ""}` }), data.items.length ? table(columns, data.items) : emptyState(SOCifyLocale.text("لا سجلات في النطاق"), SOCifyLocale.text("أضف ملفًا أو غيّر مرشح البحث داخل القضية."))]);
  if (page > 1) tableContent.append(linkedButton(SOCifyLocale.text("السجلات السابقة"), autopsyCaseURL(caseId, { tab: "logs", page: page - 1 })));
  if (data.has_next ?? (page * data.limit < data.total)) tableContent.append(linkedButton(SOCifyLocale.text("السجلات التالية"), autopsyCaseURL(caseId, { tab: "logs", page: page + 1 })));
  if (data.items.length && autopsy.current.can_update && autopsy.current.status !== "closed") {
    tableContent.append(autopsyForm({ event_id: { required: true, choices: data.items.map((item) => ({ value: item.id, label: `${item.title} · ${item.event_id}` })) } }, async (body) => {
      await api(`/api/cases/${caseId}/logs/${body.event_id}/exhibit`, { method: "POST", body: {} });
      await autopsyCase(caseId);
    }));
  }
  root.append(panel(SOCifyLocale.text("مستكشف سجلات القضية"), tableContent, true));
  if (imports.items.some((job) => ["queued", "processing", "interrupted"].includes(job.status))) {
    let remaining = 60;
    const poll = async () => {
      if (!root.isConnected || remaining-- <= 0) return;
      try {
        const latest = await api(`/api/cases/${caseId}/imports`);
        if (JSON.stringify(latest.items.map((job) => [job.id, job.status, job.progress])) !== JSON.stringify(imports.items.map((job) => [job.id, job.status, job.progress]))) { await autopsyCase(caseId); return; }
        window.setTimeout(poll, 1500);
      } catch (error) { handleError(error); }
    };
    window.setTimeout(poll, 1500);
  }
  return root;
}

window.SOCifyAutopsy.logs = autopsyLogsPanel;
