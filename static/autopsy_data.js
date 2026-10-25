"use strict";

autopsyLabels.event_id = "السجل المعتمد كدليل";

function autopsyImportForm(caseId) {
  const file = node("input", { type: "file", name: "file", required: true, accept: ".csv,.json,.jsonl,.ndjson,.txt,.log,.xml,.evtx,.pcap,.pcapng" });
  const source = node("input", { name: "source_label", maxlength: 100, value: "file-import", required: true });
  const format = autopsySelect("format", autopsy.catalog.import_formats, "auto");
  const zone = autopsyChoice("source_timezone", autopsy.catalog.source_timezones, "UTC", true);
  const encoding = autopsySelect("encoding", ["utf-8-sig", "utf-8", "utf-16", "latin-1"], "utf-8-sig");
  const delimiter = node("select", { name: "delimiter" }, [[",", "فاصلة ,"], [";", "فاصلة منقوطة ;"], ["\t", "Tab"], ["|", "فاصل |"]].map(([value, label]) => node("option", { value, text: label })));
  const form = node("form", { class: "form-grid", "aria-label": "استيراد أدلة القضية" }, [field("ملف السجلات أو الأدلة الشبكية", file, true), field("مصدر جمع السجلات", source), field("الصيغة", format), field("المنطقة الزمنية للمصدر", zone.control), field("الترميز", encoding), field("فاصل CSV", delimiter)]);
  const preview = node("div", { class: "span-2", "aria-live": "polite" });
  const mappingView = node("div", { class: "span-2" });
  const mapping = Object.create(null);
  let confirmed = null;
  const identity = () => JSON.stringify([file.files[0]?.name, file.files[0]?.size, file.files[0]?.lastModified, source.value, format.value, zone.input.value, encoding.value, delimiter.value, mapping]);
  const commit = node("button", { type: "submit", class: "button primary", text: "اعتماد الاستيراد", disabled: true });
  const body = () => {
    if (!file.files[0]) throw new Error("اختر ملفًا أولًا");
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
  const previewButton = button("معاينة السجلات والبصمة", async () => {
    previewButton.disabled = true;
    try {
      const result = await api(`/api/cases/${caseId}/imports/preview`, { method: "POST", body: body() });
      preview.replaceChildren(node("p", { text: `الصيغة: ${result.format} · SHA-256: ${result.content_hash}` }), node("pre", { text: JSON.stringify(result.preview, null, 2) }));
      const header = result.preview.find((record) => record.raw_payload)?.raw_payload;
      if (header && typeof header === "object" && !mappingView.children.length) {
        const from = autopsyChoice("mapping_from", Object.keys(header), "", true);
        const to = autopsyChoice("mapping_to", autopsy.catalog.mapping_fields, "", true);
        const list = node("div", { "aria-live": "polite" });
        mappingView.append(node("fieldset", {}, [node("legend", { text: "ربط حقول المصدر بالحقول الموحّدة" }), field("حقل المصدر", from.control), field("الحقل الموحّد", to.control), button("إضافة ربط حقل", () => {
          try {
            mapping[from.input.autopsyValue()] = to.input.autopsyValue();
            list.replaceChildren(...Object.entries(mapping).map(([sourceField, target]) => node("p", {}, [node("bdi", { text: `${sourceField} → ${target}` }), button("إزالة الربط", () => { delete mapping[sourceField]; list.replaceChildren(); markChanged(); })])));
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
  if (autopsy.current.can_update && autopsy.current.status !== "closed") root.append(panel("استيراد مرتبط بالقضية", node("div", { class: "panel-body" }, autopsyImportForm(caseId)), true));
  const jobColumns = [{ label: "الملف", value: (job) => job.original_filename || job.filename }, { label: "الحالة", value: "status" }, { label: "مقبول", value: "accepted" }, { label: "مرفوض", value: "rejected" }, { label: "متكرر", value: "skipped" }, { label: "الأصل", value: (job) => permission("evidence.download") ? linkedButton("تنزيل الأصل", `/api/cases/${caseId}/imports/${job.id}/original`) : "—" }, { label: "التفاصيل", value: (job) => button("حالة الاستيراد", async () => {
    try {
      const result = await api(`/api/cases/${caseId}/imports/${job.id}`);
      const content = node("div", {}, [node("p", { text: `الحالة ${result.status} · ${result.accepted} مقبول · ${result.rejected} مرفوض` }), node("p", { text: `SHA-256: ${result.content_hash}` }), node("pre", { text: JSON.stringify(result.errors, null, 2) })]);
      if (autopsy.current.can_update && ["queued", "processing", "interrupted"].includes(result.status)) content.append(button("إلغاء الاستيراد", async () => { try { await api(`/api/cases/${caseId}/imports/${job.id}/cancel`, { method: "POST", body: {} }); await autopsyCase(caseId); } catch (error) { handleError(error); } }));
      if (autopsy.current.can_update && ["failed", "interrupted", "cancelled"].includes(result.status)) content.append(button("استئناف الاستيراد", async () => { try { await api(`/api/cases/${caseId}/imports/${job.id}/resume`, { method: "POST", body: {} }); await autopsyCase(caseId); } catch (error) { handleError(error); } }));
      autopsyModal("حالة الأصل ومهمة المعالجة", content);
    } catch (error) { handleError(error); }
  }) }];
  jobColumns.push({ label: "الإصدار المشتق", value: (job) => `${job.active_version ? "فعال" : "تاريخي"}${job.restricted ? " · وصول مقيد" : ""}` }, { label: "النطاق", value: (job) => linkedButton("سجلات هذه النسخة", autopsyCaseURL(caseId, { tab: "logs", job_id: job.id, page: null })) });
  if (autopsy.current.can_manage) jobColumns.push({ label: "إدارة النسخة والدفعة", value: (job) => autopsyAction("إدارة الدفعة", async () => {
    const members = node("select", { multiple: true, "aria-label": "أعضاء الدفعة" }, autopsy.team.members.filter((member) => member.is_active).map((member) => node("option", { value: member.id, selected: job.batch_members?.includes(member.id), text: `${member.name} · ${autopsyLabel(member.role)}` })));
    const content = node("div");
    const form = autopsyForm({ scope: { required: true, choices: ["team", "restricted"] }, reason: { required: true, max: 1000 } }, async (body) => { await api(`/api/cases/${caseId}/imports/${job.id}/access`, { method: "PUT", body: { restricted: body.scope === "restricted", members: [...members.selectedOptions].map((option) => Number(option.value)), reason: body.reason } }); await autopsyCase(caseId); }, { scope: job.restricted ? "restricted" : "team" });
    form.prepend(field("أعضاء مخولون عند تقييد الدفعة؛ يبقى مالك الأصل والمدير مخولين", members)); content.append(form);
    if (!job.active_version && ["completed", "completed_with_errors"].includes(job.status) && job.accepted > 0) content.append(autopsyForm({ reason: { required: true, max: 1000 } }, async (body) => { await api(`/api/cases/${caseId}/imports/${job.id}/activate`, { method: "POST", body: { ...body, version: autopsy.current.version } }); await autopsyCase(caseId); }));
    autopsyModal("نطاق الدفعة وتفعيل النسخة؛ أعد فحص القواعد بعد التفعيل", content);
  }) });
  if (selectedJob) root.append(node("p", { text: "تعرض سجلات نسخة محددة، وقد تكون تاريخية." }), linkedButton("عرض النسخ الفعالة", autopsyCaseURL(caseId, { tab: "logs", job_id: null, page: null })));
  root.append(panel("أصول الاستيراد والمعالجة", imports.items.length ? table(jobColumns, imports.items) : emptyState("لا استيرادات بعد", "الأصل وبصمته ومصدره محفوظة منفصلة عن السجلات المطبّعة."), true));
  const search = node("input", { type: "search", name: "q", value: query, maxlength: 200 });
  const form = node("form", { class: "filter-row", "aria-label": "بحث سجلات القضية" }, [field("عنوان أو عنوان شبكة أو مستخدم أو مضيف", search), node("button", { type: "submit", class: "button ghost", text: "بحث السجلات" })]);
  form.addEventListener("submit", (event) => { event.preventDefault(); window.location.assign(autopsyCaseURL(caseId, { tab: "logs", q: search.value, page: null })); });
  const exports = node("div", { class: "action-row" });
  if (permission("cases.export")) for (const format of ["csv", "json", "jsonl"]) {
    exports.append(linkedButton(`${format.toUpperCase()} · بيانات وصفية محجوبة`, `/api/cases/${caseId}/logs/export?format=${format}&redacted=1&q=${encodeURIComponent(query)}${jobFilter}`));
    if (permission("evidence.download")) exports.append(linkedButton(`${format.toUpperCase()} · غير منقّح`, `/api/cases/${caseId}/logs/export?format=${format}&redacted=0&q=${encodeURIComponent(query)}${jobFilter}`));
  }
  const columns = [{ label: "وقت الحدث", value: (row) => row.normalized_fields.event_time_known === false ? "غير متوفر؛ محفوظ وقت الإدخال" : formatTime(row.event_time) }, { label: "العنوان", value: "title" }, { label: "المصدر", value: "source" }, { label: "الخطورة", value: (row) => autopsyLabel(row.severity) }, { label: "فحص", value: (row) => button("تفاصيل السجل", async () => { try { const detail = await api(`/api/cases/${caseId}/logs/${row.id}`); autopsyModal("السجل الخام والمطبع", node("pre", { text: JSON.stringify(detail, null, 2) })); } catch (error) { handleError(error); } }) }];
  const tableContent = node("div", { class: "panel-body" }, [form, exports, node("p", { text: `${data.total_relation === "gte" ? "على الأقل " : ""}${data.total} سجل في نطاق البحث${data.total_relation === "gte" ? " · الحد الأدنى للعدد يحافظ على سرعة البحث؛ تستمر الصفحات التالية" : ""}` }), data.items.length ? table(columns, data.items) : emptyState("لا سجلات في النطاق", "أضف ملفًا أو غيّر مرشح البحث داخل القضية.")]);
  if (page > 1) tableContent.append(linkedButton("السجلات السابقة", autopsyCaseURL(caseId, { tab: "logs", page: page - 1 })));
  if (data.has_next ?? (page * data.limit < data.total)) tableContent.append(linkedButton("السجلات التالية", autopsyCaseURL(caseId, { tab: "logs", page: page + 1 })));
  if (data.items.length && autopsy.current.can_update && autopsy.current.status !== "closed") {
    tableContent.append(autopsyForm({ event_id: { required: true, choices: data.items.map((item) => ({ value: item.id, label: `${item.title} · ${item.event_id}` })) } }, async (body) => {
      await api(`/api/cases/${caseId}/logs/${body.event_id}/exhibit`, { method: "POST", body: {} });
      await autopsyCase(caseId);
    }));
  }
  root.append(panel("مستكشف سجلات القضية", tableContent, true));
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
