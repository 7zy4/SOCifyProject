"use strict";

window.SOCifyAutopsy.analysis = async (caseId) => {
  const samples = await api(`/api/cases/${caseId}/samples`);
  const indicators = (await api(`/api/cases/${caseId}/records?kind=indicator&limit=100`)).items;
  const root = node("div");
  const packs = await api("/api/autopsy/yara");
  const packChoice = autopsyChoice("yara_pack_id", [{ value: "", label: "الافتراضي · علامة اختبار EICAR فقط" }, ...packs.items.map((pack) => ({ value: pack.id, label: `${pack.name} · v${pack.version} · ${pack.license}` }))]);
  const body = node("div", { class: "panel-body" }, node("p", { text: "حجر مشفر، وتحليل ساكن محلي بموارد محدودة. لا تنفيذ للعينة، ولا sandbox ديناميكي، ولا إرسال إلى خدمة خارجية. YARA الافتراضي يكتشف علامة اختبار EICAR فقط؛ غياب التطابق لا يثبت السلامة." }));
  body.append(field("حزمة YARA لهذا الفحص · يحفظ الإصدار والبصمة", packChoice.control), linkedButton("إدارة حزم YARA المحلية", "/analysis-library"));
  if (permission("evidence.add") && autopsy.current.status !== "closed") {
    const file = node("input", { type: "file", required: true, name: "sample" });
    const form = node("form", { class: "filter-row" }, [field("عينة للفحص المحلي", file), node("button", { type: "submit", class: "button primary", text: "حجر العينة" })]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); try { const data = new FormData(); data.set("file", file.files[0]); await api(`/api/cases/${caseId}/samples`, { method: "POST", body: data }); await autopsyCase(caseId); } catch (error) { handleError(error); } });
    body.append(form);
  }
  body.append(table([{ label: "العينة", value: "filename" }, { label: "SHA-256", value: (row) => node("bdi", { text: row.sha256 }) }, { label: "الحجم", value: "size" }, { label: "الفحص", value: (row) => autopsy.current.can_update && autopsy.current.status !== "closed" ? button("تحليل ساكن محلي", async () => {
    try {
      const selected = packChoice.input.autopsyValue();
      const queued = await api(`/api/cases/${caseId}/samples/${row.id}/analyze`, { method: "POST", body: selected ? { yara_pack_id: Number(selected) } : {} });
      const status = node("p", { role: "status", text: "العمل في الطابور المحلي. يمكنك إغلاق هذه النافذة؛ ستبقى المهمة محفوظة." });
      const dialog = autopsyModal("التحليل المحلي", node("div", {}, [status, button("تحديث النتيجة", () => { dialog.close(); autopsyCase(caseId).catch(handleError); })]));
      let attempts = 0;
      const poll = async () => {
        if (!dialog.isConnected || ++attempts > 40) return;
        try { const job = await api(`/api/cases/${caseId}/jobs/${queued.id}`); status.textContent = `${job.state}${job.error_code ? ` · ${job.error_code}` : ""}`; if (["queued", "processing"].includes(job.state)) setTimeout(poll, 1500); else if (job.state === "completed") { dialog.close(); await autopsyCase(caseId); } } catch (error) { status.textContent = error.message; }
      };
      setTimeout(poll, 1000);
    } catch (error) { handleError(error); }
  }) : "—" }, { label: "الأصل المحجور", value: (row) => permission("samples.download") ? linkedButton("تنزيل ثنائي للمتخصص المصرح", `/api/cases/${caseId}/samples/${row.id}/download`) : "تنزيل الأصل مقيد بدور مستقل" }], samples.items));
  root.append(panel("العينات والتحليل الساكن", body, true));
  if (autopsy.current.can_update && autopsy.current.status !== "closed") {
    const choices = [...samples.items.map((sample) => ({ value: `sample_id:${sample.id}`, label: `عينة: ${sample.filename} · ${sample.sha256}` })), ...indicators.filter((item) => item.payload.type === "sha256").map((item) => ({ value: `indicator_id:${item.id}`, label: `مؤشر SHA-256: ${item.payload.value}` }))];
    const subject = autopsyChoice("subject", choices, "", true);
    const file = node("input", { name: "vt_report", type: "file", required: true, accept: ".json,application/json" });
    const form = node("form", { class: "form-grid panel-body" }, [node("p", { class: "span-2", text: "استيراد يدوي فقط لتقرير ملف VirusTotal v3. يجب أن يطابق SHA-256 لعينة أو مؤشر موجود في القضية؛ يحتفظ الأصل ببصمته ويعرض مصدره ووقته وحدود الثقة به. لا يوجد اتصال بـVirusTotal." }), field("العينة أو البصمة المعروفة", subject.control, true), field("تقرير JSON محفوظ محليًا", file), node("button", { type: "submit", class: "button primary", text: "استيراد نتيجة الفحص" })]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); try { const [key, value] = subject.input.autopsyValue().split(":"); const data = new FormData(); data.set(key, value); data.set("file", file.files[0]); await api(`/api/cases/${caseId}/reputation/virustotal`, { method: "POST", body: data }); await autopsyCase(caseId); } catch (error) { handleError(error); } });
    root.append(panel("نتائج VirusTotal المستوردة", form, true));
  }
  for (const kind of ["reputation", "analysis"]) {
    const records = await api(`/api/cases/${caseId}/records?kind=${kind}&limit=100`);
    root.append(panel(autopsyLabel(kind), node("div", { class: "record-grid" }, records.items.map(autopsyRecordCard)), true));
  }
  return root;
};
