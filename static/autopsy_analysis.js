"use strict";

function autopsyStaticVerdict(value) {
  const labels = { high_risk: "مؤشرات خطورة مرتفعة", suspicious: "يحتاج إلى مراجعة", low_signal_static_only: "لا مؤشرات بارزة في الفحص الساكن" };
  return SOCifyLocale.text(labels[value] || value);
}

function autopsyStaticFileType(value) {
  const labels = { pe_executable: "ملف Windows تنفيذي", dos_executable: "توقيع DOS تنفيذي", elf_executable: "ملف ELF تنفيذي", mach_o_executable: "ملف Mach-O تنفيذي", pdf: "مستند PDF", ole2_compound: "مستند OLE مركب", zip_container: "حاوية ZIP أو Office", rar_archive: "أرشيف RAR", "7z_archive": "أرشيف 7-Zip", gzip_archive: "أرشيف GZIP", rtf_document: "مستند RTF", lnk_shortcut: "اختصار Windows", html_document: "محتوى HTML", xml_document: "مستند XML", text_or_script: "نص أو برنامج نصي", unknown_binary: "نوع ثنائي غير معروف" };
  return SOCifyLocale.text(labels[value] || value || "لم يُحدد النوع");
}

function autopsyEmailView(mail, watch = () => null) {
  const t = SOCifyLocale.text;
  const body = node("div", { class: "panel-body email-result" });
  if (mail.email_verdict) body.append(node("p", { class: "notice", text: `${t("الحكم الساكن")}: ${autopsyStaticVerdict(mail.email_verdict)} · ${mail.email_risk_score || 0}/100` }));
  const summary = [];
  for (const [label, value] of [["المرسل", mail.sender_email || mail.headers?.From], ["عنوان الرد", mail.reply_to_email || mail.headers?.["Reply-To"]]]) {
    if (value) summary.push({ label: t(label), value: node("div", { class: "action-row" }, [node("bdi", { dir: "ltr", "data-user-content": "true", text: value }), watch("email", value, "Retained email address")]) });
  }
  if (summary.length) body.append(table([{ label: t("الحقل"), value: "label" }, { label: t("القيمة"), value: "value" }], summary));
  const flags = { reply_to_domain_mismatch: "نطاق الرد يختلف عن نطاق المرسل", return_path_domain_mismatch: "نطاق مسار العودة يختلف عن نطاق المرسل", auth_failure_claimed: "رأس المصادقة يذكر فشلًا؛ لم يُتحقق منه مستقلًا", urgent_lure_subject: "صياغة استعجال في عنوان الرسالة", suspicious_url_host: "رابط بعنوان IP مباشر أو نطاق Punycode" };
  if (mail.header_flags?.length) body.append(node("ul", { class: "email-findings" }, mail.header_flags.map(flag => node("li", { text: `${autopsyLabel(flag.severity)} · ${t(flags[flag.code] || flag.detail)}` }))));
  const headers = node("dl");
  for (const [key, value] of Object.entries(mail.headers || {})) if (value) headers.append(node("dt", { dir: "ltr", text: key }), node("dd", { "data-user-content": "true", text: value }));
  body.append(node("details", {}, [node("summary", { text: t("رؤوس الرسالة") }), headers, node("p", { dir: "ltr", class: "cell-meta", text: `SHA-256: ${mail.sha256}` })]));
  body.append(node("h4", { text: t("نص الرسالة") }), node("pre", { class: "email-body", tabindex: 0, "data-user-content": "true", text: mail.body || t("لا يوجد نص متاح") }));
  if (mail.body_truncated) body.append(node("p", { class: "notice", text: t("النص المعروض مختصر؛ الأصل محفوظ في الحجر.") }));
  if (mail.urls?.length) body.append(node("details", {}, [node("summary", { text: `${t("الروابط المرصودة")} · ${mail.urls.length}` }), node("ul", { class: "email-links" }, mail.urls.map(value => node("li", {}, [node("bdi", { dir: "ltr", "data-user-content": "true", text: value }), watch("url", value, "Retained email URL")])))]));
  if (mail.attachments?.length) body.append(table([
    { label: t("المرفق"), value: item => item.original_filename || item.filename },
    { label: t("النوع المعلن"), value: "content_type" },
    { label: t("الفحص الساكن (بدون تشغيل)"), value: item => item.triage ? `${autopsyStaticVerdict(item.triage.verdict)} (${item.triage.risk_score}/100) · ${autopsyStaticFileType(item.triage.detected_magic)}${item.triage.extension_mismatch ? " · " + t("تعارض امتداد") : ""}` : t("بصمة فقط") },
    { label: t("الحجم"), value: "size" },
    { label: "SHA-256", value: item => node("div", {}, [node("bdi", { dir: "ltr", text: item.sha256 }), watch("sha256", item.sha256, `Attachment ${item.original_filename || item.filename}`)]) },
  ], mail.attachments));
  return body;
}

window.SOCifyAutopsy.analysis = async (caseId) => {
  const samples = await api(`/api/cases/${caseId}/samples`);
  const indicators = (await api(`/api/cases/${caseId}/records?kind=indicator&limit=100`)).items;
  const root = node("div");
  const packs = await api("/api/autopsy/yara");
  const packChoice = autopsyChoice("yara_pack_id", [{ value: "", label: "EICAR" }, ...packs.items.map((pack) => ({ value: pack.id, label: `${pack.name} · v${pack.version} · ${pack.license}` }))]);
  const body = node("div", { class: "panel-body" });
  body.append(field("YARA", packChoice.control), linkedButton(SOCifyLocale.text("إدارة حزم YARA المحلية"), "/analysis-library"));
  if (permission("evidence.add") && autopsy.current.status !== "closed") {
    const file = node("input", { type: "file", required: true, name: "sample" });
    const quickBtn = button(SOCifyLocale.language === "ar" ? "فحص الملف" : "Inspect file", async () => {
      if (!file.files[0]) { handleError(new Error(SOCifyLocale.text("اختر ملفًا أولًا"))); return; }
      quickBtn.disabled = true;
      try {
        const data = new FormData();
        data.set("file", file.files[0]);
        const selected = packChoice.input.autopsyValue();
        if (selected) data.set("yara_pack_id", String(selected));
        const res = await api(`/api/cases/${caseId}/quick-file-triage`, { method: "POST", body: data });
        const t = res.triage;
        autopsyModal(SOCifyLocale.language === "ar" ? "نتيجة الفحص" : "Inspection result", node("div", {}, [
          node("p", { text: SOCifyLocale.template`الحكم الأولي: ${t.verdict} · درجة الخطورة: ${t.risk_score}/100 · البصمة الفعلية: ${t.file_type_observation}` }),
          node("p", { text: `SHA-256: ${t.sha256}` }),
          node("pre", { text: JSON.stringify({ flags: t.flags, urls: t.extracted_urls, ips: t.extracted_ips, emails: t.extracted_emails }, null, 2) }),
        ]));
        await autopsyCase(caseId);
      } catch (error) { handleError(error); }
      finally { quickBtn.disabled = false; }
    }, "primary");
    const form = node("form", { class: "filter-row" }, [
      field(SOCifyLocale.text("عينة للفحص المحلي"), file),
      quickBtn,
      node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("حجر العينة") }),
    ]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); try { const data = new FormData(); data.set("file", file.files[0]); await api(`/api/cases/${caseId}/samples`, { method: "POST", body: data }); await autopsyCase(caseId); } catch (error) { handleError(error); } });
    body.append(form);

    const emlFile = node("input", { type: "file", required: true, name: "eml_file", accept: ".eml,message/rfc822" });
    const emlForm = node("form", { class: "filter-row" }, [
      field(SOCifyLocale.language === "ar" ? "رسالة البريد (.eml)" : "Email (.eml)", emlFile),
      node("button", { type: "submit", class: "button primary", text: SOCifyLocale.language === "ar" ? "فحص البريد" : "Inspect email" }),
    ]);
    emlForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const data = new FormData();
        data.set("file", emlFile.files[0]);
        const res = await api(`/api/cases/${caseId}/email-triage`, { method: "POST", body: data });
        const p = res.payload;
        autopsyModal(SOCifyLocale.text("نتيجة فحص البريد والمرفقات (ساكن وآمن)"), autopsyEmailView(p));
        await autopsyCase(caseId);
      } catch (error) { handleError(error); }
    });
    body.append(emlForm);
  }
  body.append(table([{ label: SOCifyLocale.text("العينة"), value: "filename" }, { label: "SHA-256", value: (row) => node("bdi", { text: row.sha256 }) }, { label: SOCifyLocale.text("الحجم"), value: "size" }, { label: SOCifyLocale.text("فحص فوري"), value: (row) => autopsy.current.can_update && autopsy.current.status !== "closed" ? button(SOCifyLocale.text("فحص أولي فوري"), async () => {
    try {
      await api(`/api/cases/${caseId}/samples/${row.id}/quick-triage`, { method: "POST", body: {} });
      await autopsyCase(caseId);
    } catch (error) { handleError(error); }
  }, "primary") : "—" }, { label: SOCifyLocale.text("الفحص"), value: (row) => autopsy.current.can_update && autopsy.current.status !== "closed" ? button(SOCifyLocale.text("تحليل ساكن محلي"), async () => {
    try {
      const selected = packChoice.input.autopsyValue();
      const queued = await api(`/api/cases/${caseId}/samples/${row.id}/analyze`, { method: "POST", body: selected ? { yara_pack_id: Number(selected) } : {} });
      const status = node("p", { role: "status", text: SOCifyLocale.text("بانتظار التنفيذ") });
      const dialog = autopsyModal(SOCifyLocale.text("التحليل المحلي"), node("div", {}, [status, button(SOCifyLocale.text("تحديث النتيجة"), () => { dialog.close(); autopsyCase(caseId).catch(handleError); })]));
      let attempts = 0;
      const poll = async () => {
        if (!dialog.isConnected || ++attempts > 40) return;
        try { const job = await api(`/api/cases/${caseId}/jobs/${queued.id}`); status.textContent = `${job.state}${job.error_code ? ` · ${job.error_code}` : ""}`; if (["queued", "processing"].includes(job.state)) setTimeout(poll, 1500); else if (job.state === "completed") { dialog.close(); await autopsyCase(caseId); } } catch (error) { status.textContent = error.message; }
      };
      setTimeout(poll, 1000);
    } catch (error) { handleError(error); }
  }) : "—" }, { label: SOCifyLocale.text("الأصل المحجور"), value: (row) => permission("samples.download") ? linkedButton(SOCifyLocale.text("تنزيل ثنائي للمتخصص المصرح"), `/api/cases/${caseId}/samples/${row.id}/download`) : SOCifyLocale.text("تنزيل الأصل مقيد بدور مستقل") }], samples.items));
  root.append(panel(SOCifyLocale.text("العينات والتحليل الساكن"), body, true));
  if (autopsy.current.can_update && autopsy.current.status !== "closed") {
    const choices = [...samples.items.map((sample) => ({ value: `sample_id:${sample.id}`, label: SOCifyLocale.template`عينة: ${sample.filename} · ${sample.sha256}` })), ...indicators.filter((item) => item.payload.type === "sha256").map((item) => ({ value: `indicator_id:${item.id}`, label: SOCifyLocale.template`مؤشر SHA-256: ${item.payload.value}` }))];
    const subject = autopsyChoice("subject", choices, "", true);
    const file = node("input", { name: "vt_report", type: "file", required: true, accept: ".json,application/json" });
    const form = node("form", { class: "form-grid panel-body" }, [field(SOCifyLocale.text("العينة أو البصمة المعروفة"), subject.control, true), field(SOCifyLocale.text("تقرير JSON محفوظ محليًا"), file), node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("استيراد نتيجة الفحص") })]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); try { const [key, value] = subject.input.autopsyValue().split(":"); const data = new FormData(); data.set(key, value); data.set("file", file.files[0]); await api(`/api/cases/${caseId}/reputation/virustotal`, { method: "POST", body: data }); await autopsyCase(caseId); } catch (error) { handleError(error); } });
    if (choices.length) root.append(panel("VirusTotal", form, true));
  }
  for (const kind of ["reputation", "analysis"]) {
    const records = await api(`/api/cases/${caseId}/records?kind=${kind}&limit=100`);
    if (records.items.length) root.append(panel(autopsyLabel(kind), node("div", { class: "record-grid" }, records.items.map(autopsyRecordCard)), true));
  }
  return root;
};
