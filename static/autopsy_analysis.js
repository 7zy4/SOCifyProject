"use strict";

function autopsyReputationCard(record, sample = null) {
  const p = record.payload;
  const text = (ar, en) => SOCifyLocale.language === "ar" ? ar : en;
  const heading = text("نتيجة سمعة مستوردة", "Imported reputation assessment");
  const rows = node("tbody");
  const add = (label, value) => rows.append(node("tr", {}, [
    node("th", { scope: "row", text: label }),
    node("td", {}, typeof value === "string" ? node("span", { dir: "auto", text: value }) : value),
  ]));
  if (sample) add(SOCifyLocale.text("العينة"), node("bdi", { dir: "auto", "data-user-content": true, text: sample.filename }));
  add(text("بصمة العينة", "Sample SHA-256"), node("bdi", { dir: "ltr", text: p.sha256 }));
  add(SOCifyLocale.text("المصدر"), p.source);
  add(text("وقت الفحص في المصدر", "Source analysis time"), formatTime(p.examined_at));
  add(text("وقت الاستيراد", "Import time"), formatTime(p.imported_at));
  add(text("التحقق من المصدر", "Source verification"), text("تقرير مستورد غير متحقق", "Unverified imported report"));
  const categories = {
    malicious: text("أبلغ عن ضرر", "Reported malicious"),
    suspicious: text("أبلغ عن اشتباه", "Reported suspicious"),
    undetected: text("لم يكتشف", "Undetected"),
    harmless: text("صنّفه حميدًا", "Reported harmless"),
    "type-unsupported": text("نوع غير مدعوم", "Unsupported type"),
    timeout: text("انتهت المهلة", "Timeout"),
    "confirmed-timeout": text("انتهاء مهلة مؤكد", "Confirmed timeout"),
    failure: text("تعذر الفحص", "Scan failure"),
  };
  const counts = Object.entries(p.stats || {}).map(([key, count]) => ({ category: categories[key] || key, count }));
  for (const result of counts) add(`${text("المحركات", "Engines")} · ${result.category}`, String(result.count));
  add(text("بصمة التقرير الأصلي", "Original report SHA-256"), node("bdi", { dir: "ltr", text: p.source_sha256 }));
  const card = node("article", { class: "card record-card reputation-record" }, [
    node("h3", { text: heading }),
    node("table", { class: "alert-property-table", "aria-label": heading }, rows),
    node("p", { class: "notice", text: text("عدد الاكتشافات لا يثبت سلامة الملف أو تنفيذه.", "The detection count does not establish safety or execution.") }),
  ]);
  if (p.engines?.length) card.append(node("details", {}, [
    node("summary", { text: text("تفاصيل كل محرك", "Individual engine results") }),
    ...p.engines.map(engine => {
      const engineRows = [
        [text("المحرك", "Engine"), engine.engine],
        [text("التصنيف المبلّغ", "Reported classification"), categories[engine.category] || engine.category],
        [SOCifyLocale.text("النتيجة"), engine.result || "—"],
      ].map(([label, value]) => node("tr", {}, [node("th", { scope: "row", text: label }), node("td", { dir: "auto", text: value })]));
      return node("table", { class: "alert-property-table", "aria-label": engine.engine }, node("tbody", {}, engineRows));
    }),
  ]));
  if (p.evidence_id && permission("evidence.download")) card.append(linkedButton(SOCifyLocale.text("تنزيل الأصل"), `/api/incidents/${autopsy.current.id}/evidence/${p.evidence_id}/content`));
  return card;
}

function autopsyStaticVerdict(value) {
  const labels = { high_risk: "مؤشرات خطورة مرتفعة", suspicious: "يحتاج إلى مراجعة", low_signal_static_only: "لا مؤشرات بارزة في الفحص الساكن" };
  return SOCifyLocale.text(labels[value] || value);
}

function autopsyStaticFileType(value) {
  if(value === "ooxml_document")return SOCifyLocale.text("مستند Office");
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

function autopsySampleView(result) {
  const t=SOCifyLocale.text;
  const root=node("div",{class:"panel-body sample-result"});
  if(result.verdict)root.append(node("p",{class:"notice",text:`${autopsyStaticVerdict(result.verdict)} · ${result.risk_score}/100`}));
  const rows=[];
  const add=(label,value)=>{if(value!==null&&value!==undefined&&value!=="")rows.push({label:t(label),value});};
  add("الملف",result.filename);
  add("الحجم",`${Number(result.size||0).toLocaleString(SOCifyLocale.language)} ${t("بايت")}`);
  const observedTypes={"DOS signature; PE not yet verified":"dos_executable","PE header verified; content never executed":"pe_executable","ELF signature; content never executed":"elf_executable","ZIP-compatible container; not extracted or executed":"zip_container"};
  const detected=result.detected_magic||observedTypes[result.file_type_observation];
  add("النوع المكتشف",detected?autopsyStaticFileType(detected):t("نوع غير محدد"));
  add("الامتداد المعلن",result.declared_extension);
  add("النوع المعلن",result.declared_mime);
  add("SHA-256",node("bdi",{dir:"ltr",text:result.sha256}));
  root.append(table([{label:t("الحقل"),value:"label"},{label:t("القيمة"),value:"value"}],rows));
  const flags={filename_bidi_spoofing:"محارف اتجاه قد تخفي امتداد الملف",double_extension:"امتداد مزدوج مضلل",magic_extension_mismatch:"نوع الملف لا يطابق امتداده",executable_binary:"محتوى تنفيذي",zip_bomb_ratio_warning:"نسبة ضغط أو عدد ملفات مرتفع",vba_macro_detected:"وحدات ماكرو داخل المستند",archive_contains_executable_or_script:"ملفات تنفيذية أو سكربتات داخل الأرشيف",corrupt_zip_container:"أرشيف تالف أو مشفر",pdf_active_content:"محتوى نشط داخل PDF",rtf_embedded_object:"كائن مضمّن داخل RTF",html_smuggling_indicator:"مؤشرات بناء ملف من محتوى HTML",suspicious_execution_strings:"سلاسل مرتبطة بالتنفيذ أو الحقن",high_entropy_packed_or_encrypted:"محتوى قد يكون مضغوطًا أو مشفرًا",high_window_entropy_embedded_blob:"كتلة بيانات عالية العشوائية داخل النص",yara_rule_match:"تطابق مع قواعد الفحص"};
  if(result.flags?.length)root.append(table([{label:t("الخطورة"),value:flag=>autopsyLabel(flag.severity)},{label:t("النتيجة"),value:flag=>t(flags[flag.code]||flag.detail)}],result.flags));
  root.append(node("h4",{text:"YARA"}),node("p",{text:result.yara_pack?.name||"EICAR"}));
  root.append(result.yara_matches?.length ? node("ul",{},result.yara_matches.map(match=>node("li",{text:match.rule}))) : node("p",{text:t("لا تطابقات مع القواعد المختارة")}));
  for(const [key,label] of [["extracted_urls","الروابط المرصودة"],["extracted_ips","عناوين IP"],["extracted_emails","عناوين البريد"]]) {
    if(!result[key]?.length)continue;
    const values=result[key].map(value=>node("li",{},node("bdi",{dir:"ltr",text:value})));
    root.append(node("details",{},[node("summary",{text:t(label)}),node("ul",{class:"sample-observables"},values)]));
  }
  if(result.archive_summary?.sample_entries?.length)root.append(node("details",{},[node("summary",{text:t("محتويات الأرشيف")}),node("ul",{},result.archive_summary.sample_entries.map(value=>node("li",{text:value})))]));
  if(result.printable_strings_first_100?.length)root.append(node("details",{},[node("summary",{text:t("النصوص المستخرجة")}),node("pre",{class:"sample-strings",tabindex:0,text:result.printable_strings_first_100.join("\n")})]));
  return root;
}

function autopsySampleJob(caseId, initial) {
  const t=SOCifyLocale.text;
  const root=node("div",{class:"sample-job"});
  let signature=null;
  let timer;
  async function refresh() {
    if(!root.isConnected)return;
    try{render(await api(`/api/cases/${caseId}/jobs/${initial.id}`));}
    catch(error){root.replaceChildren(node("p",{role:"status",text:error.message}),button(t("تحديث النتيجة"),refresh));}
  }
  function render(job) {
    clearTimeout(timer);
    const next=JSON.stringify(job);
    if(next!==signature) {
      signature=next;
      const labels={queued:"بانتظار المعالجة",processing:"تجري المعالجة",completed:"اكتمل التحليل",failed:"تعذرت المعالجة",cancelled:"أُلغيت المعالجة"};
      root.replaceChildren(node("p",{class:"sample-job-state",role:"status",text:t(labels[job.state]||"غير متاحة")}));
      if(job.error_code&&!["completed","cancelled"].includes(job.state))root.append(node("p",{class:"notice",text:t(job.state==="queued"?"التحليل متوقف مؤقتًا. ستتم إعادة المحاولة تلقائيًا.":job.error_code==="ACCESS_REVOKED"?"تغيرت صلاحيات التحليل أو أُغلقت القضية.":"تعذر إكمال التحليل. العينة محفوظة.")}));
      if(job.state==="failed"&&job.attempts>=3)root.append(node("p",{text:t("انتهت محاولات التحليل. يمكنك طلب فحص جديد لاحقًا.")}));
      const action=(label,route)=>button(t(label),async()=>{await api(`/api/cases/${caseId}/jobs/${job.id}/${route}`,{method:"POST",body:{}});await refresh();});
      if(job.can_cancel)root.append(action("إلغاء المعالجة","cancel"));
      if(job.can_retry)root.append(action("إعادة المحاولة","retry"));
      if(job.state==="completed"&&job.result_record_id)root.append(button(t("عرض النتيجة"),async()=>{
        const records=await api(`/api/cases/${caseId}/records?kind=analysis&limit=1&before=${job.result_record_id+1}`);
        const record=records.items.find(item=>item.id===job.result_record_id);
        if(record){root.closest("dialog")?.close();autopsyModal(t("نتيجة الفحص"),autopsySampleView(record.payload));}
      }));
    }
    if(["queued","processing"].includes(job.state))timer=setTimeout(refresh,1500);
  }
  render(initial);
  return root;
}

window.SOCifyAutopsy.analysis = async (caseId) => {
  const samples = await api(`/api/cases/${caseId}/samples`);
  const indicators = (await api(`/api/cases/${caseId}/records?kind=indicator&limit=100`)).items;
  const root = node("div");
  const jobViews=new Map();
  const packs = await api("/api/autopsy/yara");
  const selectedPack=new URLSearchParams(location.search).get("yara_pack")||"";
  const packChoice = autopsyChoice("yara_pack_id", [{ value: "", label: "EICAR" }, ...packs.items.map((pack) => ({ value: pack.id, label: packs.items.filter(other=>other.name===pack.name).length>1?`${pack.name} · ${pack.sha256.slice(0,8)}`:pack.name }))], selectedPack);
  if(selectedPack&&!packs.items.some(pack=>String(pack.id)===selectedPack))packChoice.input.value=SOCifyLocale.text("الحزمة المختارة غير متاحة");
  packChoice.input.addEventListener("change",()=>{
    try{
      const value=packChoice.input.autopsyValue();
      const address=new URL(location.href);
      if(value)address.searchParams.set("yara_pack",String(value));else address.searchParams.delete("yara_pack");
      history.replaceState(history.state,"",address.pathname+address.search);
    }catch(_){ /* The field keeps an unrecognized choice for correction. */ }
  });
  const body = node("div", { class: "panel-body" });
  body.append(field("YARA", packChoice.control), linkedButton(SOCifyLocale.text("إدارة حزم YARA المحلية"), "/analysis-library"));
  if (permission("evidence.add") && autopsy.current.status !== "closed") {
    const file = node("input", { type: "file", required: true, name: "sample" });
    const errors=node("p",{role:"alert",class:"notice",hidden:true});
    const showError=error=>{errors.textContent=error.message;errors.hidden=false;};
    const quickBtn = button(SOCifyLocale.language === "ar" ? "فحص الملف" : "Inspect file", async () => {
      errors.hidden=true;
      if (!file.files[0]) { showError(new Error(SOCifyLocale.text("اختر ملفًا أولًا"))); return; }
      if(!file.files[0].size||file.files[0].size>10*1024*1024){showError(new Error(SOCifyLocale.text("اختر ملفًا غير فارغ لا يتجاوز 10 MiB")));return;}
      quickBtn.disabled = true;
      try {
        const data = new FormData();
        data.set("file", file.files[0]);
        const selected = packChoice.input.autopsyValue();
        if (selected) data.set("yara_pack_id", String(selected));
        const res = await api(`/api/cases/${caseId}/quick-file-triage`, { method: "POST", body: data });
        autopsyModal(SOCifyLocale.text("نتيجة الفحص"), autopsySampleView(res.triage));
        await autopsyCase(caseId);
      } catch (error) { showError(error); }
      finally { quickBtn.disabled = false; }
    }, "primary");
    const form = node("form", { class: "filter-row sample-upload" }, [
      field(SOCifyLocale.text("عينة للفحص المحلي"), file),
      quickBtn,
      node("button", { type: "submit", class: "button ghost", text: SOCifyLocale.text("حجر العينة") }),
      errors,
    ]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); errors.hidden=true; try { const data = new FormData(); data.set("file", file.files[0]); await api(`/api/cases/${caseId}/samples`, { method: "POST", body: data }); await autopsyCase(caseId); } catch (error) { showError(error); } });
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
  body.append(table([{ label: SOCifyLocale.text("العينة"), value: row=>{
    const progress=node("div",{},row.last_job?autopsySampleJob(caseId,row.last_job):null);
    jobViews.set(row.id,progress);
    return node("div",{class:"sample-identity"},[node("bdi",{dir:"auto",text:row.filename}),progress]);
  } }, { label: "SHA-256", value: (row) => node("bdi", { text: row.sha256 }) }, { label: SOCifyLocale.text("الحجم"), value: "size" }, { label: SOCifyLocale.text("فحص فوري"), value: (row) => autopsy.current.can_update && autopsy.current.status !=="closed" ? button(SOCifyLocale.text("فحص أولي فوري"), async () => {
    try {
      const selected=packChoice.input.autopsyValue();
      const res=await api(`/api/cases/${caseId}/samples/${row.id}/quick-triage`, { method: "POST", body: selected?{yara_pack_id:Number(selected)}:{} });
      await autopsyCase(caseId);
      autopsyModal(SOCifyLocale.text("نتيجة الفحص"),autopsySampleView(res.triage));
    } catch (error) { handleError(error); }
  }, "primary") : "—" }, { label: SOCifyLocale.text("الفحص"), value: (row) => autopsy.current.can_update && autopsy.current.status !== "closed" ? button(SOCifyLocale.text("تحليل ساكن محلي"), async () => {
    try {
      const selected = packChoice.input.autopsyValue();
      const queued = await api(`/api/cases/${caseId}/samples/${row.id}/analyze`, { method: "POST", body: selected ? { yara_pack_id: Number(selected) } : {} });
      const job=await api(`/api/cases/${caseId}/jobs/${queued.id}`);
      jobViews.get(row.id)?.replaceChildren(autopsySampleJob(caseId,job));
      autopsyModal(SOCifyLocale.text("التحليل المحلي"),autopsySampleJob(caseId,job));
    } catch (error) { handleError(error); }
  }) : "—" }, { label: SOCifyLocale.text("الأصل المحجور"), value: (row) => permission("samples.download") ? linkedButton(SOCifyLocale.text("تنزيل ثنائي للمتخصص المصرح"), `/api/cases/${caseId}/samples/${row.id}/download`) : SOCifyLocale.text("تنزيل الأصل مقيد بدور مستقل") }], samples.items));
  root.append(panel(SOCifyLocale.text("العينات والتحليل الساكن"), body, true));
  if (autopsy.current.can_update && autopsy.current.status !== "closed") {
    const choices = [...samples.items.map((sample) => ({ value: `sample_id:${sample.id}`, label: SOCifyLocale.template`عينة: ${sample.filename} · ${sample.sha256}` })), ...indicators.filter((item) => item.payload.type === "sha256").map((item) => ({ value: `indicator_id:${item.id}`, label: SOCifyLocale.template`مؤشر SHA-256: ${item.payload.value}` }))];
    const subject = autopsyChoice("subject", choices, "", true);
    const file = node("input", { name: "vt_report", type: "file", required: true, accept: ".json,application/json" });
    const error = node("p", { class: "notice span-2 reputation-import-error", role: "alert", hidden: true });
    const submit = node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("استيراد نتيجة الفحص") });
    const form = node("form", { class: "form-grid panel-body" }, [field(SOCifyLocale.text("العينة أو البصمة المعروفة"), subject.control, true), field(SOCifyLocale.text("تقرير JSON محفوظ محليًا"), file), submit, error]);
    let committed = false;
    let submittedLocation = null;
    const sameLocation = () => `${location.pathname}${location.search}` === submittedLocation;
    const saved = node("p", { role: "status", class: "notice span-2 reputation-import-saved", hidden: true });
    const retry = button(SOCifyLocale.text("إعادة المحاولة"), refresh);
    retry.hidden = true;
    form.append(saved, retry);
    async function refresh() {
      if (!sameLocation()) return;
      retry.disabled = true;
      saved.hidden = false;
      saved.textContent = SOCifyLocale.language === "ar" ? "تم حفظ النتيجة" : "Result saved";
      const previous = workspace.firstElementChild;
      try { await autopsyCase(caseId, { refresh: true }); }
      catch (_) {
        if (!sameLocation()) return;
        // A tool view may replace its workspace while refreshing. Retain the saved form and its GET-only recovery.
        if (!form.isConnected && previous) finish(previous);
        saved.textContent = SOCifyLocale.language === "ar" ? "تم حفظ النتيجة؛ تعذر تحديث العرض" : "Result saved; the view could not be refreshed";
        retry.hidden = false;
      } finally { retry.disabled = false; }
    }
    form.addEventListener("input", () => { error.hidden = true; });
    form.addEventListener("change", () => { error.hidden = true; });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (committed || submit.disabled) return;
      error.hidden = true;
      const frozen = [...form.querySelectorAll("input,button")].filter(control => !control.disabled);
      try {
        const [key, value] = subject.input.autopsyValue().split(":");
        const data = new FormData(); data.set(key, value); data.set("file", file.files[0]);
        submittedLocation = `${location.pathname}${location.search}`;
        frozen.forEach(control => { control.disabled = true; });
        await api(`/api/cases/${caseId}/reputation/virustotal`, { method: "POST", body: data });
        committed = true;
        await refresh();
      } catch (failure) { error.textContent = failure.message; error.hidden = false; }
      finally { if (!committed) frozen.forEach(control => { control.disabled = false; }); }
    });
    if (choices.length) root.append(panel("VirusTotal", form, true));
  }
  for (const kind of ["reputation", "analysis"]) {
    const records = await api(`/api/cases/${caseId}/records?kind=${kind}&limit=100`);
    if (records.items.length) root.append(panel(autopsyLabel(kind), node("div", { class: "record-grid" }, records.items.map(record => kind === "reputation" ? autopsyReputationCard(record, samples.items.find(sample => sample.id === record.payload.sample_id)) : autopsyRecordCard(record))), true));
  }
  return root;
};
