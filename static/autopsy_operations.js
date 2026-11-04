"use strict";

function autopsyAction(label, action, style = "ghost") {
  const control = button(label, async () => {
    control.disabled = true;
    try { await action(); } catch (error) { handleError(error); }
    finally { control.disabled = false; }
  }, style);
  return control;
}

async function autopsyReadJSON(input, maximum = 2 * 1024 * 1024) {
  const file = input.files?.[0];
  if (!file || file.size > maximum) throw new Error(SOCifyLocale.text("اختر ملف JSON محليًا ضمن حد الحجم المعلن"));
  return JSON.parse(await file.text());
}

function autopsyIntelligenceVerdict(value) {
  return SOCifyLocale.text({ malicious: "خبيث", benign: "حميد", suspicious: "مشتبه", unknown: "غير معروف" }[value] || "غير معروف");
}

function autopsyIntelligenceStatus(value) {
  return SOCifyLocale.text({ matched: "تطابق مع المصادر", no_match: "لا يوجد تطابق", not_configured: "لا توجد مصادر مفعلة" }[value] || "غير معروف");
}

function autopsyEnrichmentDetails(result) {
  const t = SOCifyLocale.text;
  const value = item => node("bdi", { dir: "auto", "data-user-content": "true", text: item ?? "—" });
  const facts = (caption, rows) => node("table", { class: "alert-property-table" }, [node("caption", { text: caption }), node("tbody", {}, rows.map(([label, item]) => node("tr", {}, [node("th", { scope: "row", text: label }), node("td", {}, value(item))])))]);
  const confidence = item => item === null || item === undefined ? "—" : new Intl.NumberFormat(SOCifyLocale.language, { style: "percent" }).format(item / 100);
  const matches = result.matches || [];
  const root = node("div", { class: "enrichment-detail" }, facts(t("نتيجة الفحص"), [
    [t("المؤشر"), result.value], [t("الحالة"), autopsyIntelligenceStatus(result.status)],
    [t("تصنيف المصدر"), autopsyIntelligenceVerdict(result.verdict)], [t("الثقة"), confidence(result.confidence)],
    [t("وقت الفحص"), result.checked_at ? formatTime(result.checked_at) : "—"]
  ]));
  if (new Set(matches.map(item => item.verdict).filter(item => item !== "unknown")).size > 1) root.append(node("p", { class: "notice", text: t("نتائج متعارضة") }));
  for (const match of matches) {
    const rows = [[t("المصدر"), match.source], [t("المؤشر"), match.value], [t("تصنيف المصدر"), autopsyIntelligenceVerdict(match.verdict)], [t("الثقة"), confidence(match.confidence)], [t("الرخصة وحق الاستخدام"), match.license]];
    if (match.country) rows.push([t("الدولة"), match.country]);
    if (match.asn) rows.push(["ASN", match.asn]);
    if (match.valid_from) rows.push([t("بدء صلاحية المؤشر"), formatTime(match.valid_from)]);
    if (match.valid_until) rows.push([t("انتهاء صلاحية المؤشر"), formatTime(match.valid_until)]);
    if (match.expires_at) rows.push([t("انتهاء صلاحية المصدر"), formatTime(match.expires_at)]);
    if (match.notes) rows.push([t("ملاحظة"), match.notes]);
    root.append(facts(match.name, rows));
    if (match.sha256) root.append(node("details", {}, [node("summary", { text: t("بصمة المصدر") }), node("p", {}, value(match.sha256))]));
  }
  if (result.matches_truncated) root.append(node("p", { class: "notice", text: t("تُعرض أول 100 نتيجة مطابقة") }));
  return root;
}

Object.assign(autopsyLabels, { source: SOCifyLocale.text("المصدر"), license: SOCifyLocale.text("الرخصة وحق الاستخدام"), version: SOCifyLocale.text("الإصدار"), format: SOCifyLocale.text("الصيغة"), minutes: SOCifyLocale.text("ميزانية SLA بالدقائق"), mode: SOCifyLocale.text("تقويم الاحتساب"), timezone: SOCifyLocale.text("المنطقة الزمنية"), start_hour: SOCifyLocale.text("ساعة بدء العمل"), end_hour: SOCifyLocale.text("ساعة انتهاء العمل"), weekdays: SOCifyLocale.text("أيام العمل"), mon_fri: SOCifyLocale.text("الاثنين إلى الجمعة"), sun_thu: SOCifyLocale.text("الأحد إلى الخميس"), "24x7": SOCifyLocale.text("كل ساعات الأسبوع"), business: SOCifyLocale.text("ساعات العمل"), recipe_id: SOCifyLocale.text("وصفة الجمع"), collector_id: SOCifyLocale.text("الجامع المخول"), tool: SOCifyLocale.text("أداة الجمع وإصدارها"), collected_at: SOCifyLocale.text("وقت الجمع"), executive_summary: SOCifyLocale.text("الملخص التنفيذي المراجع"), lessons: SOCifyLocale.text("الدروس والتوصيات"), override_reason: SOCifyLocale.text("سبب استثناء المراجعة المستقلة للمدير"), unverified: SOCifyLocale.text("لم يُتحقق منه"), group: SOCifyLocale.text("مجموعة التنبيهات"), suppressed_until: SOCifyLocale.text("إخفاء الإشعار حتى") });

function autopsySigmaSummary(compiled, fixtures, caption = SOCifyLocale.text("نتيجة اختبار القاعدة")) {
  const t = SOCifyLocale.text;
  const value = item => node("bdi", { dir: "auto", "data-user-content": "true", text: String(item) });
  const operators = { equals: "يساوي", contains: "يحتوي على", starts_with: "يبدأ بـ", ends_with: "ينتهي بـ", cidr: "ضمن الشبكة", exists: "وجود الحقل" };
  const condition = item => {
    if (item.logic) return node("div", {}, [node("strong", { text: t({ and: "جميع الشروط", or: "أحد الشروط", not: "استبعاد الشرط" }[item.logic]) }), node("ul", {}, item.conditions.map(child => node("li", {}, condition(child))))]);
    return node("div", {}, [node("strong", { text: autopsyLabel(item.field) }), document.createTextNode(` ${t(operators[item.operator] || item.operator)} `), value(typeof item.value === "boolean" ? t(item.value ? "نعم" : "لا") : item.value)]);
  };
  const source = compiled.logsource.category === "socify_normalized" ? t("سجلات القضية") : compiled.logsource.service === "sysmon" ? "Windows Sysmon" : "Linux auth";
  const rows = [[t("الاسم"), value(compiled.title)], [t("الخطورة"), value(autopsyLabel(compiled.level))], [t("المصدر"), value(source)], [t("شروط المطابقة"), condition(compiled.dsl.condition)]];
  if (fixtures) rows.push([t("أمثلة مطابقة اجتازت الاختبار"), value(fixtures.positive.length)], [t("أمثلة غير مطابقة اجتازت الاختبار"), value(fixtures.negative.length)]);
  if (compiled.dsl.mitre_ids.length) rows.push(["MITRE ATT&CK", value(compiled.dsl.mitre_ids.join(" · "))]);
  return node("div", { class: "sigma-summary" }, node("table", { class: "alert-property-table" }, [node("caption", { text: caption }), node("tbody", {}, rows.map(([label, content]) => node("tr", {}, [node("th", { scope: "row", text: label }), node("td", {}, content)])))]));
}

autopsyLabels.rule_id = SOCifyLocale.text("القاعدة المنشورة");
autopsyLabels.origin = SOCifyLocale.text("المصدر");
let autopsyLibraryRequest = 0, autopsyLibraryRendered = 0;

window.SOCifyAutopsy.library = async ({ refresh = false, savedForm = null } = {}) => {
  const request = ++autopsyLibraryRequest;
  if (!refresh) begin("analysis-library");
  const root = node("div", {}, pageHead(SOCifyLocale.text("مكتبة التحليل المحلي"), null));
  const bundles = await api("/api/autopsy/intelligence");
  root.append(panel(SOCifyLocale.text("إصدارات مصادر TI وGeoIP"), table([{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("الإصدار"), value: "version" }, { label: SOCifyLocale.text("المصدر والرخصة"), value: (row) => `${row.source} · ${row.license}` }, { label: SOCifyLocale.text("المؤشرات"), value: "entries" }, { label: SOCifyLocale.text("الصلاحية"), value: (row) => formatTime(row.expires_at) }, { label: SOCifyLocale.text("التفعيل"), value: (row) => row.active ? SOCifyLocale.text("الإصدار المختار") : permission("intel.manage") ? autopsyAction(SOCifyLocale.text("تفعيل الإصدار"), async () => { await api(`/api/autopsy/intelligence/${row.id}/activate`, { method: "POST", body: {} }); await window.SOCifyAutopsy.library({ refresh: true }); }) : SOCifyLocale.text("غير مختار") }], bundles.items), true));
  if (permission("intel.manage")) {
    const file = node("input", { type: "file", accept: ".json,application/json", required: true, "aria-label": SOCifyLocale.text("حزمة TI المحلية") });
    const form = autopsyForm({ name: { required: true, max: 160 }, version: { required: true, max: 80 }, source: { required: true, max: 500 }, license: { required: true, max: 500 }, expires_at: { required: true, timestamp: true }, format: { required: true, choices: bundles.formats } }, async (body) => {
      const intent = await autopsyWriteIntent("intel-import", { ...body, content: await autopsyReadJSON(file) }, { preserveBaseVersion: false });
      await api("/api/autopsy/intelligence", { method: "POST", headers: { "Idempotency-Key": intent.key }, body: intent.body });
      try { await window.SOCifyAutopsy.library({ refresh: true, savedForm: form }); }
      catch (_) { throw new Error(SOCifyLocale.text("حُفظ المصدر. تعذر تحديث القائمة؛ أعد المحاولة.")); }
      intent.acknowledged();
    });
    form.dataset.libraryForm = "intelligence";
    form.prepend(field(SOCifyLocale.text("ملف JSON محلي · حتى 2 MiB"), file));
    root.append(panel(SOCifyLocale.text("استيراد إصدار محلي جديد"), node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("flat: قائمة type/value/verdict/confidence؛ geoip: CIDR مع country أو asn. STIX يدعم مساواة مؤشر مفرد، وMISP Attribute بأنواع معلنة. يلزم التفعيل بعد الاستيراد؛ لا تتضمن المنصة قاعدة سمعة مرخصة جاهزة.") }), form]), true));
  }
  if (permission("rules.manage")) {
    const rules = await api("/api/autopsy/sigma/rules");
    root.append(panel(SOCifyLocale.text("قواعد Sigma المنشورة"), table([{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("الوصف"), value: row => row.description || "—" }, { label: SOCifyLocale.text("الحالة"), value: row => SOCifyLocale.text(row.is_active ? "مفعّلة" : "غير مفعّلة") }], rules.items), true));
    const source = node("input", { type: "file", accept: ".yml,.yaml,text/yaml", required: true, "aria-label": SOCifyLocale.text("ملف Sigma") });
    const fixtures = node("input", { type: "file", accept: ".json,application/json", required: true, "aria-label": SOCifyLocale.text("اختبارات القاعدة") });
    const preview = node("div", { "aria-live": "polite", class: "span-2 sigma-preview" });
    const previewError = node("p", { class: "notice span-2", role: "alert", hidden: true });
    const currentPreview = node("div", { class: "span-2" });
    let revision = 0;
    const rule = autopsyChoice("rule_id", rules.items.map((item) => ({ value: item.id, label: item.name })));
    const invalidate = () => { revision += 1; preview.replaceChildren(); previewError.hidden = true; previewError.textContent = ""; };
    source.addEventListener("change", invalidate);
    fixtures.addEventListener("change", invalidate);
    rule.input.addEventListener("input", () => { invalidate(); currentPreview.replaceChildren(); refresh.hidden = true; });
    const compile = async () => {
      if (!source.files[0] || source.files[0].size > 65536) throw new Error(SOCifyLocale.text("ملف Sigma مطلوب وبحد 64 KiB"));
      const selectedSource = source.files[0];
      const selectedFixtures = fixtures.files[0];
      if (!selectedFixtures || selectedFixtures.size > 512 * 1024) throw new Error(SOCifyLocale.text("ملف اختبارات القاعدة مطلوب وبحد 512 KiB"));
      try { return { source: await selectedSource.text(), fixtures: JSON.parse(await selectedFixtures.text()) }; }
      catch (error) { if (error instanceof SyntaxError) throw new Error(SOCifyLocale.text("ملف اختبارات القاعدة ليس JSON صالحًا")); throw error; }
    };
    const form = autopsyForm({ reason: { required: true, max: 1000 } }, async (body) => {
      const controls = [...form.querySelectorAll("input,button")].filter(control => !control.disabled);
      controls.forEach(control => { control.disabled = true; });
      let intent;
      try {
        const id = rule.input.autopsyValue();
        const current = rules.items.find((item) => item.id === id);
        const input = await compile();
        const payload = { ...body, ...input, ...(current ? { rule_id: id, version: current.version } : {}) };
        intent = await autopsyWriteIntent("sigma", payload);
        await api("/api/autopsy/sigma/publish", { method: "POST", headers: { "Idempotency-Key": intent.key }, body: intent.body });
        try { await window.SOCifyAutopsy.library({ refresh: true, savedForm: form }); }
        catch (_) { throw new Error(SOCifyLocale.text("حُفظت القاعدة. تعذر تحديث القائمة؛ أعد المحاولة.")); }
        intent.acknowledged();
      } catch (error) { if (error.code === "RULE_VERSION_CONFLICT") { intent?.acknowledged(); invalidate(); refresh.hidden = false; } throw error; }
      finally { controls.forEach(control => { control.disabled = false; }); }
    });
    const refresh = autopsyAction(SOCifyLocale.text("تحميل القاعدة الحالية"), async () => {
      const id = rule.input.autopsyValue();
      const selectedRevision = revision;
      const latest = await api("/api/autopsy/sigma/rules");
      const current = latest.items.find(item => item.id === id);
      if (!current) throw new Error(SOCifyLocale.text("القاعدة غير متاحة"));
      const result = await api("/api/autopsy/sigma/compile", { method: "POST", body: { source: current.source, fixtures: current.fixtures } });
      if (selectedRevision !== revision) return;
      rules.items = latest.items;
      invalidate();
      currentPreview.replaceChildren(autopsySigmaSummary(result.compiled, null, SOCifyLocale.text("القاعدة المنشورة حاليًا")));
      form.querySelector('[role="alert"]').hidden = true;
      refresh.hidden = true;
    });
    refresh.hidden = true;
    form.dataset.libraryForm = "sigma";
    form.prepend(field(SOCifyLocale.text("مصدر Sigma"), source), field(SOCifyLocale.text("اختبارات القاعدة · JSON"), fixtures), field(SOCifyLocale.text("تحديث قاعدة منشورة · اختياري"), rule.control));
    form.append(autopsyAction(SOCifyLocale.text("تحقق من الترجمة والاختبارات دون نشر"), async () => {
      invalidate();
      const selectedRevision = revision;
      try {
        const input = await compile();
        const result = await api("/api/autopsy/sigma/compile", { method: "POST", body: input });
        if (selectedRevision === revision) preview.replaceChildren(node("p", { text: SOCifyLocale.text("اجتازت الأمثلة الإيجابية والسلبية. التحقق لا يثبت تغطية جميع التهديدات.") }), autopsySigmaSummary(result.compiled, input.fixtures));
      } catch (error) { if (selectedRevision === revision) { previewError.textContent = error.message; previewError.hidden = false; } }
    }), refresh, previewError, currentPreview, preview);
    root.append(panel(SOCifyLocale.text("اختبار قاعدة ونشرها"), node("div", { class: "panel-body" }, form), true));
  }
  const yara = await api("/api/autopsy/yara");
  const yaraBody = node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("حزم محلية ثابتة بإصدارات ورخص وبصمات. تنشر بعد تجميع معزول ونجاح أمثلة إيجابية وسلبية؛ لا تنزيل أو تحديث خارجي. لا يثبت غياب التطابق سلامة العينة.") }), table([{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("الإصدار"), value: "version" }, { label: SOCifyLocale.text("المصدر والرخصة"), value: (row) => `${row.origin} · ${row.license}` }, { label: "SHA-256", value: "sha256" }], yara.items)]);
  if (permission("rules.manage")) {
    const packFile = node("input", { type: "file", accept: ".yar,.yara,text/plain", required: true, "aria-label": SOCifyLocale.text("ملف قواعد YARA") });
    const fixtureFile = node("input", { type: "file", accept: ".json,application/json", required: true, "aria-label": SOCifyLocale.text("أمثلة YARA الاصطناعية") });
    const form = autopsyForm({ name: { required: true, max: 120 }, version: { required: true, integer: true, min: 1, max: 1000000 }, origin: { required: true, max: 1000 }, license: { required: true, max: 500 } }, async (body) => { if (!packFile.files[0] || packFile.files[0].size > 65536) throw new Error(SOCifyLocale.text("ملف YARA مطلوب بحد 64 KiB")); await api("/api/autopsy/yara", { method: "POST", body: { ...body, source: await packFile.files[0].text(), fixtures: await autopsyReadJSON(fixtureFile, 768 * 1024) } }); await window.SOCifyAutopsy.library({ refresh: true, savedForm: form }); });
    form.dataset.libraryForm = "yara";
    form.prepend(field(SOCifyLocale.text("قواعد YARA محلية · حتى 64 KiB"), packFile), field(SOCifyLocale.text("fixtures JSON: positive وnegative، كل قائمة عينات base64 اصطناعية"), fixtureFile));
    yaraBody.append(form);
  }
  root.append(panel(SOCifyLocale.text("حزم YARA المحلية"), yaraBody, true));
  if (permission("cases.create") && permission("evidence.add")) {
    const file = node("input", { type: "file", accept: ".zip,application/zip", required: true, "aria-label": SOCifyLocale.text("حزمة قضية محلية") });
    const errors = node("p", { class: "notice span-2", role: "alert", hidden: true });
    const form = node("form", { class: "form-grid" }, [field(SOCifyLocale.text("حزمة ZIP محلية · حتى 64 MiB موسعة"), file), errors, node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("استعادة كقضية جديدة") })]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); const control = form.querySelector("button"); control.disabled = true; errors.hidden = true; try { if (!file.files[0] || file.files[0].size > 64 * 1024 * 1024 + 524288) throw new Error(SOCifyLocale.text("حجم الحزمة يتجاوز الحد")); const body = new FormData(); body.set("file", file.files[0]); const result = await api("/api/cases/import-capsule", { method: "POST", body }); window.location.assign(`/cases/${result.case_id}?tab=reports`); } catch (error) { errors.textContent = error.message; errors.hidden = false; control.disabled = false; } });
    form.dataset.libraryForm = "capsule";
    root.append(panel(SOCifyLocale.text("استعادة حزمة قضية"), node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("تُفحص البصمات والمسارات والحدود قبل الاستعادة. تحفظ إفادات واعتمادات المالك السابق في أرشيف ثابت للمراجعة ولا تمنح صلاحية أو اعتمادًا محليًا تلقائيًا.") }), form]), true));
  }
  if (request < autopsyLibraryRendered) {
    // A later completed refresh owns the lists. Finish only this saved form,
    // if that exact form survived while its refresh was pending.
    if (savedForm?.isConnected) {
      const replacement = root.querySelector(`form[data-library-form="${savedForm.dataset.libraryForm}"]`);
      if (replacement) savedForm.replaceWith(replacement);
    }
    return;
  }
  const active = document.activeElement;
  let retainedFocus = false;
  if (refresh) {
    for (const form of document.querySelectorAll("#workspace form[data-library-form]")) {
      if (form === savedForm || (!SOCifyDrafts.hasChanges(form) && form.dataset.saving !== "true")) continue;
      const replacement = root.querySelector(`form[data-library-form="${form.dataset.libraryForm}"]`);
      if (!replacement) continue;
      retainedFocus ||= form.contains(active);
      replacement.replaceWith(form);
    }
  }
  finish(root);
  autopsyLibraryRendered = request;
  if (retainedFocus && active?.isConnected) active.focus({ preventScroll: true });
};

function autopsyDetectionState(value) {
  return SOCifyLocale.text({ queued: "بانتظار المعالجة", processing: "تجري المعالجة", completed: "اكتمل التحليل", failed: "تعذرت المعالجة", cancelled: "أُلغيت المعالجة" }[value] || "غير متاحة");
}

function autopsyDetectionMode(value) {
  return SOCifyLocale.text(value === "anomaly" ? "مقارنة بالسجلات السابقة" : "فحص القواعد");
}

function autopsyDetectionFacts(caption, rows) {
  return node("table", { class: "alert-property-table" }, [node("caption", { text: caption }), node("tbody", {}, rows.map(([label, value]) => node("tr", {}, [node("th", { scope: "row", text: label }), node("td", {}, value instanceof Node ? value : node("bdi", { dir: "auto", text: value ?? "—" }))])))]);
}

async function autopsyQueueDetection(caseId, mode, after = 0, changed = () => {}) {
  const current = await api(`/api/cases/${caseId}`);
  const initial = await api(`/api/cases/${caseId}/detection`, { method: "POST", body: { version: current.version, mode, after_id: after } });
  autopsyModal(SOCifyLocale.text("حالة فحص السجلات"), autopsyDetectionJob(caseId, initial, changed));
  await changed();
}

function autopsyDetectionResult(record, caseId, changed = () => {}) {
  const t = SOCifyLocale.text, result = record.payload;
  const count = value => Number(value || 0).toLocaleString(SOCifyLocale.language);
  const root = node("div", { class: "detection-result" });
  const rows = [[t("نوع الفحص"), autopsyDetectionMode(result.mode)], [t("السجلات المفحوصة"), count(result.evaluated_events)]];
  if(result.mode === "anomaly") rows.push([t("سجلات المقارنة السابقة"), count(result.baseline_events)], [t("اختلافات تحتاج المراجعة"), count(result.findings?.length)]);
  else rows.push([t("التنبيهات الجديدة"), count(result.alert_ids?.length)]);
  root.append(autopsyDetectionFacts(t("نتيجة فحص السجلات"), rows));
  if(result.status === "insufficient_baseline") root.append(node("p", { class: "notice", text: t("السجلات السابقة غير كافية للمقارنة") }));
  else if(result.mode === "anomaly" && !result.findings?.length) root.append(node("p", { text: t("لا اختلافات عن السجلات السابقة ضمن النطاق المفحوص") }));
  if(result.mode === "anomaly" && result.findings?.length) {
    root.append(node("p", { class: "notice", text: t("الاختلاف لا يثبت نشاطًا خبيثًا") }));
    for(const item of result.findings)root.append(autopsyDetectionFacts(t("اختلاف يحتاج المراجعة"), [[t("عنوان IP"), item.source_ip], [t("اسم الجهاز"), item.hostname], [t("الدليل"), autopsyAction(t("عرض السجل"), async () => {
      const event = await api(`/api/cases/${caseId}/logs/${item.event_id}`);
      autopsyModal(t("تفاصيل السجل"), node("div", { class: "detection-result" }, [autopsyDetectionFacts(event.title, [[t("وقت الحدث"), event.normalized_fields?.event_time_known === false ? t("غير معروف") : formatTime(event.event_time)], [t("المصدر"), event.source], [t("الخطورة"), autopsyLabel(event.severity)]]), node("details", {}, [node("summary", { text: t("السجل الخام") }), node("pre", { dir: "auto", text: typeof event.raw_data === "string" ? event.raw_data : JSON.stringify(event.raw_data, null, 2) })])]));
    })]]));
  }
  if(result.alert_ids?.length) root.append(linkedButton(t("عرض التنبيهات"), `/monitoring?case_id=${caseId}`));
  if(result.next_after_id && autopsy.current?.can_update && autopsy.current.status !== "closed") root.append(autopsyAction(t("استكمال فحص الدفعة التالية"), async () => {
    root.closest("dialog")?.close();
    await autopsyQueueDetection(caseId, result.mode, result.next_after_id, changed);
  }));
  return root;
}

function autopsyDetectionJob(caseId, initial, changed = () => {}) {
  const t = SOCifyLocale.text, root = node("div", { class: "detection-job" });
  let signature = null, timer;
  async function refresh() {
    if(!root.isConnected)return;
    try { render(await api(`/api/cases/${caseId}/jobs/${initial.id}`)); }
    catch(error) { clearTimeout(timer); signature = null; root.replaceChildren(node("p", { role: "status", text: error.message }), autopsyAction(t("إعادة المحاولة"), refresh)); }
  }
  function render(job) {
    clearTimeout(timer);
    const next = JSON.stringify(job);
    if(next !== signature) {
      signature = next;
      root.replaceChildren(node("p", { role: "status", text: autopsyDetectionState(job.state) }));
      if(job.scope_changed) root.append(node("p", { class: "notice", text: t("تغيرت القضية؛ ابدأ فحصًا جديدًا لمراجعة السجلات الحالية") }));
      else if(job.error_code) root.append(node("p", { class: "notice", text: t(job.error_code === "ACCESS_REVOKED" ? "تغيرت صلاحيات الفحص أو نطاق القضية" : "تعذر إكمال الفحص") }));
      const action = (label, route) => autopsyAction(t(label), async () => { await api(`/api/cases/${caseId}/jobs/${job.id}/${route}`, { method: "POST", body: {} }); await refresh(); await changed(); });
      if(job.can_cancel)root.append(action("إلغاء المعالجة", "cancel"));
      if(job.can_retry)root.append(action("إعادة المحاولة", "retry"));
      if(job.state === "completed" && job.result_record_id)root.append(autopsyAction(t("عرض النتيجة"), async () => {
        const records = await api(`/api/cases/${caseId}/records?kind=analysis&limit=1&before=${job.result_record_id + 1}`);
        const record = records.items.find(item => item.id === job.result_record_id);
        if(!record)throw new Error(t("النتيجة غير متاحة"));
        root.closest("dialog")?.close();
        autopsyModal(t("نتيجة فحص السجلات"), autopsyDetectionResult(record, caseId, changed));
      }));
      if(["completed", "cancelled", "failed"].includes(job.state))Promise.resolve(changed()).catch(handleError);
    }
    if(["queued", "processing"].includes(job.state))timer = setTimeout(refresh, 1500);
  }
  render(initial);
  return root;
}

window.SOCifyAutopsy.localDetection = async (caseId) => {
  const base = `/api/cases/${caseId}`;
  const params=new URLSearchParams(location.search);
  const pageOf=key=>Math.max(1,Math.min(1000000,Number(params.get(key))||1));
  const [observables, alerts] = await Promise.all([api(base + `/observables?page=${pageOf("observables_page")}`), api(base + `/alerts?page=${pageOf("alerts_page")}`)]);
  const root = node("div", { class: "panel-body" });
  const paging=(key,data)=>{
    const nav=node("nav",{class:"pagination","aria-label":key==="alerts_page"?SOCifyLocale.text("التنبيهات"):SOCifyLocale.text("المؤشرات")});
    const link=(page,label)=>{const target=new URL(location.href);target.searchParams.set(key,String(page));return linkedButton(label,target.pathname+target.search);};
    if(data.page>1)nav.append(link(data.page-1,SOCifyLocale.text("السابق")));
    if(data.page*100<data.total)nav.append(link(data.page+1,SOCifyLocale.text("التالي")));
    if(nav.childNodes.length)root.append(nav);
  };
  root.append(linkedButton(SOCifyLocale.text("مكتبة المصادر والقواعد"), "/analysis-library"));
  root.append(table([{ label: SOCifyLocale.text("القيمة"), value: "value" }, { label: SOCifyLocale.text("النوع"), value: "type" }, { label: SOCifyLocale.text("السجلات الفعالة"), value: "occurrences" }, { label: SOCifyLocale.text("نتيجة آخر فحص"), value: (row) => `${autopsyIntelligenceStatus(row.enrichment.status)} · ${autopsyIntelligenceVerdict(row.enrichment.verdict)}` }, { label: SOCifyLocale.text("المصدر والتحقق"), value: (row) => autopsyAction(SOCifyLocale.text("تفاصيل الإثراء"), async () => { const content = autopsyEnrichmentDetails(row.enrichment); if (autopsy.current.can_update && autopsy.current.status !== "closed") content.append(autopsyAction(SOCifyLocale.text("إثراء محلي بالإصدارات الحالية"), async () => { await api(base + `/observables/${row.id}/enrich`, { method: "POST", body: {} }); await autopsyCase(caseId); })); autopsyModal(SOCifyLocale.text("مصدر نتيجة الإثراء وحدودها"), content); }) }], observables.items));
  paging("observables_page",observables);
  const history = node("div");
  const refreshHistory = async () => {
    const scans = await api(base + `/detection?page=${pageOf("detections_page")}`);
    history.replaceChildren(node("h3", { text: SOCifyLocale.text("فحوص السجلات") }), table([{ label: SOCifyLocale.text("نوع الفحص"), value: item => autopsyDetectionMode(item.mode) }, { label: SOCifyLocale.text("وقت الطلب"), value: item => formatTime(item.created_at) }, { label: SOCifyLocale.text("الحالة"), value: item => autopsyDetectionState(item.state) }, { label: SOCifyLocale.text("فتح"), value: item => autopsyAction(SOCifyLocale.text("متابعة الفحص"), async () => { const current = await api(base + `/jobs/${item.id}`); autopsyModal(SOCifyLocale.text("حالة فحص السجلات"), autopsyDetectionJob(caseId, current, refreshHistory)); }) }], scans.items));
    const navigation = node("nav", { class: "pagination", "aria-label": SOCifyLocale.text("فحوص السجلات") });
    for(const [page, label] of [[scans.page > 1 ? scans.page - 1 : null, "السابق"], [scans.has_next ? scans.page + 1 : null, "التالي"]])if(page) { const target = new URL(location.href); target.searchParams.set("detections_page", String(page)); navigation.append(linkedButton(SOCifyLocale.text(label), target.pathname + target.search)); }
    if(navigation.childNodes.length)history.append(navigation);
  };
  if (autopsy.current.can_update && autopsy.current.status !== "closed") {
    const form = autopsyForm({ mode: { label: SOCifyLocale.text("نوع الفحص"), required: true, choices: ["rules", "anomaly"].map(value => ({ value, label: autopsyDetectionMode(value) })) }, start_event: { label: SOCifyLocale.text("ابدأ من سجل"), reference: { kind: "event", caseId } } }, async (body) => autopsyQueueDetection(caseId, body.mode, body.start_event ? body.start_event - 1 : 0, refreshHistory), { mode: "rules" });
    form.querySelector("[name=start_event]").placeholder = SOCifyLocale.text("كل السجلات");
    root.append(form);
  }
  await refreshHistory(); root.append(history);
  const reviewControl = row => {
    const control = autopsyAction(SOCifyLocale.text("تفاصيل ومراجعة"), async () => {
      const evidence = node("div", { class: "dossier-content" });
      const disclosure = node("details", {}, [node("summary", { text: SOCifyLocale.text("تفاصيل التنبيه") }), evidence]);
      const content = node("div", {}, disclosure);
      let loaded = false, loading = false;
      const loadDetails = async () => {
        if (loaded || loading) return;
        loading = true;
        evidence.setAttribute("aria-busy", "true");
        evidence.replaceChildren(node("p", { role: "status", text: SOCifyLocale.text("جارٍ التحميل…") }));
        try {
          await window.SOCifyInsights.dossier({ ...row, case_id: caseId }, evidence);
          loaded = true;
        } catch (error) {
          evidence.replaceChildren(node("p", { role: "alert", text: error.message }), autopsyAction(SOCifyLocale.text("إعادة المحاولة"), loadDetails));
        } finally {
          loading = false;
          evidence.removeAttribute("aria-busy");
        }
      };
      disclosure.addEventListener("toggle", () => { if (disclosure.open) loadDetails(); });
      const view = location.pathname + location.search;
      const refreshSavedReview = async () => {
        if (location.pathname + location.search !== view) return;
        try {
          await autopsyCase(caseId);
          if (location.pathname + location.search === view) document.querySelector(`[data-alert-review-id="${row.id}"]`)?.focus();
        } catch (error) {
          if (location.pathname + location.search !== view) return;
          const retry = autopsyAction(SOCifyLocale.text("إعادة المحاولة"), refreshSavedReview, "primary");
          finish(node("section", { class: "panel-body" }, [node("p", { role: "status", text: SOCifyLocale.text("حُفظ قرار التنبيه؛ تعذر تحديث العرض.") }), node("p", { class: "notice", role: "alert", text: error.message }), retry]));
          retry.focus();
        }
      };
      if (autopsy.current.can_update && autopsy.current.status !== "closed") content.append(autopsyForm({ verdict: { label: SOCifyLocale.text("قرار المحلل"), required: true, choices: autopsy.catalog.verdicts }, attack_outcome: { label: SOCifyLocale.text("نتيجة الهجوم"), required: true, choices: autopsy.catalog.outcomes }, group: { label: SOCifyLocale.text("مجموعة التنبيهات"), max: 100 }, suppressed_until: { label: SOCifyLocale.text("إخفاء الإشعار حتى"), timestamp: true }, reason: { label: SOCifyLocale.text("سبب القرار"), required: true, max: 2000 } }, async (body) => {
        await api(base + `/alerts/${row.id}`, { method: "PATCH", body: { ...body, version: row.review_version, group: body.group || "", suppressed_until: body.suppressed_until || null } });
        content.closest("dialog")?.close();
        await refreshSavedReview();
      }, row.review, { freezeWhileSaving: true }));
      content.querySelector("textarea[name=reason]")?.setAttribute("dir", "auto");
      autopsyModal(SOCifyLocale.text("مراجعة التنبيه"), content);
    });
    control.dataset.alertReviewId = row.id;
    return control;
  };
  root.append(table([{ label: SOCifyLocale.text("التنبيه"), value: "reason" }, { label: SOCifyLocale.text("الخطر"), value: "severity" }, { label: SOCifyLocale.text("تقييم المحقق"), value: (row) => `${autopsyLabel(row.review.verdict)} · ${autopsyLabel(row.review.attack_outcome)}` }, { label: SOCifyLocale.text("مجموعة / نطاق"), value: (row) => `${row.review.group || "—"}${row.historical_derivation ? SOCifyLocale.text(" · نسخة تاريخية") : ""}${row.suppressed ? SOCifyLocale.text(" · إشعار مكبوت مؤقتًا") : ""}` }, { label: SOCifyLocale.text("المراجعة"), value: reviewControl }], alerts.items));
  paging("alerts_page",alerts);
  return panel(SOCifyLocale.text("الإثراء والكشف ومراجعة التنبيهات"), root, true);
};

window.SOCifyAutopsy.capsules = async (caseId) => {
  const root = node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("حزمة الفريق تستبعد الملاحظات الخاصة والعينات وملفات التقارير الأصلية. النسخة الكاملة تحفظها وتتطلب المدير وصلاحية تنزيل العينات. SHA-256 يثبت اتساق المحتوى ولا يثبت هوية المصدر الخارجي.") }), linkedButton(SOCifyLocale.text("استعادة حزمة كقضية جديدة"), "/analysis-library")]);
  if (permission("cases.export") && permission("evidence.download")) {
    root.append(linkedButton(SOCifyLocale.text("تصدير حزمة الفريق"), `/api/cases/${caseId}/capsule?profile=team`));
    if (autopsy.current.can_manage && permission("samples.download")) root.append(linkedButton(SOCifyLocale.text("تنزيل نسخة كاملة حساسة"), `/api/cases/${caseId}/capsule?profile=backup`));
  }
  const archives = await api(`/api/cases/${caseId}/capsules`);
  root.append(table([{ label: SOCifyLocale.text("مرجع المصدر"), value: "source_reference" }, { label: SOCifyLocale.text("السياسة"), value: "profile" }, { label: SOCifyLocale.text("البصمة"), value: "sha256" }, { label: SOCifyLocale.text("الأرشيف الأجنبي"), value: (row) => autopsyAction(SOCifyLocale.text("فحص الأرشيف"), async () => {
    const select = autopsySelect("section", ["case", "context", "autopsy_records", "revisions", "autopsy_custody", "autopsy_reports", "case_tasks", "case_history", "actors", "manifest"]);
    const display = node("pre");
    let page = 1;
    const show = async () => { const data = await api(`/api/cases/${caseId}/capsules/${row.id}/snapshot?section=${select.value}&page=${page}`); display.textContent = JSON.stringify(data, null, 2); };
    select.addEventListener("change", () => { page = 1; show().catch(handleError); });
    autopsyModal(SOCifyLocale.text("أرشيف ثابت غير معتمد محليًا"), node("div", {}, [field(SOCifyLocale.text("القسم التاريخي"), select), autopsyAction(SOCifyLocale.text("السابق"), async () => { page = Math.max(1, page - 1); await show(); }), autopsyAction(SOCifyLocale.text("التالي"), async () => { page += 1; await show(); }), display]));
    await show();
  }) }], archives.items));
  return panel(SOCifyLocale.text("حزم القضية والاستعادة والأرشيف"), root, true);
};

function autopsyWorkflowState(value) {
  return SOCifyLocale.text({ not_configured: "لم تُحدد المهلة", running: "المهلة جارية", paused: "المهلة معلقة", breached: "تجاوز المهلة", closed: "مغلقة", pending_approval: "بانتظار الاعتماد", approved: "معتمد", rejected: "مرفوض", documented: "وُثق الجمع", documented_with_gaps: "وُثق الجمع جزئيًا", draft: "مسودة", reviewed: "تمت المراجعة" }[value] || value);
}

function autopsySLASummary(sla) {
  const minutes = (seconds) => SOCifyLocale.template`${new Intl.NumberFormat(SOCifyLocale.language, { maximumFractionDigits: 1 }).format(Math.abs(seconds) / 60)} دقيقة`;
  const rows = [{ label: SOCifyLocale.text("الحالة"), value: autopsyWorkflowState(sla.status) }];
  if (sla.configured) {
    rows.push(
      { label: SOCifyLocale.text("مهلة الاستجابة"), value: minutes(sla.policy.minutes * 60) },
      { label: SOCifyLocale.text("الوقت المحتسب"), value: minutes(sla.elapsed_work_seconds) },
      { label: SOCifyLocale.text(sla.remaining_work_seconds < 0 ? "مدة التجاوز" : "الوقت المتبقي"), value: minutes(sla.remaining_work_seconds) },
      { label: SOCifyLocale.text("الموعد المتوقع"), value: sla.status === "paused" ? SOCifyLocale.text("بعد استئناف المهلة") : sla.projected_due_at ? formatTime(sla.projected_due_at) : "—" },
      { label: SOCifyLocale.text("تقويم الاحتساب"), value: `${autopsyLabel(sla.policy.calendar.mode)} · ${sla.policy.calendar.timezone}` }
    );
    if (sla.paused_work_seconds > 0) rows.push({ label: SOCifyLocale.text("الوقت المستثنى بالتعليق"), value: minutes(sla.paused_work_seconds) });
    if (sla.policy.calendar.mode === "business") rows.push({ label: SOCifyLocale.text("ساعات العمل"), value: `${autopsyLabel(sla.policy.calendar.weekdays.includes(6) ? "sun_thu" : "mon_fri")} · ${sla.policy.calendar.start_hour}:00–${sla.policy.calendar.end_hour}:00` });
  }
  const result = table([{ label: SOCifyLocale.text("مهلة الاستجابة"), value: "label" }, { label: SOCifyLocale.text("القيمة"), value: "value" }], rows);
  result.classList.add("sla-summary");
  return result;
}

function autopsyResponseMetrics(metrics) {
  const labels = {
    detection_delay_seconds: "المدة حتى الرصد بالثواني",
    first_response_delay_seconds: "المدة حتى أول استجابة بالثواني",
    acknowledgement_delay_seconds: "المدة حتى الإقرار بالثواني",
    containment_delay_seconds: "المدة حتى الاحتواء بالثواني",
    recovery_delay_seconds: "المدة حتى التعافي بالثواني",
    closure_delay_seconds: "المدة من الرصد حتى الإغلاق بالثواني",
  };
  const milestones = {
    first_evidenced_activity: "أقدم نشاط مثبت بالدليل",
    detection: "وقت الرصد المثبت",
    first_response: "وقت أول استجابة مثبتة",
    acknowledgement: "وقت إقرار الاستلام",
    containment: "وقت الاحتواء المثبت",
    recovery: "وقت التعافي المثبت",
  };
  const phases = { first_evidenced_activity: "أول نشاط مثبت", detection: "الرصد", first_response: "أول استجابة", acknowledgement: "إقرار الاستلام", containment: "الاحتواء", recovery: "التعافي", closure: "إغلاق القضية" };
  const reasons = {
    "negative interval excluded": "نهاية الفترة تسبق بدايتها؛ لم تُحسب المدة.",
    "future timestamp": "وقت مستقبلي؛ لا يدخل القياسات المؤكدة.",
    "missing or invalid timestamp": "وقت مفقود أو غير صالح؛ لا يمكن حساب المدة.",
  };
  const number = new Intl.NumberFormat(SOCifyLocale.language, { maximumFractionDigits: 6 });
  const durations = table([
    { label: SOCifyLocale.text("المقياس"), value: row => SOCifyLocale.text(row.label) },
    { label: SOCifyLocale.text("القيمة"), value: row => node("span", { "data-response-duration": row.key, text: Number.isFinite(row.value) && row.value >= 0 ? number.format(row.value) : SOCifyLocale.text("غير مقاس") }) },
  ], Object.entries(labels).map(([key, label]) => ({ key, label, value: metrics[key] })));
  durations.classList.add("response-metric-durations");
  const root = node("details", { class: "response-metrics" }, [node("summary", { text: SOCifyLocale.text("قياسات الاستجابة وأساس حسابها") }), durations]);
  if (metrics.issues?.length) root.append(node("ul", { class: "response-metric-issues" }, metrics.issues.map(issue => {
    const [phase, reason] = String(issue).split(": ");
    return node("li", { text: `${SOCifyLocale.text(phases[phase] || "قياس الاستجابة")}: ${SOCifyLocale.text(reasons[reason] || "تعذر احتساب هذا القياس؛ راجع أوقات الاستجابة.")}` });
  })));
  const moments = Object.entries(milestones).filter(([key]) => metrics.milestones?.[key] && Number.isFinite(Date.parse(metrics.milestones[key])));
  if (moments.length) root.append(table([
    { label: SOCifyLocale.text("مراحل الاستجابة"), value: row => SOCifyLocale.text(row.label) },
    { label: SOCifyLocale.text("وقت الحدث"), value: row => formatTime(row.value) },
  ], moments.map(([key, label]) => ({ label, value: metrics.milestones[key] }))));
  if (metrics.basis) root.append(node("p", { text: SOCifyLocale.text(metrics.basis) }));
  return root;
}

window.SOCifyAutopsy.workflow = async (caseId) => {
  const data = await api(`/api/cases/${caseId}/workflow`), current = autopsy.current, base = `/api/cases/${caseId}`;
  const root = node("div", { class: "panel-body" }, [autopsySLASummary(data.sla), autopsyResponseMetrics(data.metrics)]);
  if (data.scope) root.append(node("details", {}, [node("summary", { text: SOCifyLocale.text("نطاق الفحص وحدوده") }), node("p", { text: SOCifyLocale.text(data.scope.limitations) }), table([{ label: SOCifyLocale.text("تقييم الأصل"), value: (row) => autopsyLabel(row.assessment) }, { label: SOCifyLocale.text("الأصول الموثقة"), value: "count" }], Object.entries(data.scope.counts_by_assessment).map(([assessment, count]) => ({ assessment, count }))), node("details", {}, [node("summary", { text: SOCifyLocale.text("أقدم ملاحظة وأدلتها · لا تثبت بداية الهجوم") }), node("pre", { text: JSON.stringify(data.scope.earliest_retained_observation, null, 2) })])]));
  if (current.can_manage && current.status !== "closed") {
    const policy = data.sla.policy, calendar = policy?.calendar;
    const form = autopsyForm({ minutes: { required: true, integer: true, min: 1, max: 525600 }, mode: { required: true, choices: ["24x7", "business"] }, timezone: { required: true, choices: autopsy.catalog.source_timezones }, weekdays: { required: true, choices: ["mon_fri", "sun_thu"] }, start_hour: { required: true, integer: true, min: 0, max: 23 }, end_hour: { required: true, integer: true, min: 1, max: 24 }, reason: { required: true, max: 1000 } }, async (body) => { const calendar = { mode: body.mode, timezone: body.timezone }; if (body.mode === "business") Object.assign(calendar, { weekdays: body.weekdays === "sun_thu" ? [6, 0, 1, 2, 3] : [0, 1, 2, 3, 4], start_hour: body.start_hour, end_hour: body.end_hour, holidays: [] }); await api(base + "/sla", { method: "POST", body: { version: current.version, minutes: body.minutes, calendar, reason: body.reason } }); await autopsyCase(caseId); }, { minutes: policy?.minutes, mode: calendar?.mode || "24x7", timezone: calendar?.timezone || "Asia/Riyadh", weekdays: calendar?.weekdays && !calendar.weekdays.includes(6) ? "mon_fri" : "sun_thu", start_hour: calendar?.start_hour ?? 9, end_hour: calendar?.end_hour ?? 17 });
    const mode = form.querySelector("input[name=mode]");
    const showHours = () => { for (const key of ["weekdays", "start_hour", "end_hour"]) { const input = form.querySelector(`[name=${key}]`); input.closest("label").hidden = mode.value !== autopsyLabel("business"); input.required = !input.closest("label").hidden; } };
    mode.addEventListener("input", showHours); showHours();
    root.append(data.sla.configured ? node("details", { class: "sla-settings" }, [node("summary", { text: SOCifyLocale.text("تعديل مهلة الاستجابة") }), form]) : form);
    if (data.sla.configured) root.append(autopsyAction(data.sla.status === "paused" ? SOCifyLocale.text("استئناف SLA") : SOCifyLocale.text("إيقاف SLA مؤقتًا"), async () => { let dialog; dialog = autopsyModal(SOCifyLocale.text("تغيير ساعة SLA مع توثيق السبب"), autopsyForm({ reason: { required: true, max: 1000 } }, async (body) => { await api(base + `/sla/${data.sla.status === "paused" ? "resume" : "pause"}`, { method: "POST", body: { ...body, version: current.version } }); dialog.close(); await autopsyCase(caseId); })); }));
  }
  if (current.can_update && current.status !== "closed") root.append(autopsyForm({ recipe_id: { required: true, choices: Object.entries(data.recipes).map(([value, item]) => ({ value, label: SOCifyLocale.text(item.title) })) }, collector_id: { required: true, user: true, case_member: true }, reason: { required: true, max: 2000 } }, async (body) => { await api(base + "/collections", { method: "POST", body: { ...body, version: current.version } }); await autopsyCase(caseId); }));
  for (const item of data.collections) {
    const body = item.payload;
    const card = node("article", { class: "card" }, [node("h4", { text: SOCifyLocale.text(body.recipe_snapshot.title) }), node("p", { text: `${autopsyWorkflowState(body.state)} · ${body.reason}` }), node("details", {}, [node("summary", { text: SOCifyLocale.text("نطاق الجمع") }), node("p", { text: SOCifyLocale.text(body.recipe_snapshot.guidance) })])]);
    if (current.can_manage && body.state === "pending_approval") for (const action of ["approve", "reject"]) card.append(autopsyAction(action === "approve" ? SOCifyLocale.text("اعتماد نطاق الجمع") : SOCifyLocale.text("رفض نطاق الجمع"), async () => { let dialog; dialog = autopsyModal(SOCifyLocale.text("توثيق قرار نطاق الجمع"), autopsyForm({ reason: { required: true, max: 1000 } }, async (values) => { await api(base + `/collections/${item.id}/${action}`, { method: "POST", body: { ...values, version: item.version, case_version: current.version } }); dialog.close(); await autopsyCase(caseId); })); }));
    if (body.artifacts?.length) card.append(table([{ label: SOCifyLocale.text("المصادر المجمعة فعليًا"), value: "value" }], body.artifacts.map((value) => ({ value }))));
    if (body.missing_artifacts?.length) card.append(table([{ label: SOCifyLocale.text("المصادر التي لم تُجمع"), value: "value" }], body.missing_artifacts.map((value) => ({ value }))));
    if (current.can_update && current.status !== "closed" && ["approved", "documented_with_gaps"].includes(body.state) && (current.can_manage || body.collector_id === state.user.id)) card.append(autopsyAction(SOCifyLocale.text(body.state === "documented_with_gaps" ? "استكمال توثيق الجمع" : "توثيق الجمع المنفذ محليًا"), async () => {
      let dialog;
      const artifacts = node("select", { multiple: true, required: true, "aria-label": SOCifyLocale.text("المصادر المجمعة فعليًا") }, body.recipe_snapshot.artifacts.map((value) => node("option", { value, text: value, selected: body.artifacts?.includes(value) })));
      const form = autopsyForm({ evidence_id: { required: true, evidence: true }, tool: { required: true, max: 255 }, source: { required: true, max: 500 }, collected_at: { required: true, timestamp: true } }, async (values) => { await api(base + `/collections/${item.id}/document`, { method: "POST", body: { ...values, artifacts: [...artifacts.selectedOptions].map((option) => option.value), version: item.version, case_version: current.version } }); dialog.close(); await autopsyCase(caseId); }, body);
      form.prepend(field(SOCifyLocale.text("المصادر التي جُمعت فعليًا · يمكن اختيار عدة عناصر"), artifacts));
      dialog = autopsyModal(SOCifyLocale.text("توثيق جمع أدلة مخول؛ لا تنفيذ أوامر على الأجهزة"), form);
    }));
    root.append(card);
  }
  if (current.can_update && ["closed", "awaiting_review", "recovered", "remediated", "contained"].includes(current.status)) root.append(autopsyAction(SOCifyLocale.text("إنشاء مسودة مراجعة ما بعد الحادثة"), async () => { await api(base + "/postmortems", { method: "POST", body: { version: current.version } }); await autopsyCase(caseId); }));
  for (const item of data.postmortems) {
    const card = node("article", { class: "card" }, [node("h4", { text: SOCifyLocale.template`مراجعة ما بعد الحادثة · ${autopsyWorkflowState(item.payload.state)}` }), node("p", { text: item.payload.executive_summary }), node("p", { text: item.payload.lessons || SOCifyLocale.text("الدروس تحتاج مراجعة المحقق") }), node("p", { text: item.payload.limitations })]);
    if (current.can_approve && item.payload.state === "draft") card.append(autopsyAction(SOCifyLocale.text("مراجعة المسودة"), async () => { let dialog; dialog = autopsyModal(SOCifyLocale.text("مراجعة مستقلة للدروس والقيود"), autopsyForm({ executive_summary: { required: true, max: 5000 }, lessons: { required: true, max: 5000 }, limitations: { required: true, max: 5000 }, override_reason: { max: 1000 } }, async (values) => { await api(base + `/postmortems/${item.id}/review`, { method: "POST", body: { ...values, version: item.version, case_version: current.version } }); dialog.close(); await autopsyCase(caseId); }, item.payload)); }));
    root.append(card);
  }
  return panel(SOCifyLocale.text("SLA وجمع الأدلة ومراجعة ما بعد الحادثة"), root, true);
};
