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

Object.assign(autopsyLabels, { source: SOCifyLocale.text("المصدر"), license: SOCifyLocale.text("الرخصة وحق الاستخدام"), version: SOCifyLocale.text("الإصدار"), format: SOCifyLocale.text("الصيغة"), minutes: SOCifyLocale.text("ميزانية SLA بالدقائق"), mode: SOCifyLocale.text("تقويم الاحتساب"), timezone: SOCifyLocale.text("المنطقة الزمنية"), start_hour: SOCifyLocale.text("ساعة بدء العمل"), end_hour: SOCifyLocale.text("ساعة انتهاء العمل"), weekdays: SOCifyLocale.text("أيام العمل"), mon_fri: SOCifyLocale.text("الاثنين إلى الجمعة"), sun_thu: SOCifyLocale.text("الأحد إلى الخميس"), "24x7": SOCifyLocale.text("كل ساعات الأسبوع"), business: SOCifyLocale.text("ساعات العمل"), recipe_id: SOCifyLocale.text("وصفة الجمع"), collector_id: SOCifyLocale.text("الجامع المخول"), tool: SOCifyLocale.text("أداة الجمع وإصدارها"), collected_at: SOCifyLocale.text("وقت الجمع"), executive_summary: SOCifyLocale.text("الملخص التنفيذي المراجع"), lessons: SOCifyLocale.text("الدروس والتوصيات"), override_reason: SOCifyLocale.text("سبب استثناء المراجعة المستقلة للمدير"), unverified: SOCifyLocale.text("لم يُتحقق منه"), group: SOCifyLocale.text("مجموعة التنبيهات"), suppressed_until: SOCifyLocale.text("إخفاء الإشعار حتى") });

window.SOCifyAutopsy.library = async () => {
  begin("analysis-library");
  const root = node("div", {}, pageHead(SOCifyLocale.text("مكتبة التحليل المحلي"), null));
  const bundles = await api("/api/autopsy/intelligence");
  root.append(panel(SOCifyLocale.text("إصدارات مصادر TI وGeoIP"), table([{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("الإصدار"), value: "version" }, { label: SOCifyLocale.text("المصدر والرخصة"), value: (row) => `${row.source} · ${row.license}` }, { label: SOCifyLocale.text("المؤشرات"), value: "entries" }, { label: SOCifyLocale.text("الصلاحية"), value: (row) => formatTime(row.expires_at) }, { label: SOCifyLocale.text("التفعيل"), value: (row) => row.active ? SOCifyLocale.text("الإصدار المختار") : permission("intel.manage") ? autopsyAction(SOCifyLocale.text("تفعيل الإصدار"), async () => { await api(`/api/autopsy/intelligence/${row.id}/activate`, { method: "POST", body: {} }); await window.SOCifyAutopsy.library(); }) : SOCifyLocale.text("غير مختار") }], bundles.items), true));
  if (permission("intel.manage")) {
    const file = node("input", { type: "file", accept: ".json,application/json", required: true, "aria-label": SOCifyLocale.text("حزمة TI المحلية") });
    const form = autopsyForm({ name: { required: true, max: 160 }, version: { required: true, max: 80 }, source: { required: true, max: 500 }, license: { required: true, max: 500 }, expires_at: { required: true, timestamp: true }, format: { required: true, choices: bundles.formats } }, async (body) => { await api("/api/autopsy/intelligence", { method: "POST", body: { ...body, content: await autopsyReadJSON(file) } }); await window.SOCifyAutopsy.library(); });
    form.prepend(field(SOCifyLocale.text("ملف JSON محلي · حتى 2 MiB"), file));
    root.append(panel(SOCifyLocale.text("استيراد إصدار محلي جديد"), node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("flat: قائمة type/value/verdict/confidence؛ geoip: CIDR مع country أو asn. STIX يدعم مساواة مؤشر مفرد، وMISP Attribute بأنواع معلنة. يلزم التفعيل بعد الاستيراد؛ لا تتضمن المنصة قاعدة سمعة مرخصة جاهزة.") }), form]), true));
  }
  if (permission("rules.manage")) {
    const rules = await api("/api/autopsy/sigma/rules");
    root.append(panel(SOCifyLocale.text("قواعد Sigma المنشورة"), table([{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("الإصدار"), value: "version" }, { label: SOCifyLocale.text("المترجم"), value: "compiler" }, { label: "SHA-256", value: "sha256" }], rules.items), true));
    const source = node("input", { type: "file", accept: ".yml,.yaml,text/yaml", required: true, "aria-label": SOCifyLocale.text("ملف Sigma") });
    const fixtures = node("input", { type: "file", accept: ".json,application/json", required: true, "aria-label": SOCifyLocale.text("اختبارات القاعدة") });
    const preview = node("div", { "aria-live": "polite" });
    const rule = autopsyChoice("rule_id", rules.items.map((item) => ({ value: item.id, label: `${item.name} · ${item.id}` })));
    const compile = async () => {
      if (!source.files[0] || source.files[0].size > 65536) throw new Error(SOCifyLocale.text("ملف Sigma مطلوب وبحد 64 KiB"));
      return { source: await source.files[0].text(), fixtures: await autopsyReadJSON(fixtures, 512 * 1024) };
    };
    const form = autopsyForm({ reason: { required: true, max: 1000 } }, async (body) => {
      const id = rule.input.autopsyValue();
      const current = rules.items.find((item) => item.id === id);
      await api("/api/autopsy/sigma/publish", { method: "POST", body: { ...body, ...await compile(), ...(current ? { rule_id: id, version: current.version } : {}) } });
      await window.SOCifyAutopsy.library();
    });
    form.prepend(field(SOCifyLocale.text("مصدر Sigma"), source), field(SOCifyLocale.text("fixtures JSON: positive وnegative، كل قائمة أحداث مطبّعة"), fixtures), field(SOCifyLocale.text("إصدار جديد لقاعدة موجودة · اتركه فارغًا لقاعدة جديدة"), rule.control));
    form.append(autopsyAction(SOCifyLocale.text("تحقق من الترجمة والاختبارات دون نشر"), async () => { const result = await api("/api/autopsy/sigma/compile", { method: "POST", body: await compile() }); preview.replaceChildren(node("p", { text: SOCifyLocale.text("اجتازت الأمثلة الإيجابية والسلبية. التحقق لا يثبت تغطية جميع التهديدات.") }), node("pre", { text: JSON.stringify(result.compiled, null, 2) })); }), preview);
    root.append(panel(SOCifyLocale.text("تحقق ونشر Sigma subset"), node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.template`النطاق: ${rules.capabilities.conditions}. غير المدعوم يُرفض: ${rules.capabilities.unsupported.join(SOCifyLocale.text("، "))}. لا يثبت اجتياز fixtures دقة الكشف في بيانات الشركة.` }), form]), true));
  }
  const yara = await api("/api/autopsy/yara");
  const yaraBody = node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("حزم محلية ثابتة بإصدارات ورخص وبصمات. تنشر بعد تجميع معزول ونجاح أمثلة إيجابية وسلبية؛ لا تنزيل أو تحديث خارجي. لا يثبت غياب التطابق سلامة العينة.") }), table([{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("الإصدار"), value: "version" }, { label: SOCifyLocale.text("المصدر والرخصة"), value: (row) => `${row.origin} · ${row.license}` }, { label: "SHA-256", value: "sha256" }], yara.items)]);
  if (permission("rules.manage")) {
    const packFile = node("input", { type: "file", accept: ".yar,.yara,text/plain", required: true, "aria-label": SOCifyLocale.text("ملف قواعد YARA") });
    const fixtureFile = node("input", { type: "file", accept: ".json,application/json", required: true, "aria-label": SOCifyLocale.text("أمثلة YARA الاصطناعية") });
    const form = autopsyForm({ name: { required: true, max: 120 }, version: { required: true, integer: true, min: 1, max: 1000000 }, origin: { required: true, max: 1000 }, license: { required: true, max: 500 } }, async (body) => { if (!packFile.files[0] || packFile.files[0].size > 65536) throw new Error(SOCifyLocale.text("ملف YARA مطلوب بحد 64 KiB")); await api("/api/autopsy/yara", { method: "POST", body: { ...body, source: await packFile.files[0].text(), fixtures: await autopsyReadJSON(fixtureFile, 768 * 1024) } }); await window.SOCifyAutopsy.library(); });
    form.prepend(field(SOCifyLocale.text("قواعد YARA محلية · حتى 64 KiB"), packFile), field(SOCifyLocale.text("fixtures JSON: positive وnegative، كل قائمة عينات base64 اصطناعية"), fixtureFile));
    yaraBody.append(form);
  }
  root.append(panel(SOCifyLocale.text("حزم YARA المحلية"), yaraBody, true));
  if (permission("cases.create") && permission("evidence.add")) {
    const file = node("input", { type: "file", accept: ".zip,application/zip", required: true, "aria-label": SOCifyLocale.text("حزمة قضية محلية") });
    const errors = node("p", { class: "notice span-2", role: "alert", hidden: true });
    const form = node("form", { class: "form-grid" }, [field(SOCifyLocale.text("حزمة ZIP محلية · حتى 64 MiB موسعة"), file), errors, node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("استعادة كقضية جديدة") })]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); const control = form.querySelector("button"); control.disabled = true; errors.hidden = true; try { if (!file.files[0] || file.files[0].size > 64 * 1024 * 1024 + 524288) throw new Error(SOCifyLocale.text("حجم الحزمة يتجاوز الحد")); const body = new FormData(); body.set("file", file.files[0]); const result = await api("/api/cases/import-capsule", { method: "POST", body }); window.location.assign(`/cases/${result.case_id}?tab=reports`); } catch (error) { errors.textContent = error.message; errors.hidden = false; control.disabled = false; } });
    root.append(panel(SOCifyLocale.text("استعادة حزمة قضية"), node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.text("تُفحص البصمات والمسارات والحدود قبل الاستعادة. تحفظ إفادات واعتمادات المالك السابق في أرشيف ثابت للمراجعة ولا تمنح صلاحية أو اعتمادًا محليًا تلقائيًا.") }), form]), true));
  }
  finish(root);
};

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
  root.append(table([{ label: SOCifyLocale.text("القيمة"), value: "value" }, { label: SOCifyLocale.text("النوع"), value: "type" }, { label: SOCifyLocale.text("السجلات الفعالة"), value: "occurrences" }, { label: SOCifyLocale.text("نتيجة آخر فحص"), value: (row) => `${row.enrichment.status} · ${row.enrichment.verdict}` }, { label: SOCifyLocale.text("المصدر والتحقق"), value: (row) => autopsyAction(SOCifyLocale.text("تفاصيل الإثراء"), async () => { const content = node("div", {}, node("pre", { text: JSON.stringify(row.enrichment, null, 2) })); if (autopsy.current.can_update && autopsy.current.status !== "closed") content.append(autopsyAction(SOCifyLocale.text("إثراء محلي بالإصدارات الحالية"), async () => { await api(base + `/observables/${row.id}/enrich`, { method: "POST", body: {} }); await autopsyCase(caseId); })); autopsyModal(SOCifyLocale.text("مصدر نتيجة الإثراء وحدودها"), content); }) }], observables.items));
  paging("observables_page",observables);
  if (autopsy.current.can_update && autopsy.current.status !== "closed") {
    root.append(autopsyForm({ mode: { required: true, choices: ["rules", "anomaly"] }, after_id: { integer: true, min: 0, max: Number.MAX_SAFE_INTEGER } }, async (body) => { const job = await api(base + "/detection", { method: "POST", body: { ...body, after_id: body.after_id || 0, version: autopsy.current.version } }); autopsyModal(SOCifyLocale.text("تحليل محلي في الطابور"), node("div", {}, [node("p", { text: SOCifyLocale.template`العمل ${job.id} · حد الدفعة 1000 سجل. نتائج الشذوذ تحتاج 20 سجلًا سابقًا صالحًا للـbaseline. استخدم next_after_id من النتيجة لاستكمال النطاق.` }), autopsyAction(SOCifyLocale.text("تحديث حالة العمل"), async () => { const status = await api(base + `/jobs/${job.id}`); autopsyModal(SOCifyLocale.text("حالة التحليل"), node("pre", { text: JSON.stringify(status, null, 2) })); }), linkedButton(SOCifyLocale.text("نتائج التحليل داخل القضية"), `/cases/${caseId}?tab=analysis`)])); }));
  }
  root.append(table([{ label: SOCifyLocale.text("التنبيه"), value: "reason" }, { label: SOCifyLocale.text("الخطر"), value: "severity" }, { label: SOCifyLocale.text("تقييم المحقق"), value: (row) => `${autopsyLabel(row.review.verdict)} · ${autopsyLabel(row.review.attack_outcome)}` }, { label: SOCifyLocale.text("مجموعة / نطاق"), value: (row) => `${row.review.group || "—"}${row.historical_derivation ? SOCifyLocale.text(" · نسخة تاريخية") : ""}${row.suppressed ? SOCifyLocale.text(" · إشعار مكبوت مؤقتًا") : ""}` }, { label: SOCifyLocale.text("المراجعة"), value: (row) => autopsyAction(SOCifyLocale.text("تفاصيل ومراجعة"), async () => {
    const content = node("div", {}, node("pre", { text: JSON.stringify({ evidence: row.evidence, trace: row.trace, review: row.review }, null, 2) }));
    if (autopsy.current.can_update && autopsy.current.status !== "closed") content.append(autopsyForm({ verdict: { required: true, choices: autopsy.catalog.verdicts }, attack_outcome: { required: true, choices: autopsy.catalog.outcomes }, group: { max: 100 }, suppressed_until: { timestamp: true }, reason: { required: true, max: 2000 } }, async (body) => { await api(base + `/alerts/${row.id}`, { method: "PATCH", body: { ...body, version: row.review_version, group: body.group || "", suppressed_until: body.suppressed_until || null } }); await autopsyCase(caseId); }, row.review));
    autopsyModal(SOCifyLocale.text("الأدلة وقرار التنبيه منفصل عن نتيجة الهجوم"), content);
  }) }], alerts.items));
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

window.SOCifyAutopsy.workflow = async (caseId) => {
  const data = await api(`/api/cases/${caseId}/workflow`), current = autopsy.current, base = `/api/cases/${caseId}`;
  const root = node("div", { class: "panel-body" }, [autopsySLASummary(data.sla), node("details", {}, [node("summary", { text: SOCifyLocale.text("قياسات الاستجابة وأساس حسابها") }), node("pre", { text: JSON.stringify(data.metrics, null, 2) })])]);
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
