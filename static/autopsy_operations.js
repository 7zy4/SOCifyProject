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
  if (!file || file.size > maximum) throw new Error("اختر ملف JSON محليًا ضمن حد الحجم المعلن");
  return JSON.parse(await file.text());
}

Object.assign(autopsyLabels, { source: "المصدر", license: "الرخصة وحق الاستخدام", version: "الإصدار", format: "الصيغة", minutes: "ميزانية SLA بالدقائق", mode: "تقويم الاحتساب", timezone: "المنطقة الزمنية", start_hour: "ساعة بدء العمل", end_hour: "ساعة انتهاء العمل", weekdays: "أيام العمل", mon_fri: "الاثنين إلى الجمعة", sun_thu: "الأحد إلى الخميس", "24x7": "كل ساعات الأسبوع", business: "ساعات العمل", recipe_id: "وصفة الجمع", collector_id: "الجامع المخول", tool: "أداة الجمع وإصدارها", collected_at: "وقت الجمع", executive_summary: "الملخص التنفيذي المراجع", lessons: "الدروس والتوصيات", override_reason: "سبب استثناء المراجعة المستقلة للمدير", unverified: "لم يُتحقق منه", group: "مجموعة التنبيهات", suppressed_until: "إخفاء الإشعار حتى" });

window.SOCifyAutopsy.library = async () => {
  begin("analysis-library");
  const root = node("div", {}, pageHead("مكتبة التحليل المحلي", "مصادر الشركة المحلية وقواعد الكشف. لا ترسل المنصة مؤشرات أو سجلات للخارج."));
  const bundles = await api("/api/autopsy/intelligence");
  root.append(panel("إصدارات مصادر TI وGeoIP", table([{ label: "الاسم", value: "name" }, { label: "الإصدار", value: "version" }, { label: "المصدر والرخصة", value: (row) => `${row.source} · ${row.license}` }, { label: "المؤشرات", value: "entries" }, { label: "الصلاحية", value: (row) => formatTime(row.expires_at) }, { label: "التفعيل", value: (row) => row.active ? "الإصدار المختار" : permission("intel.manage") ? autopsyAction("تفعيل الإصدار", async () => { await api(`/api/autopsy/intelligence/${row.id}/activate`, { method: "POST", body: {} }); await window.SOCifyAutopsy.library(); }) : "غير مختار" }], bundles.items), true));
  if (permission("intel.manage")) {
    const file = node("input", { type: "file", accept: ".json,application/json", required: true, "aria-label": "حزمة TI المحلية" });
    const form = autopsyForm({ name: { required: true, max: 160 }, version: { required: true, max: 80 }, source: { required: true, max: 500 }, license: { required: true, max: 500 }, expires_at: { required: true, timestamp: true }, format: { required: true, choices: bundles.formats } }, async (body) => { await api("/api/autopsy/intelligence", { method: "POST", body: { ...body, content: await autopsyReadJSON(file) } }); await window.SOCifyAutopsy.library(); });
    form.prepend(field("ملف JSON محلي · حتى 2 MiB", file));
    root.append(panel("استيراد إصدار محلي جديد", node("div", { class: "panel-body" }, [node("p", { text: "flat: قائمة type/value/verdict/confidence؛ geoip: CIDR مع country أو asn. STIX يدعم مساواة مؤشر مفرد، وMISP Attribute بأنواع معلنة. يلزم التفعيل بعد الاستيراد؛ لا تتضمن المنصة قاعدة سمعة مرخصة جاهزة." }), form]), true));
  }
  if (permission("rules.manage")) {
    const rules = await api("/api/autopsy/sigma/rules");
    root.append(panel("قواعد Sigma المنشورة", table([{ label: "الاسم", value: "name" }, { label: "الإصدار", value: "version" }, { label: "المترجم", value: "compiler" }, { label: "SHA-256", value: "sha256" }], rules.items), true));
    const source = node("input", { type: "file", accept: ".yml,.yaml,text/yaml", required: true, "aria-label": "ملف Sigma" });
    const fixtures = node("input", { type: "file", accept: ".json,application/json", required: true, "aria-label": "اختبارات القاعدة" });
    const preview = node("div", { "aria-live": "polite" });
    const rule = autopsyChoice("rule_id", rules.items.map((item) => ({ value: item.id, label: `${item.name} · ${item.id}` })));
    const compile = async () => {
      if (!source.files[0] || source.files[0].size > 65536) throw new Error("ملف Sigma مطلوب وبحد 64 KiB");
      return { source: await source.files[0].text(), fixtures: await autopsyReadJSON(fixtures, 512 * 1024) };
    };
    const form = autopsyForm({ reason: { required: true, max: 1000 } }, async (body) => {
      const id = rule.input.autopsyValue();
      const current = rules.items.find((item) => item.id === id);
      await api("/api/autopsy/sigma/publish", { method: "POST", body: { ...body, ...await compile(), ...(current ? { rule_id: id, version: current.version } : {}) } });
      await window.SOCifyAutopsy.library();
    });
    form.prepend(field("مصدر Sigma", source), field("fixtures JSON: positive وnegative، كل قائمة أحداث مطبّعة", fixtures), field("إصدار جديد لقاعدة موجودة · اتركه فارغًا لقاعدة جديدة", rule.control));
    form.append(autopsyAction("تحقق من الترجمة والاختبارات دون نشر", async () => { const result = await api("/api/autopsy/sigma/compile", { method: "POST", body: await compile() }); preview.replaceChildren(node("p", { text: "اجتازت الأمثلة الإيجابية والسلبية. التحقق لا يثبت تغطية جميع التهديدات." }), node("pre", { text: JSON.stringify(result.compiled, null, 2) })); }), preview);
    root.append(panel("تحقق ونشر Sigma subset", node("div", { class: "panel-body" }, [node("p", { text: `النطاق: ${rules.capabilities.conditions}. غير المدعوم يُرفض: ${rules.capabilities.unsupported.join("، ")}. لا يثبت اجتياز fixtures دقة الكشف في بيانات الشركة.` }), form]), true));
  }
  if (permission("cases.create") && permission("evidence.add")) {
    const file = node("input", { type: "file", accept: ".zip,application/zip", required: true, "aria-label": "حزمة قضية محلية" });
    const form = node("form", { class: "form-grid" }, [field("حزمة ZIP محلية · حتى 64 MiB موسعة", file), node("button", { type: "submit", class: "button primary", text: "استعادة كقضية جديدة" })]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); const control = form.querySelector("button"); control.disabled = true; try { if (!file.files[0] || file.files[0].size > 64 * 1024 * 1024 + 524288) throw new Error("حجم الحزمة يتجاوز الحد"); const body = new FormData(); body.set("file", file.files[0]); const result = await api("/api/cases/import-capsule", { method: "POST", body }); window.location.assign(`/cases/${result.case_id}?tab=reports`); } catch (error) { handleError(error); control.disabled = false; } });
    root.append(panel("استعادة حزمة قضية", node("div", { class: "panel-body" }, [node("p", { text: "تُفحص البصمات والمسارات والحدود قبل الاستعادة. تحفظ إفادات واعتمادات المالك السابق في أرشيف ثابت للمراجعة ولا تمنح صلاحية أو اعتمادًا محليًا تلقائيًا." }), form]), true));
  }
  finish(root);
};

window.SOCifyAutopsy.localDetection = async (caseId) => {
  const base = `/api/cases/${caseId}`;
  const [observables, alerts] = await Promise.all([api(base + "/observables"), api(base + "/alerts")]);
  const root = node("div", { class: "panel-body" });
  root.append(node("p", { text: "الإثراء من snapshots الشركة المحلية فقط؛ عدم التطابق أو انتهاء المصدر لا يثبت سلامة المؤشر. تعرض الصفحة أول 100 مؤشر وتنبيه؛ بقية الصفحات متاحة عبر API." }), linkedButton("مكتبة المصادر والقواعد", "/analysis-library"));
  root.append(table([{ label: "القيمة", value: "value" }, { label: "النوع", value: "type" }, { label: "السجلات الفعالة", value: "occurrences" }, { label: "نتيجة آخر فحص", value: (row) => `${row.enrichment.status} · ${row.enrichment.verdict}` }, { label: "المصدر والتحقق", value: (row) => autopsyAction("تفاصيل الإثراء", async () => { const content = node("div", {}, node("pre", { text: JSON.stringify(row.enrichment, null, 2) })); if (autopsy.current.can_update && autopsy.current.status !== "closed") content.append(autopsyAction("إثراء محلي بالإصدارات الحالية", async () => { await api(base + `/observables/${row.id}/enrich`, { method: "POST", body: {} }); await autopsyCase(caseId); })); autopsyModal("مصدر نتيجة الإثراء وحدودها", content); }) }], observables.items));
  if (autopsy.current.can_update && autopsy.current.status !== "closed") {
    root.append(autopsyForm({ mode: { required: true, choices: ["rules", "anomaly"] }, after_id: { integer: true, min: 0, max: Number.MAX_SAFE_INTEGER } }, async (body) => { const job = await api(base + "/detection", { method: "POST", body: { ...body, after_id: body.after_id || 0, version: autopsy.current.version } }); autopsyModal("تحليل محلي في الطابور", node("div", {}, [node("p", { text: `العمل ${job.id} · حد الدفعة 1000 سجل. نتائج الشذوذ تحتاج 20 سجلًا سابقًا صالحًا للـbaseline. استخدم next_after_id من النتيجة لاستكمال النطاق.` }), autopsyAction("تحديث حالة العمل", async () => { const status = await api(base + `/jobs/${job.id}`); autopsyModal("حالة التحليل", node("pre", { text: JSON.stringify(status, null, 2) })); }), linkedButton("نتائج التحليل داخل القضية", `/cases/${caseId}?tab=analysis`)])); }));
  }
  root.append(table([{ label: "التنبيه", value: "reason" }, { label: "الخطر", value: "severity" }, { label: "تقييم المحقق", value: (row) => `${autopsyLabel(row.review.verdict)} · ${autopsyLabel(row.review.attack_outcome)}` }, { label: "مجموعة / نطاق", value: (row) => `${row.review.group || "—"}${row.historical_derivation ? " · نسخة تاريخية" : ""}${row.suppressed ? " · إشعار مكبوت مؤقتًا" : ""}` }, { label: "المراجعة", value: (row) => autopsyAction("تفاصيل ومراجعة", async () => {
    const content = node("div", {}, node("pre", { text: JSON.stringify({ evidence: row.evidence, trace: row.trace, review: row.review }, null, 2) }));
    if (autopsy.current.can_update && autopsy.current.status !== "closed") content.append(autopsyForm({ verdict: { required: true, choices: autopsy.catalog.verdicts }, attack_outcome: { required: true, choices: autopsy.catalog.outcomes }, group: { max: 100 }, suppressed_until: { timestamp: true }, reason: { required: true, max: 2000 } }, async (body) => { await api(base + `/alerts/${row.id}`, { method: "PATCH", body: { ...body, version: row.review_version, group: body.group || "", suppressed_until: body.suppressed_until || null } }); await autopsyCase(caseId); }, row.review));
    autopsyModal("الأدلة وقرار التنبيه منفصل عن نتيجة الهجوم", content);
  }) }], alerts.items));
  return panel("الإثراء والكشف ومراجعة التنبيهات", root, true);
};

window.SOCifyAutopsy.capsules = async (caseId) => {
  const root = node("div", { class: "panel-body" }, [node("p", { text: "حزمة الفريق تستبعد الملاحظات الخاصة والعينات وملفات التقارير الأصلية. النسخة الكاملة تحفظها وتتطلب المدير وصلاحية تنزيل العينات. SHA-256 يثبت اتساق المحتوى ولا يثبت هوية المصدر الخارجي." }), linkedButton("استعادة حزمة كقضية جديدة", "/analysis-library")]);
  if (permission("cases.export") && permission("evidence.download")) {
    root.append(linkedButton("تصدير حزمة الفريق", `/api/cases/${caseId}/capsule?profile=team`));
    if (autopsy.current.can_manage && permission("samples.download")) root.append(linkedButton("تنزيل نسخة كاملة حساسة", `/api/cases/${caseId}/capsule?profile=backup`));
  }
  const archives = await api(`/api/cases/${caseId}/capsules`);
  root.append(table([{ label: "مرجع المصدر", value: "source_reference" }, { label: "السياسة", value: "profile" }, { label: "البصمة", value: "sha256" }, { label: "الأرشيف الأجنبي", value: (row) => autopsyAction("فحص الأرشيف", async () => {
    const select = autopsySelect("section", ["case", "context", "autopsy_records", "revisions", "autopsy_custody", "autopsy_reports", "case_tasks", "case_history", "actors", "manifest"]);
    const display = node("pre");
    let page = 1;
    const show = async () => { const data = await api(`/api/cases/${caseId}/capsules/${row.id}/snapshot?section=${select.value}&page=${page}`); display.textContent = JSON.stringify(data, null, 2); };
    select.addEventListener("change", () => { page = 1; show().catch(handleError); });
    autopsyModal("أرشيف ثابت غير معتمد محليًا", node("div", {}, [field("القسم التاريخي", select), autopsyAction("السابق", async () => { page = Math.max(1, page - 1); await show(); }), autopsyAction("التالي", async () => { page += 1; await show(); }), display]));
    await show();
  }) }], archives.items));
  return panel("حزم القضية والاستعادة والأرشيف", root, true);
};

window.SOCifyAutopsy.workflow = async (caseId) => {
  const data = await api(`/api/cases/${caseId}/workflow`), current = autopsy.current, base = `/api/cases/${caseId}`;
  const root = node("div", { class: "panel-body" }, [node("p", { text: `SLA: ${data.sla.status} · ${data.sla.notification || "لا إشعار تجاوز مسجل"}` }), node("details", {}, [node("summary", { text: "قياسات الاستجابة وأساس حسابها" }), node("pre", { text: JSON.stringify(data.metrics, null, 2) })])]);
  if (current.can_manage && current.status !== "closed") {
    root.append(autopsyForm({ minutes: { required: true, integer: true, min: 1, max: 525600 }, mode: { required: true, choices: ["24x7", "business"] }, timezone: { required: true, choices: autopsy.catalog.source_timezones }, weekdays: { required: true, choices: ["mon_fri", "sun_thu"] }, start_hour: { required: true, integer: true, min: 0, max: 23 }, end_hour: { required: true, integer: true, min: 1, max: 24 }, reason: { required: true, max: 1000 } }, async (body) => { const calendar = { mode: body.mode, timezone: body.timezone }; if (body.mode === "business") Object.assign(calendar, { weekdays: body.weekdays === "sun_thu" ? [6, 0, 1, 2, 3] : [0, 1, 2, 3, 4], start_hour: body.start_hour, end_hour: body.end_hour, holidays: [] }); await api(base + "/sla", { method: "POST", body: { version: current.version, minutes: body.minutes, calendar, reason: body.reason } }); await autopsyCase(caseId); }, { mode: "24x7", timezone: "Asia/Riyadh", weekdays: "sun_thu", start_hour: 9, end_hour: 17 }));
    if (data.sla.configured) root.append(autopsyAction(data.sla.status === "paused" ? "استئناف SLA" : "إيقاف SLA مؤقتًا", async () => { let dialog; dialog = autopsyModal("تغيير ساعة SLA مع توثيق السبب", autopsyForm({ reason: { required: true, max: 1000 } }, async (body) => { await api(base + `/sla/${data.sla.status === "paused" ? "resume" : "pause"}`, { method: "POST", body: { ...body, version: current.version } }); dialog.close(); await autopsyCase(caseId); })); }));
  }
  if (current.can_update && current.status !== "closed") root.append(autopsyForm({ recipe_id: { required: true, choices: Object.entries(data.recipes).map(([value, item]) => ({ value, label: item.title })) }, collector_id: { required: true, user: true, case_member: true }, reason: { required: true, max: 2000 } }, async (body) => { await api(base + "/collections", { method: "POST", body: { ...body, version: current.version } }); await autopsyCase(caseId); }));
  for (const item of data.collections) {
    const body = item.payload;
    const card = node("article", { class: "card" }, [node("h4", { text: body.recipe_snapshot.title }), node("p", { text: `${body.state} · ${body.reason}` }), node("p", { text: body.recipe_snapshot.guidance })]);
    if (current.can_manage && body.state === "pending_approval") for (const action of ["approve", "reject"]) card.append(autopsyAction(action === "approve" ? "اعتماد نطاق الجمع" : "رفض نطاق الجمع", async () => { let dialog; dialog = autopsyModal("توثيق قرار نطاق الجمع", autopsyForm({ reason: { required: true, max: 1000 } }, async (values) => { await api(base + `/collections/${item.id}/${action}`, { method: "POST", body: { ...values, version: item.version, case_version: current.version } }); dialog.close(); await autopsyCase(caseId); })); }));
    if (current.can_update && body.state === "approved" && (current.can_manage || body.collector_id === state.user.id)) card.append(autopsyAction("توثيق الجمع المنفذ محليًا", async () => {
      let dialog;
      const artifacts = node("select", { multiple: true, required: true, "aria-label": "المصادر المجمعة فعليًا" }, body.recipe_snapshot.artifacts.map((value) => node("option", { value, text: value })));
      const form = autopsyForm({ evidence_id: { required: true, evidence: true }, tool: { required: true, max: 255 }, source: { required: true, max: 500 }, collected_at: { required: true, timestamp: true } }, async (values) => { await api(base + `/collections/${item.id}/document`, { method: "POST", body: { ...values, artifacts: [...artifacts.selectedOptions].map((option) => option.value), version: item.version, case_version: current.version } }); dialog.close(); await autopsyCase(caseId); });
      form.prepend(field("المصادر التي جُمعت فعليًا · يمكن اختيار عدة عناصر", artifacts));
      dialog = autopsyModal("توثيق جمع أدلة مخول؛ لا تنفيذ أوامر على الأجهزة", form);
    }));
    root.append(card);
  }
  if (current.can_update && ["closed", "awaiting_review", "recovered", "remediated", "contained"].includes(current.status)) root.append(autopsyAction("إنشاء مسودة مراجعة ما بعد الحادثة", async () => { await api(base + "/postmortems", { method: "POST", body: { version: current.version } }); await autopsyCase(caseId); }));
  for (const item of data.postmortems) {
    const card = node("article", { class: "card" }, [node("h4", { text: `مراجعة ما بعد الحادثة · ${item.payload.state}` }), node("p", { text: item.payload.executive_summary }), node("p", { text: item.payload.lessons || "الدروس تحتاج مراجعة المحقق" }), node("p", { text: item.payload.limitations })]);
    if (current.can_approve && item.payload.state === "draft") card.append(autopsyAction("مراجعة المسودة", async () => { let dialog; dialog = autopsyModal("مراجعة مستقلة للدروس والقيود", autopsyForm({ executive_summary: { required: true, max: 5000 }, lessons: { required: true, max: 5000 }, limitations: { required: true, max: 5000 }, override_reason: { max: 1000 } }, async (values) => { await api(base + `/postmortems/${item.id}/review`, { method: "POST", body: { ...values, version: item.version, case_version: current.version } }); dialog.close(); await autopsyCase(caseId); }, item.payload)); }));
    root.append(card);
  }
  return panel("SLA وجمع الأدلة ومراجعة ما بعد الحادثة", root, true);
};
