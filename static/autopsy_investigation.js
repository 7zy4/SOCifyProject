"use strict";

Object.assign(autopsyLabels, { bookmark: "علامات السجلات المهمة", timeline_view: "مناظر الخط الزمني", query: "كلمات البحث", color: "لون العلامة", blue: "أزرق", orange: "برتقالي", gold: "ذهبي", start: "بداية الفترة", end: "نهاية الفترة", suggested: "مقترح", verified: "مثبت بدليل", rejected: "مرفوض بدليل" });
Object.assign(autopsyLabels, { documentation_time: "وقت التوثيق؛ ليس وقت وقوع الهجوم", reported_action_time: "وقت إجراء مسجل بواسطة المنفذ", investigator_observation_time: "وقت ملاحظة أدخله المحقق", hypothesis_time: "توقيت فرضية غير مؤكدة", escalation_time: "وقت إحالة داخل الفريق؛ ليس وقت وقوع الهجوم", legacy_note: "ملاحظة محفوظة" });

window.SOCifyAutopsy.investigation = async (caseId) => {
  const root = node("div");
  const viewport = node("div");
  const filters = node("form", { class: "filter-row" });
  const query = node("input", { name: "timeline_q", type: "search", maxlength: 200 });
  const start = node("input", { name: "timeline_start", type: "datetime-local" });
  const end = node("input", { name: "timeline_end", type: "datetime-local" });
  let visibleEvents = [];
  const localTime = (value) => { if (!value) return ""; const date = new Date(value); if (!Number.isFinite(date.getTime()) || !/(?:Z|[+-]\d{2}:\d{2})$/.test(value)) throw new Error("مرشح الوقت غير صالح أو لا يحدد منطقة زمنية؛ راجع رابط القضية"); return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
  const severity = node("select", { name: "timeline_severity" }, [node("option", { value: "", text: "كل درجات الخطورة" }), ...["critical", "high", "medium", "low"].map((value) => node("option", { value, text: autopsyLabel(value) }))]);
  const scope = node("select", { name: "timeline_scope" }, [node("option", { value: "all", text: "السجلات والتحقيق والإجراءات" }), node("option", { value: "logs", text: "السجلات فقط" })]);
  const saved = new URLSearchParams(window.location.search);
  query.value = saved.get("timeline_q") || "";
  severity.value = saved.get("timeline_severity") || "";
  start.value = localTime(saved.get("timeline_start"));
  end.value = localTime(saved.get("timeline_end"));
  if (saved.has("timeline_scope") && !["all", "logs"].includes(saved.get("timeline_scope"))) throw new Error("نطاق الخط الزمني غير معروف؛ راجع رابط القضية");
  scope.value = saved.get("timeline_scope") || "all";
  filters.append(field("نطاق الخط الزمني", scope), field("بحث الخط الزمني", query), field("خطورة السجلات", severity), field("بداية الفترة · وقت المتصفح", start), field("نهاية الفترة · وقت المتصفح", end), node("button", { type: "submit", class: "button ghost", text: "تطبيق الفلاتر" }));
  const load = async (page = 1) => {
    const parameters = new URLSearchParams({ page, limit: 50, q: query.value });
    if (severity.value) parameters.set("severity", severity.value);
    if (start.value) parameters.set("start", new Date(start.value).toISOString());
    if (end.value) parameters.set("end", new Date(end.value).toISOString());
    const data = await api(`/api/cases/${caseId}/${scope.value === "all" ? "chronology" : "timeline"}?${parameters}`);
    window.history.replaceState(null, "", autopsyCaseURL(caseId, { timeline_scope: scope.value, timeline_q: query.value, timeline_severity: severity.value, timeline_start: parameters.get("start"), timeline_end: parameters.get("end"), timeline_page: page > 1 ? page : null }));
    visibleEvents = data.items.filter((item) => !item.entry_type || item.entry_type === "log");
    const timeline = node("ol", { class: "autopsy-timeline" });
    for (const event of data.items) {
      if (event.entry_type && event.entry_type !== "log") {
        const actor = autopsy.team.members.find((member) => member.id === event.actor_id);
        const item = node("li", {}, [node("h3", { text: `${autopsyLabel(event.kind)} · ${event.title}` }), node("p", { text: `${formatTime(event.event_time)} · ${autopsyLabel(event.time_basis)}` }), node("small", { text: `${actor?.name || `عضو ${event.actor_id}`} · الإصدار ${event.version} · آخر تعديل ${formatTime(event.updated_at)}` })]);
        if (event.body) item.append(node("p", { text: event.body }));
        if (event.record) {
          const payload = event.record.payload;
          item.append(node("p", { text: payload.body || payload.details || payload.notes || payload.source || "" }));
          if (payload.decision) item.append(node("p", { text: `القرار: ${payload.decision}` }));
          if (event.kind === "response") item.append(node("p", { text: `${autopsyLabel(payload.phase)} · ${autopsyLabel(payload.status)}` }));
          if (payload.evidence_id) item.append(node("p", { text: `دليل القضية ${payload.evidence_id}` }));
          item.append(button("تفاصيل ملاحظة التحقيق", () => autopsyModal("سجل التحقيق وإصداره وأدلته", autopsyRecordCard(event.record))));
        }
        if (event.future_time) item.append(node("p", { class: "notice", text: "طابع زمني مستقبلي يحتاج مراجعة؛ لا يدخل قياسات الاستجابة المؤكدة." }));
        timeline.append(item);
        continue;
      }
      const marks = data.bookmarks.filter((item) => item.payload.event_id === event.id);
      const content = node("li", { class: marks.length ? `timeline-mark-${marks[0].payload.color || "blue"}` : "" }, [node("h3", { text: event.title }), node("p", { text: `${event.observed_time_known ? formatTime(event.event_time) : "وقت الحدث غير معروف؛ لا يُستبدل بوقت الاستيراد"} · ${event.source} · ${autopsyLabel(event.severity)}` }), node("p", { text: `أساس التوقيت: ${event.time_basis}` }), node("small", { text: `وقت الاستيراد: ${formatTime(event.ingested_at)}` })]);
      for (const mark of marks) content.append(node("p", { text: `${mark.payload.title} · ${mark.payload.notes || ""} · ${(mark.payload.tags || []).join(", ")}` }));
      content.append(button("تفاصيل السجل", async () => { try { const detail = await api(`/api/cases/${caseId}/logs/${event.id}`); autopsyModal("الدليل الخام والمطبع", node("pre", { text: JSON.stringify(detail, null, 2) })); } catch (error) { handleError(error); } }));
      if (autopsy.current.can_update && autopsy.current.status !== "closed") content.append(button("تمييز السجل وإضافة ملاحظة", () => {
        let dialog;
        const form = autopsyForm({ title: { required: true, max: 255 }, color: { choices: ["blue", "orange", "gold"] }, tags: { list: true }, notes: { max: 2000 }, visibility: { required: true, choices: ["team", "private"] } }, async (payload) => { await api(`/api/cases/${caseId}/records/bookmark`, { method: "POST", body: { ...payload, event_id: event.id } }); dialog.close(); await load(page); }, { title: event.title, color: "blue", visibility: "team" });
        dialog = autopsyModal("علامة مرتبطة بسجل القضية", form);
      }));
      timeline.append(content);
    }
    const pages = node("div", { class: "action-row" }, node("p", { text: `${data.total_relation === "gte" ? "على الأقل " : ""}${data.total} عنصر · الصفحة ${page}` }));
    if (page > 1) pages.append(button("السابق", () => load(page - 1).catch(handleError)));
    if (data.has_next ?? (page * 50 < data.total)) pages.append(button("التالي", () => load(page + 1).catch(handleError)));
    const views = node("div", { class: "action-row" });
    for (const view of data.views) views.append(button(view.payload.title, () => { scope.value = view.payload.scope || "logs"; query.value = view.payload.query || ""; severity.value = view.payload.severity || ""; start.value = localTime(view.payload.start); end.value = localTime(view.payload.end); load().catch(handleError); }));
    viewport.replaceChildren(views, node("p", { class: "notice", text: data.limits }), timeline, pages);
  };
  filters.addEventListener("submit", (event) => { event.preventDefault(); load().catch(handleError); });
  if (autopsy.current.can_update && autopsy.current.status !== "closed") filters.append(button("حفظ منظر البحث", () => {
    let dialog;
    const form = autopsyForm({ title: { required: true, max: 160 }, visibility: { required: true, choices: ["team", "private"] } }, async (payload) => { await api(`/api/cases/${caseId}/records/timeline_view`, { method: "POST", body: { ...payload, scope: scope.value, query: query.value, ...(severity.value ? { severity: severity.value } : {}), ...(start.value ? { start: new Date(start.value).toISOString() } : {}), ...(end.value ? { end: new Date(end.value).toISOString() } : {}) } }); dialog.close(); await load(); }, { visibility: "team" });
    dialog = autopsyModal("حفظ مرشحات الخط الزمني", form);
  }));
  root.append(panel("الخط الزمني الموحد للسجلات", node("div", { class: "panel-body" }, [filters, viewport]), true));
  await load(Math.max(1, Number(saved.get("timeline_page")) || 1));
  const graph = await api(`/api/cases/${caseId}/graph?limit=30`);
  const graphBody = node("div", { class: "panel-body" }, node("p", { text: `${graph.event_count} سجل · ${graph.nodes.length} كيان · ${graph.edges.length} علاقة. ${graph.limitations}${graph.truncated ? " عرض محدود؛ لا يمثل كل السجلات." : ""}` }));
  const graphNodes = graph.nodes.slice(0, 180);
  const canvas = node("div", { class: "graph-canvas", tabindex: "0", "aria-label": "علاقات الأدلة؛ يوجد جدول بديل أسفل الرسم" });
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const width = 900, height = Math.max(200, Math.ceil(graphNodes.length / 3) * 90);
  svg.setAttribute("width", width); svg.setAttribute("height", height); svg.setAttribute("viewBox", `0 0 ${width} ${height}`); svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "علاقات مرصودة ضمن القضية الحالية");
  const positions = new Map(graphNodes.map((item, index) => [item.id, { x: 150 + (index % 3) * 300, y: 45 + Math.floor(index / 3) * 90 }]));
  for (const edge of graph.edges) {
    const from = positions.get(edge.source), to = positions.get(edge.target);
    if (!from || !to) continue;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    for (const [key, value] of Object.entries({ x1: from.x, y1: from.y, x2: to.x, y2: to.y, stroke: "#1C4286" })) line.setAttribute(key, String(value));
    svg.append(line);
  }
  for (const item of graphNodes) {
    const position = positions.get(item.id);
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", position.x); text.setAttribute("y", position.y); text.setAttribute("text-anchor", "middle"); text.setAttribute("fill", "#1C4286");
    text.textContent = displayText(`${item.type}: ${item.label}`).slice(0, 30);
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title"); title.textContent = displayText(item.label); text.append(title); svg.append(text);
  }
  canvas.append(svg);
  graphBody.append(canvas, panel("جدول العلاقات ومراجع الأدلة", table([{ label: "الكيان", value: "label" }, { label: "النوع", value: "type" }, { label: "المرجع", value: "reference_id" }, { label: "طبيعة الربط", value: "provenance" }], graph.nodes)));
  root.append(panel("رسم العلاقات داخل القضية", graphBody));
  const attackBody = node("div", { class: "panel-body" });
  const search = node("input", { name: "attack_search", type: "search", maxlength: 100, placeholder: "T1059 أو اسم التقنية" });
  const results = node("div");
  const searchForm = node("form", { class: "filter-row" }, [field("بحث كتالوج MITRE المحلي", search), node("button", { type: "submit", class: "button ghost", text: "بحث التقنيات" })]);
  const searchAttack = async () => {
    const catalog = await api(`/api/cases/${caseId}/attack?q=${encodeURIComponent(search.value)}`);
    const select = autopsyChoice("technique_id", catalog.items.filter((item) => !item.revoked && !item.deprecated).map((item) => ({ value: item.technique_id, label: `${item.technique_id} · ${item.name}` })), "", true);
    const evidence = autopsyChoice("event_id", visibleEvents.map((item) => ({ value: item.id, label: `${item.title} · ${item.id}` })), "", false);
    const annotation = autopsyForm({ assessment: { required: true, choices: ["suggested", "verified", "rejected"] }, reason: { required: true, max: 2000 } }, async (payload) => { const eventId = evidence.input.autopsyValue(); await api(`/api/cases/${caseId}/attack`, { method: "POST", body: { ...payload, technique_id: select.input.autopsyValue(), ...(eventId ? { event_id: eventId } : {}) } }); await searchAttack(); });
    annotation.prepend(field("تقنية من نتائج البحث المحلية", select.control), field("دليل من صفحة السجلات الحالية · أعد بحث التقنيات بعد تغيير مرشحات السجلات", evidence.control));
    results.replaceChildren(node("p", { text: `MITRE ATT&CK ${catalog.attack_version} · نسخة محلية · الحد ${catalog.limit} نتيجة. مرجع سجل الدليل ظاهر في الخط الزمني؛ الربط المثبت يتطلب سجلًا من القضية.` }));
    if (autopsy.current.can_update && autopsy.current.status !== "closed") results.append(annotation);
    results.append(table([{ label: "التقنية", value: "technique_id" }, { label: "الاسم", value: "name" }, { label: "الحكم", value: (item) => autopsyLabel(item.assessment) }, { label: "سجل الدليل", value: "event_id" }, { label: "السبب", value: "reason" }, { label: "إصدار ATT&CK", value: "attack_version" }], catalog.annotations));
  };
  searchForm.addEventListener("submit", (event) => { event.preventDefault(); searchAttack().catch(handleError); });
  attackBody.append(searchForm, results); await searchAttack();
  root.append(panel("توثيق MITRE ATT&CK بالأدلة", attackBody, true));
  return root;
};
