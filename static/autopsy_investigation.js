"use strict";

Object.assign(autopsyLabels, { bookmark: "علامات السجلات المهمة", timeline_view: "مناظر الخط الزمني", query: "كلمات البحث", color: "لون العلامة", blue: "أزرق", orange: "برتقالي", gold: "ذهبي", start: "بداية الفترة", end: "نهاية الفترة", suggested: "مقترح", verified: "مثبت بدليل", rejected: "مرفوض بدليل" });

window.SOCifyAutopsy.investigation = async (caseId) => {
  const root = node("div");
  const viewport = node("div");
  const filters = node("form", { class: "filter-row" });
  const query = node("input", { name: "timeline_q", type: "search", maxlength: 200 });
  const start = node("input", { name: "timeline_start", type: "datetime-local" });
  const end = node("input", { name: "timeline_end", type: "datetime-local" });
  let visibleEvents = [];
  const localTime = (value) => { if (!value) return ""; const date = new Date(value); return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
  const severity = node("select", { name: "timeline_severity" }, [node("option", { value: "", text: "كل درجات الخطورة" }), ...["critical", "high", "medium", "low"].map((value) => node("option", { value, text: autopsyLabel(value) }))]);
  filters.append(field("بحث الخط الزمني", query), field("الخطورة", severity), field("بداية الفترة · وقت المتصفح", start), field("نهاية الفترة · وقت المتصفح", end), node("button", { type: "submit", class: "button ghost", text: "تطبيق الفلاتر" }));
  const load = async (page = 1) => {
    const parameters = new URLSearchParams({ page, limit: 50, q: query.value });
    if (severity.value) parameters.set("severity", severity.value);
    if (start.value) parameters.set("start", new Date(start.value).toISOString());
    if (end.value) parameters.set("end", new Date(end.value).toISOString());
    const data = await api(`/api/cases/${caseId}/timeline?${parameters}`);
    visibleEvents = data.items;
    const timeline = node("ol", { class: "autopsy-timeline" });
    for (const event of data.items) {
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
    const pages = node("div", { class: "action-row" }, node("p", { text: `${data.total} سجل · الصفحة ${page}` }));
    if (page > 1) pages.append(button("السابق", () => load(page - 1).catch(handleError)));
    if (page * 50 < data.total) pages.append(button("التالي", () => load(page + 1).catch(handleError)));
    const views = node("div", { class: "action-row" });
    for (const view of data.views) views.append(button(view.payload.title, () => { query.value = view.payload.query || ""; severity.value = view.payload.severity || ""; start.value = localTime(view.payload.start); end.value = localTime(view.payload.end); load().catch(handleError); }));
    viewport.replaceChildren(views, timeline, pages);
  };
  filters.addEventListener("submit", (event) => { event.preventDefault(); load().catch(handleError); });
  if (autopsy.current.can_update && autopsy.current.status !== "closed") filters.append(button("حفظ منظر البحث", () => {
    let dialog;
    const form = autopsyForm({ title: { required: true, max: 160 }, visibility: { required: true, choices: ["team", "private"] } }, async (payload) => { await api(`/api/cases/${caseId}/records/timeline_view`, { method: "POST", body: { ...payload, query: query.value, ...(severity.value ? { severity: severity.value } : {}), ...(start.value ? { start: new Date(start.value).toISOString() } : {}), ...(end.value ? { end: new Date(end.value).toISOString() } : {}) } }); dialog.close(); await load(); }, { visibility: "team" });
    dialog = autopsyModal("حفظ مرشحات الخط الزمني", form);
  }));
  root.append(panel("الخط الزمني الموحد للسجلات", node("div", { class: "panel-body" }, [filters, viewport]), true));
  await load();
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
