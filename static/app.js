"use strict";

const state = {
  section: document.querySelector('meta[name="section"]').content,
  csrf: document.querySelector('meta[name="csrf-token"]').content,
  permissions: new Set(),
  user: null
};

const workspace = document.getElementById("workspace");
const messageBox = document.getElementById("global-message");
const titles = {
  dashboard: ["مركز العمليات", "SECURITY OPERATIONS"],
  events: ["مستكشف السجلات", "NORMALIZED EVENT DATA"],
  alerts: ["قائمة التنبيهات", "DETECTION TRIAGE"],
  rules: ["قواعد الكشف", "DETECTION ENGINE"],
  sources: ["مصادر البيانات", "SOURCE MANAGEMENT"],
  imports: ["مركز الاستيراد", "SAFE INGESTION"],
  incidents: ["مساحة التحقيقات", "CASE MANAGEMENT"],
  lab: ["مختبر المحاكاة", "ATTACK CHAIN TRAINING"],
  attack: ["MITRE ATT&CK", "COVERAGE ANALYTICS"],
  hunt: ["مساحة الصيد", "PARAMETERIZED HUNTING"],
  graph: ["الرسم والأثر الزمني", "EVIDENCE VISUALIZATION"],
  playbooks: ["خطط الاستجابة", "SIMULATED SOAR"],
  scores: ["التقييم والنتائج", "ASSESSMENT ENGINE"],
  audit: ["سجل التدقيق", "IMMUTABLE ACTIVITY"],
  admin: ["إدارة المنصة", "ROLE GOVERNANCE"],
  profile: ["الملف والأمان", "ACCOUNT SECURITY"]
};

function node(tag, attributes = {}, children = []) {
  const element = document.createElement(tag);
  Object.entries(attributes).forEach(([key, value]) => {
    if (key === "class") element.className = value;
    else if (key === "text") element.textContent = value == null ? "—" : String(value);
    else if (key.startsWith("on") && typeof value === "function") element.addEventListener(key.slice(2), value);
    else if (value !== false && value != null) element.setAttribute(key, String(value));
  });
  const values = Array.isArray(children) ? children : [children];
  values.filter((value) => value != null).forEach((value) => element.append(value instanceof Node ? value : document.createTextNode(String(value))));
  return element;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat("ar-SA", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(date) + " UTC";
}

function badge(value) {
  return node("span", { class: `badge ${String(value || "").toLowerCase()}`, text: value || "—" });
}

function showMessage(text, type = "error") {
  messageBox.textContent = text;
  messageBox.className = `global-message ${type}`;
  messageBox.hidden = false;
  window.setTimeout(() => { messageBox.hidden = true; }, 5500);
}

async function api(path, options = {}) {
  const config = { credentials: "same-origin", ...options, headers: { Accept: "application/json", ...(options.headers || {}) } };
  if (config.body && !(config.body instanceof FormData) && typeof config.body !== "string") {
    config.headers["Content-Type"] = "application/json";
    config.body = JSON.stringify(config.body);
  }
  if (config.method && !["GET", "HEAD"].includes(config.method.toUpperCase())) config.headers["X-CSRFToken"] = state.csrf;
  const response = await fetch(path, config);
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("انتهت الجلسة");
  }
  let payload = null;
  if (response.status !== 204) {
    const contentType = response.headers.get("content-type") || "";
    payload = contentType.includes("json") ? await response.json() : await response.text();
  }
  if (!response.ok) {
    const error = new Error(payload?.error?.message || `تعذر إكمال الطلب (${response.status})`);
    error.code = payload?.error?.code;
    error.status = response.status;
    error.details = payload?.error?.details;
    throw error;
  }
  return payload;
}

function setHeading(section) {
  const [title, kicker] = titles[section] || titles.dashboard;
  document.getElementById("section-title").textContent = title;
  document.getElementById("section-kicker").textContent = kicker;
  document.title = `${title} | SOCify`;
  document.querySelectorAll("#primary-nav a").forEach((link) => link.classList.toggle("active", link.dataset.section === section));
}

function begin(section) {
  setHeading(section);
  workspace.setAttribute("aria-busy", "true");
  workspace.replaceChildren(node("div", { class: "loading" }, [node("span"), node("p", { text: "جارٍ تحميل البيانات المصرّح بها…" })]));
}

function finish(content) {
  workspace.replaceChildren(content);
  workspace.setAttribute("aria-busy", "false");
}

function pageHead(title, description, actions = []) {
  return node("div", { class: "workspace-head" }, [node("div", {}, [node("h2", { text: title }), node("p", { text: description })]), node("div", { class: "action-row" }, actions)]);
}

function emptyState(title, description, actions = []) {
  return node("div", { class: "empty" }, [node("strong", { text: title }), node("p", { text: description }), node("div", { class: "action-row" }, actions)]);
}

function table(columns, rows) {
  const head = node("thead", {}, node("tr", {}, columns.map((column) => node("th", { text: column.label, scope: "col" }))));
  const body = node("tbody");
  rows.forEach((row) => {
    body.append(node("tr", {}, columns.map((column) => {
      const value = typeof column.value === "function" ? column.value(row) : row[column.value];
      return node("td", {}, value instanceof Node ? value : value == null || value === "" ? "—" : String(value));
    })));
  });
  return node("div", { class: "table-wrap" }, node("table", {}, [head, body]));
}

function panel(title, content, wide = false, extra = null) {
  return node("section", { class: `panel${wide ? " wide" : ""}` }, [node("header", { class: "panel-head" }, [node("h3", { text: title }), extra]), content]);
}

function metric(label, value, style = "", detail = "من قاعدة البيانات") {
  return node("article", { class: `metric ${style}` }, [node("span", { text: label }), node("strong", { text: Number(value || 0).toLocaleString("ar-SA") }), node("small", { text: detail })]);
}

function button(label, handler, style = "ghost") {
  return node("button", { type: "button", class: `button ${style}`, text: label, onclick: handler });
}

function linkedButton(label, href, style = "ghost") {
  return node("a", { class: `button ${style}`, href, text: label });
}

function permission(name) {
  return state.permissions.has("*") || state.permissions.has(name);
}

async function renderDashboard() {
  begin("dashboard");
  const data = await api("/api/dashboard");
  const root = node("div");
  root.append(pageHead("الموقف الأمني الآن", `النطاق: ${data.scope} · آخر تحديث ${formatTime(data.generated_at)}`, [linkedButton("تشغيل سيناريو", "/lab", "primary"), linkedButton("استيراد سجلات", "/imports")]));
  root.append(node("section", { class: "metric-grid", "aria-label": "مؤشرات المنصة" }, [
    metric("السجلات", data.counts.events), metric("تنبيهات مفتوحة", data.counts.open_alerts, "attention"), metric("تحقيقات نشطة", data.counts.active_cases), metric("أحداث حرجة", data.counts.critical_events, "critical"), metric("SLA متجاوز", data.counts.overdue_cases, "attention")
  ]));
  const grid = node("div", { class: "panel-grid" });
  const alertColumns = [
    { label: "المعرف", value: (row) => node("a", { href: `/alerts?selected=${row.id}`, class: "mono", text: row.alert_id }) },
    { label: "السبب", value: "reason" }, { label: "الخطورة", value: (row) => badge(row.severity) }, { label: "الحالة", value: (row) => badge(row.status) }, { label: "الوقت", value: (row) => formatTime(row.detected_at) }
  ];
  const caseColumns = [
    { label: "المرجع", value: (row) => node("a", { href: `/incidents?selected=${row.id}`, class: "mono", text: row.reference }) },
    { label: "العنوان", value: "title" }, { label: "الخطورة", value: (row) => badge(row.severity) }, { label: "الحالة", value: (row) => badge(row.status) }, { label: "آخر تحديث", value: (row) => formatTime(row.updated_at) }
  ];
  grid.append(panel("أحدث التنبيهات", data.recent_alerts.length ? table(alertColumns, data.recent_alerts) : emptyState("لا توجد تنبيهات", "لا تعرض المنصة عينات وهمية. ابدأ سيناريو أو استورد بيانات لتشغيل الكشف.", [linkedButton("ابدأ من المختبر", "/lab", "primary")])));
  grid.append(panel("التحقيقات النشطة", data.recent_cases.length ? table(caseColumns, data.recent_cases) : emptyState("مساحة التحقيق خالية", "أنشئ تحقيقًا يدويًا أو افتح واحدًا من تنبيه موثّق.", [linkedButton("إنشاء تحقيق", "/incidents", "primary")])));
  const healthColumns = [{ label: "القاعدة", value: "name" }, { label: "نشطة", value: (row) => badge(row.is_active ? "active" : "disabled") }, { label: "مطابقات", value: "match_count" }, { label: "إخفاقات", value: "failed_evaluations" }, { label: "متوسط ms", value: "average_evaluation_ms" }, { label: "آخر تشغيل", value: (row) => formatTime(row.last_triggered_at) }];
  grid.append(panel("صحة قواعد الكشف", data.rule_health.length ? table(healthColumns, data.rule_health) : emptyState("لا توجد قواعد", "يحتاج الكشف إلى قواعد منشورة قبل استقبال الأحداث."), true));
  root.append(grid);
  finish(root);
}

async function renderEvents() {
  begin("events");
  const root = node("div");
  const search = node("input", { type: "search", placeholder: "ابحث في العنوان أو المستخدم أو IP", "aria-label": "بحث السجلات" });
  const severity = node("select", { "aria-label": "تصفية الخطورة" }, [node("option", { value: "", text: "كل الخطورات" }), ...["critical", "high", "medium", "low"].map((value) => node("option", { value, text: value }))]);
  const body = node("div");
  async function load() {
    body.replaceChildren(node("div", { class: "loading" }, node("span")));
    const params = new URLSearchParams({ page_size: "100" });
    if (search.value) params.set("q", search.value);
    if (severity.value) params.set("severity", severity.value);
    const data = await api(`/api/events?${params}`);
    const columns = [
      { label: "الوقت", value: (row) => formatTime(row.event_time) }, { label: "السجل", value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.title }), node("small", { text: `${row.event_id} · ${row.event_type}` })]) },
      { label: "المصدر", value: "source" }, { label: "المستخدم / المضيف", value: (row) => `${row.username || "—"} / ${row.hostname || "—"}` }, { label: "IP المصدر", value: (row) => node("span", { class: "mono", text: row.source_ip }) }, { label: "الخطورة", value: (row) => badge(row.severity) }, { label: "الحالة", value: (row) => badge(row.status) }
    ];
    body.replaceChildren(data.items.length ? table(columns, data.items) : emptyState("لا توجد سجلات مطابقة", "جرّب تغيير المرشح أو استورد ملفًا مصرحًا.", [linkedButton("مركز الاستيراد", "/imports", "primary")]));
  }
  const filter = node("div", { class: "filter-row" }, [search, severity, button("تطبيق", () => load().catch(handleError), "primary"), linkedButton("تصدير CSV آمن", "/api/events/export")]);
  root.append(pageHead("السجلات الموحّدة", "بيانات فعلية محفوظة مع المصدر الخام وأثر التطبيع", [linkedButton("استيراد جديد", "/imports", "primary")]), filter, panel("النتائج", body, true));
  finish(root);
  await load();
}

async function renderAlerts() {
  begin("alerts");
  const data = await api("/api/alerts?page_size=100");
  const root = node("div");
  const content = node("div");
  const columns = [
    { label: "التنبيه", value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.reason }), node("small", { class: "mono", text: row.alert_id })]) }, { label: "القاعدة", value: "rule_name" },
    { label: "الخطورة", value: (row) => badge(row.severity) }, { label: "الثقة", value: (row) => `${Math.round(Number(row.confidence) * 100)}%` }, { label: "الحالة", value: (row) => badge(row.status) }, { label: "الوقت", value: (row) => formatTime(row.detected_at) },
    { label: "إجراء", value: (row) => node("div", { class: "action-row" }, [button("تحقيق", async () => { try { const created = await api(`/api/alerts/${row.id}/case`, { method: "POST", body: {} }); showMessage(`أُنشئ التحقيق ${created.reference}`, "success"); } catch (error) { handleError(error); } }, "compact"), button("فرز", async () => { try { await api(`/api/alerts/${row.id}/triage`, { method: "POST", body: { status: "triaged" } }); await renderAlerts(); } catch (error) { handleError(error); } }, "compact")]) }
  ];
  content.append(data.items.length ? table(columns, data.items) : emptyState("لا توجد تنبيهات", "شغّل سيناريو أو استورد بيانات. لن نعرض أرقامًا تجريبية زائفة.", [linkedButton("تشغيل سيناريو", "/lab", "primary")]));
  root.append(pageHead("قائمة الفرز", `${data.total} تنبيهًا ضمن النطاق المصرح`, [linkedButton("قواعد الكشف", "/rules")]), panel("التنبيهات", content, true));
  finish(root);
}

async function renderRules() {
  begin("rules");
  const data = await api("/api/rules");
  const root = node("div");
  const drawer = node("section", { class: "drawer", hidden: true });
  drawer.innerHTML = '<h3>قاعدة كشف جديدة</h3><form id="rule-form" class="form-grid"><label>الاسم<input name="name" required minlength="3" maxlength="150"></label><label>الخطورة<select name="severity"><option>medium</option><option>critical</option><option>high</option><option>low</option></select></label><label class="span-2">الوصف<textarea name="description" maxlength="2000"></textarea></label><label class="span-2">DSL آمن<textarea class="json-input" name="dsl" required>{"all":[{"field":"event_type","operator":"equals","value":"failed_login"}],"window":{"seconds":600,"threshold":5,"group_by":["source_ip"]},"mitre_ids":["T1110"]}</textarea></label><label><input name="active" type="checkbox"> نشر وتفعيل فورًا</label><div class="action-row"><button class="button primary" type="submit">حفظ القاعدة</button><button id="cancel-rule" class="button ghost" type="button">إلغاء</button></div></form>';
  const columns = [
    { label: "القاعدة", value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.name }), node("small", { text: row.description })]) }, { label: "الإصدار", value: (row) => `v${row.version}` }, { label: "النشر", value: (row) => badge(row.deployment_state) }, { label: "مطابقات", value: "match_count" }, { label: "False +", value: "false_positive_count" }, { label: "ms", value: "average_evaluation_ms" },
    { label: "إجراء", value: (row) => permission("rules.manage") ? button(row.is_active ? "تعطيل" : "تفعيل", async () => { try { await api(`/api/rules/${row.id}/toggle`, { method: "POST", body: { active: !Boolean(row.is_active) } }); await renderRules(); } catch (error) { handleError(error); } }, "compact") : "قراءة فقط" }
  ];
  const actions = permission("rules.manage") ? [button("قاعدة جديدة", () => { drawer.hidden = false; drawer.querySelector("input").focus(); }, "primary")] : [];
  root.append(pageHead("منضدة قواعد الكشف", "DSL typed بلا eval أو SQL من المستخدم، مع إصدارات وصحة قابلة للقياس", actions), drawer, panel("القواعد", data.items.length ? table(columns, data.items) : emptyState("لا توجد قواعد كشف", "أنشئ قاعدة من DSL الصارم أو فعّل بيانات التطوير الصريحة."), true));
  finish(root);
  const form = document.getElementById("rule-form");
  if (form) {
    document.getElementById("cancel-rule").addEventListener("click", () => { drawer.hidden = true; });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const values = new FormData(form);
      try {
        await api("/api/rules", { method: "POST", body: { name: values.get("name"), description: values.get("description"), dsl: JSON.parse(values.get("dsl")), action: { severity: values.get("severity"), confidence: .85 }, active: values.get("active") === "on", change_summary: "Created from rules workbench" } });
        showMessage("تم حفظ القاعدة وإصدارها الأول", "success");
        await renderRules();
      } catch (error) { handleError(error); }
    });
  }
}

async function renderSources() {
  begin("sources");
  const items = await api("/api/sources");
  const root = node("div");
  const drawer = node("section", { class: "drawer", hidden: true });
  const sourceForm = node("form", { id: "source-form", class: "form-grid" }, [
    field("الاسم", node("input", { name: "name", required: true, minlength: "2" })),
    field("النوع", selectControl("type", ["file", "training", "syslog", "windows", "linux", "web", "http"])),
    field("Endpoint اختياري", node("input", { name: "endpoint", type: "url", placeholder: "https://sandbox.example" }), true),
    field("بيانات اعتماد مشفرة", node("input", { name: "credential", type: "password", autocomplete: "new-password" }), true),
    formActions("حفظ المصدر", "cancel-source")
  ]);
  drawer.append(node("h3", { text: "مصدر جديد" }), sourceForm);
  const columns = [{ label: "المصدر", value: "name" }, { label: "النوع", value: "type" }, { label: "الحالة", value: (row) => badge(row.status) }, { label: "اعتماد محفوظ", value: (row) => row.credentials_stored ? "نعم · مخفي" : "لا" }, { label: "صفوف", value: "rows_ingested" }, { label: "آخر تحقق", value: (row) => formatTime(row.last_validation) }, { label: "إجراء", value: (row) => permission("sources.manage") ? button("اختبار صادق", async () => { try { const result = await api(`/api/sources/${row.id}/test`, { method: "POST", body: {} }); showMessage(`${result.status}: ${result.message}`, result.status === "connected" ? "success" : "error"); await renderSources(); } catch (error) { handleError(error); } }, "compact") : "قراءة فقط" }];
  const actions = permission("sources.manage") ? [button("إضافة مصدر", () => { drawer.hidden = false; drawer.querySelector("input").focus(); }, "primary")] : [];
  root.append(pageHead("إدارة المصادر", "الاعتمادات مشفرة ولا تعاد عبر API. اتصال HTTP مقيد بقائمة سماح.", actions), drawer, panel("المصادر المعرّفة", items.length ? table(columns, items) : emptyState("لا توجد مصادر", "يمكن استيراد ملف مباشرة أو تعريف مصدر محلي مصرح."), true));
  finish(root);
  const form = document.getElementById("source-form");
  if (form) {
    document.getElementById("cancel-source").addEventListener("click", () => { drawer.hidden = true; });
    form.addEventListener("submit", async (event) => { event.preventDefault(); const values = new FormData(form); try { await api("/api/sources", { method: "POST", body: { name: values.get("name"), type: values.get("type"), endpoint: values.get("endpoint") || null, credential: values.get("credential") || null, is_active: true } }); showMessage("تم حفظ المصدر", "success"); await renderSources(); } catch (error) { handleError(error); } });
  }
}

async function renderImports() {
  begin("imports");
  const jobs = await api("/api/imports");
  const root = node("div");
  const importer = node("section", { class: "drawer" });
  const importActions = node("div", { class: "action-row" }, [
    node("button", { name: "mode", value: "preview", class: "button ghost", type: "submit", text: "معاينة" }),
    node("button", { name: "mode", value: "commit", class: "button primary", type: "submit", text: "تحقق واستورد" })
  ]);
  const importForm = node("form", { id: "import-form", class: "form-grid" }, [
    field("الملف", node("input", { name: "file", type: "file", required: true, accept: ".csv,.json,.jsonl,.ndjson,.log,.xml,.evtx" }), true),
    field("الصيغة", selectControl("format", ["csv", "json", "jsonl", "syslog", "linux_auth", "web", "sysmon_xml", "evtx"], "اكتشاف تلقائي")),
    importActions
  ]);
  importer.append(node("h3", { text: "استيراد آمن" }), importForm, node("div", { id: "import-result", "aria-live": "polite" }));
  const columns = [{ label: "المهمة", value: (row) => node("span", { class: "mono", text: row.job_id }) }, { label: "الملف", value: "filename" }, { label: "الصيغة", value: "format" }, { label: "الحالة", value: (row) => badge(row.status) }, { label: "مقبول", value: "accepted" }, { label: "مرفوض", value: "rejected" }, { label: "مكرر", value: "skipped" }, { label: "الوقت", value: (row) => formatTime(row.created_at) }];
  root.append(pageHead("مركز الاستيراد", "CSV وJSON(L) وSyslog وLinux وWeb وSysmon XML وEVTX ضمن حدود موارد صارمة"), importer, panel("سجل المهام", jobs.items.length ? table(columns, jobs.items) : emptyState("لم تنفذ مهام استيراد", "اختر ملفًا تدريبيًا مصرحًا لمعاينته قبل الحفظ."), true));
  finish(root);
  const form = document.getElementById("import-form");
  let submitter = "preview";
  form.querySelectorAll("button[name=mode]").forEach((item) => item.addEventListener("click", () => { submitter = item.value; }));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    data.delete("mode");
    try {
      const result = await api(submitter === "preview" ? "/api/imports/preview" : "/api/imports", { method: "POST", body: data });
      const output = document.getElementById("import-result");
      output.replaceChildren(node("pre", { class: "code-box", text: JSON.stringify(result, null, 2) }));
      if (submitter === "commit") showMessage("اكتملت مهمة الاستيراد وتقييم الكشف", "success");
    } catch (error) { handleError(error); }
  });
}

async function renderIncidents() {
  begin("incidents");
  const data = await api("/api/incidents?page_size=100");
  const root = node("div");
  const drawer = node("section", { class: "drawer", hidden: true });
  drawer.innerHTML = '<h3>تحقيق جديد</h3><form id="case-form" class="form-grid"><label class="span-2">العنوان<input name="title" required minlength="3" maxlength="255"></label><label>الخطورة<select name="severity"><option>medium</option><option>critical</option><option>high</option><option>low</option></select></label><label>الأولوية<select name="priority"><option>medium</option><option>urgent</option><option>high</option><option>low</option></select></label><label class="span-2">الوصف<textarea name="description" maxlength="10000"></textarea></label><div class="action-row"><button class="button primary" type="submit">إنشاء التحقيق</button><button id="cancel-case" class="button ghost" type="button">إلغاء</button></div></form>';
  const columns = [{ label: "المرجع", value: (row) => node("span", { class: "mono", text: row.reference }) }, { label: "التحقيق", value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.title }), node("small", { text: row.description })]) }, { label: "الخطورة", value: (row) => badge(row.severity) }, { label: "الأولوية", value: (row) => badge(row.priority) }, { label: "الحالة", value: (row) => badge(row.status) }, { label: "المسؤول", value: "assignee_name" }, { label: "أدلة", value: "evidence_count" }, { label: "SLA", value: (row) => row.overdue ? badge("overdue") : formatTime(row.sla_due_at) }];
  root.append(pageHead("مساحة التحقيقات", "حالات مضبوطة، أدلة محمية، قفل تفاؤلي، وتقارير بإصدارات", [button("تحقيق جديد", () => { drawer.hidden = false; drawer.querySelector("input").focus(); }, "primary"), linkedButton("ابدأ Guided Demo", "/lab")]), drawer, panel("التحقيقات", data.items.length ? table(columns, data.items) : emptyState("لا توجد تحقيقات بعد", "أنشئ تحقيقًا أو شغّل سيناريو لتوليد تنبيه ثم اربطه بقضية.", [button("إنشاء تحقيق", () => { drawer.hidden = false; }, "primary"), linkedButton("تشغيل سيناريو", "/lab")]), true));
  finish(root);
  document.getElementById("cancel-case").addEventListener("click", () => { drawer.hidden = true; });
  document.getElementById("case-form").addEventListener("submit", async (event) => { event.preventDefault(); const values = new FormData(event.currentTarget); try { const created = await api("/api/incidents", { method: "POST", body: Object.fromEntries(values.entries()) }); showMessage(`تم إنشاء ${created.reference}`, "success"); await renderIncidents(); } catch (error) { handleError(error); } });
}

async function renderLab() {
  begin("lab");
  const [data, runs] = await Promise.all([api("/api/scenarios"), api("/api/training/runs")]);
  const root = node("div");
  const cards = node("div", { class: "cards" });
  data.items.forEach((scenario) => {
    const start = button("بدء جلسة", async () => {
      try {
        const run = await api("/api/training/runs", { method: "POST", body: { scenario_id: scenario.id, difficulty: scenario.difficulty, auto_play: false } });
        const result = await api(`/api/training/runs/${run.id}/play`, { method: "POST", body: { steps: 50 } });
        showMessage(`أُنشئت ${result.event_ids?.length || 0} واقعة تدريبية. يمكنك التحقيق قبل تسليم محاولتك ${run.id}.`, "success");
        await renderLab();
      } catch (error) {
        handleError(error);
      }
    }, "primary");
    cards.append(node("article", { class: "card" }, [
      node("div", { class: "card-meta" }, [badge(scenario.difficulty), badge(scenario.state), badge(`${scenario.step_count} خطوات`)]),
      node("h3", { text: scenario.name }),
      node("p", { text: scenario.description }),
      node("p", { text: `المدة ${scenario.duration_minutes} دقيقة · محاولاتك ${scenario.attempt_count}` }),
      node("div", { class: "action-row" }, [start]),
    ]));
  });
  const runColumns = [
    { label: "المحاولة", value: (run) => node("span", { class: "mono", text: run.run_id }) },
    { label: "السيناريو", value: "scenario_name" },
    { label: "الحالة", value: (run) => badge(run.state) },
    { label: "تاريخ البدء", value: (run) => formatTime(run.started_at) },
    { label: "الإجراء", value: (run) => run.state === "awaiting_submission"
      ? button("تسليم التقييم بعد التحقيق", async () => {
        try {
          await api(`/api/training/runs/${run.id}/submit`, { method: "POST", body: {} });
          showMessage("تم اعتماد المحاولة وحساب الدرجة بناءً على قراراتك وأدلتك المسجلة", "success");
          await renderLab();
        } catch (error) {
          handleError(error);
        }
      }, "primary")
      : run.state === "completed" ? linkedButton("عرض التقييم", "/scores") : badge(run.state) },
  ];
  root.append(
    pageHead("سيناريوهات سلاسل الهجوم", "المختبر يولّد أحداثًا تدريبية؛ التقييم لا يُحتسب حتى تسلّم المحاولة بنفسك"),
    data.items.length ? cards : emptyState("لا توجد سيناريوهات منشورة", "شغّل seed-data في بيئة development أو أنشئ سيناريو كمدرّب."),
    panel("محاولاتي التدريبية", runs.items.length ? table(runColumns, runs.items) : emptyState("لا توجد محاولات", "ابدأ جلسة ثم عالج الأحداث والتنبيهات في التحقيقات قبل تسليم تقييمك."), true),
  );
  finish(root);
}
async function renderAttack() {
  begin("attack");
  const [matrix, coverage] = await Promise.all([api("/api/attack/matrix"), api("/api/attack/coverage")]);
  const root = node("div");
  const columns = [{ label: "التقنية", value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: `${row.technique_id} · ${row.name}` }), node("small", { text: row.tactic })]) }, { label: "قواعد", value: "configured" }, { label: "مختبرة", value: "tested" }, { label: "شوهدت", value: "seen" }, { label: "كُشفت", value: "detected_in_run" }, { label: "حُققت", value: "investigated" }, { label: "تم التحقق", value: "validated" }, { label: "فائتة", value: "missed" }];
  root.append(pageHead("تغطية ATT&CK المبنية على الأدلة", `Enterprise ATT&CK v${coverage.attack_version} · Snapshot محلي`, [linkedButton("تصدير Navigator", "/api/attack/navigator-layer", "primary")]), node("section", { class: "metric-grid" }, [metric("التقنيات", matrix.techniques?.length || coverage.items.length), metric("تكتيكات", matrix.tactics?.length || 0), metric("إصدار ATT&CK", coverage.attack_version, "", "مثبت ومعلن")]), panel("مصفوفة التغطية", table(columns, coverage.items), true));
  finish(root);
}

async function renderHunt() {
  begin("hunt");
  const [saved, iocs] = await Promise.all([api("/api/hunt/saved-queries"), api("/api/iocs")]);
  const root = node("div");
  const hunt = node("section", { class: "drawer" });
  hunt.innerHTML = '<h3>استعلام Typed وآمن</h3><form id="hunt-form" class="form-grid"><label class="span-2">الاستعلام<input class="mono" name="query" required value="severity = high OR severity = critical"></label><div class="action-row"><button class="button primary" type="submit">تنفيذ</button><button id="save-hunt" class="button ghost" type="button">حفظ</button></div></form><div id="hunt-results"></div>';
  const iocColumns = [{ label: "النوع", value: "type" }, { label: "القيمة", value: (row) => node("span", { class: "mono", text: row.value }) }, { label: "الثقة", value: (row) => `${Math.round(Number(row.confidence) * 100)}%` }, { label: "المصدر", value: "source" }, { label: "آخر مشاهدة", value: (row) => formatTime(row.last_seen) }, { label: "إجراء", value: (row) => button("إثراء Offline", async () => { try { const result = await api(`/api/iocs/${row.id}/enrich`, { method: "POST", body: {} }); showMessage(`${result.verdict}: ${result.reason}`, "success"); } catch (error) { handleError(error); } }, "compact") }];
  root.append(pageHead("الصيد والـIoCs", `${saved.items.length} استعلامات محفوظة · ${iocs.items.length} مؤشرات`), hunt, panel("المؤشرات المستخرجة", iocs.items.length ? table(iocColumns, iocs.items) : emptyState("لا توجد مؤشرات", "استخرج مؤشرات من سجل محفوظ لتظهر هنا."), true));
  finish(root);
  const form = document.getElementById("hunt-form");
  form.addEventListener("submit", async (event) => { event.preventDefault(); const query = new FormData(form).get("query"); try { const result = await api("/api/hunt/query", { method: "POST", body: { query, page_size: 100 } }); const columns = [{ label: "الوقت", value: (row) => formatTime(row.event_time) }, { label: "السجل", value: "title" }, { label: "المصدر", value: "source" }, { label: "الخطورة", value: (row) => badge(row.severity) }]; document.getElementById("hunt-results").replaceChildren(node("p", { text: `${result.total} نتيجة · الاستعلام parameterized` }), result.items.length ? table(columns, result.items) : emptyState("لا نتائج", "الاستعلام صالح لكنه لم يطابق سجلات.")); } catch (error) { handleError(error); } });
  document.getElementById("save-hunt").addEventListener("click", async () => { const query = new FormData(form).get("query"); const name = window.prompt("اسم الاستعلام المحفوظ"); if (!name) return; try { await api("/api/hunt/saved-queries", { method: "POST", body: { name, query, visibility: "private", tags: [] } }); showMessage("تم حفظ الاستعلام", "success"); } catch (error) { handleError(error); } });
}

async function renderGraph() {
  begin("graph");
  const [graph, timeline] = await Promise.all([api("/api/visualizations/graph?limit=150"), api("/api/visualizations/timeline?limit=200")]);
  const root = node("div");
  const canvas = node("div", { class: "graph-canvas", tabindex: "0", "aria-label": "رسم الأدلة، استخدم الجدول البديل للتنقل الكامل" });
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const width = 900;
  const height = 430;
  const positions = new Map();
  graph.nodes.forEach((item, index) => {
    const angle = index * 2.399963;
    const radius = 45 + 17 * Math.sqrt(index);
    positions.set(item.id, { x: width / 2 + Math.cos(angle) * radius, y: height / 2 + Math.sin(angle) * radius });
  });
  graph.edges.forEach((item) => {
    const source = positions.get(item.source);
    const target = positions.get(item.target);
    if (!source || !target) return;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", source.x); line.setAttribute("y1", source.y); line.setAttribute("x2", target.x); line.setAttribute("y2", target.y); line.setAttribute("class", "graph-edge"); svg.append(line);
  });
  graph.nodes.forEach((item) => {
    const position = positions.get(item.id);
    const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
    group.setAttribute("class", "graph-node"); group.setAttribute("tabindex", "0"); group.setAttribute("transform", `translate(${position.x} ${position.y})`);
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle"); circle.setAttribute("r", "18");
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text"); label.setAttribute("x", "24"); label.setAttribute("y", "4"); label.textContent = String(item.label).slice(0, 34);
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title"); title.textContent = `${item.type}: ${item.label}`;
    group.append(title, circle, label); svg.append(group);
  });
  canvas.append(svg);
  const nodeColumns = [{ label: "النوع", value: "type" }, { label: "التسمية", value: "label" }, { label: "المرجع", value: "reference_id" }, { label: "الثقة", value: (row) => `${Math.round(Number(row.confidence) * 100)}%` }, { label: "المصدر", value: "provenance" }];
  const timeList = node("ol", { class: "timeline" }, timeline.items.slice(0, 100).map((item) => node("li", {}, [node("time", { text: formatTime(item.timestamp) }), node("i"), node("p", { text: `${item.type}: ${item.title || item.label || item.reference_id}` })])));
  root.append(pageHead("رسم الأدلة والأثر الزمني", `${graph.nodes.length} عقد · ${graph.edges.length} علاقات موثقة`, [linkedButton("تصدير JSON", "/api/visualizations/graph/export", "primary")]), panel("Graph", canvas, true), node("div", { class: "panel-grid" }, [panel("بديل جدولي قابل للوصول", table(nodeColumns, graph.nodes)), panel("Timeline", timeList)]));
  finish(root);
}

async function renderPlaybooks() {
  begin("playbooks");
  const data = await api("/api/playbooks");
  const root = node("div");
  const cards = node("div", { class: "cards" });
  data.items.forEach((item) => cards.append(node("article", { class: "card" }, [node("div", { class: "card-meta" }, [badge(`v${item.active_version}`), badge(`${item.step_count} خطوات`), badge(item.trigger_type)]), node("h3", { text: item.name }), node("p", { text: item.description }), node("p", { text: "تأثير محاكى داخل DB فقط · لا أوامر خارجية" }), node("div", { class: "action-row" }, [button("معاينة", async () => { try { const result = await api(`/api/playbooks/${item.id}/preview`, { method: "POST", body: { parameters: {} } }); window.alert(JSON.stringify(result, null, 2)); } catch (error) { handleError(error); } }, "primary")])])));
  root.append(pageHead("مكتبة الاستجابة المحاكية", "State machine بإصدارات وموافقات وتراجع؛ external_effects=false"), data.items.length ? cards : emptyState("لا توجد Playbooks منشورة", "فعّل بيانات التطوير أو أنشئ Playbook بإصدار منشور."));
  finish(root);
}

async function renderScores() {
  begin("scores");
  const [scores, leaders] = await Promise.all([api("/api/scores/me"), api("/api/leaderboards")]);
  const root = node("div");
  const scoreColumns = [{ label: "السيناريو", value: "scenario_name" }, { label: "الصعوبة", value: (row) => badge(row.difficulty) }, { label: "النتيجة", value: (row) => `${Number(row.total_score).toFixed(1)} / 100` }, { label: "MTTD", value: () => "غير مقاس" }, { label: "MTTR", value: () => "غير مقاس" }, { label: "Precision", value: (row) => row.components?.metrics?.detection_precision == null ? "غير مقاس" : Number(row.components.metrics.detection_precision).toFixed(3) }, { label: "Recall", value: (row) => row.components?.metrics?.detection_recall == null ? "غير مقاس" : Number(row.components.metrics.detection_recall).toFixed(3) }, { label: "التاريخ", value: (row) => formatTime(row.created_at) }];
  const leaderColumns = [{ label: "الترتيب", value: "rank" }, { label: "المتدرب", value: "name" }, { label: "السيناريو", value: "scenario_name" }, { label: "الصعوبة", value: (row) => badge(row.difficulty) }, { label: "النتيجة", value: "score" }];
  root.append(pageHead("التقييم الحتمي", "Snapshots قابلة لإعادة الحساب دون تغيير النتائج"), node("div", { class: "panel-grid" }, [panel("نتائجي", scores.items.length ? table(scoreColumns, scores.items) : emptyState("لا توجد نتائج", "أكمل سيناريو لتوليد Snapshot تقييم.")), panel("لوحة الترتيب", leaders.items.length ? table(leaderColumns, leaders.items) : emptyState("لا توجد نتائج منشورة", "يحترم العرض مساحة العمل وإخفاء أسماء الآخرين."))]));
  finish(root);
}

async function renderAudit() {
  begin("audit");
  const data = await api("/api/audit?page_size=200");
  const root = node("div");
  const columns = [{ label: "الوقت", value: (row) => formatTime(row.created_at) }, { label: "الفاعل", value: (row) => row.actor_name || `#${row.actor_id || "system"}` }, { label: "العملية", value: "action" }, { label: "المورد", value: (row) => `${row.resource_type}${row.resource_id ? ` #${row.resource_id}` : ""}` }, { label: "النتيجة", value: (row) => badge(row.result) }, { label: "Correlation", value: (row) => node("span", { class: "mono", text: row.correlation_id }) }, { label: "التفاصيل", value: (row) => JSON.stringify(row.details) }];
  root.append(pageHead("سجل التدقيق", `${data.total} عملية ضمن مساحة العمل · البيانات الحساسة محجوبة`), panel("النشاط", data.items.length ? table(columns, data.items) : emptyState("لا يوجد نشاط مسجل", "ستظهر عمليات المصادقة والقواعد والمصادر والتحقيقات هنا."), true));
  finish(root);
}

async function renderAdmin() {
  begin("admin");
  const [users, roles] = await Promise.all([api("/api/admin/users"), api("/api/admin/role-matrix")]);
  const root = node("div");
  const userColumns = [{ label: "المستخدم", value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.name }), node("small", { text: row.email })]) }, { label: "الدور", value: (row) => badge(row.role) }, { label: "الفريق", value: "team" }, { label: "نشط", value: (row) => row.is_active ? "نعم" : "لا" }, { label: "آخر دخول", value: (row) => formatTime(row.last_login) }];
  const roleColumns = [{ label: "الدور", value: (row) => badge(row.role) }, { label: "الصلاحيات", value: (row) => node("span", { text: row.permissions.join(" · ") }) }];
  root.append(pageHead("الحوكمة والصلاحيات", "Default deny ومصفوفة أدوار معلنة"), node("div", { class: "panel-grid" }, [panel("المستخدمون", table(userColumns, users.items)), panel("مصفوفة الصلاحيات", table(roleColumns, roles.items))]));
  finish(root);
}

async function renderProfile() {
  begin("profile");
  const [profile, sessions, settings] = await Promise.all([api("/api/profile"), api("/api/auth/sessions"), api("/api/settings")]);
  const root = node("div");
  const account = node("div", { class: "panel-body" }, [node("p", { text: `الاسم: ${profile.user.name}` }), node("p", { text: `البريد: ${profile.user.email}` }), node("p", { text: `الدور: ${profile.user.role}` }), node("p", { text: `MFA: ${profile.mfa.enabled ? "مفعّل" : "غير مفعّل"}` }), node("p", { text: `جلسات نشطة: ${profile.active_sessions}` })]);
  const sessionColumns = [{ label: "بدأت", value: (row) => formatTime(row.created_at) }, { label: "آخر نشاط", value: (row) => formatTime(row.last_seen_at) }, { label: "تنتهي", value: (row) => formatTime(row.expires_at) }, { label: "IP", value: (row) => node("span", { class: "mono", text: row.ip_address }) }, { label: "الحالة", value: (row) => badge(row.revoked_at ? "revoked" : "active") }];
  root.append(pageHead("أمان الحساب", `${settings.environment} · Registration ${settings.registration_enabled ? "enabled" : "disabled"}`), node("div", { class: "panel-grid" }, [panel("الحساب", account), panel("الجلسات", table(sessionColumns, sessions.items))]));
  finish(root);
}

function handleError(error) {
  const details = error.details ? ` · ${JSON.stringify(error.details)}` : "";
  showMessage(`${error.message || "حدث خطأ غير متوقع"}${details}`);
  console.error(error.code || error.name, error.status || "", error.message);
}

const renderers = { dashboard: renderDashboard, events: renderEvents, alerts: renderAlerts, rules: renderRules, sources: renderSources, imports: renderImports, incidents: renderIncidents, lab: renderLab, attack: renderAttack, hunt: renderHunt, graph: renderGraph, playbooks: renderPlaybooks, scores: renderScores, audit: renderAudit, admin: renderAdmin, profile: renderProfile };

async function initialize() {
  const me = await api("/api/auth/me");
  state.user = me.user;
  state.permissions = new Set(me.permissions);
  const renderer = renderers[state.section] || renderDashboard;
  try { await renderer(); } catch (error) {
    handleError(error);
    if (error.status === 403) finish(emptyState("هذا القسم غير متاح لدورك", "تطبق المنصة صلاحيات الخادم حتى عند فتح الرابط مباشرة.", [linkedButton("العودة إلى النظرة العامة", "/dashboard", "primary")]));
  }
}

const menu = document.getElementById("menu-toggle");
menu.addEventListener("click", () => {
  const sidebar = document.querySelector(".sidebar");
  const open = sidebar.classList.toggle("open");
  menu.setAttribute("aria-expanded", String(open));
});

initialize().catch(handleError);
