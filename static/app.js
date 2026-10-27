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
  dashboard: [SOCifyLocale.text("مركز العمليات"), "SECURITY OPERATIONS"],
  events: [SOCifyLocale.text("مستكشف السجلات"), "NORMALIZED EVENT DATA"],
  alerts: [SOCifyLocale.text("قائمة التنبيهات"), "DETECTION TRIAGE"],
  rules: [SOCifyLocale.text("قواعد الكشف"), "DETECTION ENGINE"],
  sources: [SOCifyLocale.text("مصادر البيانات"), "SOURCE MANAGEMENT"],
  imports: [SOCifyLocale.text("مركز الاستيراد"), "SAFE INGESTION"],
  incidents: [SOCifyLocale.text("مساحة التحقيقات"), "CASE MANAGEMENT"],
  lab: [SOCifyLocale.text("مختبر المحاكاة"), "ATTACK CHAIN TRAINING"],
  attack: ["MITRE ATT&CK", "COVERAGE ANALYTICS"],
  hunt: [SOCifyLocale.text("مساحة الصيد"), "PARAMETERIZED HUNTING"],
  graph: [SOCifyLocale.text("الرسم والأثر الزمني"), "EVIDENCE VISUALIZATION"],
  playbooks: [SOCifyLocale.text("خطط الاستجابة"), "SIMULATED SOAR"],
  scores: [SOCifyLocale.text("التقييم والنتائج"), "ASSESSMENT ENGINE"],
  audit: [SOCifyLocale.text("سجل التدقيق"), "IMMUTABLE ACTIVITY"],
  admin: [SOCifyLocale.text("إدارة المنصة"), "ROLE GOVERNANCE"],
  profile: [SOCifyLocale.text("الملف والأمان"), "ACCOUNT SECURITY"],
  "analysis-library": [SOCifyLocale.text("مكتبة التحليل المحلي"), "OFFLINE ANALYSIS"],
  team: [SOCifyLocale.text("الفريق والمهام"), "TEAM OPERATIONS"]
};

function displayText(value) {
  const text = value == null ? "—" : String(value);
  if (document.querySelector('meta[name="product-mode"]')?.content !== "autopsy") return text;
  return text.replace(/[\u202a-\u202e\u2066-\u2069]/gu, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function node(tag, attributes = {}, children = []) {
  const element = document.createElement(tag);
  Object.entries(attributes).forEach(([key, value]) => {
    if (key === "class") element.className = value;
    else if (key === "text") element.textContent = displayText(value);
    else if (key.startsWith("on") && typeof value === "function") element.addEventListener(key.slice(2), value);
    else if (value !== false && value != null) element.setAttribute(key, String(value));
  });
  const values = Array.isArray(children) ? children : [children];
  values.filter((value) => value != null).forEach((value) => element.append(value instanceof Node ? value : document.createTextNode(displayText(value))));
  return element;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat(window.SOCifyLocale?.language === "en" ? "en-GB" : "ar-SA", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(date) + " UTC";
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
    throw new Error(SOCifyLocale.text("انتهت الجلسة"));
  }
  let payload = null;
  if (response.status !== 204) {
    const contentType = response.headers.get("content-type") || "";
    payload = contentType.includes("json") ? await response.json() : await response.text();
  }
  if (!response.ok) {
    const error = new Error(SOCifyLocale.error(payload?.error?.code, payload?.error?.message) || SOCifyLocale.template`تعذر إكمال الطلب (${response.status})`);
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
  workspace.replaceChildren(node("div", { class: "loading" }, [node("span"), node("p", { text: SOCifyLocale.text("جارٍ تحميل البيانات المصرّح بها…") })]));
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
  const head = node("thead", {}, node("tr", {}, columns.map((column) => node("th", { text: column.label, scope: "col", class: rows.some((row) => typeof (typeof column.value === "string" ? row[column.value] : undefined) === "number") ? "numeric-cell" : "" }))));
  const body = node("tbody");
  rows.forEach((row) => {
    body.append(node("tr", {}, columns.map((column) => {
      const value = typeof column.value === "function" ? column.value(row) : row[column.value];
      return node("td", { class: typeof value === "number" ? "numeric-cell" : "" }, value instanceof Node ? value : value == null || value === "" ? "—" : String(value));
    })));
  });
  return node("div", { class: "table-wrap", tabindex: "0", role: "region", "aria-label": SOCifyLocale.template`جدول بيانات: ${columns.map((column) => column.label).join(SOCifyLocale.text("، "))}` }, node("table", {}, [head, body]));
}

function panel(title, content, wide = false, extra = null) {
  return node("section", { class: `panel${wide ? " wide" : ""}` }, [node("header", { class: "panel-head" }, [node("h3", { text: title }), extra]), content]);
}

function metric(label, value, style = "", detail = SOCifyLocale.text("من قاعدة البيانات")) {
  return node("article", { class: `metric ${style}` }, [node("span", { text: label }), node("strong", { text: Number(value || 0).toLocaleString("ar-SA") }), node("small", { text: detail })]);
}

function button(label, handler, style = "ghost") {
  return node("button", { type: "button", class: `button ${style}`, text: label, onclick: handler });
}

function linkedButton(label, href, style = "ghost") {
  return node("a", { class: `button ${style}`, href, text: label });
}

function field(label, control, wide = false) {
  const caption = node("span", { id: `field-label-${crypto.randomUUID()}`, text: label });
  const input = control.matches?.("input,select,textarea") ? control : control.querySelector?.("input,select,textarea");
  if (input && !input.hasAttribute("aria-label") && !input.hasAttribute("aria-labelledby")) input.setAttribute("aria-labelledby", caption.id);
  return node("label", { class: wide ? "span-2" : "" }, [caption, control]);
}

function selectControl(name, values, placeholder = null) {
  const options = placeholder ? [node("option", { value: "auto", text: placeholder })] : [];
  options.push(...values.map((value) => node("option", { value, text: value })));
  return node("select", { name }, options);
}

function formActions(submitLabel, cancelId) {
  return node("div", { class: "action-row span-2" }, [
    node("button", { type: "submit", class: "button primary", text: submitLabel }),
    node("button", { type: "button", id: cancelId, class: "button ghost", text: SOCifyLocale.text("إلغاء") })
  ]);
}

function permission(name) {
  return state.permissions.has("*") || state.permissions.has(name);
}

async function renderDashboard() {
  begin("dashboard");
  const data = await api("/api/dashboard");
  const root = node("div");
  root.append(pageHead(SOCifyLocale.text("الموقف الأمني الآن"), SOCifyLocale.template`النطاق: ${data.scope} · آخر تحديث ${formatTime(data.generated_at)}`, [linkedButton(SOCifyLocale.text("تشغيل سيناريو"), "/lab", "primary"), linkedButton(SOCifyLocale.text("استيراد سجلات"), "/imports")]));
  root.append(node("section", { class: "metric-grid", "aria-label": SOCifyLocale.text("مؤشرات المنصة") }, [
    metric(SOCifyLocale.text("السجلات"), data.counts.events), metric(SOCifyLocale.text("تنبيهات مفتوحة"), data.counts.open_alerts, "attention"), metric(SOCifyLocale.text("تحقيقات نشطة"), data.counts.active_cases), metric(SOCifyLocale.text("أحداث حرجة"), data.counts.critical_events, "critical"), metric(SOCifyLocale.text("SLA متجاوز"), data.counts.overdue_cases, "attention")
  ]));
  const grid = node("div", { class: "panel-grid" });
  const alertColumns = [
    { label: SOCifyLocale.text("المعرف"), value: (row) => node("a", { href: `/alerts?selected=${row.id}`, class: "mono", text: row.alert_id }) },
    { label: SOCifyLocale.text("السبب"), value: "reason" }, { label: SOCifyLocale.text("الخطورة"), value: (row) => badge(row.severity) }, { label: SOCifyLocale.text("الحالة"), value: (row) => badge(row.status) }, { label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.detected_at) }
  ];
  const caseColumns = [
    { label: SOCifyLocale.text("المرجع"), value: (row) => node("a", { href: `/incidents?selected=${row.id}`, class: "mono", text: row.reference }) },
    { label: SOCifyLocale.text("العنوان"), value: "title" }, { label: SOCifyLocale.text("الخطورة"), value: (row) => badge(row.severity) }, { label: SOCifyLocale.text("الحالة"), value: (row) => badge(row.status) }, { label: SOCifyLocale.text("آخر تحديث"), value: (row) => formatTime(row.updated_at) }
  ];
  grid.append(panel(SOCifyLocale.text("أحدث التنبيهات"), data.recent_alerts.length ? table(alertColumns, data.recent_alerts) : emptyState(SOCifyLocale.text("لا توجد تنبيهات"), SOCifyLocale.text("لا تعرض المنصة عينات وهمية. ابدأ سيناريو أو استورد بيانات لتشغيل الكشف."), [linkedButton(SOCifyLocale.text("ابدأ من المختبر"), "/lab", "primary")])));
  grid.append(panel(SOCifyLocale.text("التحقيقات النشطة"), data.recent_cases.length ? table(caseColumns, data.recent_cases) : emptyState(SOCifyLocale.text("مساحة التحقيق خالية"), SOCifyLocale.text("أنشئ تحقيقًا يدويًا أو افتح واحدًا من تنبيه موثّق."), [linkedButton(SOCifyLocale.text("إنشاء تحقيق"), "/incidents", "primary")])));
  const healthColumns = [{ label: SOCifyLocale.text("القاعدة"), value: "name" }, { label: SOCifyLocale.text("نشطة"), value: (row) => badge(row.is_active ? "active" : "disabled") }, { label: SOCifyLocale.text("مطابقات"), value: "match_count" }, { label: SOCifyLocale.text("إخفاقات"), value: "failed_evaluations" }, { label: SOCifyLocale.text("متوسط ms"), value: "average_evaluation_ms" }, { label: SOCifyLocale.text("آخر تشغيل"), value: (row) => formatTime(row.last_triggered_at) }];
  grid.append(panel(SOCifyLocale.text("صحة قواعد الكشف"), data.rule_health.length ? table(healthColumns, data.rule_health) : emptyState(SOCifyLocale.text("لا توجد قواعد"), SOCifyLocale.text("يحتاج الكشف إلى قواعد منشورة قبل استقبال الأحداث.")), true));
  root.append(grid);
  finish(root);
}

async function renderEvents() {
  begin("events");
  const root = node("div");
  const search = node("input", { type: "search", placeholder: SOCifyLocale.text("ابحث في العنوان أو المستخدم أو IP"), "aria-label": SOCifyLocale.text("بحث السجلات") });
  const severity = node("select", { "aria-label": SOCifyLocale.text("تصفية الخطورة") }, [node("option", { value: "", text: SOCifyLocale.text("كل الخطورات") }), ...["critical", "high", "medium", "low"].map((value) => node("option", { value, text: value }))]);
  const body = node("div");
  async function load() {
    body.replaceChildren(node("div", { class: "loading" }, node("span")));
    const params = new URLSearchParams({ page_size: "100" });
    if (search.value) params.set("q", search.value);
    if (severity.value) params.set("severity", severity.value);
    const data = await api(`/api/events?${params}`);
    const columns = [
      { label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.event_time) }, { label: SOCifyLocale.text("السجل"), value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.title }), node("small", { text: `${row.event_id} · ${row.event_type}` })]) },
      { label: SOCifyLocale.text("المصدر"), value: "source" }, { label: SOCifyLocale.text("المستخدم / المضيف"), value: (row) => `${row.username || "—"} / ${row.hostname || "—"}` }, { label: SOCifyLocale.text("IP المصدر"), value: (row) => node("span", { class: "mono", text: row.source_ip }) }, { label: SOCifyLocale.text("الخطورة"), value: (row) => badge(row.severity) }, { label: SOCifyLocale.text("الحالة"), value: (row) => badge(row.status) }
    ];
    body.replaceChildren(data.items.length ? table(columns, data.items) : emptyState(SOCifyLocale.text("لا توجد سجلات مطابقة"), SOCifyLocale.text("جرّب تغيير المرشح أو استورد ملفًا مصرحًا."), [linkedButton(SOCifyLocale.text("مركز الاستيراد"), "/imports", "primary")]));
  }
  const filter = node("div", { class: "filter-row" }, [search, severity, button(SOCifyLocale.text("تطبيق"), () => load().catch(handleError), "primary"), linkedButton(SOCifyLocale.text("تصدير CSV آمن"), "/api/events/export")]);
  root.append(pageHead(SOCifyLocale.text("السجلات الموحّدة"), SOCifyLocale.text("بيانات فعلية محفوظة مع المصدر الخام وأثر التطبيع"), [linkedButton(SOCifyLocale.text("استيراد جديد"), "/imports", "primary")]), filter, panel(SOCifyLocale.text("النتائج"), body, true));
  finish(root);
  await load();
}

async function renderAlerts() {
  begin("alerts");
  const data = await api("/api/alerts?page_size=100");
  const root = node("div");
  const content = node("div");
  const columns = [
    { label: SOCifyLocale.text("التنبيه"), value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.reason }), node("small", { class: "mono", text: row.alert_id })]) }, { label: SOCifyLocale.text("القاعدة"), value: "rule_name" },
    { label: SOCifyLocale.text("الخطورة"), value: (row) => badge(row.severity) }, { label: SOCifyLocale.text("الثقة"), value: (row) => `${Math.round(Number(row.confidence) * 100)}%` }, { label: SOCifyLocale.text("الحالة"), value: (row) => badge(row.status) }, { label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.detected_at) },
    { label: SOCifyLocale.text("إجراء"), value: (row) => node("div", { class: "action-row" }, [button(SOCifyLocale.text("تحقيق"), async () => { try { const created = await api(`/api/alerts/${row.id}/case`, { method: "POST", body: {} }); showMessage(SOCifyLocale.template`أُنشئ التحقيق ${created.reference}`, "success"); } catch (error) { handleError(error); } }, "compact"), button(SOCifyLocale.text("فرز"), async () => { try { await api(`/api/alerts/${row.id}/triage`, { method: "POST", body: { status: "triaged" } }); await renderAlerts(); } catch (error) { handleError(error); } }, "compact")]) }
  ];
  content.append(data.items.length ? table(columns, data.items) : emptyState(SOCifyLocale.text("لا توجد تنبيهات"), SOCifyLocale.text("شغّل سيناريو أو استورد بيانات. لن نعرض أرقامًا تجريبية زائفة."), [linkedButton(SOCifyLocale.text("تشغيل سيناريو"), "/lab", "primary")]));
  root.append(pageHead(SOCifyLocale.text("قائمة الفرز"), SOCifyLocale.template`${data.total} تنبيهًا ضمن النطاق المصرح`, [linkedButton(SOCifyLocale.text("قواعد الكشف"), "/rules")]), panel(SOCifyLocale.text("التنبيهات"), content, true));
  finish(root);
}

async function renderRules() {
  begin("rules");
  const data = await api("/api/rules");
  const root = node("div");
  const drawer = node("section", { class: "drawer", hidden: true });
  drawer.innerHTML = SOCifyLocale.text('<h3>قاعدة كشف جديدة</h3><form id="rule-form" class="form-grid"><label>الاسم<input name="name" required minlength="3" maxlength="150"></label><label>الخطورة<select name="severity"><option>medium</option><option>critical</option><option>high</option><option>low</option></select></label><label class="span-2">الوصف<textarea name="description" maxlength="2000"></textarea></label><label class="span-2">DSL آمن<textarea class="json-input" name="dsl" required>{"all":[{"field":"event_type","operator":"equals","value":"failed_login"}],"window":{"seconds":600,"threshold":5,"group_by":["source_ip"]},"mitre_ids":["T1110"]}</textarea></label><label><input name="active" type="checkbox"> نشر وتفعيل فورًا</label><div class="action-row"><button class="button primary" type="submit">حفظ القاعدة</button><button id="cancel-rule" class="button ghost" type="button">إلغاء</button></div></form>');
  const columns = [
    { label: SOCifyLocale.text("القاعدة"), value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.name }), node("small", { text: row.description })]) }, { label: SOCifyLocale.text("الإصدار"), value: (row) => `v${row.version}` }, { label: SOCifyLocale.text("النشر"), value: (row) => badge(row.deployment_state) }, { label: SOCifyLocale.text("مطابقات"), value: "match_count" }, { label: "False +", value: "false_positive_count" }, { label: "ms", value: "average_evaluation_ms" },
    { label: SOCifyLocale.text("إجراء"), value: (row) => permission("rules.manage") ? button(row.is_active ? SOCifyLocale.text("تعطيل") : SOCifyLocale.text("تفعيل"), async () => { try { await api(`/api/rules/${row.id}/toggle`, { method: "POST", body: { active: !Boolean(row.is_active) } }); await renderRules(); } catch (error) { handleError(error); } }, "compact") : SOCifyLocale.text("قراءة فقط") }
  ];
  const actions = permission("rules.manage") ? [button(SOCifyLocale.text("قاعدة جديدة"), () => { drawer.hidden = false; drawer.querySelector("input").focus(); }, "primary")] : [];
  root.append(pageHead(SOCifyLocale.text("منضدة قواعد الكشف"), SOCifyLocale.text("DSL typed بلا eval أو SQL من المستخدم، مع إصدارات وصحة قابلة للقياس"), actions), drawer, panel(SOCifyLocale.text("القواعد"), data.items.length ? table(columns, data.items) : emptyState(SOCifyLocale.text("لا توجد قواعد كشف"), SOCifyLocale.text("أنشئ قاعدة من DSL الصارم أو فعّل بيانات التطوير الصريحة.")), true));
  finish(root);
  const form = document.getElementById("rule-form");
  if (form) {
    document.getElementById("cancel-rule").addEventListener("click", () => { drawer.hidden = true; });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const values = new FormData(form);
      try {
        await api("/api/rules", { method: "POST", body: { name: values.get("name"), description: values.get("description"), dsl: JSON.parse(values.get("dsl")), action: { severity: values.get("severity"), confidence: .85 }, active: values.get("active") === "on", change_summary: "Created from rules workbench" } });
        showMessage(SOCifyLocale.text("تم حفظ القاعدة وإصدارها الأول"), "success");
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
    field(SOCifyLocale.text("الاسم"), node("input", { name: "name", required: true, minlength: "2" })),
    field(SOCifyLocale.text("النوع"), selectControl("type", ["file", "training", "syslog", "windows", "linux", "web", "http"])),
    field(SOCifyLocale.text("Endpoint اختياري"), node("input", { name: "endpoint", type: "url", placeholder: "https://sandbox.example" }), true),
    field(SOCifyLocale.text("بيانات اعتماد مشفرة"), node("input", { name: "credential", type: "password", autocomplete: "new-password" }), true),
    formActions(SOCifyLocale.text("حفظ المصدر"), "cancel-source")
  ]);
  drawer.append(node("h3", { text: SOCifyLocale.text("مصدر جديد") }), sourceForm);
  const columns = [{ label: SOCifyLocale.text("المصدر"), value: "name" }, { label: SOCifyLocale.text("النوع"), value: "type" }, { label: SOCifyLocale.text("الحالة"), value: (row) => badge(row.status) }, { label: SOCifyLocale.text("اعتماد محفوظ"), value: (row) => row.credentials_stored ? SOCifyLocale.text("نعم · مخفي") : SOCifyLocale.text("لا") }, { label: SOCifyLocale.text("صفوف"), value: "rows_ingested" }, { label: SOCifyLocale.text("آخر تحقق"), value: (row) => formatTime(row.last_validation) }, { label: SOCifyLocale.text("إجراء"), value: (row) => permission("sources.manage") ? button(SOCifyLocale.text("اختبار صادق"), async () => { try { const result = await api(`/api/sources/${row.id}/test`, { method: "POST", body: {} }); showMessage(`${result.status}: ${result.message}`, result.status === "connected" ? "success" : "error"); await renderSources(); } catch (error) { handleError(error); } }, "compact") : SOCifyLocale.text("قراءة فقط") }];
  const actions = permission("sources.manage") ? [button(SOCifyLocale.text("إضافة مصدر"), () => { drawer.hidden = false; drawer.querySelector("input").focus(); }, "primary")] : [];
  root.append(pageHead(SOCifyLocale.text("إدارة المصادر"), SOCifyLocale.text("الاعتمادات مشفرة ولا تعاد عبر API. اتصال HTTP مقيد بقائمة سماح."), actions), drawer, panel(SOCifyLocale.text("المصادر المعرّفة"), items.length ? table(columns, items) : emptyState(SOCifyLocale.text("لا توجد مصادر"), SOCifyLocale.text("يمكن استيراد ملف مباشرة أو تعريف مصدر محلي مصرح.")), true));
  finish(root);
  const form = document.getElementById("source-form");
  if (form) {
    document.getElementById("cancel-source").addEventListener("click", () => { drawer.hidden = true; });
    form.addEventListener("submit", async (event) => { event.preventDefault(); const values = new FormData(form); try { await api("/api/sources", { method: "POST", body: { name: values.get("name"), type: values.get("type"), endpoint: values.get("endpoint") || null, credential: values.get("credential") || null, is_active: true } }); showMessage(SOCifyLocale.text("تم حفظ المصدر"), "success"); await renderSources(); } catch (error) { handleError(error); } });
  }
}

async function renderImports() {
  begin("imports");
  const jobs = await api("/api/imports");
  const root = node("div");
  const importer = node("section", { class: "drawer" });
  const importActions = node("div", { class: "action-row" }, [
    node("button", { name: "mode", value: "preview", class: "button ghost", type: "submit", text: SOCifyLocale.text("معاينة") }),
    node("button", { name: "mode", value: "commit", class: "button primary", type: "submit", text: SOCifyLocale.text("تحقق واستورد") })
  ]);
  const importForm = node("form", { id: "import-form", class: "form-grid" }, [
    field(SOCifyLocale.text("الملف"), node("input", { name: "file", type: "file", required: true, accept: ".csv,.json,.jsonl,.ndjson,.log,.xml,.evtx" }), true),
    field(SOCifyLocale.text("الصيغة"), selectControl("format", ["csv", "json", "jsonl", "syslog", "linux_auth", "web", "sysmon_xml", "evtx"], SOCifyLocale.text("اكتشاف تلقائي"))),
    importActions
  ]);
  importer.append(node("h3", { text: SOCifyLocale.text("استيراد آمن") }), importForm, node("div", { id: "import-result", "aria-live": "polite" }));
  const jobActions = (row) => {
    const actions = [linkedButton(SOCifyLocale.text("الدليل الخام"), `/api/imports/${row.id}/evidence`, "compact")];
    if (["queued", "interrupted", "failed"].includes(row.status)) actions.push(button(SOCifyLocale.text("استئناف"), async () => { try { await api(`/api/imports/${row.id}/resume`, { method: "POST", body: {} }); showMessage(SOCifyLocale.text("تم استئناف مهمة الاستيراد"), "success"); await renderImports(); } catch (error) { handleError(error); } }, "compact"));
    if (["queued", "processing", "interrupted", "failed"].includes(row.status)) actions.push(button(SOCifyLocale.text("إلغاء"), async () => { try { await api(`/api/imports/${row.id}/cancel`, { method: "POST", body: {} }); showMessage(SOCifyLocale.text("تم إلغاء مهمة الاستيراد"), "success"); await renderImports(); } catch (error) { handleError(error); } }, "compact"));
    return node("div", { class: "action-row" }, actions);
  };
  const columns = [{ label: SOCifyLocale.text("المهمة"), value: (row) => node("span", { class: "mono", text: row.job_id }) }, { label: SOCifyLocale.text("الملف"), value: "filename" }, { label: SOCifyLocale.text("الصيغة"), value: "format" }, { label: SOCifyLocale.text("الحالة"), value: (row) => badge(row.status) }, { label: SOCifyLocale.text("التقدم"), value: (row) => `${Math.round(Number(row.progress) * 100)}%` }, { label: SOCifyLocale.text("مقبول"), value: "accepted" }, { label: SOCifyLocale.text("مرفوض"), value: "rejected" }, { label: SOCifyLocale.text("مكرر"), value: "skipped" }, { label: SOCifyLocale.text("إجراء"), value: jobActions }, { label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.created_at) }];
  root.append(pageHead(SOCifyLocale.text("مركز الاستيراد"), SOCifyLocale.text("CSV وJSON(L) وSyslog وLinux وWeb وSysmon XML وEVTX ضمن حدود موارد صارمة")), importer, panel(SOCifyLocale.text("سجل المهام"), jobs.items.length ? table(columns, jobs.items) : emptyState(SOCifyLocale.text("لم تنفذ مهام استيراد"), SOCifyLocale.text("اختر ملفًا تدريبيًا مصرحًا لمعاينته قبل الحفظ.")), true));
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
      if (submitter === "commit") showMessage(result.status === "queued" ? SOCifyLocale.text("أضيفت مهمة الاستيراد إلى العامل") : SOCifyLocale.text("اكتملت مهمة الاستيراد وتقييم الكشف"), "success");
    } catch (error) { handleError(error); }
  });
}

const caseTransitions = {
  new: ["open", "triaged", "investigating", "cancelled"],
  open: ["triaged", "investigating", "escalated", "cancelled"],
  triaged: ["investigating", "false_positive", "escalated"],
  investigating: ["contained", "escalated", "false_positive"],
  contained: ["remediated", "recovered"],
  remediated: ["recovered"],
  recovered: ["closed"],
  escalated: ["investigating", "closed"],
  false_positive: ["closed", "reopened"],
  closed: ["reopened"],
  reopened: ["investigating", "contained"],
  cancelled: ["reopened"]
};

function caseDetailView(item) {
  const root = node("section", { class: "case-workspace", "aria-label": SOCifyLocale.template`التحقيق ${item.reference}` });
  const actions = [
    button(SOCifyLocale.text("تعيين لي"), async () => {
      try {
        await api(`/api/incidents/${item.id}`, { method: "PATCH", body: { assignee: state.user.id, version: item.version, reason: "Self assignment from investigation workspace" } });
        showMessage(SOCifyLocale.text("تم تعيين التحقيق لك"), "success");
        await renderIncidents(item.id);
      } catch (error) { handleError(error); }
    }, "primary"),
    linkedButton(SOCifyLocale.text("فتح الرسم الزمني"), `/graph?case_id=${item.id}`)
  ];
  if (item.status === "closed") actions.push(linkedButton(SOCifyLocale.text("تنزيل التقرير"), `/api/incidents/${item.id}/report?format=html`));
  if (["admin", "soc_manager"].includes(state.user.role)) actions.push(linkedButton(SOCifyLocale.text("إسناد سجلات الفريق"), `/team?case_id=${item.id}`));
  root.append(pageHead(`${item.reference} · ${item.title}`, SOCifyLocale.template`${item.description || SOCifyLocale.text("لا يوجد وصف")} · الإصدار ${item.version}`, actions));
  root.append(node("section", { class: "metric-grid", "aria-label": SOCifyLocale.text("ملخص التحقيق") }, [
    node("article", { class: "metric" }, [node("span", { text: SOCifyLocale.text("الحالة") }), badge(item.status), node("small", { text: SOCifyLocale.template`آخر تحديث ${formatTime(item.updated_at)}` })]),
    node("article", { class: "metric" }, [node("span", { text: SOCifyLocale.text("الخطورة") }), badge(item.severity), node("small", { text: SOCifyLocale.template`الأولوية ${item.priority}` })]),
    metric(SOCifyLocale.text("الأدلة"), item.evidence.length),
    metric(SOCifyLocale.text("المهام المفتوحة"), item.tasks.filter((task) => task.status !== "completed").length, item.overdue ? "critical" : ""),
    node("article", { class: `metric ${item.overdue ? "critical" : ""}` }, [node("span", { text: "SLA" }), node("strong", { text: item.overdue ? SOCifyLocale.text("متجاوز") : SOCifyLocale.text("ضمن المهلة") }), node("small", { text: formatTime(item.sla_due_at) })])
  ]));

  const workflow = node("form", { class: "form-grid", id: "case-transition-form" });
  const target = node("select", { name: "status", required: true }, [node("option", { value: "", text: SOCifyLocale.text("اختر الحالة التالية") }), ...(caseTransitions[item.status] || []).map((value) => node("option", { value, text: value }))]);
  workflow.append(
    node("label", {}, [SOCifyLocale.text("الحالة التالية"), target]),
    node("label", {}, [SOCifyLocale.text("سبب القرار"), node("input", { name: "reason", required: true, minlength: "3", maxlength: "500" })]),
    node("label", {}, [SOCifyLocale.text("التصنيف النهائي"), node("input", { name: "disposition", maxlength: "500" })]),
    node("label", {}, [SOCifyLocale.text("السبب الجذري"), node("input", { name: "root_cause", maxlength: "2000" })]),
    node("label", {}, [SOCifyLocale.text("الأثر"), node("input", { name: "impact", maxlength: "2000" })]),
    node("label", {}, [SOCifyLocale.text("ملخص الاستجابة"), node("input", { name: "response_summary", maxlength: "2000" })]),
    node("label", { class: "span-2" }, [SOCifyLocale.text("ملخص الأدلة"), node("textarea", { name: "evidence_summary", maxlength: "5000" })]),
    node("label", { class: "span-2" }, [SOCifyLocale.text("الدروس المستفادة"), node("textarea", { name: "lessons_learned", maxlength: "5000" })]),
    node("label", { class: "span-2" }, [SOCifyLocale.text("التحقق من صحة الإغلاق"), node("textarea", { name: "validation", maxlength: "2000" })]),
    node("div", { class: "action-row span-2" }, button(SOCifyLocale.text("تسجيل الانتقال"), () => {}, "primary"))
  );
  workflow.querySelector("button").setAttribute("type", "submit");
  workflow.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(workflow).entries());
    const payload = { ...values, version: item.version };
    if (payload.status !== "closed") ["disposition", "root_cause", "impact", "response_summary", "evidence_summary", "lessons_learned", "validation"].forEach((field) => delete payload[field]);
    try {
      await api(`/api/incidents/${item.id}/transitions`, { method: "POST", body: payload });
      showMessage(SOCifyLocale.text("تم تحديث دورة حياة التحقيق"), "success");
      await renderIncidents(item.id);
    } catch (error) { handleError(error); }
  });

  const noteForm = node("form", { class: "form-grid" }, [
    node("label", { class: "span-2" }, [SOCifyLocale.text("ملاحظة التحقيق"), node("textarea", { name: "body", required: true, maxlength: "5000" })]),
    node("label", {}, [SOCifyLocale.text("الرؤية"), node("select", { name: "visibility" }, [node("option", { value: "team", text: SOCifyLocale.text("الفريق") }), node("option", { value: "private", text: SOCifyLocale.text("خاصة") })])]),
    node("div", { class: "action-row" }, node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("إضافة الملاحظة") }))
  ]);
  noteForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api(`/api/incidents/${item.id}/notes`, { method: "POST", body: Object.fromEntries(new FormData(noteForm).entries()) });
      showMessage(SOCifyLocale.text("تم حفظ الملاحظة في سجل التحقيق"), "success");
      await renderIncidents(item.id);
    } catch (error) { handleError(error); }
  });

  const logLinkForm = node("form", { class: "form-grid", "aria-label": SOCifyLocale.text("ربط سجلات الاستيراد") }, [
    field(SOCifyLocale.text("رقم مهمة الاستيراد المكتملة"), node("input", { name: "job_id", type: "number", min: "1", required: true })),
    node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("ربط سجلات الاستيراد بالقضية") }),
    linkedButton(SOCifyLocale.text("رفع سجلات جديدة"), "/imports"),
  ]);
  logLinkForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = logLinkForm.querySelector("button");
    submit.disabled = true;
    try {
      const jobId = Number(new FormData(logLinkForm).get("job_id"));
      let afterId = 0;
      let added = 0;
      let result;
      do {
        result = await api(`/api/incidents/${item.id}/imports`, { method: "POST", body: { job_id: jobId, after_id: afterId } });
        afterId = result.next_after_id;
        added += result.added;
      } while (result.has_more);
      showMessage(SOCifyLocale.template`تم ربط ${added} سجلًا جديدًا بالقضية`, "success");
      await renderIncidents(item.id);
    } catch (error) { handleError(error); } finally { submit.disabled = false; }
  });
  const techniqueForm = node("form", { class: "form-grid", "aria-label": SOCifyLocale.text("تسجيل تحليل ATT&CK") }, [
    field("MITRE Technique ID", node("input", { name: "technique_id", placeholder: "T1110", required: true, maxlength: "20" })),
    field(SOCifyLocale.text("تصنيف الربط"), selectControl("assessment", ["suggested", "verified", "rejected"])),
    field(SOCifyLocale.text("رقم سجل الدليل المرتبط"), node("input", { name: "event_id", type: "number", min: "1" })),
    field(SOCifyLocale.text("سبب الاستنتاج"), node("textarea", { name: "reason", required: true, minlength: "3", maxlength: "2000" }), true),
    node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("حفظ تحليل التقنية") }),
  ]);
  techniqueForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(techniqueForm));
    try {
      await api(`/api/incidents/${item.id}/techniques`, { method: "POST", body: { ...values, event_id: values.event_id ? Number(values.event_id) : null } });
      showMessage(SOCifyLocale.text("تم حفظ الاستنتاج ودليله في سجل التحقيق"), "success");
      await renderIncidents(item.id);
    } catch (error) { handleError(error); }
  });

  const taskColumns = [
    { label: SOCifyLocale.text("المهمة"), value: "title" },
    { label: SOCifyLocale.text("الحالة"), value: (task) => badge(task.status) },
    { label: SOCifyLocale.text("إلزامية"), value: (task) => task.required ? SOCifyLocale.text("نعم") : SOCifyLocale.text("لا") },
    { label: SOCifyLocale.text("إجراء"), value: (task) => task.status === "completed" ? SOCifyLocale.text("مكتملة") : button(SOCifyLocale.text("إكمال"), async () => {
      try {
        await api(`/api/incidents/${item.id}/tasks/${task.id}`, { method: "PATCH", body: { status: "completed" } });
        await renderIncidents(item.id);
      } catch (error) { handleError(error); }
    }, "compact") }
  ];
  const evidenceColumns = [
    { label: SOCifyLocale.text("النوع"), value: "evidence_type" }, { label: SOCifyLocale.text("العنوان"), value: "title" }, { label: "SHA-256", value: (evidence) => node("span", { class: "mono", text: evidence.sha256 }) }, { label: SOCifyLocale.text("أضيف"), value: (evidence) => formatTime(evidence.added_at) },
    { label: SOCifyLocale.text("سلسلة الحيازة"), value: (evidence) => button(SOCifyLocale.text("عرض بيانات الدليل"), async () => {
      try {
        const detail = await api(`/api/incidents/${item.id}/evidence/${evidence.id}`);
        const existing = root.querySelector(".evidence-detail");
        if (existing) existing.remove();
        root.append(node("section", { class: "panel evidence-detail", "aria-label": SOCifyLocale.text("بيانات الدليل") }, [
          node("h3", { text: detail.title }),
          node("p", { text: SOCifyLocale.template`أضافه المستخدم ${detail.added_by} · ${formatTime(detail.added_at)}` }),
          node("p", { text: SOCifyLocale.template`آخر وصول ${formatTime(detail.accessed_at)}` }),
          node("pre", { class: "code-box", text: JSON.stringify(detail.provenance, null, 2) }),
          detail.content_available
            ? linkedButton(SOCifyLocale.text("تنزيل المحتوى الأصلي"), `/api/incidents/${item.id}/evidence/${evidence.id}/content`)
            : node("p", { text: SOCifyLocale.text("المحتوى الأصلي غير محفوظ هنا؛ راجع مرجع المصدر.") }),
        ]));
      } catch (error) { handleError(error); }
    }, "compact") }
  ];
  const noteColumns = [
    { label: SOCifyLocale.text("الكاتب"), value: "author_name" }, { label: SOCifyLocale.text("الملاحظة"), value: "body" }, { label: SOCifyLocale.text("الرؤية"), value: (note) => badge(note.visibility) }, { label: SOCifyLocale.text("الوقت"), value: (note) => formatTime(note.created_at) }
  ];
  const alertColumns = [{ label: SOCifyLocale.text("التنبيه"), value: "alert_id" }, { label: SOCifyLocale.text("السبب"), value: "reason" }, { label: SOCifyLocale.text("الخطورة"), value: (alert) => badge(alert.severity) }, { label: SOCifyLocale.text("الحالة"), value: (alert) => badge(alert.status) }];
  const eventColumns = [{ label: SOCifyLocale.text("الواقعة"), value: "event_id" }, { label: SOCifyLocale.text("العنوان"), value: "title" }, { label: SOCifyLocale.text("المصدر"), value: "source" }, { label: SOCifyLocale.text("الخطورة"), value: (event) => badge(event.severity) }, { label: SOCifyLocale.text("الوقت"), value: (event) => formatTime(event.event_time) }];
  const observableColumns = [{ label: SOCifyLocale.text("النوع"), value: "type" }, { label: SOCifyLocale.text("القيمة"), value: (observable) => node("span", { class: "mono", text: observable.value }) }, { label: SOCifyLocale.text("الثقة"), value: (observable) => `${Math.round(Number(observable.confidence) * 100)}%` }, { label: SOCifyLocale.text("المشاهدات"), value: "observation_count" }, { label: SOCifyLocale.text("آخر ظهور"), value: (observable) => formatTime(observable.last_seen) }];
  const similarColumns = [{ label: SOCifyLocale.text("المرجع"), value: (entry) => linkedButton(entry.reference, `/incidents?selected=${entry.id}`, "compact") }, { label: SOCifyLocale.text("العنوان"), value: "title" }, { label: SOCifyLocale.text("الحالة"), value: (entry) => badge(entry.status) }, { label: SOCifyLocale.text("الخطورة"), value: (entry) => badge(entry.severity) }, { label: SOCifyLocale.text("مؤشرات مشتركة"), value: "shared_observables" }];
  const history = node("ol", { class: "timeline" }, item.history.map((entry) => node("li", {}, [node("time", { text: formatTime(entry.created_at) }), node("i"), node("p", { text: `${entry.actor_name}: ${entry.action}${entry.reason ? ` · ${entry.reason}` : ""}` })])));
  root.append(
    node("div", { class: "panel-grid" }, [panel(SOCifyLocale.text("دورة الحياة"), workflow), panel(SOCifyLocale.text("المهام"), table(taskColumns, item.tasks))]),
    node("div", { class: "panel-grid" }, [panel(SOCifyLocale.text("ملاحظات التحقيق"), node("div", {}, [noteForm, item.notes.length ? table(noteColumns, item.notes) : emptyState(SOCifyLocale.text("لا توجد ملاحظات"), SOCifyLocale.text("أضف نتيجة تحليل أو قرارًا موثقًا."))])), panel(SOCifyLocale.text("الأدلة وسلسلة الحيازة"), item.evidence.length ? table(evidenceColumns, item.evidence) : emptyState(SOCifyLocale.text("لا توجد أدلة"), SOCifyLocale.text("اربط تنبيهًا أو سجلًا بالتحقيق.")))]),
    panel(SOCifyLocale.text("التنبيهات المرتبطة"), item.alerts.length ? table(alertColumns, item.alerts) : emptyState(SOCifyLocale.text("لا توجد تنبيهات مرتبطة"), SOCifyLocale.text("أنشئ التحقيق من قائمة التنبيهات لربط الأدلة تلقائيًا.")), true),
    panel(SOCifyLocale.text("السجلات المرتبطة"), item.events.length ? table(eventColumns, item.events) : emptyState(SOCifyLocale.text("لا توجد سجلات مرتبطة"), SOCifyLocale.text("أضف سجلًا من مسار التحقيق المصرح.")), true),
    node("div", { class: "panel-grid" }, [panel("Observables", item.observables.length ? table(observableColumns, item.observables) : emptyState(SOCifyLocale.text("لا توجد مؤشرات مستخرجة"), SOCifyLocale.text("استخرج IoCs من السجلات المرتبطة لتفعيل الارتباط بين القضايا."))), panel(SOCifyLocale.text("تحقيقات مشابهة"), item.similar_cases.length ? table(similarColumns, item.similar_cases) : emptyState(SOCifyLocale.text("لا توجد قضايا مشابهة"), SOCifyLocale.text("يظهر التشابه عند اشتراك التحقيقات في مؤشرات موثقة.")))]),
    panel(SOCifyLocale.text("ربط سجلات القضية"), logLinkForm, true),
    panel(SOCifyLocale.text("تحليل MITRE ATT&CK"), node("div", {}, [techniqueForm, table([
      { label: SOCifyLocale.text("التقنية"), value: "technique_id" }, { label: SOCifyLocale.text("التقييم"), value: "assessment" }, { label: SOCifyLocale.text("الدليل"), value: "event_id" },
      { label: SOCifyLocale.text("السبب"), value: "reason" }, { label: SOCifyLocale.text("المحلل"), value: "author_name" }, { label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.created_at) },
    ], item.technique_annotations || [])]), true),
    panel(SOCifyLocale.text("سجل النشاط"), history, true)
  );
  return root;
}

async function renderIncidents(selectedId = null) {
  begin("incidents");
  const data = await api("/api/incidents?page_size=100");
  const root = node("div");
  const drawer = node("section", { class: "drawer", hidden: true });
  drawer.innerHTML = SOCifyLocale.text('<h3>تحقيق جديد</h3><form id="case-form" class="form-grid"><label class="span-2">العنوان<input name="title" required minlength="3" maxlength="255"></label><label>الخطورة<select name="severity"><option>medium</option><option>critical</option><option>high</option><option>low</option></select></label><label>الأولوية<select name="priority"><option>medium</option><option>urgent</option><option>high</option><option>low</option></select></label><label class="span-2">الوصف<textarea name="description" maxlength="10000"></textarea></label><div class="action-row"><button class="button primary" type="submit">إنشاء التحقيق</button><button id="cancel-case" class="button ghost" type="button">إلغاء</button></div></form>');
  const columns = [{ label: SOCifyLocale.text("المرجع"), value: (row) => button(row.reference, async () => { window.history.replaceState({}, "", `/incidents?selected=${row.id}`); await renderIncidents(row.id); }, "compact") }, { label: SOCifyLocale.text("التحقيق"), value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.title }), node("small", { text: row.description })]) }, { label: SOCifyLocale.text("الخطورة"), value: (row) => badge(row.severity) }, { label: SOCifyLocale.text("الأولوية"), value: (row) => badge(row.priority) }, { label: SOCifyLocale.text("الحالة"), value: (row) => badge(row.status) }, { label: SOCifyLocale.text("المسؤول"), value: "assignee_name" }, { label: SOCifyLocale.text("أدلة"), value: "evidence_count" }, { label: "SLA", value: (row) => row.overdue ? badge("overdue") : formatTime(row.sla_due_at) }];
  root.append(pageHead(SOCifyLocale.text("مساحة التحقيقات"), SOCifyLocale.text("حالات مضبوطة، أدلة محمية، قفل تفاؤلي، وتقارير بإصدارات"), [button(SOCifyLocale.text("تحقيق جديد"), () => { drawer.hidden = false; drawer.querySelector("input").focus(); }, "primary"), linkedButton(SOCifyLocale.text("ابدأ Guided Demo"), "/lab")]), drawer, panel(SOCifyLocale.text("التحقيقات"), data.items.length ? table(columns, data.items) : emptyState(SOCifyLocale.text("لا توجد تحقيقات بعد"), SOCifyLocale.text("أنشئ تحقيقًا أو شغّل سيناريو لتوليد تنبيه ثم اربطه بقضية."), [button(SOCifyLocale.text("إنشاء تحقيق"), () => { drawer.hidden = false; }, "primary"), linkedButton(SOCifyLocale.text("تشغيل سيناريو"), "/lab")]), true));
  finish(root);
  document.getElementById("cancel-case").addEventListener("click", () => { drawer.hidden = true; });
  document.getElementById("case-form").addEventListener("submit", async (event) => { event.preventDefault(); const values = new FormData(event.currentTarget); try { const created = await api("/api/incidents", { method: "POST", body: Object.fromEntries(values.entries()) }); showMessage(SOCifyLocale.template`تم إنشاء ${created.reference}`, "success"); await renderIncidents(); } catch (error) { handleError(error); } });
  const querySelected = new URLSearchParams(window.location.search).get("selected");
  const activeId = selectedId || (querySelected && /^\d+$/.test(querySelected) ? Number(querySelected) : null);
  if (activeId) {
    try {
      const detail = await api(`/api/incidents/${activeId}`);
      root.append(caseDetailView(detail));
    } catch (error) { handleError(error); }
  }
}

async function renderLab() {
  begin("lab");
  const [data, runs] = await Promise.all([api("/api/scenarios"), api("/api/training/runs")]);
  const root = node("div");
  const cards = node("div", { class: "cards" });
  data.items.forEach((scenario) => {
    const start = button(SOCifyLocale.text("بدء جلسة"), async () => {
      try {
        const run = await api("/api/training/runs", { method: "POST", body: { scenario_id: scenario.id, difficulty: scenario.difficulty, auto_play: false } });
        const result = await api(`/api/training/runs/${run.id}/play`, { method: "POST", body: { steps: 1 } });
        showMessage(SOCifyLocale.template`بدأت المحاولة ${run.id} وأُنشئت ${result.event_ids?.length || 0} واقعة تدريبية.`, "success");
        await renderLab();
      } catch (error) {
        handleError(error);
      }
    }, "primary");
    cards.append(node("article", { class: "card" }, [
      node("div", { class: "card-meta" }, [badge(scenario.difficulty), badge(scenario.state), badge(SOCifyLocale.template`${scenario.step_count} خطوات`)]),
      node("h3", { text: scenario.name }),
      node("p", { text: scenario.description }),
      node("p", { text: SOCifyLocale.template`المدة ${scenario.duration_minutes} دقيقة · محاولاتك ${scenario.attempt_count}` }),
      node("div", { class: "action-row" }, [start]),
    ]));
  });
  const runColumns = [
    { label: SOCifyLocale.text("المحاولة"), value: (run) => node("span", { class: "mono", text: run.run_id }) },
    { label: SOCifyLocale.text("السيناريو"), value: "scenario_name" },
    { label: SOCifyLocale.text("الحالة"), value: (run) => badge(run.state) },
    { label: SOCifyLocale.text("تاريخ البدء"), value: (run) => formatTime(run.started_at) },
    { label: SOCifyLocale.text("الإجراء"), value: (run) => run.state === "awaiting_submission"
      ? button(SOCifyLocale.text("تسليم التقييم بعد التحقيق"), async () => {
        try {
          await api(`/api/training/runs/${run.id}/submit`, { method: "POST", body: {} });
          showMessage(SOCifyLocale.text("تم اعتماد المحاولة وحساب الدرجة بناءً على قراراتك وأدلتك المسجلة"), "success");
          await renderLab();
        } catch (error) {
          handleError(error);
        }
      }, "primary")
      : run.state === "completed" ? linkedButton(SOCifyLocale.text("عرض التقييم"), "/scores") : badge(run.state) },
  ];
  const activeRun = runs.items.find((run) => ["running", "paused", "awaiting_submission"].includes(run.state));
  let mission = null;
  if (activeRun) {
    const [detail, scenario, timeline] = await Promise.all([
      api(`/api/training/runs/${activeRun.id}`),
      api(`/api/scenarios/${activeRun.scenario_id}`),
      api(`/api/visualizations/timeline?training_run_id=${activeRun.id}&limit=100`),
    ]);
    const objectiveList = node("ul", { class: "mission-objectives" }, scenario.objectives.map((objective) => node("li", { text: objective })));
    const progressValue = Math.round(Number(detail.progress) * 100);
    const progressView = node("div", { class: "mission-progress" }, [
      node("progress", { max: 100, value: progressValue, "aria-label": SOCifyLocale.text("تقدم السيناريو") }),
      node("strong", { text: SOCifyLocale.template`${detail.current_step} من ${detail.total_steps} خطوات · ${progressValue}%` }),
      node("small", { text: SOCifyLocale.template`البذرة ${detail.seed} · السرعة ${detail.playback_rate}x · التلميحات المستخدمة ${detail.hints_used}` }),
    ]);
    const eventColumns = [
      { label: SOCifyLocale.text("الوقت"), value: (event) => formatTime(event.event_time) },
      { label: SOCifyLocale.text("النوع"), value: "event_type" },
      { label: SOCifyLocale.text("الواقعة"), value: "title" },
      { label: SOCifyLocale.text("الخطورة"), value: (event) => badge(event.severity) },
    ];
    const timelineView = node("ol", { class: "timeline" }, timeline.items.map((item) => node("li", {}, [
      node("time", { datetime: item.event_time, text: formatTime(item.event_time) }),
      node("i", { "aria-hidden": "true" }),
      node("p", { text: `${item.title} · ${item.event_type}` }),
    ])));
    const actions = [];
    if (detail.state === "running") {
      actions.push(button(SOCifyLocale.text("تشغيل الخطوة التالية"), async () => {
        try {
          await api(`/api/training/runs/${detail.id}/play`, { method: "POST", body: { steps: 1 } });
          await renderLab();
        } catch (error) { handleError(error); }
      }, "primary"));
      actions.push(button(SOCifyLocale.text("إيقاف مؤقت"), async () => {
        try {
          await api(`/api/training/runs/${detail.id}/pause`, { method: "POST", body: {} });
          await renderLab();
        } catch (error) { handleError(error); }
      }));
    }
    if (detail.state === "paused") {
      actions.push(button(SOCifyLocale.text("استئناف"), async () => {
        try {
          await api(`/api/training/runs/${detail.id}/resume`, { method: "POST", body: {} });
          await renderLab();
        } catch (error) { handleError(error); }
      }, "primary"));
    }
    if (["running", "paused"].includes(detail.state)) {
      actions.push(button(SOCifyLocale.text("طلب تلميح"), async () => {
        try {
          const hint = await api(`/api/training/runs/${detail.id}/hints`, { method: "POST", body: {} });
          showMessage(SOCifyLocale.template`التلميح: ${hint.hint} · مرات الاستخدام ${hint.hints_used}`, "success");
          await renderLab();
        } catch (error) { handleError(error); }
      }));
    }
    mission = node("section", { class: "mission-console", "aria-label": SOCifyLocale.text("جلسة التدريب النشطة") }, [
      pageHead("Mission Briefing", scenario.description, actions),
      node("div", { class: "panel-grid" }, [
        panel("Objectives", objectiveList),
        panel("Progress", progressView),
      ]),
      panel("Live Event Feed", detail.events.length ? table(eventColumns, detail.events) : emptyState(SOCifyLocale.text("لا توجد وقائع"), SOCifyLocale.text("شغّل الخطوة التالية لتوليد وقائع التدريب.")), true),
      panel("Timeline", timeline.items.length ? timelineView : emptyState(SOCifyLocale.text("الخط الزمني فارغ"), SOCifyLocale.text("ستظهر الوقائع بترتيب وقت الحدث.")), true),
    ]);
  }
  root.append(pageHead(SOCifyLocale.text("سيناريوهات سلاسل الهجوم"), SOCifyLocale.text("المختبر يولّد أحداثًا تدريبية؛ التقييم لا يُحتسب حتى تسلّم المحاولة بنفسك")));
  if (mission) root.append(mission);
  root.append(
    data.items.length ? cards : emptyState(SOCifyLocale.text("لا توجد سيناريوهات منشورة"), SOCifyLocale.text("شغّل seed-data في بيئة development أو أنشئ سيناريو كمدرّب.")),
    panel(SOCifyLocale.text("محاولاتي التدريبية"), runs.items.length ? table(runColumns, runs.items) : emptyState(SOCifyLocale.text("لا توجد محاولات"), SOCifyLocale.text("ابدأ جلسة ثم عالج الأحداث والتنبيهات في التحقيقات قبل تسليم تقييمك.")), true),
  );
  finish(root);
}
async function renderAttack() {
  begin("attack");
  const [matrix, coverage] = await Promise.all([api("/api/attack/matrix"), api("/api/attack/coverage")]);
  const root = node("div");
  const columns = [{ label: SOCifyLocale.text("التقنية"), value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: `${row.technique_id} · ${row.name}` }), node("small", { text: row.tactic })]) }, { label: SOCifyLocale.text("قواعد"), value: "configured" }, { label: SOCifyLocale.text("مختبرة"), value: "tested" }, { label: SOCifyLocale.text("شوهدت"), value: "seen" }, { label: SOCifyLocale.text("كُشفت"), value: "detected_in_run" }, { label: SOCifyLocale.text("حُققت"), value: "investigated" }, { label: SOCifyLocale.text("تم التحقق"), value: "validated" }, { label: SOCifyLocale.text("فائتة"), value: "missed" }];
  root.append(pageHead(SOCifyLocale.text("تغطية ATT&CK المبنية على الأدلة"), SOCifyLocale.template`Enterprise ATT&CK v${coverage.attack_version} · Snapshot محلي`, [linkedButton(SOCifyLocale.text("تصدير Navigator"), "/api/attack/navigator-layer", "primary")]), node("section", { class: "metric-grid" }, [metric(SOCifyLocale.text("التقنيات"), matrix.techniques?.length || coverage.items.length), metric(SOCifyLocale.text("تكتيكات"), matrix.tactics?.length || 0), metric(SOCifyLocale.text("إصدار ATT&CK"), coverage.attack_version, "", SOCifyLocale.text("مثبت ومعلن"))]), panel(SOCifyLocale.text("مصفوفة التغطية"), table(columns, coverage.items), true));
  finish(root);
}

async function renderHunt() {
  begin("hunt");
  const [saved, iocs] = await Promise.all([api("/api/hunt/saved-queries"), api("/api/iocs")]);
  const root = node("div");
  const hunt = node("section", { class: "drawer" });
  hunt.innerHTML = SOCifyLocale.text('<h3>استعلام Typed وآمن</h3><form id="hunt-form" class="form-grid"><label class="span-2">الاستعلام<input class="mono" name="query" required value="severity = high OR severity = critical"></label><div class="action-row"><button class="button primary" type="submit">تنفيذ</button><button id="save-hunt" class="button ghost" type="button">حفظ</button></div></form><div id="hunt-results"></div>');
  const iocColumns = [{ label: SOCifyLocale.text("النوع"), value: "type" }, { label: SOCifyLocale.text("القيمة"), value: (row) => node("span", { class: "mono", text: row.value }) }, { label: SOCifyLocale.text("الثقة"), value: (row) => `${Math.round(Number(row.confidence) * 100)}%` }, { label: SOCifyLocale.text("المصدر"), value: "source" }, { label: SOCifyLocale.text("آخر مشاهدة"), value: (row) => formatTime(row.last_seen) }, { label: SOCifyLocale.text("إجراء"), value: (row) => button(SOCifyLocale.text("إثراء Offline"), async () => { try { const result = await api(`/api/iocs/${row.id}/enrich`, { method: "POST", body: {} }); showMessage(`${result.verdict}: ${result.reason}`, "success"); } catch (error) { handleError(error); } }, "compact") }];
  root.append(pageHead(SOCifyLocale.text("الصيد والـIoCs"), SOCifyLocale.template`${saved.items.length} استعلامات محفوظة · ${iocs.items.length} مؤشرات`), hunt, panel(SOCifyLocale.text("المؤشرات المستخرجة"), iocs.items.length ? table(iocColumns, iocs.items) : emptyState(SOCifyLocale.text("لا توجد مؤشرات"), SOCifyLocale.text("استخرج مؤشرات من سجل محفوظ لتظهر هنا.")), true));
  finish(root);
  const form = document.getElementById("hunt-form");
  form.addEventListener("submit", async (event) => { event.preventDefault(); const query = new FormData(form).get("query"); try { const result = await api("/api/hunt/query", { method: "POST", body: { query, page_size: 100 } }); const columns = [{ label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.event_time) }, { label: SOCifyLocale.text("السجل"), value: "title" }, { label: SOCifyLocale.text("المصدر"), value: "source" }, { label: SOCifyLocale.text("الخطورة"), value: (row) => badge(row.severity) }]; document.getElementById("hunt-results").replaceChildren(node("p", { text: SOCifyLocale.template`${result.total} نتيجة · الاستعلام parameterized` }), result.items.length ? table(columns, result.items) : emptyState(SOCifyLocale.text("لا نتائج"), SOCifyLocale.text("الاستعلام صالح لكنه لم يطابق سجلات."))); } catch (error) { handleError(error); } });
  document.getElementById("save-hunt").addEventListener("click", async () => { const query = new FormData(form).get("query"); const name = window.prompt(SOCifyLocale.text("اسم الاستعلام المحفوظ")); if (!name) return; try { await api("/api/hunt/saved-queries", { method: "POST", body: { name, query, visibility: "private", tags: [] } }); showMessage(SOCifyLocale.text("تم حفظ الاستعلام"), "success"); } catch (error) { handleError(error); } });
}

async function renderGraph() {
  begin("graph");
  const filters = new URLSearchParams(window.location.search);
  filters.set("limit", "150");
  const [graph, timeline] = await Promise.all([api(`/api/visualizations/graph?${filters}`), api(`/api/visualizations/timeline?${filters}`)]);
  const root = node("div");
  const canvas = node("div", { class: "graph-canvas", tabindex: "0", "aria-label": SOCifyLocale.text("رسم الأدلة، استخدم الجدول البديل للتنقل الكامل") });
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const width = 900;
  const height = Math.max(430, Math.ceil(graph.nodes.length / 3) * 110 + 60);
  svg.setAttribute("width", String(width));
  svg.setAttribute("height", String(height));
  svg.setAttribute("role", "group");
  svg.setAttribute("aria-label", SOCifyLocale.text("عقد الأدلة التفاعلية"));
  let zoom = 1;
  let offsetX = 0;
  let offsetY = 0;
  const updateViewport = () => svg.setAttribute("viewBox", `${offsetX} ${offsetY} ${width / zoom} ${height / zoom}`);
  updateViewport();
  const controls = node("div", { class: "action-row" }, [
    button(SOCifyLocale.text("تكبير الرسم"), () => { zoom = Math.min(zoom * 1.25, 5); updateViewport(); }),
    button(SOCifyLocale.text("تصغير الرسم"), () => { zoom = Math.max(zoom / 1.25, 0.5); updateViewport(); }),
    button(SOCifyLocale.text("ملاءمة الرسم"), () => { zoom = 1; offsetX = 0; offsetY = 0; updateViewport(); }),
  ]);
  canvas.addEventListener("keydown", (event) => {
    const directions = { ArrowLeft: [-30, 0], ArrowRight: [30, 0], ArrowUp: [0, -30], ArrowDown: [0, 30] };
    if (!directions[event.key]) return;
    event.preventDefault();
    offsetX += directions[event.key][0] / zoom;
    offsetY += directions[event.key][1] / zoom;
    updateViewport();
  });
  const details = node("div", { class: "panel-body", "aria-live": "polite" }, SOCifyLocale.text("اختر عقدة أو واقعة من الخط الزمني لعرض مصدرها وعلاقاتها."));
  const selectNode = (item) => {
    svg.querySelectorAll(".graph-node").forEach((entry) => entry.classList.toggle("selected", entry.dataset.nodeId === item.id));
    const neighbors = graph.edges.filter((edge) => edge.source === item.id || edge.target === item.id);
    details.replaceChildren(node("h4", { text: item.label }), node("p", { text: `${item.type} · ${item.provenance} · ${formatTime(item.timestamp)}` }), node("p", { text: SOCifyLocale.template`الثقة ${Math.round(Number(item.confidence) * 100)}% · المرجع ${item.reference_id}` }));
    if (item.type === "Event") details.append(linkedButton(SOCifyLocale.text("عرض الواقعة"), `/api/events/${item.reference_id}`));
    if (item.type === "Incident") details.append(linkedButton(SOCifyLocale.text("فتح التحقيق"), `/incidents?selected=${item.reference_id}`));
    const adjacent = new Set(neighbors.map((edge) => edge.source === item.id ? edge.target : edge.source));
    details.append(node("div", { class: "action-row" }, graph.nodes.filter((entry) => adjacent.has(entry.id)).map((entry) => button(`${entry.type}: ${entry.label}`, () => selectNode(entry), "compact"))));
  };
  const form = node("form", { class: "filter-row", "aria-label": SOCifyLocale.text("تصفية الرسم") });
  for (const [name, label] of [["start", SOCifyLocale.text("من الوقت UTC")], ["end", SOCifyLocale.text("إلى الوقت UTC")], ["case_id", SOCifyLocale.text("رقم التحقيق")], ["training_run_id", SOCifyLocale.text("رقم المحاولة")]]) {
    form.append(field(label, node("input", { name, value: filters.get(name) || "", placeholder: name === "start" || name === "end" ? "2026-10-24T00:00:00Z" : "" })));
  }
  const severity = selectControl("severity", ["low", "medium", "high", "critical"], SOCifyLocale.text("كل درجات الخطورة"));
  severity.setAttribute("aria-label", SOCifyLocale.text("الخطورة"));
  severity.value = filters.get("severity") || "auto";
  form.append(field(SOCifyLocale.text("الخطورة"), severity), node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("تطبيق التصفية") }));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const query = new URLSearchParams();
    for (const [key, value] of new FormData(form)) if (value && value !== "auto") query.set(key, value);
    window.history.replaceState({}, "", `/graph?${query}`);
    try { await renderGraph(); } catch (error) { handleError(error); }
  });
  const positions = new Map();
  graph.nodes.forEach((item, index) => {
    positions.set(item.id, { x: 45 + (index % 3) * 300, y: 55 + Math.floor(index / 3) * 110 });
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
    const shortLabel = String(item.label).length > 24 ? String(item.label).slice(0, 24) + "…" : String(item.label);
    group.setAttribute("role", "button"); group.setAttribute("aria-label", `${item.type}: ${shortLabel}`); group.dataset.nodeId = item.id;
    group.addEventListener("click", () => selectNode(item));
    group.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectNode(item); } });
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle"); circle.setAttribute("r", "18");
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text"); label.setAttribute("x", "24"); label.setAttribute("y", "4"); label.textContent = shortLabel;
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title"); title.textContent = `${item.type}: ${item.label}`;
    group.append(title, circle, label); svg.append(group);
  });
  canvas.append(svg);
  const nodeColumns = [{ label: SOCifyLocale.text("النوع"), value: "type" }, { label: SOCifyLocale.text("التسمية"), value: (row) => button(row.label, () => selectNode(row), "compact") }, { label: SOCifyLocale.text("المرجع"), value: "reference_id" }, { label: SOCifyLocale.text("الثقة"), value: (row) => `${Math.round(Number(row.confidence) * 100)}%` }, { label: SOCifyLocale.text("المصدر"), value: "provenance" }];
  const timeList = node("ol", { class: "timeline" }, timeline.items.map((item) => node("li", {}, [node("time", { datetime: item.event_time, text: formatTime(item.event_time) }), node("i", { "aria-hidden": "true" }), button(`${item.event_type}: ${item.title}`, () => { const target = graph.nodes.find((entry) => entry.id === `event:${item.id}`); if (target) selectNode(target); }, "compact")])));
  root.append(pageHead(SOCifyLocale.text("رسم الأدلة والأثر الزمني"), SOCifyLocale.template`${graph.nodes.length} عقد · ${graph.edges.length} علاقات موثقة`, [linkedButton(SOCifyLocale.text("تصدير JSON"), `/api/visualizations/graph/export?${filters}`, "primary")]), form, controls);
  if (graph.truncated || timeline.truncated) root.append(node("p", { class: "notice", text: SOCifyLocale.text("النتائج محدودة؛ ضيّق الفترة أو التحقيق لعرض بقية الأدلة.") }));
  root.append(panel("Graph", canvas, true), panel(SOCifyLocale.text("تفاصيل العقدة"), details), node("div", { class: "panel-grid" }, [panel(SOCifyLocale.text("بديل جدولي قابل للوصول"), table(nodeColumns, graph.nodes)), panel("Timeline", timeList)]));
  finish(root);
}

async function renderPlaybooks() {
  begin("playbooks");
  const data = await api("/api/playbooks");
  const root = node("div");
  const cards = node("div", { class: "cards" });
  data.items.forEach((item) => cards.append(node("article", { class: "card" }, [node("div", { class: "card-meta" }, [badge(`v${item.active_version}`), badge(SOCifyLocale.template`${item.step_count} خطوات`), badge(item.trigger_type)]), node("h3", { text: item.name }), node("p", { text: item.description }), node("p", { text: SOCifyLocale.text("تأثير محاكى داخل DB فقط · لا أوامر خارجية") }), node("div", { class: "action-row" }, [button(SOCifyLocale.text("معاينة"), async () => { try { const result = await api(`/api/playbooks/${item.id}/preview`, { method: "POST", body: { parameters: {} } }); window.alert(JSON.stringify(result, null, 2)); } catch (error) { handleError(error); } }, "primary")])])));
  root.append(pageHead(SOCifyLocale.text("مكتبة الاستجابة المحاكية"), SOCifyLocale.text("State machine بإصدارات وموافقات وتراجع؛ external_effects=false")), data.items.length ? cards : emptyState(SOCifyLocale.text("لا توجد Playbooks منشورة"), SOCifyLocale.text("فعّل بيانات التطوير أو أنشئ Playbook بإصدار منشور.")));
  finish(root);
}

async function renderScores() {
  begin("scores");
  const [scores, leaders] = await Promise.all([api("/api/scores/me"), api("/api/leaderboards")]);
  const root = node("div");
  const scoreColumns = [{ label: SOCifyLocale.text("السيناريو"), value: "scenario_name" }, { label: SOCifyLocale.text("الصعوبة"), value: (row) => badge(row.difficulty) }, { label: SOCifyLocale.text("النتيجة"), value: (row) => `${Number(row.total_score).toFixed(1)} / 100` }, { label: SOCifyLocale.text("كشف الآلة"), value: (row) => row.components?.metrics?.machine_detection_latency_seconds == null ? SOCifyLocale.text("غير مقاس") : `${Number(row.components.metrics.machine_detection_latency_seconds).toFixed(1)}s` }, { label: SOCifyLocale.text("قرار المتدرب"), value: (row) => row.components?.metrics?.learner_discovery_latency_seconds == null ? SOCifyLocale.text("غير مقاس") : `${Number(row.components.metrics.learner_discovery_latency_seconds).toFixed(1)}s` }, { label: "MTTR", value: (row) => row.components?.metrics?.mean_time_to_resolve_seconds == null ? SOCifyLocale.text("غير مقاس") : `${Number(row.components.metrics.mean_time_to_resolve_seconds).toFixed(1)}s` }, { label: "Precision", value: (row) => row.components?.metrics?.detection_precision == null ? SOCifyLocale.text("غير مقاس") : Number(row.components.metrics.detection_precision).toFixed(3) }, { label: "Recall", value: (row) => row.components?.metrics?.detection_recall == null ? SOCifyLocale.text("غير مقاس") : Number(row.components.metrics.detection_recall).toFixed(3) }, { label: SOCifyLocale.text("التقرير"), value: (row) => linkedButton(SOCifyLocale.text("تنزيل"), `/api/assessments/${row.id}/report`, "compact") }, { label: SOCifyLocale.text("التاريخ"), value: (row) => formatTime(row.created_at) }];
  const leaderColumns = [{ label: SOCifyLocale.text("الترتيب"), value: "rank" }, { label: SOCifyLocale.text("المتدرب"), value: "name" }, { label: SOCifyLocale.text("المجموعة"), value: "cohort" }, { label: SOCifyLocale.text("السيناريو"), value: "scenario_name" }, { label: SOCifyLocale.text("الصعوبة"), value: (row) => badge(row.difficulty) }, { label: SOCifyLocale.text("النتيجة"), value: "score" }];
  const preference = button(leaders.opted_in ? SOCifyLocale.text("إيقاف الظهور في الترتيب") : SOCifyLocale.text("الاشتراك في الترتيب"), async () => { try { await api("/api/profile/leaderboard", { method: "PUT", body: { opt_in: !leaders.opted_in } }); await renderScores(); } catch (error) { handleError(error); } }, leaders.opted_in ? "danger" : "primary");
  root.append(pageHead(SOCifyLocale.text("التقييم الحتمي"), SOCifyLocale.template`Snapshots ثابتة · مجموعة الترتيب: ${leaders.cohort || SOCifyLocale.text("غير محددة")}`, [preference]), node("div", { class: "panel-grid" }, [panel(SOCifyLocale.text("نتائجي"), scores.items.length ? table(scoreColumns, scores.items) : emptyState(SOCifyLocale.text("لا توجد نتائج"), SOCifyLocale.text("أكمل سيناريو لتوليد Snapshot تقييم."))), panel(SOCifyLocale.text("لوحة الترتيب"), leaders.items.length ? table(leaderColumns, leaders.items) : emptyState(SOCifyLocale.text("لا توجد نتائج منشورة"), leaders.opted_in ? SOCifyLocale.text("لم ينشر أعضاء مجموعتك نتائج بعد.") : SOCifyLocale.text("الظهور والمقارنة اختياريان ويتطلبان الاشتراك.")))]));
  finish(root);
}

async function renderAudit() {
  begin("audit");
  const data = await api("/api/audit?page_size=200");
  const root = node("div");
  const columns = [{ label: SOCifyLocale.text("الوقت"), value: (row) => formatTime(row.created_at) }, { label: SOCifyLocale.text("الفاعل"), value: (row) => row.actor_name || `#${row.actor_id || "system"}` }, { label: SOCifyLocale.text("العملية"), value: "action" }, { label: SOCifyLocale.text("المورد"), value: (row) => `${row.resource_type}${row.resource_id ? ` #${row.resource_id}` : ""}` }, { label: SOCifyLocale.text("النتيجة"), value: (row) => badge(row.result) }, { label: "Correlation", value: (row) => node("span", { class: "mono", text: row.correlation_id }) }, { label: SOCifyLocale.text("التفاصيل"), value: (row) => JSON.stringify(row.details) }];
  root.append(pageHead(SOCifyLocale.text("سجل التدقيق"), SOCifyLocale.template`${data.total} عملية ضمن مساحة العمل · البيانات الحساسة محجوبة`), panel(SOCifyLocale.text("النشاط"), data.items.length ? table(columns, data.items) : emptyState(SOCifyLocale.text("لا يوجد نشاط مسجل"), SOCifyLocale.text("ستظهر عمليات المصادقة والقواعد والمصادر والتحقيقات هنا.")), true));
  finish(root);
}

async function renderAdmin() {
  begin("admin");
  const [users, roles] = await Promise.all([api("/api/admin/users"), api("/api/admin/role-matrix")]);
  const root = node("div");
  const userColumns = [{ label: SOCifyLocale.text("المستخدم"), value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.name }), node("small", { text: row.email })]) }, { label: SOCifyLocale.text("الدور"), value: (row) => badge(row.role) }, { label: SOCifyLocale.text("الفريق"), value: "team" }, { label: SOCifyLocale.text("نشط"), value: (row) => row.is_active ? SOCifyLocale.text("نعم") : SOCifyLocale.text("لا") }, { label: SOCifyLocale.text("آخر دخول"), value: (row) => formatTime(row.last_login) }];
  const roleColumns = [{ label: SOCifyLocale.text("الدور"), value: (row) => badge(row.role) }, { label: SOCifyLocale.text("الصلاحيات"), value: (row) => node("span", { text: row.permissions.join(" · ") }) }];
  root.append(pageHead(SOCifyLocale.text("الحوكمة والصلاحيات"), SOCifyLocale.text("Default deny ومصفوفة أدوار معلنة")), node("div", { class: "panel-grid" }, [panel(SOCifyLocale.text("المستخدمون"), table(userColumns, users.items)), panel(SOCifyLocale.text("مصفوفة الصلاحيات"), table(roleColumns, roles.items))]));
  finish(root);
}

async function renderTeam() {
  begin("team");
  const data = await api("/api/team");
  const root = node("div", {}, pageHead(SOCifyLocale.text("الفريق وتوزيع التحقيقات"), SOCifyLocale.text("الإسناد مرتبط بالاستيراد والقضية والتقرير؛ السجلات المشتركة تعاونية داخل الفريق")));
  const save = async (path, method, body) => { try { await api(path, { method, body }); await renderTeam(); } catch (error) { handleError(error); } };
  const memberColumns = [{ label: SOCifyLocale.text("العضو"), value: "name" }, { label: SOCifyLocale.text("البريد"), value: "email" }, { label: SOCifyLocale.text("الدور"), value: "role" }];
  if (data.can_manage) memberColumns.push({ label: SOCifyLocale.text("تغيير الدور"), value: (member) => {
    if (member.role === "admin") return SOCifyLocale.text("مدير النظام");
    const select = selectControl("role", data.roles.map((entry) => entry.role));
    select.value = member.role; select.setAttribute("aria-label", SOCifyLocale.template`دور ${member.name}`);
    return node("div", { class: "action-row" }, [select, button(SOCifyLocale.text("حفظ الدور"), () => save(`/api/team/members/${member.id}`, "PATCH", { role: select.value }), "compact")]);
  }});
  root.append(panel(SOCifyLocale.text("أعضاء الفريق"), table(memberColumns, data.members), true));
  const columns = [{ label: SOCifyLocale.text("المسؤول"), value: "assignee_name" }, { label: SOCifyLocale.text("الملف"), value: "filename" }, { label: SOCifyLocale.text("القضية"), value: (row) => linkedButton(row.reference, `/incidents?selected=${row.case_id}`, "compact") }, { label: SOCifyLocale.text("التعليمات"), value: "instructions" }, { label: SOCifyLocale.text("الحالة"), value: "task_status" }, { label: SOCifyLocale.text("الإجراء"), value: (row) => node("div", { class: "action-row" }, [linkedButton(SOCifyLocale.text("الخط الزمني"), `/graph?case_id=${row.case_id}`, "compact"), button(SOCifyLocale.text("بدء التحليل"), () => save(`/api/team/assignments/${row.id}`, "PATCH", { status: "in_progress" }), "compact"), button(SOCifyLocale.text("إكمال المهمة"), () => save(`/api/team/assignments/${row.id}`, "PATCH", { status: "completed" }), "compact")]) }];
  root.append(panel(SOCifyLocale.text("مهام تحليل السجلات"), data.assignments.length ? table(columns, data.assignments) : emptyState(SOCifyLocale.text("لا مهام مسندة"), SOCifyLocale.text("يسند المدير استيرادًا مكتملًا مرتبطًا بقضية إلى عضو الفريق.")), true));
  if (data.can_manage) {
    const invite = node("form", { class: "form-grid", "aria-label": SOCifyLocale.text("دعوة عضو") }, [field(SOCifyLocale.text("البريد الإلكتروني"), node("input", { name: "email", type: "email", required: true })), field(SOCifyLocale.text("دور العضو"), selectControl("role", data.roles.map((entry) => entry.role))), node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("إنشاء دعوة") })]);
    const resultView = node("div", { class: "panel-body", "aria-live": "polite" });
    invite.addEventListener("submit", async (event) => { event.preventDefault(); try { const result = await api("/api/team/invitations", { method: "POST", body: Object.fromEntries(new FormData(invite)) }); resultView.replaceChildren(node("p", { text: SOCifyLocale.text("شارك الرمز مع صاحب البريد ليستخدمه عند التسجيل؛ صالح ليوم واحد ومرة واحدة.") }), node("code", { text: result.invitation_token })); } catch (error) { handleError(error); } });
    root.append(panel(SOCifyLocale.text("دعوة عضو"), node("div", { class: "panel-body" }, [invite, resultView])));
    const assignment = node("form", { class: "form-grid", "aria-label": SOCifyLocale.text("إسناد سجلات") }, [field(SOCifyLocale.text("رقم الاستيراد"), node("input", { name: "job_id", type: "number", min: 1, required: true })), field(SOCifyLocale.text("رقم القضية"), node("input", { name: "case_id", type: "number", min: 1, required: true })), field(SOCifyLocale.text("المسؤول"), node("select", { name: "assignee" }, data.members.filter((member) => member.is_active && ["analyst", "soc_manager"].includes(member.role)).map((member) => node("option", { value: member.id, text: member.name })))), field(SOCifyLocale.text("تعليمات التحليل"), node("textarea", { name: "instructions", minlength: 3, maxlength: 2000, required: true })), node("button", { type: "submit", class: "button primary", text: SOCifyLocale.text("إسناد التحليل") }), linkedButton(SOCifyLocale.text("الاستيراد"), "/imports"), linkedButton(SOCifyLocale.text("القضايا وربط السجلات"), "/incidents")]);
    assignment.elements.namedItem("case_id").value = new URLSearchParams(window.location.search).get("case_id") || "";
    assignment.addEventListener("submit", (event) => { event.preventDefault(); const values = Object.fromEntries(new FormData(assignment)); return save("/api/team/assignments", "POST", { ...values, job_id: Number(values.job_id), case_id: Number(values.case_id), assignee: Number(values.assignee) }); });
    root.append(panel(SOCifyLocale.text("توزيع دفعة سجلات"), node("div", { class: "panel-body" }, assignment)));
    for (const role of data.roles.filter((entry) => entry.role !== "soc_manager")) {
      const form = node("form", { class: "panel-body", "aria-label": SOCifyLocale.template`صلاحيات ${role.role}` });
      for (const permission of role.available) form.append(node("label", {}, [node("input", { type: "checkbox", name: "permissions", value: permission, checked: role.permissions.includes(permission) }), permission]));
      form.append(node("button", { type: "submit", class: "button primary", text: SOCifyLocale.template`حفظ صلاحيات ${role.role}` }));
      form.addEventListener("submit", (event) => { event.preventDefault(); return save(`/api/team/roles/${role.role}`, "PUT", { permissions: new FormData(form).getAll("permissions") }); });
      root.append(panel(SOCifyLocale.template`صلاحيات ${role.role}`, form));
    }
  }
  finish(root);
}

async function renderProfile() {
  begin("profile");
  const [profile, sessions, settings] = await Promise.all([api("/api/profile"), api("/api/auth/sessions"), api("/api/settings")]);
  const root = node("div");
  const account = node("div", { class: "panel-body" }, [node("p", { text: SOCifyLocale.template`الاسم: ${profile.user.name}` }), node("p", { text: SOCifyLocale.template`البريد: ${profile.user.email}` }), node("p", { text: SOCifyLocale.template`الدور: ${profile.user.role}` }), node("p", { text: SOCifyLocale.template`لوحة الترتيب: ${profile.user.leaderboard_opt_in ? SOCifyLocale.text("مشترك") : SOCifyLocale.text("غير مشترك")}` }), node("p", { text: `MFA: ${profile.mfa.enabled ? SOCifyLocale.text("مفعّل") : SOCifyLocale.text("غير مفعّل")}` }), node("p", { text: SOCifyLocale.template`جلسات نشطة: ${profile.active_sessions}` })]);
  const sessionColumns = [{ label: SOCifyLocale.text("بدأت"), value: (row) => formatTime(row.created_at) }, { label: SOCifyLocale.text("آخر نشاط"), value: (row) => formatTime(row.last_seen_at) }, { label: SOCifyLocale.text("تنتهي"), value: (row) => formatTime(row.expires_at) }, { label: "IP", value: (row) => node("span", { class: "mono", text: row.ip_address }) }, { label: SOCifyLocale.text("الحالة"), value: (row) => badge(row.revoked_at ? "revoked" : "active") }];
  root.append(pageHead(SOCifyLocale.text("أمان الحساب"), `${settings.environment} · Registration ${settings.registration_enabled ? "enabled" : "disabled"}`), node("div", { class: "panel-grid" }, [panel(SOCifyLocale.text("الحساب"), account), panel(SOCifyLocale.text("الجلسات"), table(sessionColumns, sessions.items))]));
  finish(root);
}

function handleError(error) {
  const details = error.details ? ` · ${JSON.stringify(error.details)}` : "";
  showMessage(`${error.message || SOCifyLocale.text("حدث خطأ غير متوقع")}${details}`);
  console.error(error.code || error.name, error.status || "", error.message);
}

const renderers = { dashboard: renderDashboard, events: renderEvents, alerts: renderAlerts, rules: renderRules, sources: renderSources, imports: renderImports, incidents: renderIncidents, lab: renderLab, attack: renderAttack, hunt: renderHunt, graph: renderGraph, playbooks: renderPlaybooks, scores: renderScores, audit: renderAudit, admin: renderAdmin, profile: renderProfile };

async function initialize() {
  const me = await api("/api/auth/me");
  state.user = me.user;
  state.permissions = new Set(me.permissions);
  if (document.querySelector('meta[name="product-mode"]')?.content === "autopsy") {
    await window.SOCifyAutopsy.start();
    return;
  }
  const renderer = state.section === "team" ? renderTeam : renderers[state.section] || renderDashboard;
  try { await renderer(); } catch (error) {
    handleError(error);
    if (error.status === 403) finish(emptyState(SOCifyLocale.text("هذا القسم غير متاح لدورك"), SOCifyLocale.text("تطبق المنصة صلاحيات الخادم حتى عند فتح الرابط مباشرة."), [linkedButton(SOCifyLocale.text("العودة إلى النظرة العامة"), "/dashboard", "primary")]));
  }
}

const menu = document.getElementById("menu-toggle");
menu.addEventListener("click", () => {
  const sidebar = document.querySelector(".sidebar");
  const open = sidebar.classList.toggle("open");
  menu.setAttribute("aria-expanded", String(open));
});
function closeNavigation() {
  document.querySelector(".sidebar").classList.remove("open");
  menu.setAttribute("aria-expanded", "false");
}
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && document.querySelector(".sidebar.open")) { closeNavigation(); menu.focus(); }
});
document.addEventListener("click", (event) => {
  if (!event.target.closest(".sidebar, #menu-toggle")) closeNavigation();
});


document.addEventListener("DOMContentLoaded", () => initialize().catch(handleError), { once: true });
