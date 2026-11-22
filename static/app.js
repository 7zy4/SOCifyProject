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
  playbooks: [SOCifyLocale.text("الكتيبات"), "PLAYBOOKS"],
  audit: [SOCifyLocale.text("التدقيق"), "AUDIT"],
  admin: [SOCifyLocale.text("الإدارة"), "ADMIN"],
  profile: [SOCifyLocale.text("الملف الشخصي"), "PROFILE"],
  "analysis-library": [SOCifyLocale.text("مكتبة القواعد"), "RULE LIBRARY"],
  team: [SOCifyLocale.text("الفريق"), "TEAM"]
};

function displayText(value) {
  const text = value == null ? "—" : String(value);
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
  // Text a person writes may be Arabic or English whatever the interface language: let its own first strong character set
  // the direction, so English in the Arabic interface (and the reverse) keeps its punctuation and shows its beginning.
  // Browsers give an empty dir=auto field a left-to-right direction that CSS cannot override, which would push an Arabic
  // placeholder to the left; so a field follows its own text only while it holds some.
  const freeText = tag === "textarea" || (tag === "input" && ["", "text", "search"].includes(String(attributes.type || "")));
  if (!element.hasAttribute("dir") && freeText) {
    const follow = () => (element.value ? element.setAttribute("dir", "auto") : element.removeAttribute("dir"));
    follow();
    element.addEventListener("input", follow);
    element.addEventListener("change", follow);
    queueMicrotask(() => element.form?.addEventListener("reset", () => setTimeout(follow)));
  } else if (!element.hasAttribute("dir") && element.hasAttribute("data-user-content")) element.setAttribute("dir", "auto");
  return element;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  // One calendar and one digit system in both languages: Gregorian dates with Western digits, always in UTC.
  return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat(window.SOCifyLocale?.language === "en" ? "en-GB" : "ar-u-ca-gregory-nu-latn", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(date) + " UTC";
}

// An analyst's name as a tag with the same height and frame as the status tag; the full name stays in the tooltip.
function personChip(name) {
  const text = name || SOCifyLocale.text("غير مسند");
  return node("span", { class: `badge badge-person${name ? "" : " unassigned"}`, title: text, "data-user-content": name ? "true" : null, text });
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

function recoverSession() {
  if (!state.user || !window.SOCifyDrafts?.hasChanges()) { window.location.assign("/login"); return; }
  const existing = document.getElementById("session-recovery");
  if (existing) { if (!existing.open) existing.showModal(); return; }
  const principal = { id: state.user.id, workspace_id: state.user.workspace_id };
  const previous = document.activeElement;
  const errors = node("p", { role: "alert", class: "notice", hidden: true });
  const login = node("a", { href: "/login", target: "_blank", rel: "noopener", class: "button primary", text: SOCifyLocale.text("تسجيل الدخول") });
  const dialog = node("dialog", { id: "session-recovery", class: "autopsy-modal", "aria-label": SOCifyLocale.text("تجديد الجلسة") });
  const resume = button(SOCifyLocale.text("متابعة العمل"), async () => {
    resume.disabled = true;
    errors.hidden = true;
    try {
      const current = await fetch("/api/auth/me", { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (!current.ok) { await current.text(); throw new Error(SOCifyLocale.text("سجّل الدخول أولًا ثم تابع العمل.")); }
      const identity = await current.json();
      if (identity.user.id !== principal.id || identity.user.workspace_id !== principal.workspace_id) throw new Error(SOCifyLocale.text("سجّل الدخول بالحساب نفسه لمتابعة هذه المسودة."));
      const token = identity.csrf_token;
      if (typeof token !== "string" || !token) throw new Error(SOCifyLocale.text("تعذر تجديد الجلسة. أعد المحاولة."));
      state.csrf = token;
      state.permissions = new Set(identity.permissions);
      state.user = identity.user;
      dialog.close();
    } catch (error) {
      errors.textContent = error instanceof TypeError ? SOCifyLocale.text("تعذر الاتصال. أعد المحاولة.") : error.message;
      errors.hidden = false;
    } finally { resume.disabled = false; }
  });
  dialog.append(node("h2", { text: SOCifyLocale.text("تجديد الجلسة") }), node("p", { text: SOCifyLocale.text("مسودتك باقية هنا. سجّل الدخول في النافذة الجديدة ثم تابع العمل.") }), node("div", { class: "action-row" }, [login, resume, button(SOCifyLocale.text("إغلاق"), () => dialog.close())]), errors);
  dialog.addEventListener("close", () => { dialog.remove(); if (previous?.isConnected) previous.focus(); });
  document.body.append(dialog);
  dialog.showModal();
}

async function api(path, options = {}) {
  const config = { credentials: "same-origin", ...options, headers: { Accept: "application/json", "X-SOCify-Language": SOCifyLocale.language, ...(options.headers || {}) } };
  if (config.body && !(config.body instanceof FormData) && typeof config.body !== "string") {
    config.headers["Content-Type"] = "application/json";
    config.body = JSON.stringify(config.body);
  }
  if (config.method && !["GET", "HEAD"].includes(config.method.toUpperCase())) config.headers["X-CSRFToken"] = state.csrf;
  let response;
  try { response = await fetch(path, config); }
  catch (error) {
    if (error.name === "AbortError") throw error;
    throw new Error(SOCifyLocale.text("تعذر الاتصال. أعد المحاولة."));
  }
  if (response.status === 401) {
    recoverSession();
    await response.text().catch(() => {});
    throw new Error(SOCifyLocale.text("انتهت الجلسة"));
  }
  let payload = null;
  if (response.status !== 204) {
    const contentType = response.headers.get("content-type") || "";
    try {
      if (response.ok && !contentType.includes("json")) throw new Error();
      payload = contentType.includes("json") ? await response.json() : await response.text();
    } catch (_) { throw new Error(SOCifyLocale.text("تعذر قراءة الرد. أعد المحاولة.")); }
  }
  if (!response.ok) {
    const renewalRequired = ["CSRF_FAILED", "CSRF_VALIDATION_FAILED"].includes(payload?.error?.code);
    if (renewalRequired) recoverSession();
    const error = new Error(renewalRequired ? SOCifyLocale.text("تحتاج الجلسة إلى تجديد. سجّل الدخول ثم أعد محاولة الحفظ.") : SOCifyLocale.error(payload?.error?.code, payload?.error?.message) || SOCifyLocale.template`تعذر إكمال الطلب (${response.status})`);
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
  document.querySelectorAll("#primary-nav a").forEach((link) => {
    const active = link.dataset.section === section || (section === "case" && link.dataset.section === "cases");
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  });
}

function begin(section) {
  setHeading(section);
  workspace.setAttribute("aria-busy", "true");
  workspace.replaceChildren(node("div", { class: "loading" }, [node("span"), node("p", { text: SOCifyLocale.text("جارٍ التحميل…") })]));
}

function finish(content) {
  workspace.replaceChildren(content);
  workspace.setAttribute("aria-busy", "false");
  document.dispatchEvent(new CustomEvent("socify:workspace-ready"));
}

// Callers pass a page description as the second argument; the header shows only the title and actions.
function pageHead(title, _description, actions = []) {
  return node("div", { class: "workspace-head" }, [node("div", {}, [node("h2", { text: title })]), node("div", { class: "action-row" }, actions)]);
}

function emptyState(title, description, actions = []) {
  return node("div", { class: "empty" }, [node("strong", { text: title }), ...(description ? [node("p", { text: description })] : []), node("div", { class: "action-row" }, actions)]);
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

function stackedTable(columns, rows) {
  const content = table(columns, rows);
  content.classList.add("assignment-table");
  content.querySelector("table").setAttribute("role", "table");
  content.querySelectorAll("thead,tbody").forEach(group => group.setAttribute("role", "rowgroup"));
  content.querySelectorAll("tr").forEach(row => row.setAttribute("role", "row"));
  content.querySelectorAll("th").forEach(cell => cell.setAttribute("role", "columnheader"));
  content.querySelectorAll("tbody tr").forEach(row => [...row.cells].forEach((cell, index) => { cell.setAttribute("role", "cell"); cell.prepend(node("span", { class: "assignment-cell-label", "aria-hidden": "true", text: columns[index].label })); }));
  return content;
}

function metric(label, value, style = "", detail = SOCifyLocale.text("من قاعدة البيانات")) {
  return node("article", { class: `metric ${style}` }, [node("span", { text: label }), node("strong", { text: Number(value || 0).toLocaleString(SOCifyLocale.locale) }), node("small", { text: detail })]);
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

function permission(name) {
  return state.permissions.has("*") || state.permissions.has(name);
}

async function renderAudit() {
  begin("audit");
  const t = SOCifyLocale.text;
  const url = new URL(location.href);
  const applied = Object.fromEntries(["q", "action", "resource", "result"].map(key => [key, url.searchParams.get(key) || ""]));
  const requestedPage = Number(url.searchParams.get("page") || 1);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 && requestedPage <= 1000000 ? requestedPage : 1;
  const params = new URLSearchParams({...applied, page, page_size:25});
  const data = await api(`/api/audit?${params}`);
  const labels = {login:"تسجيل الدخول",logout:"خروج",create:"إنشاء",update:"تعديل",review:"مراجعة",selection_changed:"تحديد نطاق التحقيق",case_linked:"ربط القضايا",read:"عرض",download:"تنزيل",ingest:"استقبال السجلات",ingest_retry:"إعادة إرسال السجلات",rotate_key:"تجديد مفتاح المصدر",case:"قضية",auth:"المصادقة",source:"مصدر السجلات",rule:"قاعدة كشف",investigation:"نطاق التحقيق",user:"عضو",auth_session:"جلسة دخول",case_evidence:"دليل",case_report:"تقرير",workspace:"مساحة العمل",success:"نجاح",denied:"مرفوض",failure:"فشل",error:"خطأ"};
  Object.assign(labels, {decision:"القرار",approved:"معتمد",rejected:"مرفوض",events:"السجلات",alerts:"التنبيهات",fields:"الحقول",case_ids:"القضايا",case_id:"القضية",reason:"السبب"});
  const label = value => t(labels[value] || value);
  const detailValue = (value, key = "") => {
    if (Array.isArray(value)) return value.length ? node("ul", {}, value.map(item => node("li", {}, detailValue(item,key)))) : node("span", {text:"—"});
    if (value && typeof value === "object") return node("dl", {}, Object.entries(value).flatMap(([name, item]) => [node("dt", {text:label(name)}),node("dd", {}, detailValue(item,name))]));
    return node("bdi", {text:["decision","result","status"].includes(key) && typeof value === "string" ? label(value) : String(value ?? "—")});
  };
  const navigate = async (filters, nextPage = 1) => {
    const next = new URL(location.href);
    for (const key of ["q", "action", "resource", "result"]) {
      if (filters[key]) next.searchParams.set(key, filters[key]); else next.searchParams.delete(key);
    }
    if (nextPage > 1) next.searchParams.set("page", nextPage); else next.searchParams.delete("page");
    history.replaceState(null, "", next.pathname + next.search + next.hash);
    try { await renderAudit(); } catch (error) { handleError(error); }
  };
  const query = node("input", {name:"q",type:"search",maxlength:200,value:applied.q});
  const controls = {};
  for (const [key, facet] of [["action","actions"],["resource","resources"],["result","results"]]) {
    const values = [...new Set([...(data.filters?.[facet] || []), ...(applied[key] ? [applied[key]] : [])])];
    controls[key] = node("select", {name:key}, [node("option", {value:"",text:t("الكل")}), ...values.map(value => node("option", {value,selected:value === applied[key],text:label(value)}))]);
  }
  const filters = node("form", {class:"filter-row", "aria-label":t("بحث سجل التدقيق")}, [field(t("بحث"),query),field(t("العملية"),controls.action),field(t("المورد"),controls.resource),field(t("النتيجة"),controls.result),node("button", {type:"submit",class:"button ghost",text:t("بحث")}),button(t("مسح المرشحات"), () => navigate({}))]);
  filters.addEventListener("submit", event => { event.preventDefault(); navigate({q:query.value.trim(),action:controls.action.value,resource:controls.resource.value,result:controls.result.value}); });
  const columns = [
    {label:t("الوقت"),value:row => formatTime(row.created_at)},
    {label:t("الفاعل"),value:row => row.actor_name || t("النظام")},
    {label:t("العملية"),value:row => label(row.action)},
    {label:t("المورد"),value:row => node("div", {class:"cell-title"}, [node("strong", {text:row.resource_title || label(row.resource_type)}),node("bdi", {text:row.resource_reference || (row.resource_id ? `#${row.resource_id}` : "—")})])},
    {label:t("النتيجة"),value:row => node("span", {class:`badge ${String(row.result).replace(/[^a-z_]/g, "")}`,text:label(row.result)})},
    {label:t("التفاصيل"),value:row => node("details", {class:"audit-entry-details"}, [node("summary", {text:t("تفاصيل العملية")}),node("dl", {}, [node("dt", {text:t("معرف التتبع")}),node("dd", {}, node("bdi", {text:row.correlation_id}))]),...(Object.keys(row.details).length ? [detailValue(row.details)] : [])])}
  ];
  const pages = node("div", {class:"action-row pagination"}, node("p", {role:"status",text:SOCifyLocale.template`${data.total} عملية | الصفحة ${page}`}));
  if (page > 1) pages.append(button(t("السابق"), () => navigate(applied,page - 1)));
  if (page * data.page_size < data.total) pages.append(button(t("التالي"), () => navigate(applied,page + 1)));
  const root = node("div", {class:"audit-view"}, [pageHead(t("التدقيق"),null),filters,panel(t("النشاط"),data.items.length ? table(columns,data.items) : emptyState(t("لا توجد نتائج"),null),true),pages]);
  finish(root);
}

async function renderAdmin() {
  begin("admin");
  const [users, roles] = await Promise.all([api("/api/admin/users"), api("/api/admin/role-matrix")]);
  const root = node("div");
  const userColumns = [{ label: SOCifyLocale.text("المستخدم"), value: (row) => node("div", { class: "cell-title" }, [node("strong", { text: row.name }), node("small", { text: row.email })]) }, { label: SOCifyLocale.text("الدور"), value: (row) => badge(row.role) }, { label: SOCifyLocale.text("الفريق"), value: "team" }, { label: SOCifyLocale.text("نشط"), value: (row) => row.is_active ? SOCifyLocale.text("نعم") : SOCifyLocale.text("لا") }, { label: SOCifyLocale.text("آخر دخول"), value: (row) => formatTime(row.last_login) }];
  const roleColumns = [{ label: SOCifyLocale.text("الدور"), value: (row) => badge(row.role) }, { label: SOCifyLocale.text("الصلاحيات"), value: (row) => node("span", { text: row.permissions.join(" | ") }) }];
  root.append(pageHead(SOCifyLocale.text("الصلاحيات"), null), node("div", { class: "panel-grid" }, [panel(SOCifyLocale.text("المستخدمون"), table(userColumns, users.items)), panel(SOCifyLocale.text("مصفوفة الصلاحيات"), table(roleColumns, roles.items))]));
  finish(root);
}

function handleError(error) {
  const details = error.details ? ` | ${JSON.stringify(error.details)}` : "";
  showMessage(`${error.message || SOCifyLocale.text("حدث خطأ غير متوقع")}${details}`);
  console.error(error.code || error.name, error.status || "", error.message);
}

async function initialize() {
  const me = await api("/api/auth/me");
  state.user = me.user;
  state.permissions = new Set(me.permissions);
  await window.SOCifyAutopsy.start();
}

const menu = document.getElementById("menu-toggle");
const navigationSidebar = document.querySelector(".sidebar");
const navigationCompact = window.matchMedia(document.body.classList.contains("autopsy-shell") ? "(max-width:1099px)" : "(max-width:900px)");
navigationSidebar.inert = navigationCompact.matches;
const navigationShade = node("div", { class: "navigation-shade", hidden: true, "aria-hidden": "true" });
document.body.append(navigationShade);
const navigationHeader = document.querySelector(".topbar");
new ResizeObserver(() => {
  document.documentElement.style.setProperty("--navigation-top", `${navigationHeader.getBoundingClientRect().bottom}px`);
}).observe(navigationHeader);
menu.addEventListener("click", () => {
  const open = navigationSidebar.classList.toggle("open");
  menu.setAttribute("aria-expanded", String(open));
  navigationSidebar.inert = !open && navigationCompact.matches;
  navigationShade.hidden = !open || !navigationCompact.matches;
  if (open) document.querySelector(".account-menu")?.removeAttribute("open");
});
function closeNavigation() {
  navigationSidebar.classList.remove("open");
  navigationSidebar.inert = navigationCompact.matches;
  navigationShade.hidden = true;
  menu.setAttribute("aria-expanded", "false");
}
menu.addEventListener("keydown", event => {
  if (event.key !== "ArrowDown") return;
  event.preventDefault();
  if (menu.getAttribute("aria-expanded") !== "true") menu.click();
  navigationSidebar.querySelector("nav a:not([hidden])")?.focus();
});
navigationCompact.addEventListener("change", () => {
  const focused = navigationSidebar.contains(document.activeElement);
  closeNavigation();
  if (navigationCompact.matches && focused) menu.focus();
});
document.addEventListener("focusin", event => {
  if (!event.target.closest(".sidebar, #menu-toggle")) closeNavigation();
  if (!event.target.closest(".account-menu")) document.querySelector(".account-menu")?.removeAttribute("open");
});
// Escape closes the innermost layer first: the account menu, then the navigation drawer around it.
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  const account = document.querySelector(".account-menu[open]");
  if (account) { account.open = false; account.querySelector("summary").focus(); return; }
  if (document.querySelector(".sidebar.open")) { closeNavigation(); menu.focus(); }
});
document.addEventListener("click", (event) => {
  if (!event.target.closest(".sidebar, #menu-toggle")) closeNavigation();
  if (!event.target.closest(".account-menu")) document.querySelector(".account-menu")?.removeAttribute("open");
});

document.addEventListener("DOMContentLoaded", () => initialize().catch((error) => {
  handleError(error);
  finish(emptyState(SOCifyLocale.text("تعذر تحميل مساحة العمل"), error.message || SOCifyLocale.text("حدث خطأ غير متوقع"), [button(SOCifyLocale.text("إعادة المحاولة"), () => window.location.reload(), "primary")]));
}), { once: true });
