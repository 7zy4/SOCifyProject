"use strict";

(() => {
  const t = value => SOCifyLocale.text(value);
  const sections = ["monitoring", "log-management", "endpoint-security", "threat-intel", "email-security", "sandbox", "reports"];
  const names = {
    monitoring: [t("المراقبة"), null],
    "log-management": [t("إدارة السجلات"), null],
    "endpoint-security": [t("أمن الأجهزة والأصول"), null],
    "threat-intel": [t("استخبارات التهديدات"), null],
    "email-security": [t("أمن البريد الإلكتروني"), t("افحص رؤوس الرسالة وروابطها ومرفقاتها دون تشغيل محتواها.")],
    sandbox: [t("تحليل الأدلة"), null],
    reports: [t("التقارير"), null]
  };
  const tabs = {"log-management":"logs", "endpoint-security":"analysis", "threat-intel":"analysis", "email-security":"analysis", sandbox:"analysis", reports:"reports"};
  Object.assign(titles, Object.fromEntries(Object.entries(names).map(([key, value]) => [key, [value[0], "SOCIFY"]])));
  titles.cases = [t("إدارة القضايا"), "CASE MANAGEMENT"];
  let requestVersion = 0;
  const url = (path, changes = {}) => {
    const target = new URL(path, location.origin);
    for (const [key, value] of Object.entries(changes)) if (value !== "" && value !== null && value !== undefined) target.searchParams.set(key, String(value));
    return target.pathname + target.search;
  };
  const number = value => new Intl.NumberFormat(SOCifyLocale.language === "ar" ? "ar" : "en").format(value);
  function navigation() {
    document.querySelectorAll("[data-nav-permission]").forEach(link => { link.hidden = !permission(link.dataset.navPermission); });
    const group = state.section === "reports" ? "reports" : ["cases", "case"].includes(state.section) ? "cases" : "operations";
    document.querySelectorAll("[data-global-section]").forEach(link => {
      if (link.dataset.globalSection === group) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
    });
  }
  function bindCase(current) {
    for (const link of document.querySelectorAll("#primary-nav [data-section]")) {
      if (tabs[link.dataset.section]) link.href = url(`/${link.dataset.section}`, {case_id:current.id});
    }
    const reports = document.querySelector('[data-global-section="reports"]');
    if (reports) reports.href = url("/reports", {case_id:current.id});
  }
  function reportButton(current) {
    const control = button(t("تقرير فوري"), async () => {
      control.disabled = true;
      control.textContent = t("جارٍ إعداد نسخة التقرير…");
      try {
        await api(`/api/cases/${current.id}/reports`, {method:"POST",body:{version:current.version,profile:permission("evidence.download")?"full":"metadata_only_v1"}});
        location.assign(autopsyCaseURL(current.id, {tab:"reports"}));
      } catch (error) { handleError(error); control.disabled = false; control.textContent = t("تقرير فوري"); }
    }, "primary");
    control.dataset.quickReport = "";
    return control;
  }
  const channels = [["main", t("القناة الرئيسية")], ["investigation", t("قناة التحقيق")], ["closed", t("التنبيهات المغلقة")]];
  async function monitoring() {
    const version = ++requestVersion;
    begin("monitoring");
    if(window.SOCifyWorkspace?.selection.required && !window.SOCifyWorkspace.selection.case_ids.length) {
      finish(emptyState(t("اختر قضية لبدء العمل"),null,[linkedButton(t("اختيار نطاق التحقيق"),"/cases")])); return;
    }
    const params = new URLSearchParams(location.search);
    const data = await api("/api/soc/monitoring?" + params);
    if (version !== requestVersion) return;
    const root = node("div", {class:"monitoring-view"}, pageHead(...names.monitoring, permission("cases.create")?[button(t("إنشاء قضية"),autopsyNewCase,"primary")]:[]));
    const change = changes => {
      const next = new URL(location.href);
      next.searchParams.set("page", "1");
      for (const [key,value] of Object.entries(changes)) { if (value === "") next.searchParams.delete(key); else next.searchParams.set(key,String(value)); }
      location.assign(next.pathname + next.search);
    };
    root.append(node("nav", {class:"channel-tabs","aria-label":t("قنوات التنبيهات")}, channels.map(([value,label]) => {
      const target = new URL(location.href); target.searchParams.set("channel",value); target.searchParams.delete("page");
      return node("a", {class:"channel-tab",href:target.pathname+target.search,"aria-current":value===data.channel?"page":null}, [node("span",{text:label}),node("span",{class:"channel-count",text:number(data.counts[value])})]);
    })));
    const search = node("input",{name:"q",type:"search",maxlength:200,value:params.get("q")||"",autocomplete:"off",placeholder:t("القاعدة أو التنبيه أو مرجع القضية…")});
    const severity = node("select",{name:"severity"}, [["",t("جميع الدرجات")],...["critical","high","medium","low"].map(value=>[value,autopsyLabel(value)])].map(([value,label])=>node("option",{value,selected:value===(params.get("severity")||""),text:label})));
    const mine = node("select",{name:"mine"}, [["0",t("جميع القضايا المصرح بها")],["1",t("المسندة إليّ")]].map(([value,label])=>node("option",{value,selected:value===(params.get("mine")||"0"),text:label})));
    const sort = node("select",{name:"sort"}, [["detected_at",t("الأحدث أولًا")],["severity",t("الأعلى خطورة")],["rule_name",t("اسم القاعدة")]].map(([value,label])=>node("option",{value,selected:value===(params.get("sort")||"detected_at"),text:label})));
    const form = node("form",{class:"monitoring-toolbar","aria-label":t("مرشحات التنبيهات")},[field(t("بحث التنبيهات"),search),field(t("الخطورة"),severity),field(t("المسؤول"),mine),field(t("ترتيب التنبيهات"),sort),node("button",{type:"submit",class:"button primary",text:t("تطبيق")}),button(t("تحديث"),()=>monitoring().catch(handleError),"ghost")]);
    form.addEventListener("submit",event=>{event.preventDefault();change({q:search.value,severity:severity.value,mine:mine.value,sort:sort.value,direction:sort.value==="rule_name"?"asc":"desc"});});
    const surface = node("section",{class:"monitoring-surface","aria-label":t("نتائج التنبيهات")},[form,node("div",{class:"monitoring-caption"},[node("p",{text:t("آخر تحديث")+": "+formatTime(data.fetched_at)})])]);
    if (!data.items.length) surface.append(emptyState(t("لا توجد تنبيهات تطابق هذا النطاق"),null,[linkedButton(t("فتح إدارة القضايا"),"/cases")]));
    else {
      const body=node("tbody");
      const head=node("thead",{},node("tr",{},[t("التفاصيل"),t("الخطورة"),t("وقت الاكتشاف"),t("اسم القاعدة"),t("معرف التنبيه"),t("القضية"),t("المسؤول"),t("الإجراء")].map(label=>node("th",{scope:"col",text:label}))));
      for (const item of data.items) {
        const detailId=`alert-details-${item.id}`;
        const detail=node("tr",{id:detailId,hidden:true},node("td",{colspan:8,class:"alert-detail-cell"}));
        const expandedContent=node("div",{class:"dossier-content"});
        detail.querySelector("td").append(expandedContent,node("div",{class:"action-row"},[linkedButton(t("مراجعة التنبيه"),url(`/cases/${item.case_id}`,{tab:"analysis"})),linkedButton(t("السجلات والأدلة"),url(`/cases/${item.case_id}`,{tab:"logs"})),linkedButton(t("التقارير"),url("/reports",{case_id:item.case_id}))]));
        let loaded=false;
        const expand=button("",async()=>{
          detail.hidden=!detail.hidden;expand.setAttribute("aria-expanded",String(!detail.hidden));ruleToggle.setAttribute("aria-expanded",String(!detail.hidden));
          if(!detail.hidden&&!loaded){
            expand.disabled=true;
            try{await window.SOCifyInsights.dossier(item,expandedContent);loaded=true;}
            catch(error){expandedContent.replaceChildren(node("p",{role:"alert",text:error.message}));}
            finally{expand.disabled=false;}
          }
        },"row-expand");
        expand.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
        expand.className="row-expand"; expand.setAttribute("aria-label",t("تفاصيل التنبيه")+" "+item.alert_id);expand.setAttribute("aria-expanded","false");expand.setAttribute("aria-controls",detailId);
        const ruleToggle=node("button",{type:"button",class:"alert-name","data-alert-toggle":"","data-user-content":"true","aria-expanded":"false","aria-controls":detailId,text:item.rule_name||item.reason,onclick:()=>expand.click()});
        const cells=[expand,node("span",{class:`severity ${item.severity}`,text:autopsyLabel(item.severity)}),node("time",{datetime:item.detected_at,text:formatTime(item.detected_at)}),node("div",{class:"rule-cell"},[ruleToggle]),node("bdi",{dir:"ltr",text:item.alert_id}),node("div",{},[node("a",{class:"case-link",href:`/cases/${item.case_id}`,text:item.reference}),node("span",{class:"cell-meta",text:autopsyLabel(item.case_status)})]),node("span",{"data-user-content":"true",text:item.assignee_name||t("غير مسند")}),linkedButton(t("فتح التحقيق"),`/cases/${item.case_id}`)];
        body.append(node("tr",{"data-alert-row":item.id},cells.map((value,index)=>node("td",{"data-label":[t("التفاصيل"),t("الخطورة"),t("وقت الاكتشاف"),t("اسم القاعدة"),t("معرف التنبيه"),t("القضية"),t("المسؤول"),t("الإجراء")][index]},value))),detail);
      }
      surface.append(node("div",{class:"table-wrap",role:"region",tabindex:0,"aria-label":t("جدول التنبيهات")},node("table",{class:"monitoring-table"},[head,body])));
    }
    root.append(surface);
    if(data.total>data.page_size || data.page>1) {
      const pages=node("nav",{class:"pagination monitoring-pagination","aria-label":t("جدول التنبيهات")},node("p",{text:t("الصفحة")+" "+number(data.page)+" / "+number(Math.max(1,Math.ceil(data.total/data.page_size)))}));
      for(const [label,page] of [[t("السابق"),data.page-1],[t("التالي"),data.page+1]]) {
        if(page<1||page===data.page+1&&data.page*data.page_size>=data.total)continue;
        const target=new URL(location.href);target.searchParams.set("page",String(page));pages.append(linkedButton(label,target.pathname+target.search));
      }
      root.append(pages);
    }
    finish(root);
  }
  async function chooseCase(section, selected) {
    if (window.SOCifyWorkspace?.selection.required) {
      const root = node("section",{class:"case-switcher","aria-label":t("سياق القضية")});
      if (!selected) root.append(linkedButton(t("اختيار نطاق التحقيق"),"/cases"));
      return root;
    }
    const params=new URLSearchParams(location.search),page=Math.max(1,Number(params.get("selector_page"))||1),query=params.get("selector_q")||"";
    const root=node("section",{class:"case-switcher","aria-label":t("سياق القضية")});
    const search=node("input",{name:"selector_q",type:"search",maxlength:200,value:query,autocomplete:"off",placeholder:t("اسم القضية أو مرجعها…")});
    const form=node("form",{class:"filter-row"},[field(t("اختيار القضية"),search),node("button",{type:"submit",class:"button ghost",text:t("بحث القضايا")})]);
    form.addEventListener("submit",e=>{e.preventDefault();location.assign(url(`/${section}`,{case_id:selected?.id,selector_q:search.value,choose:1}));});
    root.append(form);
    if(selected) {
      const summary=node("div",{class:"context-summary"},[node("div",{},[node("strong",{"data-user-content":"true",text:selected.title}),node("p",{},[node("bdi",{text:selected.reference})," · ",autopsyLabel(selected.status)])]),node("div",{class:"action-row"},[linkedButton(t("فتح التحقيق"),`/cases/${selected.id}`),linkedButton(t("تغيير القضية"),url(`/${section}`,{case_id:selected.id,choose:1}))])]);
      root.append(summary);
    }
    if(!selected||params.has("choose")||query) {
      const cases=await api(`/api/cases?page=${page}&page_size=25&q=${encodeURIComponent(query)}`);
      const list=node("div",{class:"case-selector-list"});
      for(const item of cases.items)list.append(node("a",{href:url(`/${section}`,{case_id:item.id})},[node("span",{text:item.title}),node("bdi",{text:item.reference})]));
      if(!cases.items.length)list.append(node("p",{text:t("لا توجد قضايا في النطاق المصرح")}));
      root.append(list);
      const pages=node("div",{class:"pagination"},node("p",{text:number(cases.total)+" · "+t("الصفحة")+" "+number(page)}));
      if(page>1)pages.append(linkedButton(t("السابق"),url(`/${section}`,{case_id:selected?.id,choose:1,selector_q:query,selector_page:page-1})));
      if(page*25<cases.total)pages.append(linkedButton(t("التالي"),url(`/${section}`,{case_id:selected?.id,choose:1,selector_q:query,selector_page:page+1})));
      root.append(pages);
    }
    return root;
  }
  function quickWatchlistBtn(indicatorType, rawValue, caseId, noteText = "") {
    if (!rawValue || !permission("cases.update")) return node("span", { text: "" });
    const btn = button(t("+ قائمة المراقبة"), async () => {
      btn.disabled = true;
      try {
        const body = { indicator_type: indicatorType, value: String(rawValue).trim(), severity: "high", note: noteText };
        if (caseId) body.source_case_id = Number(caseId);
        await api("/api/watchlist", { method: "POST", body });
        btn.textContent = t("في المراقبة");
      } catch (error) {
        btn.disabled = false;
        handleError(error);
      }
    }, "ghost");
    return btn;
  }
  async function watchlistPanel(caseId) {
    const wl = await api("/api/watchlist");
    const body = node("div", { class: "panel-body" });
    if (permission("cases.update")) {
      const typeSel = node("select", { name: "indicator_type" }, [
        ["email", "Email"],
        ["ip", "IPv4 / IPv6"],
        ["cidr", "CIDR Subnet"],
        ["domain", "Domain"],
        ["url", "URL"],
        ["sha256", "SHA-256"],
      ].map(([v, l]) => node("option", { value: v, text: l })));
      const valInput = node("input", { name: "value", required: true, maxlength: 512, placeholder: "attacker@evil.example / 203.0.113.0/24" });
      const sevSel = node("select", { name: "severity" }, ["critical", "high", "medium", "low"].map(v => node("option", { value: v, selected: v === "high", text: autopsyLabel(v) })));
      const noteInput = node("input", { name: "note", maxlength: 200, placeholder: t("سبب الاشتباه أو مصدر المؤشر…") });
      const addForm = node("form", { class: "filter-row", "aria-label": t("إضافة مؤشر لقائمة المراقبة") }, [
        field(t("النوع"), typeSel),
        field(t("المؤشر المشبوه"), valInput),
        field(t("الخطورة"), sevSel),
        field(t("ملاحظة"), noteInput),
        node("button", { type: "submit", class: "button primary", text: t("إضافة لقائمة المراقبة") }),
      ]);
      addForm.addEventListener("submit", async e => {
        e.preventDefault();
        try {
          const payload = { indicator_type: typeSel.value, value: valInput.value.trim(), severity: sevSel.value, note: noteInput.value.trim() };
          if (caseId) payload.source_case_id = Number(caseId);
          await api("/api/watchlist", { method: "POST", body: payload });
          await start("threat-intel");
        } catch (error) { handleError(error); }
      });
      body.append(addForm);
      if (caseId && autopsy.current?.can_update && autopsy.current?.status !== "closed") {
        const scanNotice = node("span", { "aria-live": "polite" });
        const scanBtn = button(t("فحص سجلات القضية مقابل قائمة المراقبة الآن"), async () => {
          scanBtn.disabled = true;
          try {
            const res = await api(`/api/cases/${caseId}/watchlist-scan`, { method: "POST", body: {} });
            scanNotice.textContent = ` · ${t("تم فحص")} ${number(res.events_scanned)} — ${t("تنبيهات جديدة")}: ${number(res.alerts_created)}`;
          } catch (error) { handleError(error); }
          finally { scanBtn.disabled = false; }
        }, "ghost");
        body.append(node("div", { class: "action-row" }, [scanBtn, scanNotice]));
      }
    }
    if (wl.items.length) {
      body.append(table([
        { label: t("النوع"), value: item => item.indicator_type.toUpperCase() },
        { label: t("القيمة"), value: item => node("bdi", { dir: "ltr", "data-user-content": "true", text: item.value }) },
        { label: t("الخطورة"), value: item => autopsyLabel(item.severity) },
        { label: t("التطابقات"), value: item => number(item.hits_count) },
        { label: t("ملاحظة"), value: item => item.note || "—" },
        { label: t("الحالة"), value: item => item.is_active ? t("نشط") : t("متوقف") },
        {
          label: t("إدارة"),
          value: item => permission("cases.update") ? node("div", { class: "action-row" }, [
            button(item.is_active ? t("إيقاف") : t("تفعيل"), async () => {
              try { await api(`/api/watchlist/${item.id}`, { method: "PATCH", body: { is_active: !item.is_active } }); await start("threat-intel"); }
              catch (error) { handleError(error); }
            }, "ghost"),
            button(t("حذف"), async () => {
              try { await api(`/api/watchlist/${item.id}`, { method: "DELETE" }); await start("threat-intel"); }
              catch (error) { handleError(error); }
            }, "ghost"),
          ]) : "—",
        },
      ], wl.items));
    } else {
      body.append(emptyState(t("قائمة المراقبة فارغة"),null));
    }
    return panel(t("قائمة مراقبة الإيميلات والـ IPs المشبوهة (Watchlist)"), body, true);
  }
  async function managerEscalatedReportsPanel() {
    const inbox = await api("/api/reports/escalated");
    const body = node("div", { class: "panel-body" });
    if (!inbox.items.length) {
      body.append(emptyState(t("لا توجد تقارير مصعّدة حاليًا"),null));
      return panel(t("صندوق التقارير المصعّدة لمدير مركز العمليات"), body, false);
    }
    body.append(table([
      { label: t("القضية"), value: item => node("a", { class: "case-link", href: `/cases/${item.case_id}?tab=reports`, text: `${item.case_reference} · ${item.case_title}` }) },
      { label: t("المحقق"), value: "investigator_name" },
      { label: t("التصنيف"), value: "incident_classification_label" },
      { label: t("حكم الفرز"), value: "triage_verdict_label" },
      { label: t("الاستعجال"), value: "urgency_level_label" },
      { label: t("الحالة"), value: item => item.manager_decision ? `${item.status} (${item.manager_decision})` : item.status },
      {
        label: t("الطباعة والاعتماد"),
        value: item => {
          const printBtn = linkedButton(t("طباعة التقرير"), item.print_url);
          printBtn.target = "_blank";
          printBtn.rel = "noopener";
          const controls = [printBtn];
          if (inbox.can_acknowledge && item.status === "escalated") {
            controls.push(button(t("اعتماد المدير"), async () => {
              try {
                await api(`/api/cases/${item.case_id}/quick-report/acknowledge`, { method: "POST", body: { decision: "approved", comment: "Approved from Manager Inbox" } });
                await start("reports");
              } catch (error) { handleError(error); }
            }, "primary"));
          }
          return node("div", { class: "action-row" }, controls);
        },
      },
    ], inbox.items));
    return panel(t("صندوق التقارير المصعّدة لمدير مركز العمليات"), body, true);
  }
  async function email(caseId) {
    const root=node("div",{class:"tool-results email-review"});
    if(autopsy.current.can_update&&permission("evidence.add")&&autopsy.current.status!=="closed") {
      const file=node("input",{type:"file",name:"email",accept:".eml,message/rfc822",required:true});
      const submit=node("button",{type:"submit",class:"button primary",text:t("فحص البريد ومرفقاته بضغطة زر")});
      const form=node("form",{class:"filter-row"},[field(t("رسالة EML · حتى 5MiB (شامل فحص المرفقات ساكنًا)"),file),submit]);
      form.addEventListener("submit",async e=>{
        e.preventDefault();const chosen=file.files[0];if(!chosen||chosen.size>5*1024*1024||!chosen.name.toLowerCase().endsWith(".eml")){showMessage(t("اختر رسالة EML لا تتجاوز 5MiB"));return;}
        submit.disabled=true;submit.textContent=t("جارٍ فحص الرسالة والمرفقات…");
        try{const data=new FormData();data.set("file",chosen);await api(`/api/cases/${caseId}/email-triage`,{method:"POST",body:data});await start("email-security");}
        catch(error){handleError(error);submit.disabled=false;submit.textContent=t("فحص البريد ومرفقاته بضغطة زر");}
      });
      root.append(panel(t("فحص رسالة بريد ومرفقاتها بضغطة زر"),node("div",{class:"panel-body"},form),true));
    }
    const samples=(await api(`/api/cases/${caseId}/samples`)).items.filter(sample=>sample.filename.toLowerCase().endsWith(".eml"));
    if(autopsy.current.can_update&&permission("evidence.download")&&autopsy.current.status!=="closed"&&samples.length)root.append(panel(t("رسائل محجورة متاحة للفحص"),table([{label:t("الملف"),value:"filename"},{label:"SHA-256",value:"sha256"},{label:t("الإجراء"),value:item=>autopsyAction(t("تحليل الرسالة"),async()=>{await api(`/api/cases/${caseId}/samples/${item.id}/email-review`,{method:"POST",body:{}});await start("email-security");})}],samples),true));
    const before=new URLSearchParams(location.search).get("email_before");
    const records=await api(`/api/cases/${caseId}/email-reviews${before?"?before="+encodeURIComponent(before):""}`);
    const mails=records.items;
    for(const record of mails) {
      const mail=record.payload;
      const headers=node("dl");for(const [key,value] of Object.entries(mail.headers))if(value)headers.append(node("dt",{dir:"ltr",text:key}),node("dd",{"data-user-content":"true",text:value}));
      const body=node("div",{class:"panel-body"});
      if (mail.email_verdict) {
        body.append(node("p", { class: "notice", text: `${t("الحكم الساكن")}: ${mail.email_verdict} (${mail.email_risk_score || 0}/100)` }));
      }
      const wlActions = node("div", { class: "email-sender-row" });
      if (mail.sender_email) wlActions.append(node("span", { class: "email-sender-chip" }, [node("bdi", { class: "mono", dir: "ltr", text: `From: ${mail.sender_email}` }), quickWatchlistBtn("email", mail.sender_email, caseId, "Suspicious EML sender")]));
      if (mail.reply_to_email && mail.reply_to_email !== mail.sender_email) wlActions.append(node("span", { class: "email-sender-chip" }, [node("bdi", { class: "mono", dir: "ltr", text: `Reply-To: ${mail.reply_to_email}` }), quickWatchlistBtn("email", mail.reply_to_email, caseId, "Mismatched EML Reply-To")]));
      if (wlActions.children.length) body.append(wlActions);
      if (mail.header_flags?.length) {
        body.append(node("ul", {}, mail.header_flags.map(f => node("li", { text: `[${f.severity}] ${f.detail}` }))));
      }
      body.append(headers,node("p",{class:"cell-meta mono",dir:"ltr",text:"SHA-256: "+mail.sha256}),node("h4",{text:t("نص الرسالة")}),node("pre",{class:"email-body",tabindex:0,"data-user-content":"true",text:mail.body||t("لا يوجد نص متاح")}));
      if(mail.body_truncated)body.append(node("p",{class:"notice",text:t("النص المعروض مختصر؛ الأصل محفوظ في الحجر.")}));
      body.append(node("details",{},[node("summary",{text:t("الروابط المرصودة")+" · "+number(mail.urls.length)}),node("ul",{class:"email-links"},mail.urls.map(value=>node("li",{},[node("bdi",{dir:"ltr","data-user-content":"true",text:value}), " ", quickWatchlistBtn("url", value, caseId, "Extracted EML URL")])))]));
      body.append(table([
        {label:t("المرفق"),value:att=>att.original_filename||att.filename},
        {label:t("النوع المعلن"),value:"content_type"},
        {label:t("الفحص الساكن (بدون تشغيل)"),value:att=>att.triage?`${att.triage.verdict} (${att.triage.risk_score}/100) · ${att.triage.detected_magic}${att.triage.extension_mismatch?" · "+t("تعارض امتداد"):""}`:t("بصمة فقط")},
        {label:t("الحجم"),value:"size"},
        {label:"SHA-256",value:att=>node("div",{},[node("bdi",{dir:"ltr",text:att.sha256})," ",quickWatchlistBtn("sha256",att.sha256,caseId,`Attachment ${att.original_filename||att.filename}`)])},
      ],mail.attachments));
      root.append(panel(mail.title,body,true));
    }
    if(!mails.length)root.append(emptyState(t("لا توجد رسائل محللة بعد"),null));
    if(before)root.append(linkedButton(t("الأحدث"),url("/email-security",{case_id:caseId})));
    if(records.next_before)root.append(linkedButton(t("رسائل أقدم"),url("/email-security",{case_id:caseId,email_before:records.next_before})));
    return root;
  }
  async function assetInventory(caseId) {
    const before=new URLSearchParams(location.search).get("asset_before");
    const records=await api(`/api/cases/${caseId}/records?kind=asset&limit=25${before?"&before="+encodeURIComponent(before):""}`);
    const root=node("div",{class:"panel-body asset-table"});
    if(autopsy.current.can_update&&autopsy.current.status!=="closed")root.append(button(t("إضافة أصل"),()=>autopsyEditRecord("asset").catch(handleError),"primary"));
    if(records.items.length)root.append(table([
      {label:t("الأصل"),value:record=>node("div",{},[node("strong",{text:record.payload.name}),node("small",{text:autopsyLabel(record.payload.type)})])},
      {label:t("العنوان"),value:record=>node("bdi",{dir:"ltr",text:record.payload.address||"—"})},
      {label:t("نظام التشغيل"),value:record=>record.payload.operating_system},
      {label:t("التقييم"),value:record=>autopsyLabel(record.payload.assessment||"unexamined")},
      {label:t("الأهمية"),value:record=>autopsyLabel(record.payload.importance||"unknown")},
      {label:t("التفاصيل"),value:record=>button(t("عرض الأصل"),()=>autopsyModal(record.payload.name,node("div",{},[autopsyRecordCard(record),linkedButton(t("توثيق إجراءات الاستجابة"),url(`/cases/${caseId}`,{tab:"response"}))])))}
    ],records.items));
    else root.append(emptyState(t("لا سجلات بعد"),null));
    const pages=node("div",{class:"pagination"});
    if(before)pages.append(linkedButton(t("الأحدث"),url("/endpoint-security",{case_id:caseId})));
    if(records.next_before)pages.append(linkedButton(t("التالي"),url("/endpoint-security",{case_id:caseId,asset_before:records.next_before})));
    root.append(pages);return panel(t("جرد أصول القضية"),root,true);
  }
  async function intelligence(caseId) {
    const page=Math.max(1,Number(new URLSearchParams(location.search).get("intel_page"))||1);
    const data=await api(`/api/cases/${caseId}/observables?page=${page}`);
    const root=node("div",{class:"panel-body"});
    if(data.items.length)root.append(table([
      {label:t("القيمة"),value:"value"},{label:t("النوع"),value:"type"},{label:t("السجلات المرتبطة"),value:"occurrences"},
      {label:t("نتيجة الإثراء"),value:item=>autopsyLabel(item.enrichment.verdict||"unknown")},
      {label:t("مراقبة"),value:item=>["ip","domain","url","email","sha256"].includes(item.type)?quickWatchlistBtn(item.type,item.value,caseId,"Case observable"):"—"},
      {label:t("التفاصيل"),value:item=>button(t("تفاصيل الإثراء"),()=>{
        const content=node("div",{},node("pre",{"data-user-content":"true",text:JSON.stringify(item.enrichment,null,2)}));
        if(autopsy.current.can_update&&autopsy.current.status!=="closed")content.append(autopsyAction(t("إثراء محلي بالإصدارات الحالية"),async()=>{await api(`/api/cases/${caseId}/observables/${item.id}/enrich`,{method:"POST",body:{}});location.reload();}));
        autopsyModal(t("مصدر نتيجة الإثراء وحدودها"),content);
      })}
    ],data.items));
    else root.append(emptyState(t("لا مؤشرات مرصودة في السجلات"),null));
    const pages=node("div",{class:"pagination"},node("p",{text:number(data.total)+" · "+t("الصفحة")+" "+number(page)}));
    if(page>1)pages.append(linkedButton(t("السابق"),url("/threat-intel",{case_id:caseId,intel_page:page-1})));
    if(page*data.limit<data.total)pages.append(linkedButton(t("التالي"),url("/threat-intel",{case_id:caseId,intel_page:page+1})));
    root.append(pages);return panel(t("الإثراء المحلي"),root,true);
  }
  async function renderTool(section) {
    if(section==="monitoring")return monitoring();
    const version=++requestVersion;
    begin(section);
    const value=new URLSearchParams(location.search).get("case_id") || window.SOCifyWorkspace?.selection.case_ids[0];
    const current=value?await api(`/api/cases/${encodeURIComponent(value)}`):null;
    if(version!==requestVersion)return;
    const root=node("div",{class:"tool-view"},pageHead(...names[section]));
    if (current && window.SOCifyWorkspace?.intake(current)) return;
    root.append(await chooseCase(section,current));
    if(section==="threat-intel")root.append(await watchlistPanel(current?.id));
    if(section==="reports")root.append(await managerEscalatedReportsPanel());
    if(!current){root.append(emptyState(t("اختر قضية لبدء العمل"),null));finish(root);return;}
    autopsy.current=current;bindCase(current);
    if(current.full_case_access===false&&section!=="log-management"){
      root.append(emptyState(t("هذه الأداة تحتاج نطاق القضية الكامل"),null,[linkedButton(t("إدارة السجلات"),url("/log-management",{case_id:current.id}))]));finish(root);return;
    }
    autopsy.assets=current.full_case_access===false?[]:(await api(`/api/cases/${current.id}/records?kind=asset&limit=100`)).items;
    const content=node("div",{class:"tool-results"});
    if(section==="log-management") {
      content.append(await window.SOCifyAutopsy.logs(current.id));
      content.append(panel(t("أدلة القضية"),current.evidence.length ? table([{label:t("الدليل"),value:"title"},{label:t("النوع"),value:"evidence_type"},{label:"SHA-256",value:"sha256"}],current.evidence) : emptyState(t("لا أدلة مرتبطة"),null)));
    }
    else if(section==="endpoint-security") {
      content.append(await window.SOCifyTelemetry.endpoints(current.id));
      content.append(await window.SOCifyInsights.hosts(current.id));
      content.append(await assetInventory(current.id));
      content.append(linkedButton(t("توثيق إجراءات الاستجابة"),url(`/cases/${current.id}`,{tab:"response"})));
    }else if(section==="threat-intel") {
      content.append(await autopsyRecordPanel("indicator"));
      content.append(await intelligence(current.id));
    }else if(section==="sandbox") {
      content.append(await window.SOCifyAutopsy.analysisWorkspace(current.id));
    }
    else if(section==="email-security")content.append(await email(current.id));
    else if(section==="reports") {
      content.append(reportButton(current),await window.SOCifyAutopsy.reports(current.id));
      if(window.SOCifyAutopsy.capsules)content.append(await window.SOCifyAutopsy.capsules(current.id));
    }
    root.append(content);if(version===requestVersion)finish(root);
  }
  async function start(section) {
    try { await renderTool(section); }
    catch (error) {
      finish(emptyState(t("تعذر تحميل مساحة العمل"), error.message, [linkedButton(t("إدارة القضايا"), "/cases"), button(t("إعادة المحاولة"), () => start(section), "primary")]));
    }
  }
  window.SOCifyWorkbench={sections,start,navigation,bindCase,reportButton,tabs};
})();
