"use strict";

(() => {
  const t = value => SOCifyLocale.text(value);
  const sections = ["monitoring", "log-management", "endpoint-security", "threat-intel", "email-security", "sandbox", "reports"];
  const names = {
    monitoring: [t("المراقبة"), t("راجع التنبيهات، ثم افتح التحقيق المرتبط بالأدلة.")],
    "log-management": [t("إدارة السجلات"), t("ابحث في السجلات واستورد الأدلة ضمن قضية مصرح بها.")],
    "endpoint-security": [t("أمن الأجهزة والأصول"), t("راجع الأصول ونطاق تأثرها ووثّق إجراءات الاستجابة.")],
    "threat-intel": [t("استخبارات التهديدات"), t("اربط المؤشرات بالأدلة وراجع نتائج الإثراء المحلي ومصادرها.")],
    "email-security": [t("أمن البريد الإلكتروني"), t("افحص رؤوس الرسالة وروابطها ومرفقاتها دون تشغيل محتواها.")],
    sandbox: [t("تحليل العينات"), t("حجر مشفر وتحليل ساكن محلي؛ لا تنفيذ ديناميكي للعينات.")],
    reports: [t("التقارير"), t("أنشئ نسخة فورية من التحقيق، ثم راجع الصيغ والاعتماد.")]
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
        location.assign(url(`/cases/${current.id}`, {tab:"reports"}));
      } catch (error) { handleError(error); control.disabled = false; control.textContent = t("تقرير فوري"); }
    }, "primary");
    control.dataset.quickReport = "";
    return control;
  }
  const channels = [["main", t("القناة الرئيسية")], ["investigation", t("قناة التحقيق")], ["closed", t("التنبيهات المغلقة")]];
  async function monitoring() {
    const version = ++requestVersion;
    begin("monitoring");
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
    const surface = node("section",{class:"monitoring-surface","aria-label":t("نتائج التنبيهات")},[form,node("div",{class:"monitoring-caption"},[node("p",{text:t("القنوات تعكس حالة القضية المرتبطة؛ الإغلاق يخضع للمراجعة والاعتماد.")}),node("p",{text:t("آخر تحديث")+": "+formatTime(data.fetched_at)})])]);
    if (!data.items.length) surface.append(emptyState(t("لا توجد تنبيهات تطابق هذا النطاق"),t("عدّل المرشحات أو استورد سجلات وشغّل الكشف من داخل القضية."),[linkedButton(t("فتح إدارة القضايا"),"/cases")]));
    else {
      const body=node("tbody");
      const head=node("thead",{},node("tr",{},[t("التفاصيل"),t("الخطورة"),t("وقت الاكتشاف"),t("اسم القاعدة"),t("معرف التنبيه"),t("القضية"),t("المسؤول"),t("الإجراء")].map(label=>node("th",{scope:"col",text:label}))));
      for (const item of data.items) {
        const detailId=`alert-details-${item.id}`;
        const detail=node("tr",{id:detailId,hidden:true},node("td",{colspan:8,class:"alert-detail-cell"},node("div",{class:"alert-details"},[
          node("div",{},[node("h3",{text:t("سبب الكشف")}),node("p",{"data-user-content":"true",text:item.reason}),node("p",{class:"cell-meta",text:t("إصدار القاعدة")+": "+item.rule_version})]),
          node("div",{},[node("dl",{},[node("dt",{text:t("السجلات المرتبطة")}),node("dd",{text:number(item.evidence_events)}),node("dt",{text:t("قرار التنبيه")}),node("dd",{text:autopsyLabel(item.verdict||"undetermined")}),node("dt",{text:t("حالة القضية")}),node("dd",{text:autopsyLabel(item.case_status)})]),node("div",{class:"action-row"},[linkedButton(t("مراجعة التنبيه"),url(`/cases/${item.case_id}`,{tab:"analysis"})),linkedButton(t("السجلات والأدلة"),url(`/cases/${item.case_id}`,{tab:"logs"})),linkedButton(t("التقارير"),url("/reports",{case_id:item.case_id}))])])
        ])));
        const expand=button("⌄",()=>{detail.hidden=!detail.hidden;expand.setAttribute("aria-expanded",String(!detail.hidden));expand.textContent=detail.hidden?"⌄":"⌃";},"row-expand");
        expand.className="row-expand"; expand.setAttribute("aria-label",t("تفاصيل التنبيه")+" "+item.alert_id);expand.setAttribute("aria-expanded","false");expand.setAttribute("aria-controls",detailId);
        const cells=[expand,node("span",{class:`severity ${item.severity}`,text:autopsyLabel(item.severity)}),node("time",{datetime:item.detected_at,text:formatTime(item.detected_at)}),node("div",{class:"rule-cell"},[node("strong",{"data-user-content":"true",text:item.rule_name||item.reason}),node("small",{text:t("إصدار القاعدة")+" "+item.rule_version})]),node("bdi",{dir:"ltr",text:item.alert_id}),node("div",{},[node("a",{class:"case-link",href:`/cases/${item.case_id}`,text:item.reference}),node("span",{class:"cell-meta",text:autopsyLabel(item.case_status)})]),node("span",{"data-user-content":"true",text:item.assignee_name||t("غير مسند")}),linkedButton(t("فتح التحقيق"),`/cases/${item.case_id}`)];
        body.append(node("tr",{"data-alert-row":item.id},cells.map(value=>node("td",{},value))),detail);
      }
      surface.append(node("div",{class:"table-wrap",role:"region",tabindex:0,"aria-label":t("جدول التنبيهات")},node("table",{class:"monitoring-table"},[head,body])));
    }
    const pages=node("div",{class:"pagination"},node("p",{text:number(data.total)+" · "+t("الصفحة")+" "+number(data.page)}));
    for(const [label,page] of [[t("السابق"),data.page-1],[t("التالي"),data.page+1]]) {
      if(page<1||page===data.page+1&&data.page*data.page_size>=data.total)continue;
      const target=new URL(location.href);target.searchParams.set("page",String(page));pages.append(linkedButton(label,target.pathname+target.search));
    }
    surface.append(pages);root.append(surface);finish(root);
  }
  async function chooseCase(section, selected) {
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
  async function email(caseId) {
    const root=node("div",{class:"tool-results email-review"});
    root.append(node("p",{class:"scope-note",text:t("رؤوس المصادقة بيانات مصدر غير موثوقة؛ لا تتحقق المنصة من SPF أو DKIM عبر الشبكة. الروابط لا تُفتح والمرفقات لا تُشغّل.")}));
    if(autopsy.current.can_update&&permission("evidence.download")&&permission("evidence.add")&&autopsy.current.status!=="closed") {
      const file=node("input",{type:"file",name:"email",accept:".eml,message/rfc822",required:true});
      const submit=node("button",{type:"submit",class:"button primary",text:t("حجر الرسالة وتحليلها")});
      const form=node("form",{class:"filter-row"},[field(t("رسالة EML · حتى 2MiB"),file),submit]);
      form.addEventListener("submit",async e=>{
        e.preventDefault();const chosen=file.files[0];if(!chosen||chosen.size>2*1024*1024||!chosen.name.toLowerCase().endsWith(".eml")){showMessage(t("اختر رسالة EML لا تتجاوز 2MiB"));return;}
        submit.disabled=true;submit.textContent=t("جارٍ فحص الرسالة…");
        try{const data=new FormData();data.set("file",chosen);const sample=await api(`/api/cases/${caseId}/samples`,{method:"POST",body:data});await api(`/api/cases/${caseId}/samples/${sample.id}/email-review`,{method:"POST",body:{}});await start("email-security");}
        catch(error){handleError(error);submit.disabled=false;submit.textContent=t("حجر الرسالة وتحليلها");}
      });
      root.append(panel(t("استيراد رسالة للتحقيق"),node("div",{class:"panel-body"},form),true));
    }
    const samples=(await api(`/api/cases/${caseId}/samples`)).items.filter(sample=>sample.filename.toLowerCase().endsWith(".eml"));
    if(autopsy.current.can_update&&permission("evidence.download")&&autopsy.current.status!=="closed"&&samples.length)root.append(panel(t("رسائل محجورة متاحة للفحص"),table([{label:t("الملف"),value:"filename"},{label:"SHA-256",value:"sha256"},{label:t("الإجراء"),value:item=>autopsyAction(t("تحليل الرسالة"),async()=>{await api(`/api/cases/${caseId}/samples/${item.id}/email-review`,{method:"POST",body:{}});await start("email-security");})}],samples),true));
    const before=new URLSearchParams(location.search).get("email_before");
    const records=await api(`/api/cases/${caseId}/email-reviews${before?"?before="+encodeURIComponent(before):""}`);
    const mails=records.items;
    for(const record of mails) {
      const mail=record.payload;
      const headers=node("dl");for(const [key,value] of Object.entries(mail.headers))if(value)headers.append(node("dt",{text:key}),node("dd",{"data-user-content":"true",text:value}));
      const body=node("div",{class:"panel-body"},[headers,node("p",{class:"cell-meta",text:"SHA-256: "+mail.sha256}),node("h4",{text:t("نص الرسالة")}),node("pre",{class:"email-body",tabindex:0,"data-user-content":"true",text:mail.body||t("لا يوجد نص متاح")})]);
      if(mail.body_truncated)body.append(node("p",{class:"notice",text:t("النص المعروض مختصر؛ الأصل محفوظ في الحجر.")}));
      body.append(node("details",{},[node("summary",{text:t("الروابط المرصودة")+" · "+number(mail.urls.length)}),node("ul",{class:"email-links"},mail.urls.map(value=>node("li",{},node("bdi",{dir:"ltr","data-user-content":"true",text:value}))))]));
      body.append(table([{label:t("المرفق"),value:"filename"},{label:t("النوع"),value:"content_type"},{label:t("الحجم"),value:"size"},{label:"SHA-256",value:"sha256"}],mail.attachments));
      root.append(panel(mail.title,body,true));
    }
    if(!mails.length)root.append(emptyState(t("لا توجد رسائل محللة بعد"),t("أضف رسالة EML إلى هذه القضية، ثم راجع رؤوسها ومرفقاتها.")));
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
    else root.append(emptyState(t("لا سجلات بعد"),t("أضف أصلًا موثقًا ضمن نطاق التحقيق.")));
    const pages=node("div",{class:"pagination"});
    if(before)pages.append(linkedButton(t("الأحدث"),url("/endpoint-security",{case_id:caseId})));
    if(records.next_before)pages.append(linkedButton(t("التالي"),url("/endpoint-security",{case_id:caseId,asset_before:records.next_before})));
    root.append(pages);return panel(t("جرد أصول القضية"),root,true);
  }
  async function intelligence(caseId) {
    const page=Math.max(1,Number(new URLSearchParams(location.search).get("intel_page"))||1);
    const data=await api(`/api/cases/${caseId}/observables?page=${page}`);
    const root=node("div",{class:"panel-body"},node("p",{class:"scope-note",text:t("الإثراء من مصادر محلية فقط؛ غياب التطابق لا يثبت سلامة المؤشر.")}));
    if(data.items.length)root.append(table([
      {label:t("القيمة"),value:"value"},{label:t("النوع"),value:"type"},{label:t("السجلات المرتبطة"),value:"occurrences"},
      {label:t("نتيجة الإثراء"),value:item=>autopsyLabel(item.enrichment.verdict||"unknown")},
      {label:t("التفاصيل"),value:item=>button(t("تفاصيل الإثراء"),()=>{
        const content=node("div",{},node("pre",{"data-user-content":"true",text:JSON.stringify(item.enrichment,null,2)}));
        if(autopsy.current.can_update&&autopsy.current.status!=="closed")content.append(autopsyAction(t("إثراء محلي بالإصدارات الحالية"),async()=>{await api(`/api/cases/${caseId}/observables/${item.id}/enrich`,{method:"POST",body:{}});location.reload();}));
        autopsyModal(t("مصدر نتيجة الإثراء وحدودها"),content);
      })}
    ],data.items));
    else root.append(emptyState(t("لا مؤشرات مرصودة في السجلات"),t("استورد سجلات القضية لاستخراج القيم المرصودة؛ تبقى مؤشرات المحقق منفصلة.")));
    const pages=node("div",{class:"pagination"},node("p",{text:number(data.total)+" · "+t("الصفحة")+" "+number(page)}));
    if(page>1)pages.append(linkedButton(t("السابق"),url("/threat-intel",{case_id:caseId,intel_page:page-1})));
    if(page*data.limit<data.total)pages.append(linkedButton(t("التالي"),url("/threat-intel",{case_id:caseId,intel_page:page+1})));
    root.append(pages);return panel(t("الإثراء المحلي"),root,true);
  }
  async function renderTool(section) {
    if(section==="monitoring")return monitoring();
    const version=++requestVersion;
    begin(section);
    const value=new URLSearchParams(location.search).get("case_id");
    const current=value?await api(`/api/cases/${encodeURIComponent(value)}`):null;
    if(version!==requestVersion)return;
    const root=node("div",{class:"tool-view"},pageHead(...names[section]));
    root.append(await chooseCase(section,current));
    if(!current){root.append(emptyState(t("اختر قضية لبدء العمل"),t("تبقى السجلات والأدلة والإجراءات مرتبطة بقضيتها وصلاحياتها.")));finish(root);return;}
    autopsy.current=current;bindCase(current);
    if(current.full_case_access===false&&section!=="log-management"){
      root.append(emptyState(t("هذه الأداة تحتاج نطاق القضية الكامل"),t("صلاحيتك الحالية تخص دفعات محددة. يمكنك متابعة السجلات المصرح بها."),[linkedButton(t("إدارة السجلات"),url("/log-management",{case_id:current.id}))]));finish(root);return;
    }
    autopsy.assets=current.full_case_access===false?[]:(await api(`/api/cases/${current.id}/records?kind=asset&limit=100`)).items;
    const content=node("div",{class:"tool-results"});
    if(section==="log-management")content.append(await window.SOCifyAutopsy.logs(current.id));
    else if(section==="endpoint-security") {
      content.append(node("p",{class:"scope-note",text:t("جرد وتحقيق للأصول المسجلة؛ لا اتصال EDR حي ولا عزل تلقائي للأجهزة.")}));
      content.append(await assetInventory(current.id));
      content.append(linkedButton(t("توثيق إجراءات الاستجابة"),url(`/cases/${current.id}`,{tab:"response"})));
    }else if(section==="threat-intel") {
      content.append(await autopsyRecordPanel("indicator"));
      content.append(await intelligence(current.id));
    }else if(section==="sandbox")content.append(await window.SOCifyAutopsy.analysis(current.id));
    else if(section==="email-security")content.append(await email(current.id));
    else if(section==="reports")content.append(reportButton(current),await window.SOCifyAutopsy.reports(current.id));
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
