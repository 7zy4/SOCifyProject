"use strict";

window.SOCifyTelemetry = (() => {
  const t = (ar,en) => SOCifyLocale.language === "ar" ? ar : en;
  const n = value => value === null || value === undefined ? "—" : new Intl.NumberFormat(SOCifyLocale.language,{maximumFractionDigits:2}).format(value);
  const text = value => node("bdi",{"data-user-content":"true",text:value ?? "—"});
  const facts = (caption,rows) => node("table",{class:"alert-property-table"},[node("caption",{text:caption}),node("tbody",{},rows.map(([label,value])=>node("tr",{},[node("th",{scope:"row",text:label}),node("td",{},value instanceof Node?value:text(value))])))]);
  const actionName = value => ({added:t("مضاف","Added"),removed:t("محذوف","Removed"),snapshot:t("لقطة","Snapshot"),unchanged:t("دون تغيير","Unchanged")}[value] || value);
  async function evidence(caseId,id) {
    try {
      const event=await api(`/api/cases/${caseId}/logs/${id}`);
      autopsyModal(t("تفاصيل السجل","Event details"),node("pre",{dir:"auto",tabindex:0,"data-user-content":"true",text:JSON.stringify(event,null,2)}));
    } catch(error){handleError(error);}
  }
  function pages(data,load) {
    const nav=node("nav",{class:"pagination","aria-label":t("صفحات النتائج","Result pages")});
    if(data.page>1)nav.append(button(t("السابق","Previous"),()=>load(data.page-1)));
    if(data.page*data.page_size<data.total)nav.append(button(t("التالي","Next"),()=>load(data.page+1)));
    return nav.childNodes.length?nav:null;
  }
  async function network(caseId) {
    const root=node("div",{class:"telemetry-view"});
    const search=node("input",{name:"connection_search",type:"search",maxlength:200});
    const results=node("div",{class:"network-results","aria-live":"polite"});
    const detail=node("div",{class:"network-detail"});
    const form=node("form",{class:"filter-row"},[field(t("عنوان أو نطاق","Address or domain"),search),node("button",{type:"submit",class:"button ghost",text:t("بحث","Search")})]);
    let generation=0;
    async function select(item) {
      detail.replaceChildren(facts(t("تفاصيل الاتصال","Connection details"),[
        [t("مصدر الجمع","Collection source"),item.source],[t("المصدر","Source"),item.source_ip],[t("الوجهة","Destination"),item.destination_ip],
        [t("المنفذ","Port"),n(item.destination_port)],[t("البروتوكول","Protocol"),item.protocol],
        [t("الاتصالات","Connections"),n(item.connection_count)],[t("السجلات","Events"),n(item.event_count)],
        [t("أول اتصال","First connection"),item.first_seen?formatTime(item.first_seen):"—"],[t("آخر اتصال","Last connection"),item.last_seen?formatTime(item.last_seen):"—"],
        [t("وسيط الفاصل (ث)","Median interval (s)"),n(item.median_interval_seconds)],
        [t("تشتت الفواصل (ث)","Interval deviation (s)"),n(item.interval_mad_seconds)],
        [t("انتظام الفواصل","Interval regularity"),item.regularity_percent===null?"—":`${n(item.regularity_percent)}%`],
        [t("المرسل (بايت)","Sent (bytes)"),n(item.bytes_sent)],[t("المستقبل (بايت)","Received (bytes)"),n(item.bytes_received)],
        [t("اتصالات بقياس الحجم","Connections with size measurements"),n(item.byte_measurements)],
        [t("أطول اتصال (ث)","Longest connection (s)"),n(item.longest_connection_seconds)],
        [t("النطاقات","Domains"),item.names.join(" · ") || "—"],
        [t("الأدلة","Evidence"),node("div",{class:"evidence-links"},item.event_ids.map(id=>button(`#${id}`,()=>evidence(caseId,id),"ghost")))],
      ]));
      if(item.events_truncated)detail.append(linkedButton(t("جميع السجلات","All events"),autopsyCaseURL(caseId,{tab:"logs"})));
      detail.querySelector("caption").setAttribute("tabindex","-1");
      detail.querySelector("caption").focus({preventScroll:true});
      detail.scrollIntoView({block:"nearest",behavior:"instant"});
    }
    async function load(page=1) {
      const version=++generation;
      try {
        const data=await api(`/api/cases/${caseId}/network-insights?`+new URLSearchParams({page,q:search.value}));
        if(version!==generation)return;
        detail.replaceChildren();
        const counters=node("div",{class:"insight-counters"},[[t("الاتصالات","Connections"),data.connection_count],[t("أزواج الاتصال","Connection pairs"),data.pair_count],[t("اتصال دوري","Periodic connections"),data.periodic_count]].map(([label,value])=>node("div",{class:"insight-counter"},[node("span",{text:label}),node("strong",{text:n(value)})])));
        results.replaceChildren(counters,data.items.length?table([
          {label:t("المصدر","Source"),value:r=>text(r.source_ip)},
          {label:t("الوجهة","Destination"),value:r=>button(r.destination_ip,()=>select(r),"ghost")},
          {label:t("المنفذ","Port"),value:r=>n(r.destination_port)},
          {label:t("الاتصالات","Connections"),value:r=>n(r.connection_count)},
          {label:t("النمط","Pattern"),value:r=>r.periodic?t("دوري","Periodic"):"—"},
        ],data.items):node("p",{class:"compact-empty",text:t("لا اتصالات","No connections")}));
        const nav=pages(data,load);if(nav)results.append(nav);
      }catch(error){handleError(error);}
    }
    form.addEventListener("submit",event=>{event.preventDefault();load();});
    root.append(form,results,detail);
    await load();
    return panel(t("تحليل الشبكة","Network analysis"),root,true);
  }
  async function endpoints(caseId) {
    const root=node("div",{class:"telemetry-view"});
    const host=node("input",{name:"query_host",maxlength:512});
    const action=node("select",{name:"query_action"},["","added","removed","snapshot","unchanged"].map(value=>node("option",{value,text:value?actionName(value):t("الكل","All")})));
    const results=node("div",{class:"endpoint-results","aria-live":"polite"});
    const form=node("form",{class:"filter-row"},[field(t("الجهاز","Host"),host),field(t("التغيير","Change"),action),node("button",{class:"button ghost",type:"submit",text:t("تصفية","Filter")})]);
    let generation=0;
    async function load(page=1){
      const version=++generation;
      try{
        const data=await api(`/api/cases/${caseId}/endpoint-queries?`+new URLSearchParams({page,host:host.value.trim(),action:action.value}));
        if(version!==generation)return;
        const items=data.items.map(item=>{
          const entry=node("details",{class:"evidence-event"},node("summary",{"data-user-content":"true",text:`${item.hostname} · ${item.query} · ${actionName(item.action)}`}));
          entry.append(facts(t("نتيجة الاستعلام","Query result"),[[t("الجهاز","Host"),item.hostname],[t("الاستعلام","Query"),item.query],[t("التغيير","Change"),actionName(item.action)],[t("الوقت","Time"),item.event_time_known?formatTime(item.event_time):"—"],...Object.entries(item.columns),[t("الدليل","Evidence"),button(`#${item.id}`,()=>evidence(caseId,item.id),"ghost")]]));
          return entry;
        });
        results.replaceChildren(...items);
        if(!items.length)results.append(node("p",{class:"compact-empty",text:t("لا نتائج","No results")}));
        const nav=pages(data,load);if(nav)results.append(nav);
      }catch(error){handleError(error);}
    }
    form.addEventListener("submit",event=>{event.preventDefault();load();});
    root.append(form,results);await load();
    return panel(t("استعلامات الأجهزة","Endpoint queries"),root,true);
  }
  return {network,endpoints};
})();

window.SOCifyAutopsy.analysisWorkspace = async caseId => {
  const t=(ar,en)=>SOCifyLocale.language === "ar"?ar:en;
  const views=[["content",t("المحتوى","Content")],["network",t("الشبكة","Network")],["endpoints",t("الأجهزة","Endpoints")],["files",t("الملفات والبريد","Files & email")],["observables",t("المؤشرات","Indicators")],["detection",t("الكشف","Detection")]];
  const requested=new URLSearchParams(location.search).get("analysis")||"content";
  const selected=views.some(([id])=>id===requested)?requested:"content";
  const root=node("div",{class:"analysis-workspace"});
  root.append(node("nav",{class:"analysis-tools","aria-label":t("أدوات التحليل","Analysis tools")},views.map(([id,label])=>{
    const href=new URL(location.href);href.searchParams.set("analysis",id);
    return node("a",{href:href.pathname+href.search,class:"button ghost","aria-current":id===selected?"page":null,text:label});
  })));
  if(selected==="network")root.append(await SOCifyTelemetry.network(caseId));
  else if(selected==="endpoints")root.append(await SOCifyTelemetry.endpoints(caseId),await SOCifyInsights.hosts(caseId),await autopsyRecordPanel("asset"));
  else if(selected==="content")root.append(await SOCifyInsights.contentInspection(caseId));
  else if(selected==="files")root.append(await SOCifyAutopsy.analysis(caseId));
  else if(selected==="observables")root.append(await autopsyRecordPanel("indicator"));
  else if(SOCifyAutopsy.localDetection)root.append(await SOCifyAutopsy.localDetection(caseId));
  return root;
};
