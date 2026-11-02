"use strict";

window.SOCifyInsights = (() => {
  const t = (ar, en) => SOCifyLocale.language === "ar" ? ar : en;
  const n = value => new Intl.NumberFormat(SOCifyLocale.language).format(value);
  const label = value => autopsyLabel(value);
  const time = value => value ? formatTime(value) : "—";
  const duration = value => value === null ? "—" : value < 60 ? `${n(Math.round(value))} ${t("ث", "s")}` : value < 3600 ? `${n(Math.round(value/60))} ${t("د", "min")}` : `${n(Math.round(value/360)/10)} ${t("س", "h")}`;
  const userText = value => node("span", {"data-user-content":"true", text:value || "—"});
  function definition(items) {
    return node("dl", {class:"insight-facts"}, items.flatMap(([title,value]) => [node("dt", {text:title}), node("dd", {}, value instanceof Node ? value : userText(value))]));
  }
  async function performance() {
    begin("performance");
    try {
      const params = new URLSearchParams(location.search);
      const data = await api("/api/soc/performance?" + params);
      const personal = data.member !== "team";
      const title = personal ? t("أداء المحلل", "Analyst performance") : t("أداء الفريق", "Team performance");
      document.getElementById("section-title").textContent = title;
      const root = node("div", {class:"insights-view"}, pageHead(title, null));
      const nav = node("nav", {class:"channel-tabs", "aria-label":t("نطاق الأداء", "Performance scope")});
      const targets = [["me",t("أدائي", "My performance")]];
      if (data.can_manage) targets.unshift(["team",t("الفريق", "Team")]);
      for (const [value, name] of targets) nav.append(node("a", {class:"channel-tab", href:`/performance?member=${value}&days=${data.days}`, "aria-current":value===data.member?"page":null, text:name}));
      root.append(nav);
      const days = node("select", {name:"days"}, [["7",t("آخر ٧ أيام", "Last 7 days")],["30",t("آخر ٣٠ يومًا", "Last 30 days")],["90",t("آخر ٩٠ يومًا", "Last 90 days")],["all",t("كل الفترات", "All time")]].map(([value,text])=>node("option", {value, selected:value===data.days, text})));
      const form = node("form", {class:"filter-row"}, [field(t("فترة الإنجاز", "Completion period"),days),node("input",{type:"hidden",name:"member",value:data.member}),node("button",{class:"button primary",type:"submit",text:t("تطبيق", "Apply")})]);
      root.append(form);
      root.append(node("div", {class:"insight-counters"}, [["open",t("قضايا نشطة", "Active cases")],["closed",t("أغلقت خلال الفترة", "Closed in period")],["awaiting_review",t("بانتظار المراجعة", "Awaiting review")],["pending_tasks",t("مهام معلقة", "Pending tasks")]].map(([key,text])=>node("div",{class:"insight-counter"},[node("span",{text}),node("strong",{text:n(data.counts[key])})]))));
      const row = node("div",{class:"insight-columns"});
      const load = node("div",{class:"panel-body"});
      for(const severity of ["critical","high","medium","low"]) load.append(node("div",{class:"insight-bar-row"},[node("span",{class:`severity ${severity}`,text:label(severity)}),node("progress",{max:Math.max(data.counts.open,1),value:data.severity[severity]||0,"aria-label":label(severity)}),node("strong",{text:n(data.severity[severity]||0)})]));
      load.append(definition([[t("تنبيهات دون قرار", "Alerts without a verdict"),n(data.counts.unreviewed_alerts)],[t("قضايا دون مسؤول", "Unassigned cases"),n(data.counts.unassigned)],[t("تجاوزت موعد القضية", "Past case deadline"),n(data.counts.overdue)]]));
      row.append(panel(t("عبء العمل الحالي", "Current workload"),load,true));
      const metricTitles = {detection_delay_seconds:t("الرصد", "Detection"),acknowledgement_delay_seconds:t("إقرار الاستلام", "Acknowledgement"),containment_delay_seconds:t("الاحتواء", "Containment"),recovery_delay_seconds:t("التعافي", "Recovery"),closure_delay_seconds:t("الإغلاق", "Closure")};
      row.append(panel(t("وسيط المدد الموثقة", "Median evidenced durations"),table([{label:t("المرحلة", "Stage"),value:r=>metricTitles[r.key]},{label:t("المدة", "Duration"),value:r=>duration(r.median_seconds)},{label:t("قابل للحساب / مغلق", "Measured / closed"),value:r=>`${n(r.included)} / ${n(r.included+r.excluded)}`}],Object.entries(data.metrics).map(([key,value])=>({key,...value}))),true));
      root.append(row);
      if(data.members.length) root.append(panel(t("الفريق والإنجاز", "Team delivery"),table([{label:t("المحلل", "Analyst"),value:r=>data.can_manage?node("a",{href:`/performance?member=${r.id}&days=${data.days}`,text:r.name}):userText(r.name)},{label:t("الدور", "Role"),value:r=>label(r.role)},{label:t("نشطة", "Active"),value:"open"},{label:t("مغلقة خلال الفترة", "Closed in period"),value:"closed"},{label:t("مهام أنجزها", "Tasks completed"),value:"tasks_completed"}],data.members),true));
      if(data.trend.length) {
        const trend=node("details",{class:"insight-method"},node("summary",{text:t("حركة القضايا خلال الفترة", "Case activity during period")}));
        trend.append(table([{label:t("التاريخ", "Date"),value:"date"},{label:t("أنشئت", "Opened"),value:"opened"},{label:t("أغلقت", "Closed"),value:"closed"}],data.trend));root.append(trend);
      }
      root.append(panel(`${t("قائمة المتابعة", "Work queue")} · ${n(data.queue_total)}`,data.queue.length?table([{label:t("القضية", "Case"),value:r=>node("a",{href:`/cases/${r.id}`,text:`${r.reference} · ${r.title}`})},{label:t("الخطورة", "Severity"),value:r=>node("span",{class:`severity ${r.severity}`,text:label(r.severity)})},{label:t("المسؤول", "Owner"),value:r=>userText(r.assignee_name)},{label:t("الحالة", "Status"),value:r=>label(r.status)},{label:t("الموعد", "Deadline"),value:r=>time(r.sla_due_at)}],data.queue):emptyState(t("لا قضايا نشطة", "No active cases"),null,[linkedButton(t("إدارة القضايا", "Case management"),"/cases")]),true));
      if(data.tasks.length) root.append(panel(`${t("المهام المعلقة", "Pending tasks")} · ${n(data.task_total)}`,table([{label:t("المهمة", "Task"),value:r=>node("a",{href:`/cases/${r.case_id}?tab=procedures`,text:r.title})},{label:t("الحالة", "Status"),value:r=>label(r.status)}],data.tasks),true));
      if(data.queue_total>50||data.task_total>50)root.append(node("p",{text:t("تظهر أول ٥٠ نتيجة؛ بقية القضايا في إدارة القضايا.","Showing the first 50 results. Open Case management for all cases.")}));
      finish(root);
    } catch(error) {finish(emptyState(t("تعذر تحميل الأداء", "Unable to load performance"),error.message,[button(t("إعادة المحاولة", "Retry"),performance)]));}
  }
  async function dossier(item, container) {
    const data=await api(`/api/cases/${item.case_id}/alerts/${item.id}/dossier`);
    const root=node("div",{class:"dossier-view"});
    root.append(definition([[t("وقت الكشف", "Detection time"),time(data.alert.detected_at)],[t("الإغلاق", "Closed at"),time(data.case.closed_at)],[t("قرار المحلل", "Analyst verdict"),label(data.review?.verdict||"undetermined")],[t("نتيجة الهجوم", "Attack outcome"),label(data.review?.attack_outcome||"unknown")]]));
    if(data.review) root.append(node("section",{},[node("h3",{text:t("ملاحظة المحلل", "Analyst note")}),node("p",{"data-user-content":"true",text:data.review.reason})]));
    if(data.assessment){
      root.append(node("h3",{text:t("قرارات القضية", "Case decisions")}));
      root.append(definition(data.assessment.resolved_questions.map(q=>[SOCifyLocale.text(q.question),SOCifyLocale.text(q.answer_label)])));
      if(data.assessment.executive_note)root.append(node("p",{"data-user-content":"true",text:data.assessment.executive_note}));
      if(data.assessment.manager_comment)root.append(node("section",{},[node("h3",{text:t("ملاحظة المراجع", "Reviewer note")}),userText(data.assessment.manager_comment)]));
    }
    if(data.techniques.length)root.append(panel("MITRE ATT&CK",table([{label:t("التقنية", "Technique"),value:"technique_id"},{label:t("التقييم", "Assessment"),value:r=>label(r.assessment)},{label:t("الدليل", "Evidence"),value:"reason"}],data.techniques)));
    root.append(node("h3",{text:t("سجلات التنبيه", "Alert evidence events")}));
    for(const event of data.events){
      const detail=node("details",{class:"evidence-event"},node("summary",{text:`#${event.id} · ${event.normalized_fields.event_time_known?time(event.event_time):"—"} · ${event.hostname||event.source_ip||""}`}));
      detail.append(definition([[t("المصدر", "Source"),event.source_ip],[t("الوجهة", "Destination"),event.destination_ip],[t("الجهاز", "Host"),event.hostname],[t("الحساب", "Account"),event.username]]));
      detail.append(node("pre",{dir:"ltr",tabindex:0,"data-user-content":"true",text:JSON.stringify(event.normalized_fields,null,2)}),node("pre",{dir:"ltr",tabindex:0,"data-user-content":"true",text:event.raw_data}));
      if(event.raw_truncated)detail.append(linkedButton(t("فتح السجل الكامل", "Open complete event"),`/cases/${item.case_id}?tab=logs`));
      if(!event.autopsy_active)detail.append(node("span",{text:t("نسخة سجل سابقة", "Historical event version")}));
      root.append(detail);
    }
    if(!data.events.length)root.append(node("p",{text:t("لا سجلات مرتبطة", "No linked events")}));
    if(data.events_truncated)root.append(linkedButton(t("عرض جميع السجلات", "View all logs"),`/cases/${item.case_id}?tab=logs`));
    if(data.tasks.length)root.append(panel(t("مهام التحقيق", "Investigation tasks"),table([{label:t("المهمة", "Task"),value:"title"},{label:t("الحالة", "Status"),value:r=>label(r.status)},{label:t("أُنجزت", "Completed"),value:r=>time(r.completed_at)}],data.tasks)));
    for(const note of data.notes)root.append(node("blockquote",{"data-user-content":"true"},[node("p",{text:note.body}),node("cite",{text:`${note.author} · ${time(note.created_at)}`})]));
    container.replaceChildren(root);
  }
  async function hosts(caseId) {
    const params=new URLSearchParams(location.search);
    const query=new URLSearchParams({q:params.get("host_q")||"",host:params.get("host")||"",page:params.get("host_page")||"1"});
    const data=await api(`/api/cases/${caseId}/observed-hosts?${query}`);
    const root=node("div",{class:"panel-body"});
    const search=node("input",{type:"search",name:"host_q",maxlength:200,value:query.get("q")});
    root.append(node("form",{class:"filter-row"},[node("input",{type:"hidden",name:"case_id",value:caseId}),field(t("اسم الجهاز", "Hostname"),search),node("button",{type:"submit",class:"button primary",text:t("بحث", "Search")})]));
    const target=(host,page=1)=>`/endpoint-security?${new URLSearchParams({case_id:caseId,host,host_page:page,host_q:query.get("q")})}`;
    root.append(data.items.length?table([{label:t("الجهاز", "Host"),value:r=>node("a",{href:target(r.hostname),text:r.hostname})},{label:t("السجلات", "Events"),value:"events"},{label:t("أول ظهور", "First observed"),value:r=>time(r.first_seen)},{label:t("آخر ظهور", "Last observed"),value:r=>time(r.last_seen)}],data.items):emptyState(t("لا أجهزة", "No devices"),null));
    const pages=node("div",{class:"pagination"});
    if(data.page>1)pages.append(linkedButton(t("السابق", "Previous"),target(data.host,data.page-1)));
    if(data.page*data.page_size<data.total)pages.append(linkedButton(t("التالي", "Next"),target(data.host,data.page+1)));
    root.append(pages);
    if(data.host){
      root.append(node("h3",{"data-user-content":"true",text:data.host}));
      for(const event of data.events){
        const detail=node("details",{class:"evidence-event"},node("summary",{text:`#${event.id} · ${event.event_time_known?time(event.event_time):"—"} · ${event.process_name||event.username||""}`}));
        detail.append(definition([[t("العملية", "Process"),event.process_name],[t("العملية الأم", "Parent process"),event.parent_process],[t("سطر الأوامر", "Command line"),event.command_line],[t("المصدر", "Source"),event.source_ip],[t("الوجهة", "Destination"),event.destination_ip],[t("الحساب", "Account"),event.username],[t("بصمة الملف", "File hash"),event.file_hash]]));
        root.append(detail);
      }
      if(!data.events.length)root.append(node("p",{text:t("لا سجلات للجهاز المحدد", "No events for this host")}));
      if(data.events_truncated)root.append(linkedButton(t("عرض جميع السجلات", "View all logs"),`/cases/${caseId}?tab=logs`));
    }
    return panel(t("أجهزة القضية", "Case devices"),root,true);
  }
  return {performance,dossier,hosts};
})();
