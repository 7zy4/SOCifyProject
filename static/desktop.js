"use strict";

(() => {
  const t = value => SOCifyLocale.text(value);
  const presets = {
    workspace: [37.75, 23.69, 59.375, 64.286, 10],
    activity: [6.75, 17.27, 33.75, 29.39, 20],
    dossier: [18.25, 4.61, 31.69, 62.12, 30],
    directory: [4.31, 55.52, 34.56, 34.63, 40],
    properties: [59.31, 12.03, 30.56, 68.26, 50]
  };
  const windows = new Map();
  const compact = matchMedia("(max-width: 1099px)");
  let canvas, tasks, recentCases = [], highest = 50, refreshVersion = 0;
  let focused = false;
  const el = (tag, attrs = {}, children = []) => {
    const n = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "text") n.textContent = displayText(value);
      else if (value !== null) n.setAttribute(key, String(value));
    }
    for (const child of Array.isArray(children) ? children : [children]) if (child) n.append(child);
    return n;
  };
  const action = (label, fn, className = "") => {
    const n = el("button", { type: "button", class: className, text: label });
    n.addEventListener("click", fn);
    return n;
  };
  const icon = () => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    for (const [key, value] of Object.entries({width:48,height:40,viewBox:"0 0 48 40",fill:"none","aria-hidden":"true"})) svg.setAttribute(key,value);
    const path = document.createElementNS(svg.namespaceURI, "path");
    path.setAttribute("d", "M2 7h15l5 5h24v26H2Z M2 7V3h15l5 4");
    path.setAttribute("fill", "currentColor");
    svg.append(path);
    return svg;
  };
  function setGeometry(win, x, y, w, h) {
    const maxW = Math.max(260, canvas.clientWidth - 16), maxH = Math.max(200, canvas.clientHeight - 16);
    w = Math.max(Math.min(300, maxW), Math.min(w, maxW));
    h = Math.max(Math.min(220, maxH), Math.min(h, maxH));
    x = Math.max(0, Math.min(x, canvas.clientWidth - w));
    y = Math.max(0, Math.min(y, canvas.clientHeight - h));
    for (const [key, value] of Object.entries({x,y,w,h})) win.root.style.setProperty(`--window-${key}`, `${value}px`);
  }
  function bounds(win) {
    const a = win.root.getBoundingClientRect(), b = canvas.getBoundingClientRect();
    return {x:a.left-b.left,y:a.top-b.top,w:a.width,h:a.height};
  }
  function activate(win, restore = true) {
    if(focused && win.id !== "workspace") applyFocus(false);
    if (restore) { win.root.hidden = false; win.root.classList.remove("is-minimized"); }
    win.root.style.setProperty("--window-z", String(++highest));
    for (const other of windows.values()) {
      const active = other === win;
      other.root.classList.toggle("is-active", active);
      other.task.setAttribute("aria-pressed", String(active && !win.root.hidden));
    }
  }
  function minimize(win, close = false) {
    if(focused && win.id === "workspace") applyFocus(false);
    win.root.hidden = true;
    win.task.setAttribute("aria-pressed", "false");
    win.task.classList.toggle("is-closed", close);
    const next = [...windows.values()].filter(w=>!w.root.hidden).at(-1);
    if (next) activate(next, false);
    win.task.focus();
  }
  function maximize(win) {
    if (compact.matches) { activate(win); return; }
    const maximized = win.root.classList.toggle("is-maximized");
    win.maximize.setAttribute("aria-pressed", String(maximized));
    win.maximize.setAttribute("aria-label", t(maximized ? "استعادة النافذة" : "تكبير النافذة"));
    activate(win);
  }
  function pointerGesture(event, win, resize = false) {
    if (event.button !== 0 || compact.matches || focused || win.root.classList.contains("is-maximized") || (!resize && event.target.closest("button"))) return;
    event.preventDefault();
    activate(win);
    const start = bounds(win), startX = event.clientX, startY = event.clientY, target = event.currentTarget;
    target.setPointerCapture(event.pointerId);
    const move = e => {
      const dx=e.clientX-startX, dy=e.clientY-startY;
      setGeometry(win, start.x+(resize?0:dx), start.y+(resize?0:dy), start.w+(resize?dx:0), start.h+(resize?dy:0));
    };
    const end = () => { target.removeEventListener("pointermove",move); target.removeEventListener("pointerup",end); target.removeEventListener("pointercancel",end); };
    target.addEventListener("pointermove",move);
    target.addEventListener("pointerup",end);
    target.addEventListener("pointercancel",end);
  }
  function createWindow(id, title, content) {
    const p=presets[id];
    const root=el("section",{class:`desktop-window window-${id}`,"data-window":id,"aria-label":title});
    for(const [key,value] of Object.entries({x:p[0]+"%",y:p[1]+"%",w:p[2]+"%",h:p[3]+"%",z:p[4]}))root.style.setProperty(`--window-${key}`,String(value));
    const caption=el("span",{class:"window-caption",text:title});
    const controls=el("div",{class:"window-controls"});
    const bar=el("header",{class:"window-titlebar",tabindex:"0","aria-label":t("تحريك النافذة"),"aria-description":t("الأسهم للتحريك، وShift مع الأسهم لتغيير الحجم")},[caption,controls]);
    const body=el("div",{class:"window-body",tabindex:"0"},content);
    root.append(bar,body);
    const task=action(title,()=>{activate(win);win.task.classList.remove("is-closed");},"taskbar-window");
    task.setAttribute("aria-controls",`desktop-window-${id}`);task.setAttribute("aria-pressed","false");root.id=`desktop-window-${id}`;
    const win={id,root,body,caption,bar,task,maximize:null};
    const min=action("−",()=>minimize(win),"window-control");min.setAttribute("aria-label",t("تصغير النافذة"));
    const max=action("□",()=>maximize(win),"window-control");max.setAttribute("aria-label",t("تكبير النافذة"));max.setAttribute("aria-pressed","false");win.maximize=max;
    const close=action("×",()=>minimize(win,true),"window-control");close.setAttribute("aria-label",t("إغلاق النافذة"));
    controls.append(min,max,close);
    const handle=el("button",{type:"button",class:"window-resize","aria-label":t("تغيير حجم النافذة")});
    root.append(handle);handle.addEventListener("pointerdown",e=>pointerGesture(e,win,true));
    handle.addEventListener("keydown",e=>{if(!["ArrowLeft","ArrowRight","ArrowUp","ArrowDown"].includes(e.key))return;e.preventDefault();const b=bounds(win);setGeometry(win,b.x,b.y,b.w+(e.key==="ArrowRight"?16:e.key==="ArrowLeft"?-16:0),b.h+(e.key==="ArrowDown"?16:e.key==="ArrowUp"?-16:0));});
    bar.addEventListener("pointerdown",e=>pointerGesture(e,win));
    bar.addEventListener("dblclick",e=>{if(!e.target.closest("button"))maximize(win);});
    bar.addEventListener("keydown",e=>{
      if(e.target!==bar||!["ArrowLeft","ArrowRight","ArrowUp","ArrowDown"].includes(e.key)||compact.matches||focused||win.root.classList.contains("is-maximized"))return;
      e.preventDefault();const b=bounds(win),dx=e.key==="ArrowRight"?16:e.key==="ArrowLeft"?-16:0,dy=e.key==="ArrowDown"?16:e.key==="ArrowUp"?-16:0;
      setGeometry(win,b.x+(e.shiftKey?0:dx),b.y+(e.shiftKey?0:dy),b.w+(e.shiftKey?dx:0),b.h+(e.shiftKey?dy:0));
    });
    root.addEventListener("pointerdown",()=>activate(win,false));
    root.addEventListener("focusin",()=>activate(win,false));
    canvas.append(root);tasks.append(task);windows.set(id,win);return win;
  }
  function applyFocus(value, persist = true) {
    focused=value;document.body.classList.toggle("window-focused",focused);
    const button=document.querySelector("[data-workspace-focus]");
    button.setAttribute("aria-pressed",String(focused));button.textContent=t(focused?"عرض سطح المكتب":"تركيز مساحة العمل");
    if(focused)activate(windows.get("workspace"));
    if(persist)try{sessionStorage.setItem("socify-desktop-layout",focused?"focus":"desktop");}catch(_){}
  }
  function resetLayout() {
    applyFocus(false);
    for(const win of windows.values()){
      const p=presets[win.id];win.root.hidden=false;win.task.classList.remove("is-closed");win.root.classList.remove("is-maximized","is-minimized");win.maximize.setAttribute("aria-pressed","false");win.maximize.setAttribute("aria-label",t("تكبير النافذة"));
      for(const [key,value] of Object.entries({x:p[0]+"%",y:p[1]+"%",w:p[2]+"%",h:p[3]+"%",z:p[4]}))win.root.style.setProperty(`--window-${key}`,String(value));
    }
    highest=50;activate(windows.get(compact.matches?"workspace":"properties"));
  }
  function facts(values, className="document-facts") {
    const list=el("dl",{class:className});
    for(const [name,value] of values)list.append(el("dt",{text:name}),el("dd",{text:value??"—",dir:"auto"}));
    return list;
  }
  function empty(win, message) {win.body.replaceChildren(el("p",{class:"desktop-empty",text:message}));}
  function renderCase(record) {
    const dossier=windows.get("dossier"),props=windows.get("properties"),activity=windows.get("activity");
    if(!record){
      empty(dossier,t("اختر قضية لعرض ملف التحقيق"));empty(props,t("خصائص القضية المحددة"));empty(activity,t("يظهر هنا نشاط القضية المصرح به"));return;
    }
    const context=record.context||{},restricted=record.full_case_access===false;
    const paper=el("article",{class:"case-paper"});
    const heading=el("header",{class:"paper-heading"},[el("span",{class:"paper-wordmark",text:"SOCify",lang:"en",dir:"ltr"}),el("div",{},[el("p",{class:"paper-kicker",text:t("ملف التحقيق")}),el("h2",{text:record.title})])]);
    paper.append(heading,el("div",{class:"paper-reference",text:record.reference,dir:"ltr"}));
    paper.append(facts([[t("الحالة"),autopsyLabel(record.status)],[t("الخطورة"),autopsyLabel(record.severity)],[t("التصنيف"),autopsyLabel(context.classification)],[t("المسؤول"),record.assignee_name||recentCases.find(item=>item.id===record.id)?.assignee_name||"—"]]));
    const evidence=el("div",{class:"paper-evidence"});
    for(const item of (record.evidence||[]).slice(0,2)) evidence.append(el("div",{class:"evidence-document"},[icon(),el("strong",{text:item.title}),el("small",{text:item.evidence_type}),el("code",{text:item.sha256||"—",dir:"ltr"})]));
    if(!evidence.children.length)evidence.append(el("p",{text:t("لا أدلة مرتبطة")}));
    paper.append(evidence,el("h3",{text:t("هدف التحقيق")}),el("p",{text:restricted?t("نطاق الوصول مقيد"):context.objective||"—"}));
    paper.append(el("h3",{text:t("قرار صحة التنبيه")}),el("p",{text:autopsyLabel(context.alert_verdict)||"—"}));
    paper.append(el("footer",{class:"paper-footer"},[el("span",{text:t("مرجع القضية")}),el("bdi",{text:record.reference})]));
    dossier.body.replaceChildren(paper);dossier.caption.textContent=`${record.reference} // ${t("ملف التحقيق")}`;
    const tabbar=el("div",{class:"property-tabs",role:"group","aria-label":t("أقسام الخصائص")}),detail=el("div",{class:"property-details"});
    const tabs=[t("عام"),t("الأدلة"),t("الوصول")];
    const show=index=>{
      tabbar.querySelectorAll("button").forEach((b,i)=>b.setAttribute("aria-pressed",String(i===index)));
      detail.replaceChildren();
      detail.append(el("div",{class:"property-identity"},[icon(),el("div",{},[el("h2",{text:record.reference}),el("p",{text:record.title})])]));
      if(index===0){detail.append(el("h3",{text:t("بيانات القضية")}),facts([[t("المرجع"),record.reference],[t("الحالة"),autopsyLabel(record.status)],[t("الخطورة"),autopsyLabel(record.severity)],[t("وقت الإنشاء"),formatTime(record.created_at)],[t("التصنيف"),autopsyLabel(context.classification)],[t("قرار صحة التنبيه"),autopsyLabel(context.alert_verdict)]]));detail.append(el("h3",{text:t("هدف التحقيق")}),el("p",{text:context.objective||"—"}));}
      if(index===1){detail.append(el("h3",{text:t("فهرس الأدلة")}),facts((record.evidence||[]).map(item=>[item.title,item.sha256||item.evidence_type])));if(!record.evidence?.length)detail.append(el("p",{text:t("لا أدلة مرتبطة")}));}
      if(index===2){detail.append(el("h3",{text:t("فريق القضية")}),facts((record.members||[]).map(member=>[member.name,autopsyLabel(member.responsibility)])));if(restricted)detail.append(el("p",{text:t("نطاق الوصول مقيد")}));}
    };
    tabs.forEach((label,index)=>tabbar.append(action(label,()=>show(index),"property-tab")));
    props.body.replaceChildren(tabbar,detail,el("div",{class:"property-actions"},[el("a",{href:`/cases/${record.id}`,class:"button compact",text:t("فتح القضية")}),action(t("تحديث"),()=>refresh(),"button compact")]));show(0);
    const terminal=el("div",{class:"terminal-output"});
    terminal.append(el("p",{text:`SOCify / ${record.reference}`,dir:"ltr"}),el("p",{text:t("سجل نشاط القضية")}));
    for(const event of (record.history||[]).slice(-10))terminal.append(el("div",{class:"terminal-entry"},[el("time",{text:formatTime(event.created_at),dir:"ltr"}),el("span",{text:event.action}),el("span",{text:event.actor_name||"—"})]));
    if(!record.history?.length)terminal.append(el("p",{text:t("لا نشاط مسجل بعد")}));
    activity.body.replaceChildren(terminal);
  }
  async function refresh() {
    const version=++refreshVersion;
    try{
      const data=await api("/api/cases?page=1&page_size=25");if(version!==refreshVersion)return;recentCases=data.items;
      const directory=windows.get("directory"),list=el("div",{class:"terminal-output"});
      list.append(el("p",{text:"SOCify / cases",dir:"ltr"}),el("p",{text:t("فهرس القضايا المصرح بها")}));
      for(const record of recentCases)list.append(el("a",{class:"directory-entry",href:`/cases/${record.id}`},[el("bdi",{text:record.reference}),el("span",{text:record.title}),el("small",{text:autopsyLabel(record.status)})]));
      if(!recentCases.length)list.append(el("p",{text:t("لا توجد قضايا في النطاق المصرح")}));
      list.append(el("p",{class:"terminal-count",text:SOCifyLocale.template`${recentCases.length} عناصر معروضة`}));directory.body.replaceChildren(list);
      const id=document.querySelector('meta[name="case-id"]')?.content||recentCases[0]?.id;
      const record=id?await api(`/api/cases/${id}`):null;if(version!==refreshVersion)return;renderCase(record);
      document.body.dataset.desktopReady="true";
    }catch(error){if(version!==refreshVersion)return;renderCase(null);empty(windows.get("directory"),error.message);document.body.dataset.desktopReady="true";}
  }
  function boot() {
    if(!document.body.classList.contains("autopsy-shell"))return;
    canvas=el("div",{class:"desktop-canvas",id:"desktop-canvas"});
    const main=document.querySelector(".app-main"),workspace=document.getElementById("workspace"),sidebar=document.querySelector(".sidebar");
    main.append(canvas);
    const footer=document.querySelector(".desktop-taskbar");tasks=el("div",{class:"taskbar-windows"});
    footer.replaceChildren(el("span",{class:"taskbar-brand",text:"SOCify",lang:"en",dir:"ltr"}),tasks,action(t("استعادة التكوين"),resetLayout,"taskbar-reset"));
    const content=el("div",{class:"explorer-content"},[sidebar,workspace]);
    const explorer=createWindow("workspace",t("مساحة التحقيق"),content);
    const address=el("div",{class:"window-address",text:"SOCify / cases",dir:"ltr"});explorer.body.prepend(address);
    createWindow("activity",t("نشاط التحقيق"));createWindow("dossier",t("ملف التحقيق"));createWindow("directory",t("فهرس القضايا"));createWindow("properties",t("خصائص القضية"));
    const shortcuts=el("nav",{class:"desktop-shortcuts","aria-label":t("اختصارات سطح المكتب")});
    for(const [href,label]of [["/cases",t("ملفات القضايا")],["/analysis-library",t("التحليل المحلي")],["/playbooks",t("كتيبات الاستجابة")]])shortcuts.append(el("a",{href},[icon(),el("span",{text:label})]));
    canvas.prepend(shortcuts);
    const focusButton=document.querySelector("[data-workspace-focus]");focusButton.addEventListener("click",()=>applyFocus(!focused));
    let stored=null;try{stored=sessionStorage.getItem("socify-desktop-layout");}catch(_){}
    applyFocus(stored?stored==="focus":state.section!=="cases",false);
    if(!focused)activate(windows.get(compact.matches?"workspace":"properties"));
    compact.addEventListener("change",()=>{if(compact.matches)activate(explorer);});
    document.addEventListener("socify:workspace-ready",()=>{address.textContent=`SOCify / ${location.pathname.slice(1)}`;refresh();});
    document.addEventListener("keydown",event=>{if(event.key==="Escape"&&focused&&!document.querySelector("dialog[open]")){applyFocus(false);focusButton.focus();}});
    if(workspace.getAttribute("aria-busy")==="false")refresh();
    window.SOCifyDesktop=Object.freeze({resetLayout,focus:()=>applyFocus(true),desktop:()=>applyFocus(false)});
  }
  document.addEventListener("DOMContentLoaded",boot,{once:true});
})();
