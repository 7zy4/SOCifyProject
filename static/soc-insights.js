"use strict";

window.SOCifyInsights = (() => {
  const t = (ar, en) => SOCifyLocale.language === "ar" ? ar : en;
  const n = value => new Intl.NumberFormat(SOCifyLocale.locale).format(value);
  const label = value => autopsyLabel(value);
  const time = value => value ? formatTime(value) : "—";
  const duration = value => value === null ? "—" : value < 60 ? `${n(Math.round(value))} ${t("ث", "s")}` : value < 3600 ? `${n(Math.round(value/60))} ${t("د", "min")}` : `${n(Math.round(value/360)/10)} ${t("س", "h")}`;
  const userText = value => node("span", {"data-user-content":"true", text:value || "—"});
  function definition(items) {
    return node("dl", {class:"insight-facts"}, items.flatMap(([title,value]) => [node("dt", {text:title}), node("dd", {}, value instanceof Node ? value : userText(value))]));
  }
  function logonType(value) {
    const types={interactive:["دخول تفاعلي","Interactive"],network_logon:["دخول عبر الشبكة","Network"],batch_logon:["دخول مهمة مجدولة","Batch"],service_logon:["دخول خدمة","Service"],unlock_logon:["فتح القفل","Unlock"],network_cleartext:["مصادقة شبكة بكلمة مرور غير مجزأة","Network cleartext"],new_credentials:["بيانات اعتماد جديدة","New credentials"],remote_interactive:["دخول تفاعلي عن بُعد","Remote interactive"],cached_interactive:["دخول تفاعلي ببيانات مخزنة","Cached interactive"],cached_remote_interactive:["دخول بعيد ببيانات مخزنة","Cached remote interactive"],cached_unlock:["فتح القفل ببيانات مخزنة","Cached unlock"]};
    return types[value]?t(...types[value]):value;
  }
  function detailRows(items) {
    return items.map(([name,value])=>node("tr",{},[
        node("th",{scope:"row",text:name}),
        node("td",{},value instanceof Node?value:node("span",{"data-user-content":"true",dir:"auto",text:value===null||value===undefined||value===""?"—":typeof value==="object"?JSON.stringify(value):String(value)}))
      ]));
  }
  function detailTable(title, items) {
    return node("table", {class:"alert-property-table"}, [node("caption",{text:title}),node("tbody",{},detailRows(items))]);
  }
  function inspectionRows(inspection) {
    const names={credential_assignment:t("بيانات اعتماد مكشوفة", "Exposed credentials"),bearer_token:t("رمز وصول مكشوف", "Exposed access token"),private_key:t("مفتاح خاص مكشوف", "Exposed private key"),payment_card:t("رقم بطاقة", "Payment card"),iban:"IBAN"};
    const rows=[];
    for(const [index,finding] of inspection.findings.entries()) {
      rows.push([`${t("النتيجة", "Finding")} ${n(index+1)}`,names[finding.kind]||finding.kind],
        [t("الحقل", "Field"),finding.field],
        [t("موضع الأحرف", "Character position"),`${n(finding.offset+1)}–${n(finding.offset+finding.length)}`],
        [t("الطبقة", "Layer"),finding.layer?n(finding.layer):t("الأصل", "Original")],
        [t("القيمة", "Value"),t("محجوبة", "Redacted")]);
    }
    for(const content of inspection.decoded) {
      rows.push([t("الحقل المرمّز", "Encoded field"),content.field]);
      for(const layer of content.layers) {
        rows.push([`${t("الطبقة", "Layer")} ${n(layer.depth)} | ${layer.encoding}`,node("pre",{dir:"auto",tabindex:0,"data-user-content":"true",text:layer.text==="[REDACTED]"?t("محجوبة", "Redacted"):layer.text})]);
      }
      if(content.depth_limit_reached)rows.push([t("حد الطبقات", "Layer limit"),t("4 طبقات", "4 layers")]);
    }
    if(inspection.truncated)rows.push([t("حالة الفحص", "Inspection status"),t("فحص جزئي - تجاوز حد المحتوى", "Partial inspection - content limit exceeded")]);
    return rows;
  }
  async function contentInspection(caseId) {
    const body=node("div",{class:"panel-body content-inspection"});
    async function load(page=1) {
      const data=await api(`/api/cases/${caseId}/content-inspection?page=${page}`);
      const items=data.items.map(item=>{
        const detail=node("details",{class:"evidence-event"},node("summary",{"data-user-content":"true",text:`#${item.event_id} | ${item.title}`}));
        detail.append(detailTable(t("نتائج الفحص", "Inspection results"),inspectionRows(item.inspection)));
        return detail;
      });
      body.replaceChildren(...items);
      if(!items.length)body.append(node("p",{text:t("لا نتائج", "No findings")}));
      if(data.total>data.page_size||data.page>1){
        const nav=node("nav",{class:"pagination","aria-label":t("صفحات فحص المحتوى", "Content inspection pages")});
        const move=async page=>{try{await load(page);}catch(error){handleError(error);}};
        if(data.page>1)nav.append(button(t("السابق", "Previous"),()=>move(data.page-1)));
        if(data.page*data.page_size<data.total)nav.append(button(t("التالي", "Next"),()=>move(data.page+1)));
        body.append(nav);
      }
    }
    await load();
    return panel(t("فحص المحتوى والترميزات", "Content and encoding inspection"),body,true);
  }
  const precisePercent = value => (value > 0 && value < 1) || (value > 99 && value < 100);
  const percent = value => {
    if (!Number.isFinite(value)) return "—";
    const formatter = new Intl.NumberFormat(SOCifyLocale.locale, {style:"percent",maximumFractionDigits:precisePercent(value) ? 2 : 0});
    if (value > 0 && value < 0.01) return `<${formatter.format(0.0001)}`;
    if (value > 99.99 && value < 100) return `>${formatter.format(0.9999)}`;
    return formatter.format(value / 100);
  };
  const chartDate = value => new Intl.DateTimeFormat(SOCifyLocale.locale, {month:"short",day:"numeric",timeZone:"UTC",calendar:"gregory"}).format(new Date(value));
  function chartSVG(tag, attributes = {}, children = []) {
    const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
    for (const child of children) element.append(child);
    return element;
  }
  function chartLegend(items) {
    return node("ul", {class:"performance-legend"}, items.map(([name, kind, value]) => node("li", {}, [
      node("span", {class:`performance-key ${kind}`,"aria-hidden":"true"}),
      node("span", {text:name}),
      value === undefined ? null : node("strong", {text:n(value)}),
    ])));
  }
  // Shared drawing helpers for the indicator charts.
  function monotonePath(points) {
    if (points.length === 1) return `M${points[0][0]},${points[0][1]}`;
    const slopes = points.slice(0, -1).map((point, i) => (points[i + 1][1] - point[1]) / (points[i + 1][0] - point[0] || 1));
    const tangents = points.map((_, i) => i === 0 ? slopes[0] : i === points.length - 1 ? slopes[i - 1] : slopes[i - 1] * slopes[i] <= 0 ? 0 : (slopes[i - 1] + slopes[i]) / 2);
    let path = `M${points[0][0]},${points[0][1]}`;
    for (let i = 0; i < points.length - 1; i++) {
      const [x0, y0] = points[i], [x1, y1] = points[i + 1], step = (x1 - x0) / 3;
      path += ` C${x0 + step},${y0 + tangents[i] * step} ${x1 - step},${y1 - tangents[i + 1] * step} ${x1},${y1}`;
    }
    return path;
  }
  function figureBlock(value, caption, attributes = {}) {
    return node("div", {class:"performance-figure", ...attributes.wrapper}, [node("strong", {dir:"ltr", ...attributes.value, text:value}), node("span", {text:caption})]);
  }
  function completionChart(data) {
    const value = data.completion || {total:null,completed:null,pending:null,unmeasured:null,percentage:null};
    const body = node("div", {class:"performance-completion"});
    const head = node("div", {class:"performance-figure-row"}, [
      figureBlock(percent(value.percentage), t("مكتملة", "Completed"), {value:{"data-completion-value":"",class:precisePercent(value.percentage)?"performance-precise-value":null}}),
      value.total !== null ? node("p", {class:"performance-completion-count","data-completion-count":"",text:`${n(value.completed)} ${t("من", "of")} ${n(value.total)}`}) : null,
    ]);
    body.append(head);
    // Burn-up: cases opened and closed so far in the period; the gap between the lines is the work still open.
    const buckets = trendBuckets(data);
    const legend = value.unmeasured ? [[t("غير قابلة للحساب", "Not measurable"),"unknown",value.unmeasured]] : [];
    if (buckets.length) {
      let opened = 0, closed = 0;
      const series = buckets.map(bucket => ({opened:(opened += bucket.opened), closed:(closed += bucket.closed)}));
      const width = 320, height = 120, top = 10, bottom = height - 6, max = Math.max(1, opened, closed);
      const x = index => series.length === 1 ? width / 2 : index * width / (series.length - 1);
      const y = count => bottom - (bottom - top) * count / max;
      const openedLine = series.map((point, index) => [x(index), y(point.opened)]);
      const closedLine = series.map((point, index) => [x(index), y(point.closed)]);
      body.append(node("div", {class:"performance-burnup", dir:"ltr"}, chartSVG("svg", {viewBox:`0 0 ${width} ${height}`, preserveAspectRatio:"none", "aria-hidden":"true", focusable:"false"}, [
        ...[0.5, 1].map(share => chartSVG("line", {x1:0, x2:width, y1:y(max * share), y2:y(max * share), class:"performance-grid"})),
        chartSVG("path", {d:`${monotonePath(openedLine)} L${width},${bottom} L0,${bottom} Z`, class:"performance-burnup-open"}),
        chartSVG("path", {d:`${monotonePath(closedLine)} L${width},${bottom} L0,${bottom} Z`, class:"performance-burnup-done"}),
        chartSVG("path", {d:monotonePath(openedLine), class:"performance-burnup-line opened"}),
        chartSVG("path", {d:monotonePath(closedLine), class:"performance-burnup-line closed"}),
      ])));
      legend.unshift([t("أنشئت حتى الآن", "Opened so far"),"opened",opened],[t("أغلقت حتى الآن", "Closed so far"),"closed",closed]);
    }
    if (legend.length) body.append(chartLegend(legend));
    body.append(node("p", {class:"performance-basis",text:t("النسبة للقضايا المنشأة خلال الفترة", "Share of cases opened in this period")}));
    if (!value.total) body.append(node("p", {class:"performance-empty",text:value.total === 0 ? t("لا قضايا خلال الفترة", "No cases in this period") : t("لا قياس بعد", "Not measured yet")}));
    return panel(t("إنجاز القضايا", "Case completion"), body, true);
  }
  function trendBuckets(data) {
    if (!data.trend.length) return [];
    const day = 86400000;
    const end = Date.parse(data.fetched_at.slice(0,10) + "T00:00:00Z");
    const first = data.days === "all" ? Date.parse(data.trend[0].date + "T00:00:00Z") : end - Number(data.days) * day;
    const span = Math.max(1, Math.floor((end-first)/day)+1);
    const step = Math.max(1, Math.ceil(span / 8));
    const buckets = Array.from({length:Math.ceil(span/step)}, (_, index) => ({
      start:first+index*step*day, end:Math.min(end, first+((index+1)*step-1)*day), opened:0, closed:0,
    }));
    for (const row of data.trend) {
      const index = Math.floor((Date.parse(row.date + "T00:00:00Z")-first)/(step*day));
      if (buckets[index]) {buckets[index].opened += row.opened; buckets[index].closed += row.closed;}
    }
    return buckets;
  }
  function activityChart(data) {
    const body = node("div", {class:"panel-body performance-trend"});
    const buckets = trendBuckets(data);
    const totals = data.trend.reduce((result, row) => ({opened:result.opened+row.opened,closed:result.closed+row.closed}), {opened:0,closed:0});
    body.append(chartLegend([[t("أنشئت", "Opened"),"opened",totals.opened],[t("أغلقت", "Closed"),"closed",totals.closed]]));
    if (!buckets.length) {
      body.append(node("div", {class:"performance-chart-empty",text:t("لا حركة قضايا خلال الفترة", "No case activity in this period")}));
    } else {
      // Opened cases rise above the baseline and closed cases mirror below it, drawn as smooth curves.
      const max = Math.max(1, ...buckets.flatMap(bucket => [bucket.opened,bucket.closed]));
      const width = 1000, height = 240, middle = height / 2, reach = middle - 14;
      const x = index => buckets.length === 1 ? width / 2 : (index / (buckets.length - 1)) * width;
      // Monotone cubic interpolation: smooth, and never overshoots the counts (no dips below zero, no false peaks).
      const curve = points => {
        if (points.length === 1) return `M0,${points[0][1]} L${width},${points[0][1]}`;
        const slopes = points.slice(0, -1).map((point, i) => (points[i + 1][1] - point[1]) / (points[i + 1][0] - point[0]));
        const tangents = points.map((_, i) => i === 0 ? slopes[0] : i === points.length - 1 ? slopes[i - 1] : slopes[i - 1] * slopes[i] <= 0 ? 0 : (slopes[i - 1] + slopes[i]) / 2);
        slopes.forEach((slope, i) => {
          if (slope === 0) { tangents[i] = 0; tangents[i + 1] = 0; return; }
          const a = tangents[i] / slope, b = tangents[i + 1] / slope, h = a * a + b * b;
          if (h > 9) { const tau = 3 / Math.sqrt(h); tangents[i] = tau * a * slope; tangents[i + 1] = tau * b * slope; }
        });
        let path = `M${points[0][0]},${points[0][1]}`;
        for (let i = 0; i < points.length - 1; i++) {
          const [x0, y0] = points[i], [x1, y1] = points[i + 1], step = (x1 - x0) / 3;
          path += ` C${x0 + step},${y0 + tangents[i] * step} ${x1 - step},${y1 - tangents[i + 1] * step} ${x1},${y1}`;
        }
        return path;
      };
      const series = (key, sign) => buckets.map((bucket, index) => [x(index), middle - sign * reach * bucket[key] / max]);
      const opened = series("opened", 1), closed = series("closed", -1);
      const area = points => `${curve(points)} L${points.at(-1)[0]},${middle} L${points[0][0]},${middle} Z`;
      const svg = chartSVG("svg", {viewBox:`0 0 ${width} ${height}`, preserveAspectRatio:"none", class:"performance-curves", "aria-hidden":"true", focusable:"false"}, [
        ...[0.25, 0.5, 0.75].map(share => chartSVG("line", {x1:0, x2:width, y1:middle - reach * share, y2:middle - reach * share, class:"performance-grid"})),
        ...[0.25, 0.5, 0.75].map(share => chartSVG("line", {x1:0, x2:width, y1:middle + reach * share, y2:middle + reach * share, class:"performance-grid"})),
        chartSVG("path", {d:area(opened), class:"performance-area opened"}),
        chartSVG("path", {d:area(closed), class:"performance-area closed"}),
        chartSVG("path", {d:curve(opened), class:"performance-line opened"}),
        chartSVG("path", {d:curve(closed), class:"performance-line closed"}),
        chartSVG("line", {x1:0, x2:width, y1:middle, y2:middle, class:"performance-baseline"}),
      ]);
      const plot = node("div", {class:"performance-plot",dir:"ltr",role:"group","aria-label":t("حركة القضايا", "Case activity")});
      const scale = node("div", {class:"performance-y-axis","aria-hidden":"true"}, [n(max), "0", n(max)].map(text => node("span", {text})));
      const canvas = node("div", {class:"performance-canvas"}, [svg]);
      const columns = node("div", {class:"performance-trend-columns"});
      const detail = node("p", {class:"performance-trend-readout"});
      const show = index => {
        const bucket = buckets[index];
        const dates = bucket.start === bucket.end ? chartDate(bucket.start) : `${chartDate(bucket.start)} - ${chartDate(bucket.end)}`;
        detail.textContent = `${dates} | ${t("أنشئت", "Opened")} ${n(bucket.opened)} | ${t("أغلقت", "Closed")} ${n(bucket.closed)}`;
        [...columns.children].forEach((item, i) => {
          item.classList.toggle("selected", i === index);
          item.setAttribute("aria-pressed", String(i === index));
        });
      };
      for (const [index,bucket] of buckets.entries()) {
        const dates = bucket.start === bucket.end ? chartDate(bucket.start) : `${chartDate(bucket.start)} - ${chartDate(bucket.end)}`;
        const control = node("button", {type:"button",class:"performance-trend-bucket","aria-label":`${dates}: ${t("أنشئت", "Opened")} ${n(bucket.opened)}, ${t("أغلقت", "Closed")} ${n(bucket.closed)}`});
        control.style.setProperty("--point-opened", `${50 - 50 * (reach / middle) * bucket.opened / max}%`);
        control.style.setProperty("--point-closed", `${50 + 50 * (reach / middle) * bucket.closed / max}%`);
        control.append(node("span", {class:"performance-point opened","aria-hidden":"true"}), node("span", {class:"performance-point closed","aria-hidden":"true"}));
        control.addEventListener("pointerenter", () => show(index));
        control.addEventListener("focus", () => show(index));
        control.addEventListener("click", () => show(index));
        control.addEventListener("keydown", event => {
          if (!["ArrowLeft","ArrowRight","Home","End"].includes(event.key)) return;
          event.preventDefault();
          const next = event.key === "Home" ? 0 : event.key === "End" ? buckets.length-1 : Math.max(0,Math.min(buckets.length-1,index+(event.key === "ArrowRight" ? 1 : -1)));
          columns.children[next].focus();
        });
        columns.append(control);
      }
      columns.style.setProperty("--bucket-count", String(buckets.length));
      canvas.append(columns);
      plot.append(scale, canvas);
      const ticks = node("div", {class:"performance-x-axis",dir:"ltr","aria-hidden":"true"}, [buckets[0].start,buckets[Math.floor(buckets.length/2)].start,buckets.at(-1).end].map(date => node("span", {text:chartDate(date)})));
      body.append(plot,ticks,detail);
      show(buckets.length-1);
    }
    if (data.trend.length) {
      const detail = node("details", {class:"performance-data"}, node("summary", {text:t("عرض الأرقام اليومية", "Daily figures")}));
      detail.append(table([{label:t("التاريخ", "Date"),value:"date"},{label:t("أنشئت", "Opened"),value:r=>n(r.opened)},{label:t("أغلقت", "Closed"),value:r=>n(r.closed)}], data.trend));
      body.append(detail);
    }
    return panel(t("حركة القضايا خلال الفترة", "Case activity during period"), body, true);
  }
  function speedChart(data) {
    const value = data.speed || {on_time:0,late:0,unmeasured:0,included:0,compliance_percent:null,cases:[]};
    const body = node("div", {class:"panel-body performance-speed"});
    body.append(figureBlock(percent(value.compliance_percent), t("ضمن المهلة", "Within SLA"), {wrapper:{class:"performance-figure performance-speed-score"}, value:{"data-speed-value":"",class:precisePercent(value.compliance_percent)?"performance-precise-value":null}}));
    // Each closed case is a column, oldest first: its height is the share of its deadline it used, and columns above the line ran late.
    const cases = (value.cases || []).filter(item => Number.isFinite(item.used)).reverse();
    if (cases.length) {
      const scale = Math.max(1.25, Math.min(2.5, Math.max(...cases.map(item => item.used)) * 1.08));
      const share = used => `${(100 * Math.min(used, scale) / scale).toFixed(2)}%`;
      const chart = node("div", {class:"performance-sla-columns", dir:"ltr", role:"img", "aria-label":`${t("نسبة المهلة المستخدمة لكل قضية مغلقة", "Share of the deadline used by each closed case")}: ${t("ضمن المهلة", "Within SLA")} ${n(cases.filter(item => item.on_time).length)} | ${t("متأخرة", "Late")} ${n(cases.filter(item => !item.on_time).length)}`});
      chart.style.setProperty("--deadline", share(1));
      chart.style.setProperty("--gap", cases.length > 16 ? "2px" : "6px");
      chart.append(node("span", {class:"performance-sla-zone"}), node("span", {class:"performance-sla-line"}, node("span", {text:t("المهلة", "Deadline")})));
      for (const item of cases) {
        const column = node("span", {class:`performance-sla-column ${item.on_time ? "within" : "late"}`, title:`${item.reference} | ${percent(item.used * 100)}`});
        column.style.setProperty("--used", share(item.used));
        chart.append(column);
      }
      body.append(chart);
    }
    body.append(chartLegend([[t("ضمن المهلة", "Within SLA"),"within",value.on_time],[t("متأخرة", "Late"),"late",value.late]]));
    body.append(node("p", {class:"performance-basis",text:`${t("قضايا مغلقة قابلة للحساب", "Closed cases measured")} ${n(value.included)} ${t("من", "of")} ${n(value.included+value.unmeasured)}`}));
    if (!value.included) body.append(node("p", {class:"performance-empty",text:t("لا قياسات لمهلة الاستجابة", "No SLA measurements")}));
    return panel(t("الالتزام بمهلة الاستجابة", "Response SLA compliance"),body,true);
  }
  function durationChart(data) {
    const titles = {detection_delay_seconds:t("الرصد", "Detection"),acknowledgement_delay_seconds:t("إقرار الاستلام", "Acknowledgement"),containment_delay_seconds:t("الاحتواء", "Containment"),recovery_delay_seconds:t("التعافي", "Recovery"),closure_delay_seconds:t("الإغلاق", "Closure")};
    const values = Object.entries(titles).map(([key,title]) => ({key,title,...data.metrics[key]}));
    const body = node("div", {class:"panel-body performance-durations"});
    // One bar per step, its length the step's median time against the longest step.
    const longest = Math.max(0, ...values.map(item => item.median_seconds || 0));
    const rows = node("div", {class:"performance-duration-rows"});
    for (const item of values) {
      const track = node("div", {class:"performance-duration-track","aria-hidden":"true"});
      if (item.median_seconds !== null) {
        const bar = node("span", {class:"performance-duration-bar", title:`${item.title} | ${duration(item.median_seconds)}`});
        bar.style.setProperty("--share", `${longest ? (100 * item.median_seconds / longest).toFixed(2) : 0}%`);
        track.append(bar);
      }
      rows.append(node("div", {class:"performance-duration-row"}, [
        node("span", {class:"performance-duration-title",text:item.title}),
        track,
        node("strong", {text:duration(item.median_seconds)}),
        node("span", {class:"performance-sample",text:`${n(item.included)} ${t("من", "of")} ${n(item.included+item.excluded)}`}),
      ]));
    }
    body.append(rows);
    return panel(t("وسيط مدد القضايا المغلقة", "Median closed-case durations"),body,true);
  }
  // One capsule split by severity: each part's length is its share of the active cases.
  function severityCapsule(counts) {
    const parts = ["critical","high","medium","low"].map(severity => [severity, counts[severity] || 0]);
    const total = parts.reduce((sum, [, count]) => sum + count, 0);
    const capsule = node("div", {class:`performance-capsule${total ? "" : " empty"}`, role:"img", "aria-label":parts.map(([severity, count]) => `${label(severity)} ${n(count)}`).join(" | ")});
    for (const [severity, count] of parts) {
      if (!count) continue;
      const part = node("span", {class:`performance-capsule-part ${severity}`, title:`${label(severity)} ${n(count)}`});
      part.style.flexGrow = String(count);
      capsule.append(part);
    }
    return capsule;
  }
  function severityChart(data) {
    const body = node("div", {class:"panel-body performance-severity"});
    const legend = node("ul", {class:"performance-severity-list"});
    for (const severity of ["critical","high","medium","low"]) {
      legend.append(node("li", {}, [autopsyBadge(severity),node("strong", {text:n(data.severity[severity] || 0)})]));
    }
    // The capsule shows the active cases split by severity: here colour means severity and nothing else.
    const figure = node("div", {class:"performance-workload-figure"}, [
      node("div", {class:"performance-figure"}, [node("strong", {text:n(data.counts.open)}),node("span", {text:t("قضايا نشطة", "Active cases")})]),
      severityCapsule(data.severity),
    ]);
    body.append(node("div", {class:"performance-workload"}, [figure, legend]));
    body.append(node("dl", {class:"performance-attention"}, [
      [t("تنبيهات دون قرار", "Alerts without a verdict"),data.counts.unreviewed_alerts],
      [t("قضايا دون مسؤول", "Unassigned cases"),data.counts.unassigned],
      [t("تجاوزت موعد القضية", "Past case deadline"),data.counts.overdue],
    ].flatMap(([title,value]) => [node("dt", {text:title}),node("dd", {text:n(value)})])));
    return panel(t("عبء العمل الحالي", "Current workload"),body,true);
  }
  async function performance() {
    begin("performance");
    try {
      const params = new URLSearchParams(location.search);
      const data = await api("/api/soc/performance?" + params);
      const personal = data.member !== "team";
      const queueURL = (changes = {}, anchor = false) => `/performance?${new URLSearchParams({member:data.member, days:data.days, queue:data.queue_kind, page:String(data.queue_page), ...changes})}${anchor ? "#performance-cases" : ""}`;
      const title = personal ? t("أداء المحلل", "Analyst performance") : t("أداء الفريق", "Team performance");
      document.getElementById("section-title").textContent = title;
      document.title = `${title} | SOCify`;
      const root = node("div", {class:"insights-view performance-view"}, pageHead(title, null));
      const nav = node("nav", {class:"channel-tabs", "aria-label":t("نطاق الأداء", "Performance scope")});
      const targets = [["me",t("أدائي", "My performance")]];
      if (data.can_manage) targets.unshift(["team",t("الفريق", "Team")]);
      for (const [value, name] of targets) nav.append(node("a", {class:"channel-tab", href:queueURL({member:value,page:1}), "aria-current":value===data.member?"page":null, text:name}));
      const days = node("select", {name:"days"}, [["7",t("آخر 7 أيام", "Last 7 days")],["30",t("آخر 30 يومًا", "Last 30 days")],["90",t("آخر 90 يومًا", "Last 90 days")],["all",t("كل الفترات", "All time")]].map(([value,text])=>node("option", {value, selected:value===data.days, text})));
      const form = node("form", {class:"filter-row"}, [field(t("فترة الإنجاز", "Completion period"),days),node("input",{type:"hidden",name:"member",value:data.member}),node("input",{type:"hidden",name:"queue",value:data.queue_kind}),node("button",{class:"button ghost",type:"submit",text:t("تطبيق", "Apply")})]);
      root.append(node("div", {class:"performance-toolbar"}, [nav,form]));
      root.append(node("div", {class:"insight-counters"}, [["open",t("قضايا نشطة", "Active cases")],["closed",t("أغلقت خلال الفترة", "Closed in period")],["awaiting_review",t("بانتظار المراجعة", "Awaiting review")],["pending_tasks",t("مهام معلقة", "Pending tasks")]].map(([key,text])=>node(key === "pending_tasks" ? "div" : "a",{class:"insight-counter",href:key === "pending_tasks" ? null : queueURL({queue:key,page:1},true),"aria-current":key === data.queue_kind ? "page" : null},[node("span",{text}),node("strong",{text:n(data.counts[key])})]))));
      // Main chart beside the live workload, then the three single measures in one row.
      root.append(node("div", {class:"performance-overview"}, [activityChart(data),severityChart(data)]));
      root.append(node("div", {class:"performance-operations"}, [completionChart(data),speedChart(data),durationChart(data)]));
      if(data.members.length) {
        const members = panel(t("الفريق والإنجاز", "Team delivery"),table([{label:t("المحلل", "Analyst"),value:r=>data.can_manage?node("a",{class:"badge badge-person",href:queueURL({member:r.id,page:1}),title:r.name,text:r.name}):personChip(r.name)},{label:t("الدور", "Role"),value:r=>r.role === "instructor" ? t("مدرب", "Instructor") : label(r.role)},{label:t("نشطة", "Active"),value:r=>n(r.open)},{label:t("مغلقة خلال الفترة", "Closed in period"),value:r=>n(r.closed)},{label:t("مهام أنجزها", "Tasks completed"),value:r=>n(r.tasks_completed)}],data.members),true);
        members.classList.add("performance-members");root.append(members);
      }
      const queueTitle = data.queue_kind === "closed" ? t("القضايا المغلقة", "Closed cases") : data.queue_kind === "awaiting_review" ? t("بانتظار المراجعة", "Awaiting review") : t("قائمة المتابعة", "Work queue");
      const emptyQueue = data.queue_kind === "closed" ? t("لا قضايا مغلقة خلال الفترة", "No cases closed in this period") : data.queue_kind === "awaiting_review" ? t("لا قضايا بانتظار المراجعة", "No cases awaiting review") : t("لا قضايا نشطة", "No active cases");
      const queueContent = data.queue.length ? table([{label:t("القضية", "Case"),value:r=>node("a",{href:`/cases/${r.id}${data.queue_kind === "awaiting_review" ? "?tab=reports" : ""}`,text:`${r.reference} | ${r.title}`})},{label:t("الخطورة", "Severity"),value:r=>autopsyBadge(r.severity)},{label:t("المسؤول", "Owner"),value:r=>personChip(r.assignee_name)},{label:t("الحالة", "Status"),value:r=>autopsyBadge(r.status, "case")},{label:data.queue_kind === "closed" ? t("الإغلاق", "Closed at") : t("الموعد", "Deadline"),value:r=>time(data.queue_kind === "closed" ? r.closed_at : r.sla_due_at)}],data.queue) : emptyState(emptyQueue,null,[linkedButton(t("إدارة القضايا", "Case management"),"/cases")]);
      const queuePanel = panel(`${queueTitle} | ${n(data.queue_total)}`, queueContent, true);
      queuePanel.id = "performance-cases";
      queuePanel.setAttribute("aria-label",queueTitle);
      if(data.queue_pages > 1) {
        const paging = node("nav",{class:"pagination","aria-label":t("صفحات القضايا", "Case pages")},[
          data.queue_page > 1 ? linkedButton(t("السابق", "Previous"),queueURL({page:data.queue_page-1},true)) : null,
          node("span",{text:t(`الصفحة ${n(data.queue_page)} من ${n(data.queue_pages)}`,`Page ${n(data.queue_page)} of ${n(data.queue_pages)}`)}),
          data.queue_page < data.queue_pages ? linkedButton(t("التالي", "Next"),queueURL({page:data.queue_page+1},true)) : null,
        ]);
        queuePanel.append(paging);
      }
      root.append(queuePanel);
      if(data.tasks.length) root.append(panel(`${t("المهام المعلقة", "Pending tasks")} | ${n(data.task_total)}`,stackedTable([{label:t("المهمة", "Task"),value:r=>node("a",{href:`/cases/${r.case_id}?tab=summary#case-task-${r.id}`,text:r.display_title})},{label:t("القضية", "Case"),value:r=>node("a",{href:`/cases/${r.case_id}`,"data-user-content":"true",text:`${r.case_reference} | ${r.case_title}`})},{label:t("الحالة", "Status"),value:r=>label(r.status)}],data.tasks),true));
      if(data.task_total>50)root.append(linkedButton(t("إدارة القضايا", "Case management"),"/cases"));
      finish(root);
      if(location.hash === "#performance-cases") {queuePanel.tabIndex=-1;queuePanel.focus({preventScroll:true});queuePanel.scrollIntoView({block:"start"});}
    } catch(error) {finish(emptyState(t("تعذر تحميل الأداء", "Unable to load performance"),error.message,[button(t("إعادة المحاولة", "Retry"),performance),linkedButton(t("مسح المرشحات", "Clear filters"),"/performance")]));}
  }
  async function dossier(item, container) {
    const data=await api(`/api/cases/${item.case_id}/alerts/${item.id}/dossier`);
    const context=item.case_title===undefined||item.assignee_name===undefined?await api(`/api/cases/${item.case_id}`):null;
    const caseTitle=item.case_title??context?.title;
    const owner=item.assignee_name??context?.members?.find(member=>member.user_id===context.assignee)?.name;
    const linkedEvents=Number.isInteger(item.evidence_events)&&item.evidence_events>=0?n(item.evidence_events):`${n(data.events.length)}${data.events_truncated?"+":""}`;
    const root=node("div",{class:"dossier-view"});
    const details=detailTable(t("تفاصيل التنبيه", "Alert details"),[
      [t("معرف التنبيه", "Alert ID"),data.alert.alert_id],
      [t("اسم القاعدة", "Rule name"),data.alert.rule_name],
      [t("الخطورة", "Severity"),autopsyBadge(data.alert.severity)],
      [t("سبب الكشف", "Detection reason"),data.alert.reason],
      [t("وقت الكشف", "Detection time"),time(data.alert.detected_at)],
      [t("القضية", "Case"),node("a",{href:`/cases/${item.case_id}`,text:[data.case.reference,caseTitle].filter(Boolean).join(" | ")})],
      [t("حالة القضية", "Case status"),label(data.case.status)],
      [t("المسؤول", "Owner"),owner],
      [t("السجلات المرتبطة", "Linked events"),linkedEvents],
      [t("الإغلاق", "Closed at"),time(data.case.closed_at)],
      [t("قرار المحلل", "Analyst verdict"),label(data.review?.verdict||"undetermined")],
      [t("نتيجة الهجوم", "Attack outcome"),label(data.review?.attack_outcome||"unknown")],
      ...(data.review?[[t("ملاحظة المحلل", "Analyst note"),data.review.reason]]:[])
    ]);
    const section=(name,rows,key)=>details.append(node("tbody",{"data-dossier-section":key},[node("tr",{},node("th",{colspan:2,class:"dossier-section",text:name})),...detailRows(rows)]));
    if(data.assessment){
      const decisions=data.assessment.resolved_questions.map(q=>[SOCifyLocale.text(q.question),SOCifyLocale.text(q.answer_label)]);
      if(data.assessment.executive_note)decisions.push([t("خلاصة التحقيق", "Investigation summary"),data.assessment.executive_note]);
      if(data.assessment.manager_comment)decisions.push([t("ملاحظة المراجع", "Reviewer note"),data.assessment.manager_comment]);
      section(t("قرارات القضية", "Case decisions"),decisions,"decisions");
    }
    for(const technique of data.techniques)section("MITRE ATT&CK | "+technique.technique_id,[[t("التقنية", "Technique"),technique.technique_id],[t("التقييم", "Assessment"),label(technique.assessment)],[t("الدليل", "Evidence"),technique.reason]],"technique");
    for(const event of data.events){
      const fields=event.normalized_fields;
      const names={windows_event_id:t("معرف حدث Windows", "Windows event ID"),account_domain:t("نطاق الحساب", "Account domain"),logon_type:t("نوع الدخول", "Logon type"),logon_type_code:t("رمز نوع الدخول", "Logon type code"),authentication_package:t("آلية المصادقة", "Authentication package"),logon_id:t("معرف جلسة الدخول", "Logon session ID"),source_workstation:t("جهاز المصدر", "Source workstation"),logon_status:t("رمز الحالة", "Status code"),logon_substatus:t("رمز الحالة الفرعي", "Substatus code"),outcome:t("النتيجة", "Outcome"),ids_rule:t("معرف قاعدة الرصد", "Sensor rule ID"),ids_priority:t("أولوية الرصد", "Sensor priority"),ids_signature:t("وصف التنبيه", "Alert message"),ids_classification:t("تصنيف التنبيه", "Alert classification"),packet_number:t("رقم الحزمة", "Packet number"),source_timestamp:t("توقيت المصدر", "Source timestamp"),source_port:t("منفذ المصدر", "Source port"),destination_port:t("منفذ الوجهة", "Destination port"),protocol:t("البروتوكول", "Protocol"),process_name:t("العملية", "Process"),parent_process:t("العملية الأم", "Parent process"),command_line:t("سطر الأوامر", "Command line"),file_hash:t("بصمة الملف", "File hash"),runtime_rule:t("قاعدة الرصد", "Sensor rule"),runtime_priority:t("أولوية الرصد", "Sensor priority"),runtime_source:t("مصدر الحدث", "Event source"),sensor_hostname:t("حساس الجمع", "Collector"),process_id:t("معرف العملية", "Process ID"),parent_process_id:t("معرف العملية الأم", "Parent process ID"),process_path:t("مسار العملية", "Process path"),file_path:t("مسار الملف", "File path"),container_id:t("معرف الحاوية", "Container ID"),container_name:t("الحاوية", "Container"),container_image:t("صورة الحاوية", "Container image"),container_image_tag:t("وسم الصورة", "Image tag"),kubernetes_namespace:t("نطاق الحاويات", "Namespace"),kubernetes_pod:t("مجموعة الحاويات", "Pod"),kubernetes_node:t("عقدة التشغيل", "Node")};
      const facts=[[t("معرف السجل", "Event ID"),event.id],[t("وقت الحدث", "Event time"),fields.event_time_known?time(event.event_time):null],[t("المصدر", "Source"),event.source_ip],[t("الوجهة", "Destination"),event.destination_ip],[t("الجهاز", "Host"),event.hostname],[t("الحساب", "Account"),event.username]];
      for(const [key,value] of Object.entries(fields))if(!["auth_target","event_time_known","event_time","source_ip","destination_ip","hostname","username","telemetry_schema","content_inspection","exposed_secret_count","sensitive_data_count","decoded_threat_count"].includes(key))facts.push([names[key]||label(key),key==="logon_type"?logonType(value):key==="outcome"?(value==="success"?t("ناجح","Success"):value==="failed"?t("فشل","Failed"):label(value)):value]);
      facts.push([t("السجل الأصلي", "Original event"),node("pre",{dir:"ltr",tabindex:0,"data-user-content":"true",text:event.raw_data})]);
      if(event.raw_truncated)facts.push([t("السجل الكامل", "Complete event"),linkedButton(t("فتح السجل الكامل", "Open complete event"),`/cases/${item.case_id}?tab=logs`)]);
      if(!event.autopsy_active)facts.push([t("نسخة السجل", "Event version"),t("نسخة سجل سابقة", "Historical event version")]);
      section(t("السجل", "Event")+" #"+event.id,facts,"event");
      if(fields.content_inspection)section(t("فحص المحتوى والترميزات", "Content and encoding inspection")+" #"+event.id,inspectionRows(fields.content_inspection),"inspection");
    }
    if(!data.events.length)section(t("سجلات التنبيه", "Alert evidence events"),[[t("السجلات", "Events"),t("لا سجلات مرتبطة", "No linked events")]],"event");
    if(data.events_truncated)section(t("سجلات التنبيه", "Alert evidence events"),[[t("السجلات", "Events"),linkedButton(t("عرض جميع السجلات", "View all logs"),`/cases/${item.case_id}?tab=logs`)]],"more-events");
    for(const task of data.tasks)section(t("المهمة", "Task")+" #"+task.id,[[t("المهمة", "Task"),task.display_title],[t("الحالة", "Status"),label(task.status)],[t("أُنجزت", "Completed"),time(task.completed_at)]],"task");
    for(const [index,note] of data.notes.entries())section(t("ملاحظة التحقيق", "Investigation note")+" "+n(index+1),[[t("المحلل", "Analyst"),note.author],[t("الوقت", "Time"),time(note.created_at)],[t("الملاحظة", "Note"),note.body]],"note");
    root.append(details);
    container.replaceChildren(root);
  }
  async function hosts(caseId) {
    const params=new URLSearchParams(location.search);
    const query=new URLSearchParams({q:params.get("host_q")||"",host:params.get("host")||"",page:params.get("host_page")||"1"});
    const data=await api(`/api/cases/${caseId}/observed-hosts?${query}`);
    const root=node("div",{class:"panel-body"});
    const search=node("input",{type:"search",name:"host_q",maxlength:200,value:query.get("q")});
    root.append(node("form",{class:"filter-row"},[node("input",{type:"hidden",name:"case_id",value:caseId}),field(t("اسم الجهاز", "Hostname"),search),node("button",{type:"submit",class:"button ghost",text:t("بحث", "Search")})]));
    const target=(host,page=1)=>`/endpoint-security?${new URLSearchParams({case_id:caseId,host,host_page:page,host_q:query.get("q")})}`;
    root.append(data.items.length?table([{label:t("الجهاز", "Host"),value:r=>node("a",{href:target(r.hostname),text:r.hostname})},{label:t("السجلات", "Events"),value:"events"},{label:t("أول ظهور", "First observed"),value:r=>time(r.first_seen)},{label:t("آخر ظهور", "Last observed"),value:r=>time(r.last_seen)}],data.items):emptyState(t("لا أجهزة", "No devices"),null));
    const pages=node("div",{class:"pagination"});
    if(data.page>1)pages.append(linkedButton(t("السابق", "Previous"),target(data.host,data.page-1)));
    if(data.page*data.page_size<data.total)pages.append(linkedButton(t("التالي", "Next"),target(data.host,data.page+1)));
    root.append(pages);
    if(data.host){
      root.append(node("h3",{"data-user-content":"true",text:data.host}));
      for(const event of data.events){
        const detail=node("details",{class:"evidence-event"},node("summary",{text:`#${event.id} | ${event.event_time_known?time(event.event_time):"—"} | ${event.process_name||event.username||""}`}));
        detail.append(definition([[t("العملية", "Process"),event.process_name],[t("العملية الأم", "Parent process"),event.parent_process],[t("سطر الأوامر", "Command line"),event.command_line],[t("المصدر", "Source"),event.source_ip],[t("الوجهة", "Destination"),event.destination_ip],[t("الحساب", "Account"),event.username],[t("بصمة الملف", "File hash"),event.file_hash]]));
        root.append(detail);
      }
      if(!data.events.length)root.append(node("p",{text:t("لا سجلات للجهاز المحدد", "No events for this host")}));
      if(data.events_truncated)root.append(linkedButton(t("عرض جميع السجلات", "View all logs"),`/cases/${caseId}?tab=logs`));
    }
    return panel(t("أجهزة القضية", "Case devices"),root,true);
  }
  return {performance,dossier,hosts,contentInspection};
})();
