"use strict";

Object.assign(autopsyLabels, { any: "أي عضو مخول", manager: "المدير", analysis: "التحليل", review: "المراجعة", pending: "بانتظار التنفيذ", awaiting_approval: "بانتظار اعتماد المدير", notes: "ملاحظة القرار أو النتيجة", override_reason: "سبب استثناء استقلال المراجع إن لزم", user_id: "عضو الفريق", responsibility: "المسؤولية" });

async function autopsyProcedureLibrary() {
  begin("playbooks");
  const library = await api("/api/autopsy/procedures");
  const root = node("div", {}, pageHead("كتيبات الاستجابة", "قوالب داخلية بإصدارات ثابتة. تحفظ القضية نسخة مستقلة، وتوثق الإجراءات دون تنفيذ أوامر على الأجهزة."));
  if (library.can_manage) {
    root.append(button("إضافة القوالب الإرشادية للمراجعة", async () => { try { await api("/api/autopsy/procedures/seed", { method: "POST", body: {} }); await autopsyProcedureLibrary(); } catch (error) { handleError(error); } }));
    const name = node("input", { required: true, maxlength: 160 });
    const steps = node("div");
    const add = (initial = {}) => {
      const title = node("input", { required: true, maxlength: 255, value: initial.title || "" });
      const description = node("textarea", { maxlength: 2000 }, initial.description || "");
      const phase = autopsySelect("phase", ["triage", "analysis", "containment", "eradication", "recovery", "validation", "review"], initial.phase || "analysis");
      const role = autopsySelect("role", ["any", "l1", "l2", "investigator", "reviewer", "manager"], initial.role || "any");
      const required = node("input", { type: "checkbox", checked: initial.required !== false });
      const approval = node("input", { type: "checkbox", checked: !!initial.approval_required });
      const row = node("fieldset", { class: "form-grid" }, [node("legend", { text: "خطوة موثقة" }), field("العنوان", title), field("التفاصيل", description), field("المرحلة", phase), field("دور المنفذ", role), field("إلزامية", required), field("تتطلب اعتماد المدير", approval)]);
      row.autopsyValue = () => ({ title: title.value, description: description.value, phase: phase.value, role: role.value, required: required.checked, approval_required: approval.checked });
      row.append(button("حذف الخطوة", () => row.remove()));
      steps.append(row);
    };
    add();
    const form = node("form", { class: "panel-body" }, [field("اسم القالب أو اسم الإصدار السابق", name), steps, button("إضافة خطوة", () => { if (steps.children.length < 30) add(); }), node("button", { type: "submit", class: "button primary", text: "حفظ إصدار مسودة" })]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); try { await api("/api/autopsy/procedures", { method: "POST", body: { name: name.value, steps: [...steps.children].map((row) => row.autopsyValue()) } }); await autopsyProcedureLibrary(); } catch (error) { handleError(error); } });
    root.append(panel("إنشاء إصدار جديد", form, true));
  }
  for (const template of library.items) {
    const card = node("article", { class: "card" }, [node("h2", { text: `${template.name} · الإصدار ${template.version}` }), node("p", { text: template.state }), node("ol", {}, template.steps.map((step) => node("li", { text: `${step.title} · ${autopsyLabel(step.phase)} · ${autopsyLabel(step.role)}` })))]);
    if (library.can_manage && template.state === "draft") card.append(button("اعتماد ونشر هذا الإصدار", async () => { try { await api(`/api/autopsy/procedures/${template.id}/publish`, { method: "POST", body: {} }); await autopsyProcedureLibrary(); } catch (error) { handleError(error); } }));
    root.append(card);
  }
  finish(root);
}

window.SOCifyAutopsy.procedures = async (caseId) => {
  const [library, records] = await Promise.all([api("/api/autopsy/procedures"), api(`/api/cases/${caseId}/records?kind=playbook&limit=100`)]);
  const body = node("div", { class: "panel-body" }, [node("p", { text: "توثيق إجراءات واقعية بالأدلة؛ لا ترسل المنصة أوامر عزل أو حظر إلى أجهزة الشركة." }), linkedButton("إدارة القوالب وإصداراتها", "/playbooks")]);
  const published = library.items.filter((item) => item.state === "published");
  if (permission("playbooks.request") && autopsy.current.status !== "closed") {
    const choice = autopsyChoice("template", published.map((item) => ({ value: item.id, label: `${item.name} · ${item.version}` })), "", true);
    body.append(field("قالب منشور", choice.control), button("إضافة نسخة للقضية", async () => { try { await api(`/api/cases/${caseId}/procedures`, { method: "POST", body: { template_id: choice.input.autopsyValue() } }); await autopsyCase(caseId); } catch (error) { handleError(error); } }));
  }
  for (const record of records.items) {
    const card = node("article", { class: "card" }, node("h3", { text: `${record.payload.template_name} · الإصدار ${record.payload.template_version}` }));
    record.payload.steps.forEach((step, index) => {
      const row = node("div", { class: "procedure-step" }, [node("h4", { text: `${index + 1}. ${step.title}` }), node("p", { text: step.description }), node("p", { text: `${autopsyLabel(step.status)} · ${autopsyLabel(step.role)}${step.required ? " · إلزامية" : ""}${step.approval_required ? " · اعتماد المدير" : ""}` })]);
      if (autopsy.current.can_update && autopsy.current.status !== "closed") row.append(button("تحديث الخطوة", () => {
        let dialog;
        const form = autopsyForm({ status: { required: true, choices: ["pending", "in_progress", "completed", "failed", "not_applicable"] }, evidence_id: { evidence: true }, notes: { max: 2000 } }, async (payload) => {
          await api(`/api/cases/${caseId}/procedures/${record.id}/steps/${index + 1}`, { method: "PATCH", body: { ...payload, version: record.version } });
          dialog.close();
          await autopsyCase(caseId);
        }, step);
        dialog = autopsyModal(step.title, form);
      }));
      card.append(row);
    });
    body.append(card);
  }
  return panel("كتيب استجابة القضية", body, true);
};

window.SOCifyAutopsy.procedureLibrary = autopsyProcedureLibrary;
