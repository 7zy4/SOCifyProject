"use strict";

window.SOCifyAutopsy.team = async () => {
  begin("team");
  const data = await api("/api/team");
  autopsy.team = data;
  const root = node("div", {}, pageHead(SOCifyLocale.text("فريق التحقيق الداخلي"), SOCifyLocale.text("دعوات مرتبطة بالبريد، وصلاحيات الأدوار، وإسناد دفعات السجلات داخل قضاياها.")));
  root.append(panel(SOCifyLocale.text("أعضاء الفريق"), table([{ label: SOCifyLocale.text("الاسم"), value: "name" }, { label: SOCifyLocale.text("البريد"), value: "email" }, { label: SOCifyLocale.text("الدور"), value: (row) => autopsyLabel(row.role) }, { label: SOCifyLocale.text("الحالة"), value: (row) => row.is_active ? SOCifyLocale.text("نشط") : SOCifyLocale.text("موقوف") }, { label: SOCifyLocale.text("إدارة"), value: (row) => data.can_manage && row.is_active && row.role !== "admin" ? button(SOCifyLocale.text("إدارة العضو"), () => {
    const roleForm = autopsyForm({ role: { required: true, choices: data.roles.map((role) => role.role) } }, async (body) => { await api(`/api/team/members/${row.id}`, { method: "PATCH", body }); dialog.close(); await window.SOCifyAutopsy.team(); }, row);
    const handoff = autopsyForm({ handoff_to: { user: true }, reason: { required: true, max: 1000 } }, async (body) => { await api(`/api/team/members/${row.id}/deactivate`, { method: "POST", body }); dialog.close(); await window.SOCifyAutopsy.team(); });
    const dialog = autopsyModal(SOCifyLocale.template`إدارة ${row.name}`, node("div", {}, [panel(SOCifyLocale.text("تغيير الدور وسحب الجلسات الحالية"), roleForm, true), panel(SOCifyLocale.text("إيقاف الوصول وتسليم المسؤوليات"), handoff, true)]));
  }) : "—" }], data.members), true));
  if (data.can_manage) {
    root.append(panel(SOCifyLocale.text("دعوة عضو جديد"), node("div", { class: "panel-body" }, autopsyForm({ email: { required: true, max: 254 }, role: { required: true, choices: data.roles.map((role) => role.role) } }, async (body) => {
      const invitation = await api("/api/team/invitations", { method: "POST", body });
      const url = new URL("/register", window.location.origin);
      url.hash = new URLSearchParams({ invitation_token: invitation.invitation_token }).toString();
      autopsyModal(SOCifyLocale.text("رابط دعوة سري؛ سلّمه داخليًا لصاحب البريد المحدد"), node("div", {}, [node("p", { text: SOCifyLocale.template`ينتهي: ${formatTime(invitation.expires_at)}` }), field(SOCifyLocale.text("رابط التسجيل بالدعوة"), node("input", { readonly: true, value: url.toString(), dir: "ltr" }))]));
    })), true));
    for (const role of data.roles.filter((item) => item.role !== "soc_manager")) {
      const choices = node("div", { class: "form-grid" });
      const inputs = role.available.map((value) => {
        const input = node("input", { type: "checkbox", checked: role.permissions.includes(value), value });
        choices.append(field(value, input));
        return input;
      });
      root.append(panel(SOCifyLocale.template`صلاحيات ${autopsyLabel(role.role)}`, node("div", { class: "panel-body" }, [choices, button(SOCifyLocale.text("حفظ حدود الدور"), async () => { try { await api(`/api/team/roles/${role.role}`, { method: "PUT", body: { permissions: inputs.filter((input) => input.checked).map((input) => input.value) } }); await window.SOCifyAutopsy.team(); } catch (error) { handleError(error); } })])));
    }
    const cases = (await api("/api/cases?page_size=100")).items.filter((item) => item.status !== "closed");
    const selected = autopsyChoice("case_id", cases.map((item) => ({ value: item.id, label: `${item.reference} · ${item.title}` })), "", true);
    const batchHolder = node("div");
    let batchChoice = null;
    selected.input.addEventListener("change", async () => {
      try { const caseId = selected.input.autopsyValue(); const imports = await api(`/api/cases/${caseId}/imports`); batchChoice = autopsyChoice("job_id", imports.items.filter((job) => ["completed", "completed_with_errors"].includes(job.status)).map((job) => ({ value: job.id, label: SOCifyLocale.template`${job.original_filename || job.filename} · ${job.accepted} سجل` })), "", true); batchHolder.replaceChildren(field(SOCifyLocale.text("دفعة من القضية المحددة"), batchChoice.control)); }
      catch (error) { batchChoice = null; batchHolder.replaceChildren(node("p", { text: error.message })); }
    });
    const form = autopsyForm({ assignee: { required: true, user: true }, instructions: { required: true, max: 2000 } }, async (body) => {
      if (!batchChoice) throw new Error(SOCifyLocale.text("اختر قضية ثم دفعة مكتملة منها"));
      await api("/api/team/assignments", { method: "POST", body: { ...body, case_id: selected.input.autopsyValue(), job_id: batchChoice.input.autopsyValue() } });
      await window.SOCifyAutopsy.team();
    });
    form.prepend(field(SOCifyLocale.text("القضية"), selected.control), batchHolder);
    root.append(panel(SOCifyLocale.text("إسناد دفعة سجلات"), node("div", { class: "panel-body" }, form), true));
  }
  root.append(panel(SOCifyLocale.text("دفعات الفريق"), table([{ label: SOCifyLocale.text("القضية"), value: (row) => linkedButton(row.case_title, `/cases/${row.case_id}`) }, { label: SOCifyLocale.text("المسؤول"), value: "assignee_name" }, { label: SOCifyLocale.text("التعليمات"), value: "instructions" }, { label: SOCifyLocale.text("الحالة"), value: "task_status" }], data.assignments), true));
  finish(root);
};
