"use strict";

window.SOCifyAutopsy.team = async () => {
  begin("team");
  const data = await api("/api/team");
  autopsy.team = data;
  const root = node("div", {}, pageHead("فريق التحقيق الداخلي", "دعوات مرتبطة بالبريد، وصلاحيات الأدوار، وإسناد دفعات السجلات داخل قضاياها."));
  root.append(panel("أعضاء الفريق", table([{ label: "الاسم", value: "name" }, { label: "البريد", value: "email" }, { label: "الدور", value: (row) => autopsyLabel(row.role) }, { label: "الحالة", value: (row) => row.is_active ? "نشط" : "موقوف" }, { label: "إدارة", value: (row) => data.can_manage && row.is_active && row.role !== "admin" ? button("إدارة العضو", () => {
    const roleForm = autopsyForm({ role: { required: true, choices: data.roles.map((role) => role.role) } }, async (body) => { await api(`/api/team/members/${row.id}`, { method: "PATCH", body }); dialog.close(); await window.SOCifyAutopsy.team(); }, row);
    const handoff = autopsyForm({ handoff_to: { user: true }, reason: { required: true, max: 1000 } }, async (body) => { await api(`/api/team/members/${row.id}/deactivate`, { method: "POST", body }); dialog.close(); await window.SOCifyAutopsy.team(); });
    const dialog = autopsyModal(`إدارة ${row.name}`, node("div", {}, [panel("تغيير الدور وسحب الجلسات الحالية", roleForm, true), panel("إيقاف الوصول وتسليم المسؤوليات", handoff, true)]));
  }) : "—" }], data.members), true));
  if (data.can_manage) {
    root.append(panel("دعوة عضو جديد", node("div", { class: "panel-body" }, autopsyForm({ email: { required: true, max: 254 }, role: { required: true, choices: data.roles.map((role) => role.role) } }, async (body) => {
      const invitation = await api("/api/team/invitations", { method: "POST", body });
      const url = new URL("/register", window.location.origin);
      url.hash = new URLSearchParams({ invitation_token: invitation.invitation_token }).toString();
      autopsyModal("رابط دعوة سري؛ سلّمه داخليًا لصاحب البريد المحدد", node("div", {}, [node("p", { text: `ينتهي: ${formatTime(invitation.expires_at)}` }), field("رابط التسجيل بالدعوة", node("input", { readonly: true, value: url.toString(), dir: "ltr" }))]));
    })), true));
    for (const role of data.roles.filter((item) => item.role !== "soc_manager")) {
      const choices = node("div", { class: "form-grid" });
      const inputs = role.available.map((value) => {
        const input = node("input", { type: "checkbox", checked: role.permissions.includes(value), value });
        choices.append(field(value, input));
        return input;
      });
      root.append(panel(`صلاحيات ${autopsyLabel(role.role)}`, node("div", { class: "panel-body" }, [choices, button("حفظ حدود الدور", async () => { try { await api(`/api/team/roles/${role.role}`, { method: "PUT", body: { permissions: inputs.filter((input) => input.checked).map((input) => input.value) } }); await window.SOCifyAutopsy.team(); } catch (error) { handleError(error); } })])));
    }
    const cases = (await api("/api/cases?page_size=100")).items.filter((item) => item.status !== "closed");
    const selected = autopsyChoice("case_id", cases.map((item) => ({ value: item.id, label: `${item.reference} · ${item.title}` })), "", true);
    const batchHolder = node("div");
    let batchChoice = null;
    selected.input.addEventListener("change", async () => {
      try { const caseId = selected.input.autopsyValue(); const imports = await api(`/api/cases/${caseId}/imports`); batchChoice = autopsyChoice("job_id", imports.items.filter((job) => ["completed", "completed_with_errors"].includes(job.status)).map((job) => ({ value: job.id, label: `${job.original_filename || job.filename} · ${job.accepted} سجل` })), "", true); batchHolder.replaceChildren(field("دفعة من القضية المحددة", batchChoice.control)); }
      catch (error) { batchChoice = null; batchHolder.replaceChildren(node("p", { text: error.message })); }
    });
    const form = autopsyForm({ assignee: { required: true, user: true }, instructions: { required: true, max: 2000 } }, async (body) => {
      if (!batchChoice) throw new Error("اختر قضية ثم دفعة مكتملة منها");
      await api("/api/team/assignments", { method: "POST", body: { ...body, case_id: selected.input.autopsyValue(), job_id: batchChoice.input.autopsyValue() } });
      await window.SOCifyAutopsy.team();
    });
    form.prepend(field("القضية", selected.control), batchHolder);
    root.append(panel("إسناد دفعة سجلات", node("div", { class: "panel-body" }, form), true));
  }
  root.append(panel("دفعات الفريق", table([{ label: "القضية", value: (row) => linkedButton(row.case_title, `/cases/${row.case_id}`) }, { label: "المسؤول", value: "assignee_name" }, { label: "التعليمات", value: "instructions" }, { label: "الحالة", value: "task_status" }], data.assignments), true));
  finish(root);
};
