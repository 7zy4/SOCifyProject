"use strict";

window.SOCifyV4 = (() => {
  const t = value => SOCifyLocale.text(value);
  autopsyLabels.related_case_id = SOCifyLocale.text("القضية المرتبطة");
  let selection = {case_ids: [], items: [], required: true};
  async function initialize() {
    selection = await api("/api/investigation-selection");
    const current = Number(document.querySelector('meta[name="case-id"]')?.content || new URLSearchParams(location.search).get("case_id"));
    const active = selection.items.find(item => item.id === current) || selection.items[0];
    const header = document.querySelector("[data-investigation-context]");
    if (header) {
      header.replaceChildren(node("span", {class:"scope-caption",text:t("نطاق التحقيق")}));
      if (selection.items.length) {
        const control = node("select", {"aria-label":t("القضية النشطة")}, selection.items.map(item => node("option", {value:item.id,selected:item.id === active.id,text:`${item.reference} · ${item.title}`})));
        control.addEventListener("change", () => location.assign(`/cases/${control.value}`));
        header.append(control);
        window.SOCifyWorkbench.bindCase(active);
      } else header.append(node("span", {text:t("لم تُحدد قضية بعد")}));
    }
    const switcher = document.querySelector("[data-account-switch]");
    if (switcher && !switcher.dataset.bound) {
      switcher.dataset.bound = "true";
      switcher.addEventListener("click", async () => {
        try {
          const data = await api("/api/demo/accounts");
          if (!data.enabled) {
            const form = document.querySelector(".user-menu form");
            form.requestSubmit();
            return;
          }
          const content = node("div", {class:"panel-body account-options"}, node("p", {class:"notice",text:t("بيئة تجربة معزولة · تبديل الحساب يمسح نطاق التحقيق")}));
          for (const user of data.items) content.append(button(`${user.name} · ${autopsyLabel(user.role)}`, async () => {
            try { await api("/api/demo/switch", {method:"POST",body:{user_id:user.id}}); location.assign("/cases"); }
            catch (error) { handleError(error); }
          }));
          content.append(button(t("خروج"), () => document.querySelector(".user-menu form").requestSubmit()));
          autopsyModal(t("تبديل الحساب"),content);
        } catch (error) { handleError(error); }
      });
    }
  }
  function approvalLabel(value) {
    return t({pending:"بانتظار اعتماد المدير",approved:"معتمدة",rejected:"مرفوضة"}[value] || "معتمدة");
  }
  async function select(ids) {
    await api("/api/investigation-selection", {method:"POST",body:{case_ids:ids}});
    location.assign(`/cases/${ids[0]}`);
  }
  function intake(current) {
    if (current.approval_enforced === false && !current.selection_required) return false;
    const review = current.approval || {state:"approved"};
    if (review.state === "approved" && !current.selection_required) return false;
    const root = node("div", {class:"intake-view"}, pageHead(current.title,approvalLabel(review.state)));
    root.append(panel(t("طلب القضية"),node("div", {class:"panel-body"}, [node("bdi", {text:current.reference}),node("p", {text:current.context?.reason||""}),node("p", {text:current.context?.objective||""}),review.reason?node("p", {text:review.reason}):null]),true));
    if (review.state === "pending" && current.can_review_request) {
      const reason = node("textarea", {name:"review_reason",required:true,minlength:3,maxlength:1000});
      const decision = node("select", {name:"decision"}, [node("option", {value:"approved",text:t("اعتماد القضية")}),node("option", {value:"rejected",text:t("رفض الطلب")})]);
      const submit = node("button", {type:"submit",class:"button primary",text:t("حفظ قرار المدير")});
      const form = node("form", {class:"panel-body form-grid"}, [field(t("القرار"),decision),field(t("سبب القرار"),reason),submit]);
      form.addEventListener("submit", async event => {
        event.preventDefault(); submit.disabled = true;
        try { await api(`/api/cases/${current.id}/approval`, {method:"POST",body:{decision:decision.value,version:review.version,reason:reason.value}}); location.reload(); }
        catch (error) { handleError(error); submit.disabled = false; }
      });
      root.append(panel(t("مراجعة المدير"),form,true));
    } else if (review.state === "approved") root.append(button(t("بدء التحقيق في هذه القضية"), () => select([current.id]).catch(handleError), "primary"));
    else root.append(node("p", {class:"notice",text:t("لا يمكن بدء التحقيق قبل اعتماد المدير")}));
    finish(root); return true;
  }
  function chooser(items) {
    const chosen = new Set(selection.case_ids);
    const body = node("div", {class:"case-selection-grid"});
    const status = node("p", {role:"status",text:t("اختر قضية واحدة أو قضيتين مرتبطتين ثم ابدأ التحقيق")});
    const submit = button(t("بدء التحقيق بالنطاق المحدد"), async () => {
      submit.disabled = true;
      try { await select([...chosen]); }
      catch (error) { handleError(error); submit.disabled = chosen.size === 0; }
    }, "primary");
    const update = () => {
      submit.disabled = chosen.size === 0;
      status.replaceChildren(t("القضايا المختارة") + ": ",node("bdi", {text:`${chosen.size} / 2`})," · ",t("اختر قضية واحدة أو قضيتين مرتبطتين ثم ابدأ التحقيق"));
      body.querySelectorAll("input[type=checkbox]").forEach(input => {
        const item = items.find(value => value.id === Number(input.value));
        const unrelated = chosen.size === 1 && !item?.related_case_ids?.includes([...chosen][0]);
        input.disabled = !!input.closest(".case-selection-locked") || !input.checked && (chosen.size === 2 || unrelated);
      });
    };
    for (const item of items) {
      const input = node("input", {type:"checkbox",value:item.id,checked:chosen.has(item.id),"aria-label":item.title});
      input.addEventListener("change", () => { if (input.checked) chosen.add(item.id); else chosen.delete(item.id); update(); });
      const label = node("label", {class:"case-selection-label"}, [input,node("span", {}, [node("bdi", {text:item.reference}),node("strong", {text:item.title}),node("small", {text:approvalLabel(item.approval?.state)})])]);
      const card = node("article", {class:"case-selection-card"},[label,node("div", {class:"case-card-facts"},[autopsyBadge(item.status),autopsyBadge(item.severity),node("span", {text:item.assignee_name||"—"})]),linkedButton(t("فتح القضية"),`/cases/${item.id}`)]);
      if (item.approval?.state !== "approved") { input.disabled = true; card.classList.add("case-selection-locked"); }
      body.append(card);
    }
    update();
    // Pending requests remain disabled even when the two-case limit changes.
    for (const input of body.querySelectorAll(".case-selection-locked input")) input.disabled = true;
    return panel(t("مساحة التحقيق"),node("div", {class:"panel-body"},[status,body,submit]),true);
  }
  function relationship(current) {
    if (!current.can_review_request) return null;
    const form = autopsyForm({related_case_id:{required:true,integer:true,min:1,max:Number.MAX_SAFE_INTEGER},reason:{required:true,max:1000}}, async payload => {
      await api(`/api/cases/${current.id}/relationships`, {method:"POST",body:{...payload,related_case_id:Number(payload.related_case_id)}});
      showMessage(t("تم ربط القضيتين؛ يمكنك اختيارهما من صفحة القضايا"));
    });
    return autopsyEditPanel(t("ربط قضية ذات صلة"),node("div", {class:"panel-body"},[node("p", {text:t("أدخل رقم القضية الداخلي وسبب الربط؛ تبقى أدلة كل قضية مستقلة")}),form]));
  }
  return {initialize,intake,chooser,approvalLabel,relationship,get selection(){return selection;}};
})();
