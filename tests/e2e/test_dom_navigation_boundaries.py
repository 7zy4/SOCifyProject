"""Adversarial component checks in Chromium; these are not user-study participants."""

import pytest

from tests.e2e.test_review_workflow import review_session


@pytest.mark.e2e
def test_modified_select_values_cannot_change_navigation_or_download_target(app):
    with review_session(app, "en", "security-dom-paths") as (j, _manager, result):
        evidence = j.page.evaluate(
            """async caseId => {
              const originalApi = api, originalReports = autopsy.current.reports;
              const report = {id:71,case_version:autopsy.current.version,created_at:'2026-11-04T00:00:00Z',
                created_by:state.user.id,state:'draft',sha256:'a'.repeat(64),job:{state:'succeeded'},
                formats:['pdf','json','javascript:alert(1)','../../private','<img src=x onerror=window.__injected=1>']};
              const hostile=['javascript:alert(1)','//outside.invalid','../../private','9007199254740993','999999999'];
              let root;
              try {
                api = async (path,options) => {
                  if(path === '/api/investigation-selection') return {required:true,case_ids:[caseId],items:[{id:caseId,reference:'CASE',title:'Retained case'}]};
                  if(path === `/api/cases/${caseId}/reports/71`) return report;
                  return originalApi(path,options);
                };
                await SOCifyWorkspace.initialize();
                const active=document.querySelector('[data-investigation-context] select');
                const before=location.href;
                for(const value of hostile) {
                  active.add(new Option(value,value)); active.value=value;
                  active.dispatchEvent(new Event('change',{bubbles:true}));
                  if(location.href !== before) throw new Error('Unsafe case navigation');
                }
                autopsy.current.reports=[{id:71}];
                root=await SOCifyAutopsy.reports(caseId); workspace.append(root);
                const select=root.querySelector('.report-revision select');
                const download=select.closest('.report-downloads').querySelector('a');
                const originalHref=download.getAttribute('href');
                const values=[...select.options].map(option=>option.value);
                for(const value of hostile) {
                  select.add(new Option(value,value)); select.value=value;
                  select.dispatchEvent(new Event('change',{bubbles:true}));
                  if(download.getAttribute('href') !== originalHref) throw new Error('Unsafe download navigation');
                }
                select.value='json'; select.dispatchEvent(new Event('change',{bubbles:true}));
                const validHref=download.getAttribute('href');
                const links=[...root.querySelectorAll('.report-revision a')].map(a=>a.getAttribute('href'));
                if(window.__injected) throw new Error('Injected content executed');
                root.remove(); root=null;
                report.formats=['../../private','javascript:alert(1)'];
                root=await SOCifyAutopsy.reports(caseId); workspace.append(root);
                const invalidControls=root.querySelectorAll('.report-revision select,.report-revision a').length;
                return {values,validHref,links,invalidControls,caseUrl:location.href,originalUrl:before};
              } finally { root?.remove(); api=originalApi; autopsy.current.reports=originalReports; }
            }""",
            j.case_id,
        )
        assert evidence["values"] == ["pdf", "json"]
        path = f"/api/cases/{j.case_id}/reports/71/files/"
        assert evidence["validHref"] == path + "json"
        assert set(evidence["links"]) == {path + "pdf", path + "json"}
        assert evidence["invalidControls"] == 0
        assert evidence["caseUrl"] == evidence["originalUrl"]
        result["kind"] = "adversarial DOM component check with controlled response fixture"
        result["outcomes"] = evidence
