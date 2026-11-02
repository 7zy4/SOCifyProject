import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import review_session


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_manager_can_find_and_apply_readable_role_permissions(app, language):
    with review_session(app, language, "role-permission-change") as (analyst, manager, result):
        manager.login("manager@socify.local")
        manager.nav("الفريق")
        invite = manager.page.locator("section.panel").filter(has=manager.page.get_by_role("heading", name=manager.text("دعوة عضو جديد"), exact=True))
        expect(invite.get_by_label(manager.text("الدور") + " *", exact=True)).to_be_visible()
        role = manager.page.locator('.team-role-policy[data-role="analyst"]')
        expect(role.locator("input[type=checkbox]").first).not_to_be_visible()
        role.locator("summary").click()
        create = role.get_by_label(manager.text("إنشاء القضايا"), exact=True)
        expect(create).to_be_checked()
        assert "cases.create" not in role.inner_text()
        create.uncheck()
        manager.click("button", "حفظ حدود الدور", role)
        analyst.nav("إدارة القضايا")
        expect(analyst.page.get_by_role("button", name=analyst.text("إنشاء قضية"), exact=True)).to_have_count(0)
        role.locator("summary").click()
        expect(create).not_to_be_checked()
        create.check()
        manager.click("button", "حفظ حدود الدور", role)
        analyst.page.reload()
        analyst.settle()
        analyst.create_case()
        expect(analyst.page.get_by_role("heading", name="Authorized maintenance investigation", exact=True).first).to_be_visible()
        role.locator("summary").click()
        for width in (390, 768, 1440):
            manager.page.set_viewport_size({"width": width, "height": 1000})
            assert manager.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
        assert_accessible(manager.page)
        result["outcomes"] = [
            "role controls collapsed until selected",
            "permission labels readable in selected language",
            "revoked create permission removes creation action",
            "restored permission allows actual case creation",
        ]
