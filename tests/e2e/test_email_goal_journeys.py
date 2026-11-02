"""Read and investigate uploaded mail through the actual analyst interface."""

from email.message import EmailMessage
from email.policy import SMTP

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import ARTIFACTS, review_session


def message(subject="Retained service notice", *, mismatch=False, attachment=False, html=False):
    mail = EmailMessage(policy=SMTP)
    mail["From"] = "Service Desk <notice@example.test>"
    mail["To"] = "reviewer@internal.test"
    mail["Subject"] = subject
    mail["Date"] = "Tue, 03 Nov 2026 08:00:00 +0300"
    if mismatch:
        mail["Reply-To"] = "response@another.test"
        mail["Authentication-Results"] = "untrusted.example; spf=fail"
    if html:
        mail.set_content(
            '<html><style>hidden style marker</style><script>window.mailExecuted=true</script><p>Retained visible content</p><a href="https://example.test/review">Review</a><img src="https://example.test/pixel"></html>',
            subtype="html",
        )
    else:
        mail.set_content("The scheduled service review is complete. No action is requested.")
    if attachment:
        mail.add_attachment(b"MZ" + b"\x00" * 70, maintype="application", subtype="pdf", filename="statement.pdf")
        mail.set_boundary("socify-retained-mail-boundary")
    return mail.as_bytes()


def upload(j, content, filename="retained.eml"):
    j.page.locator("input[name=email][type=file]").set_input_files({"name": filename, "mimeType": "message/rfc822", "buffer": content})
    j.click("button", "فحص البريد ومرفقاته بضغطة زر")


def reviews(j):
    return j.page.evaluate("id => api(`/api/cases/${id}/email-reviews`)", j.case_id)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "mail-readable-summary",
        "mail-attachment-mismatch",
        "mail-header-language",
        "mail-repeated-upload",
        "mail-invalid-recovery",
        "mail-html-no-execution",
        "mail-body-truncated",
        "mail-same-name-new-content",
        "mail-case-isolation",
        "mail-history-pagination",
        "mail-upload-from-history",
        "mail-repeat-from-history",
        "mail-oversized-recovery",
    ],
)
def test_mail_findings_are_readable_and_recoverable(app, language, scenario):
    with review_session(app, language, scenario) as (j, _manager, result):
        j.nav("أمن البريد الإلكتروني")
        if scenario in {"mail-invalid-recovery", "mail-oversized-recovery"}:
            upload(j, b"X" * (5 * 1024 * 1024 + 1) if scenario == "mail-oversized-recovery" else b"This is not an email message")
            assert not reviews(j)["items"]
            expect(j.page.locator(".email-review form [role=alert]")).to_be_visible()
            upload(j, message())
            expect(j.page.get_by_role("heading", name="Retained service notice", exact=True)).to_be_visible()
            expect(j.page.locator(".email-review form [role=alert]")).to_be_hidden()
        elif scenario == "mail-html-no-execution":
            external = []
            j.page.on("request", lambda request: external.append(request.url) if request.url.startswith("https://example.test/") else None)
            upload(j, message(html=True))
            expect(j.page.locator(".email-body")).to_contain_text("Retained visible content")
            expect(j.page.locator(".email-body")).not_to_contain_text("hidden style marker")
            assert j.page.locator(".email-review img,.email-review iframe,.email-review script").count() == 0
            assert j.page.evaluate("typeof window.mailExecuted === 'undefined'")
            j.page.locator("summary").filter(has_text=j.text("الروابط المرصودة")).click()
            expect(j.page.locator(".email-links")).to_contain_text("https://example.test/review")
            assert j.page.locator(".email-links a").count() == 0 and external == []
        elif scenario == "mail-body-truncated":
            content = message().replace(b"The scheduled service review is complete. No action is requested.", b"Retained review text " * 1100)
            upload(j, content)
            expect(j.page.locator(".email-result")).to_contain_text(j.text("النص المعروض مختصر؛ الأصل محفوظ في الحجر."))
            assert reviews(j)["items"][0]["payload"]["body_truncated"] is True
            assert len(reviews(j)["items"][0]["payload"]["body"]) == 16384
        elif scenario in {"mail-same-name-new-content", "mail-case-isolation"}:
            upload(j, message())
            first = reviews(j)["items"][0]
            first_case = j.case_id
            if scenario == "mail-case-isolation":
                j.nav("إدارة القضايا")
                j.create_case()
                j.nav("أمن البريد الإلكتروني")
                expect(j.page.get_by_role("heading", name="Retained service notice", exact=True)).to_have_count(0)
                upload(j, message())
                current = reviews(j)["items"][0]
                original = j.page.evaluate("id => api(`/api/cases/${id}/email-reviews`)", first_case)["items"]
                assert current["id"] != first["id"] and current["payload"]["sample_id"] != first["payload"]["sample_id"]
                assert current["payload"]["sha256"] == first["payload"]["sha256"] and original == [first]
            else:
                upload(j, message("Updated service notice"))
                assert len(reviews(j)["items"]) == 2
                assert reviews(j)["items"][0]["payload"]["sha256"] != first["payload"]["sha256"]
                expect(j.page.get_by_role("heading", name="Updated service notice", exact=True)).to_be_visible()
        elif scenario in {"mail-history-pagination", "mail-upload-from-history", "mail-repeat-from-history"}:
            for index in range(11):
                upload(j, message(f"Retained message {index:02d}"), f"review-{index:02d}.eml")
            result["setup_only_messages"] = 10
            expect(j.page.get_by_role("heading", name="Retained message 00", exact=True)).to_have_count(0)
            j.page.set_viewport_size({"width": 390, "height": 1000})
            result["interaction_viewport"] = 390
            j.click("link", "رسائل أقدم")
            expect(j.page.get_by_role("heading", name="Retained message 00", exact=True)).to_be_visible()
            j.page.reload()
            j.settle()
            expect(j.page.get_by_role("heading", name="Retained message 00", exact=True)).to_be_visible()
            if scenario == "mail-upload-from-history":
                upload(j, message("Newly retained message"), "newly-retained.eml")
                expect(j.page.get_by_role("heading", name="Newly retained message", exact=True)).to_be_visible()
                assert "email_before=" not in j.page.url
                assert j.page.locator("section[id^=email-review-]:focus").count() == 1
                heading = j.page.get_by_role("heading", name="Newly retained message", exact=True).bounding_box()
                header = j.page.locator(".topbar").bounding_box()
                assert heading["y"] >= header["y"] + header["height"]
            elif scenario == "mail-repeat-from-history":
                retained = reviews(j)["items"]
                version = j.state()["version"]
                upload(j, message("Retained message 10"), "renamed-review.eml")
                expect(j.page.get_by_role("heading", name="Retained message 10", exact=True)).to_be_visible()
                assert reviews(j)["items"] == retained and j.state()["version"] == version
                assert j.page.locator("section[id^=email-review-]:focus").count() == 1
            else:
                j.click("link", "الأحدث")
                expect(j.page.get_by_role("heading", name="Retained message 10", exact=True)).to_be_visible()
        else:
            content = message(mismatch=scenario == "mail-header-language", attachment=scenario == "mail-attachment-mismatch")
            upload(j, content)
            expect(j.page.get_by_role("heading", name="Retained service notice", exact=True)).to_be_visible()
            if scenario == "mail-readable-summary":
                expect(j.page.locator(".email-review")).not_to_contain_text("low_signal_static_only")
                expect(j.page.locator(".email-review")).to_contain_text(j.text("لا مؤشرات بارزة في الفحص الساكن"))
            elif scenario == "mail-attachment-mismatch":
                expect(j.page.get_by_role("cell", name="statement.pdf", exact=True)).to_be_visible()
                expect(j.page.locator(".email-review")).not_to_contain_text("dos_executable")
                expect(j.page.locator(".email-review")).to_contain_text(j.text("تعارض امتداد"))
                assert reviews(j)["items"][0]["payload"]["attachments"][0]["triage"]["extension_mismatch"]
            elif scenario == "mail-header-language":
                expect(j.page.locator(".email-review")).to_contain_text(j.text("نطاق الرد يختلف عن نطاق المرسل"))
                if language == "en":
                    expect(j.page.locator(".email-review")).not_to_contain_text("رؤوس المصادقة تسجل")
                    expect(j.page.get_by_role("cell", name="Sender", exact=True)).to_be_visible()
            elif scenario == "mail-repeated-upload":
                before = reviews(j)["items"]
                version = j.state()["version"]
                upload(j, content, "renamed-retained.eml")
                assert reviews(j)["items"] == before, "Identical mail should not produce another identical review"
                assert j.state()["version"] == version
        assert_accessible(j.page)
        for width in (390, 1440):
            j.page.set_viewport_size({"width": width, "height": 1000})
            j.page.evaluate("window.scrollTo(0, 0)")
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            j.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-{width}.png"), full_page=True)
        result["outcomes"] = [scenario, "retained message parsed through UI", "independent read-only review verification"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["mail-case-analysis-entry", "mail-subjectless-repeat"])
def test_mail_investigation_entry_and_untitled_identity(app, language, scenario):
    with review_session(app, language, scenario) as (j, _manager, result):
        if scenario == "mail-case-analysis-entry":
            j.nav("تحليل الأدلة")
            j.page.get_by_role("link", name="الملفات والبريد" if language == "ar" else "Files & email", exact=True).click()
            j.settle()
            j.page.locator("input[name=eml_file]").set_input_files({"name": "review.eml", "mimeType": "message/rfc822", "buffer": message(attachment=True)})
            j.page.get_by_role("button", name="فحص البريد" if language == "ar" else "Inspect email", exact=True).click()
            dialog = j.page.get_by_role("dialog")
            expect(dialog.locator(".email-result")).to_be_visible()
            expect(dialog).not_to_contain_text("dos_executable")
            expect(dialog).to_contain_text(j.text("تعارض امتداد"))
            assert_accessible(j.page)
            j.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-dialog.png"), full_page=True)
            j.click("button", "إغلاق", dialog)
            expect(j.page.locator(".record-card .email-result")).to_be_visible()
            expect(j.page.locator(".record-card")).not_to_contain_text("dos_executable")
            expect(j.page.locator(".record-card")).not_to_contain_text("email_risk_score")
            j.page.evaluate("window.scrollTo(0, 0)")
            j.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-record.png"), full_page=True)
            j.nav("أمن البريد الإلكتروني")
            expect(j.page.get_by_role("heading", name="Retained service notice", exact=True)).to_be_visible()
            assert len(reviews(j)["items"]) == 1
        else:
            j.nav("أمن البريد الإلكتروني")
            content = message().replace(b"Subject: Retained service notice\r\n", b"")
            upload(j, content, "untitled.eml")
            before = reviews(j)["items"]
            version = j.state()["version"]
            upload(j, content, "renamed-untitled.eml")
            assert reviews(j)["items"] == before and j.state()["version"] == version
            expect(j.page.get_by_role("heading", name="untitled.eml", exact=True)).to_be_visible()
        assert_accessible(j.page)
        for width in (390, 1440):
            j.page.set_viewport_size({"width": width, "height": 1000})
            j.page.evaluate("window.scrollTo(0, 0)")
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            j.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-{width}.png"), full_page=True)
        result["outcomes"] = [scenario, "same retained result across entry points or filename changes"]
