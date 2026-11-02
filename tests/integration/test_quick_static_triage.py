import io
import struct
import zipfile
from email.message import EmailMessage


def _minimal_pe_bytes(extra_ascii: bytes = b"") -> bytes:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 64)
    pe_hdr = b"PE\x00\x00" + struct.pack("<HHI", 0x8664, 3, 1700000000) + b"\x00" * 16
    return bytes(dos) + pe_hdr + b"\x00" * 32 + extra_ascii


def test_one_click_disguised_pe_and_extension_mismatch_triage(app, client, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("analyst")
    case_id = client.post("/api/cases", json={"title": "Suspicious attachment triage"}).json["id"]

    pe_payload = _minimal_pe_bytes(b"CreateRemoteThread VirtualAllocEx http://198.51.100.44/stage2.bin")
    resp = client.post(
        f"/api/cases/{case_id}/quick-file-triage",
        data={"file": (io.BytesIO(pe_payload), "invoice.pdf")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201, resp.json
    triage = resp.json["triage"]
    assert triage["execution"] == "never executed"
    assert triage["detected_magic"] == "pe_executable"
    assert triage["extension_mismatch"] is True
    assert triage["verdict"] == "high_risk"
    assert triage["risk_score"] >= 70
    assert "http://198.51.100.44/stage2.bin" in triage["extracted_urls"]
    assert "198.51.100.44" in triage["extracted_ips"]

    # Sample is quarantined and can also be re-triaged by sample_id in 1 click
    sample_id = resp.json["sample_id"]
    re_triage = client.post(f"/api/cases/{case_id}/samples/{sample_id}/quick-triage", json={})
    assert re_triage.status_code in (200, 201), re_triage.json
    assert re_triage.json["triage"]["sha256"] == triage["sha256"]


def test_ooxml_vba_macro_pdf_active_content_and_html_smuggling_triage(app, client, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("analyst")
    case_id = client.post("/api/cases", json={"title": "Document & HTML static triage"}).json["id"]

    # 1. OOXML document containing word/vbaProject.bin with AutoOpen + WScript.Shell
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        archive.writestr("word/document.xml", "<w:document>Quarterly Invoice</w:document>")
        archive.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0AutoOpen WScript.Shell powershell.exe -enc AAA")
    macro_resp = client.post(
        f"/api/cases/{case_id}/quick-file-triage",
        data={"file": (io.BytesIO(buf.getvalue()), "quarterly_budget.docm")},
        content_type="multipart/form-data",
    )
    assert macro_resp.status_code == 201, macro_resp.json
    macro_triage = macro_resp.json["triage"]
    assert macro_triage["verdict"] == "high_risk"
    assert any(flag["code"] == "vba_macro_detected" for flag in macro_triage["flags"])

    # 2. PDF with /OpenAction and /JavaScript
    pdf_bytes = b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.launchURL('https://evil.example')) >> >> endobj\n%%EOF"
    pdf_resp = client.post(
        f"/api/cases/{case_id}/quick-file-triage",
        data={"file": (io.BytesIO(pdf_bytes), "wire_transfer.pdf")},
        content_type="multipart/form-data",
    )
    assert pdf_resp.status_code == 201, pdf_resp.json
    pdf_triage = pdf_resp.json["triage"]
    assert pdf_triage["verdict"] == "high_risk"
    assert any(flag["code"] == "pdf_active_content" for flag in pdf_triage["flags"])

    # 3. HTML smuggling page with high-entropy 256-byte window + atob/Blob
    high_entropy_blob = bytes(range(256)).hex()
    html_bytes = (
        f"<html><body><script>const raw = atob('{high_entropy_blob}');const b = new Blob([raw], {{type:'application/octet-stream'}});</script></body></html>"
    ).encode()
    html_resp = client.post(
        f"/api/cases/{case_id}/quick-file-triage",
        data={"file": (io.BytesIO(html_bytes), "portal_login.html")},
        content_type="multipart/form-data",
    )
    assert html_resp.status_code == 201, html_resp.json
    html_triage = html_resp.json["triage"]
    assert html_triage["verdict"] in ("suspicious", "high_risk")
    assert html_triage["max_window_entropy_256b"] >= 3.5
    assert any(flag["code"] == "html_smuggling_indicator" for flag in html_triage["flags"])


def test_one_click_email_and_attachment_static_triage(app, client, login_as, database):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("analyst")
    case_id = client.post("/api/cases", json={"title": "Phishing EML 1-click triage"}).json["id"]

    msg = EmailMessage()
    msg["From"] = "CFO Office <cfo@corp.example>"
    msg["To"] = "ap-clerk@corp.example"
    msg["Reply-To"] = "collector@evil-drop.example"
    msg["Subject"] = "URGENT: Immediate Wire Settlement"
    msg["Message-ID"] = "<phish-001@evil-drop.example>"
    msg["Authentication-Results"] = "mx.corp.example; spf=fail smtp.mailfrom=evil-drop.example; dkim=fail"
    msg.set_content("Please review the attached remittance PDF and confirm at https://evil-drop.example/confirm immediately.")
    msg.add_attachment(
        _minimal_pe_bytes(b"cmd.exe /c powershell -w hidden"),
        maintype="application",
        subtype="pdf",
        filename="remittance_advice.pdf",
    )

    resp = client.post(
        f"/api/cases/{case_id}/email-triage",
        data={"file": (io.BytesIO(msg.as_bytes()), "urgent_wire.eml")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201, resp.json
    payload = resp.json["payload"]
    assert payload["method"] == "email_static_triage"
    assert payload["email_verdict"] == "high_risk"
    assert payload["sender_email"] == "cfo@corp.example"
    assert payload["reply_to_email"] == "collector@evil-drop.example"
    flag_codes = {f["code"] for f in payload["header_flags"]}
    assert "reply_to_domain_mismatch" in flag_codes
    assert "auth_failure_claimed" in flag_codes
    assert "https://evil-drop.example/confirm" in payload["urls"]
    assert len(payload["attachments"]) == 1
    att_triage = payload["attachments"][0]["triage"]
    assert att_triage["execution"] == "never executed"
    assert att_triage["detected_magic"] == "pe_executable"
    assert att_triage["extension_mismatch"] is True
    assert att_triage["verdict"] == "high_risk"

    # Listed in email-reviews endpoint seamlessly
    reviews = client.get(f"/api/cases/{case_id}/email-reviews")
    assert reviews.status_code == 200
    assert any(item["payload"]["method"] == "email_static_triage" for item in reviews.json["items"])

    # Archived method labels remain readable without rewriting stored evidence.
    legacy_method = "v0_email_static_triage"
    database.execute(
        "UPDATE autopsy_records SET payload=json_set(payload, '$.method', ?) WHERE case_id=? AND kind='analysis'",
        (legacy_method, case_id),
    )
    archived = client.get(f"/api/cases/{case_id}/email-reviews").json["items"]
    assert any(item["payload"]["method"] == legacy_method for item in archived)
    summary = client.get(f"/api/cases/{case_id}/quick-report").json["auto_summary"]
    assert any(item["kind"] == "email" and item["sha256"] == payload["sha256"] for item in summary["static_triage_items"])
