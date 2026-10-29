import hashlib
import io
from email.message import EmailMessage, Message

import pytest

from socify.autopsy_email import inspect_email
from socify.file_names import evidence_filename
from socify.ingestion import parse_records


def nested_mail(depth):
    message = EmailMessage()
    message.set_content("Retained body")
    for _ in range(depth):
        parent = EmailMessage()
        parent.make_mixed()
        parent.attach(message)
        message = parent
    message["From"] = "sender@example.test"
    return message.as_bytes()


def test_email_depth_boundary_rejects_before_decoding(monkeypatch):
    assert "Retained body" in inspect_email(nested_mail(5))["body"]
    too_deep = nested_mail(6)
    original, decoded = Message.get_payload, []

    def tracked(self, i=None, decode=False):
        if decode:
            decoded.append(self)
        return original(self, i=i, decode=decode)

    monkeypatch.setattr(Message, "get_payload", tracked)
    with pytest.raises(ValueError, match="MIME"):
        inspect_email(too_deep)
    assert not decoded


def test_email_attachment_limit_is_an_error_instead_of_silent_truncation(monkeypatch):
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message.set_content("Retained body")
    for index in range(25):
        message.add_attachment(b"bounded", maintype="application", subtype="octet-stream", filename=f"evidence-{index}.bin")
    assert len(inspect_email(message.as_bytes())["attachments"]) == 25
    message.add_attachment(b"overflow", maintype="application", subtype="octet-stream", filename="overflow.bin")
    encoded = message.as_bytes()
    original, decoded = Message.get_payload, []

    def tracked(self, i=None, decode=False):
        if decode:
            decoded.append(self)
        return original(self, i=i, decode=decode)

    monkeypatch.setattr(Message, "get_payload", tracked)
    with pytest.raises(ValueError, match="المرفقات"):
        inspect_email(encoded)
    assert not decoded


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_xml_declarations_are_rejected_even_after_long_preamble(encoding, app):
    document = ('<?xml version="1.0"?>' + " " * 9000 + '<!DOCTYPE Events [<!ENTITY source SYSTEM "file:///private-marker">]><Events>&source;</Events>').encode(
        encoding
    )
    with app.app_context(), pytest.raises(ValueError):
        _, records = parse_records("events.xml", document, "sysmon_xml", "synthetic")
        list(records)


@pytest.mark.parametrize("name", ["../../payload.eml", "..\\..\\payload.eml", "رسالة.eml", "\u202e.eml", ".", "../"])
def test_evidence_display_names_are_bounded_and_keep_safe_extensions(name):
    content = b"synthetic retained bytes"
    safe = evidence_filename(name, content)
    assert safe and len(safe) <= 255 and safe.isascii()
    assert not any(value in safe for value in ("/", "\\", ".."))
    if name.endswith(".eml"):
        assert safe.endswith(".eml")
    if name == "رسالة.eml":
        assert hashlib.sha256(content).hexdigest()[:16] in safe


def test_arabic_mail_filename_remains_reviewable_and_original_bytes_survive(autopsy_case, client):
    content = b"From: sender@example.test\nSubject: Retained\n\nOriginal evidence\n"
    base = f"/api/cases/{autopsy_case}"
    response = client.post(base + "/samples", data={"file": (io.BytesIO(content), "رسالة.eml")})
    assert response.status_code == 201
    sample = response.json["id"]
    assert client.post(base + f"/samples/{sample}/email-review", json={}).status_code == 201
    listed = client.get(base + "/samples").json["items"][0]
    assert listed["filename"].endswith(".eml") and listed["filename"].isascii()
    assert listed["sha256"] == hashlib.sha256(content).hexdigest()
