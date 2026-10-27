import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

from cryptography.fernet import InvalidToken
from flask import Blueprint, jsonify, request

from .autopsy_api import insert_record
from .autopsy_pipeline import case_full_access
from .cases import _case_row
from .db import get_db, transaction
from .security import cipher, error_response, require_permission

autopsy_email_api = Blueprint("autopsy_email", __name__)
MAXIMUM = 2 * 1024 * 1024
LIMITATION = "Static MIME inspection only. Headers, including Authentication-Results, are untrusted source text; SPF/DKIM are not independently verified. URLs are not visited, attachments are not executed, and absence of findings does not establish safety."


class MailText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.hidden = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1
        if tag in {"p", "div", "br", "li"}:
            self.text.append("\n")
        for key, value in attrs:
            if key == "href" and value and re.match(r"https?://", value, re.I):
                self.links.append(value[:2048])

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def inspect_email(content: bytes) -> dict:
    if not content or len(content) > MAXIMUM:
        raise ValueError("حجم رسالة EML يجب ألا يتجاوز 2MiB")
    message = BytesParser(policy=policy.default).parsebytes(content)
    if not any(message.get(key) for key in ("From", "To", "Subject", "Message-ID")):
        raise ValueError("الملف لا يحتوي رؤوس رسالة EML معروفة")
    headers = {}
    for key in ("From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID", "Return-Path", "Authentication-Results", "Received-SPF"):
        headers[key] = "\n".join(str(value) for value in message.get_all(key, []))[:4096]
    attachments, plain, html_text, links = [], [], [], []
    part_count, header_count = 0, 0
    for part in message.walk():
        part_count += 1
        header_count += len(part.keys())
        if part_count > 100 or header_count > 200:
            raise ValueError("عدد أجزاء MIME أو رؤوس الرسالة يتجاوز الحد المسموح")
        if part.is_multipart():
            continue
        data = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment" or part.get_content_type() not in {"text/plain", "text/html"}:
            if len(attachments) >= 50:
                raise ValueError("عدد المرفقات يتجاوز الحد المسموح")
            attachments.append(
                {
                    "filename": str(filename or "unnamed")[:255],
                    "content_type": part.get_content_type()[:100],
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
            continue
        try:
            text = data.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            text = data.decode("utf-8", errors="replace")
        text = text[:65536]
        if part.get_content_type() == "text/html":
            parser = MailText()
            parser.feed(text)
            html_text.append("".join(parser.text))
            links.extend(parser.links)
        else:
            plain.append(text)
        links.extend(re.findall(r"https?://[^\s<>\"']+", text, re.I))
    body = "\n".join(plain or html_text)
    return {
        "headers": headers,
        "body": body[:16384],
        "body_truncated": len(body) > 16384,
        "urls": list(dict.fromkeys(value[:2048] for value in links))[:100],
        "attachments": attachments,
        "mime_parts": part_count,
        "limitations": LIMITATION,
    }


@autopsy_email_api.post("/api/cases/<int:case_id>/samples/<int:sample_id>/email-review")
@require_permission("cases.update")
@require_permission("evidence.download")
def review_email(case_id: int, sample_id: int):
    if request.get_json(silent=True) != {}:
        return error_response("INVALID_EMAIL_REVIEW", "أرسل كائن JSON فارغًا لتحليل الرسالة المحجورة", 422)
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if case["status"] == "closed":
        return error_response("CASE_CLOSED", "أعد فتح القضية قبل إضافة تحليل", 409)
    sample = get_db().execute("SELECT * FROM autopsy_samples WHERE case_id=? AND id=?", (case_id, sample_id)).fetchone()
    if not sample:
        return error_response("SAMPLE_NOT_FOUND", "العينة غير متاحة", 404)
    if not sample["filename"].lower().endswith(".eml") or sample["size"] > MAXIMUM:
        return error_response("INVALID_EMAIL_FILE", "اختر أصل EML محجورًا لا يتجاوز 2MiB", 422)
    try:
        content = cipher().decrypt(sample["ciphertext"])
        if hashlib.sha256(content).hexdigest() != sample["sha256"]:
            raise InvalidToken
        parsed = inspect_email(content)
    except InvalidToken:
        return error_response("SAMPLE_INTEGRITY_FAILED", "تعذر التحقق من سلامة أصل الرسالة", 409)
    except (ValueError, UnicodeError, RecursionError) as exc:
        return error_response("INVALID_EMAIL_FILE", str(exc)[:200], 422)
    with transaction():
        case = _case_row(case_id)
        if not case or not case_full_access(case_id):
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة ضمن النطاق الحالي", 404)
        if case["status"] == "closed":
            return error_response("CASE_CLOSED", "أعد فتح القضية قبل إضافة تحليل", 409)
        prior = (
            get_db()
            .execute(
                "SELECT id,payload FROM autopsy_records WHERE case_id=? AND kind='analysis' AND json_extract(payload,'$.method')='eml_static_v1' AND json_extract(payload,'$.sample_id')=? ORDER BY id DESC LIMIT 1",
                (case_id, sample_id),
            )
            .fetchone()
        )
        if prior:
            return jsonify({"id": prior["id"], "payload": json.loads(prior["payload"]), "duplicate": True})
        payload = {
            "title": parsed["headers"]["Subject"][:255] or sample["filename"],
            "method": "eml_static_v1",
            "sample_id": sample_id,
            "evidence_id": sample["evidence_id"],
            "sha256": sample["sha256"],
            **parsed,
        }
        identifier = insert_record(case_id, "analysis", payload)
    return jsonify({"id": identifier, "payload": payload}), 201


@autopsy_email_api.get("/api/cases/<int:case_id>/email-reviews")
@require_permission("cases.read")
def email_reviews(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        if set(request.args) - {"before"}:
            raise ValueError
        before = int(request.args["before"]) if "before" in request.args else 2**63 - 1
        if not 1 <= before <= 2**63 - 1:
            raise ValueError
    except ValueError:
        return error_response("INVALID_PAGE", "الصفحة غير صالحة", 422)
    rows = (
        get_db()
        .execute(
            "SELECT id,payload,created_at FROM autopsy_records WHERE case_id=? AND kind='analysis' AND json_extract(payload,'$.method')='eml_static_v1' AND id<? ORDER BY id DESC LIMIT 11",
            (case_id, before),
        )
        .fetchall()
    )
    return jsonify(
        {
            "items": [{"id": row["id"], "payload": json.loads(row["payload"]), "created_at": row["created_at"]} for row in rows[:10]],
            "next_before": rows[9]["id"] if len(rows) > 10 else None,
        }
    )
