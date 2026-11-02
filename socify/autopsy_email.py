import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

from cryptography.fernet import InvalidToken
from flask import Blueprint, jsonify, request

from .autopsy_api import insert_record
from .autopsy_pipeline import case_full_access
from .cases import _case_row
from .db import get_db, transaction
from .file_names import evidence_filename
from .security import cipher, error_response, require_permission

autopsy_email_api = Blueprint("autopsy_email", __name__)
MAXIMUM = 2 * 1024 * 1024
MAX_MIME_DEPTH = 5
MAX_ATTACHMENTS = 25
MAX_MIME_PARTS = 100
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
    try:
        message = BytesParser(policy=policy.default).parsebytes(content)
    except RecursionError as exc:
        raise ValueError("تداخل أجزاء MIME يتجاوز الحد المسموح") from exc
    if not any(message.get(key) for key in ("From", "To", "Subject", "Message-ID")):
        raise ValueError("الملف لا يحتوي رؤوس رسالة EML معروفة")
    headers = {}
    for key in ("From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID", "Return-Path", "Authentication-Results", "Received-SPF"):
        headers[key] = "\n".join(str(value) for value in message.get_all(key, []))[:4096]
    attachments: list[dict] = []
    plain, html_text, links = [], [], []
    part_count, header_count = 0, 0
    pending = [(message, 0)]
    leaves = []
    attachment_count = 0
    while pending:
        part, depth = pending.pop()
        if depth > MAX_MIME_DEPTH:
            raise ValueError("تداخل أجزاء MIME يتجاوز الحد المسموح")
        part_count += 1
        header_count += len(part.keys())
        if part_count > MAX_MIME_PARTS or header_count > 200:
            raise ValueError("عدد أجزاء MIME أو رؤوس الرسالة يتجاوز الحد المسموح")
        is_attachment = (
            bool(part.get_filename())
            or part.get_content_disposition() == "attachment"
            or (not part.is_multipart() and part.get_content_type() not in {"text/plain", "text/html"})
        )
        if is_attachment:
            attachment_count += 1
            if attachment_count > MAX_ATTACHMENTS:
                raise ValueError("عدد المرفقات يتجاوز الحد المسموح")
        if part.is_multipart():
            children = part.get_payload()
            if not isinstance(children, list):
                raise ValueError("بنية MIME غير صالحة")
            if len(children) + len(pending) + part_count > MAX_MIME_PARTS:
                raise ValueError("عدد أجزاء MIME أو رؤوس الرسالة يتجاوز الحد المسموح")
            pending.extend((child, depth + 1) for child in reversed(children))
            continue
        leaves.append((part, is_attachment))
    # Validate the entire MIME tree before decoding any body or attachment.
    for part, is_attachment in leaves:
        data = part.get_payload(decode=True) or b""
        if not isinstance(data, bytes):
            raise ValueError("محتوى جزء MIME ليس بيانات ثنائية صالحة")
        filename = part.get_filename()
        if is_attachment:
            digest = hashlib.sha256(data).hexdigest()
            attachments.append(
                {
                    "filename": evidence_filename(str(filename or ""), data, "attachment"),
                    "content_type": part.get_content_type()[:100],
                    "size": len(data),
                    "sha256": digest,
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
            "SELECT id,payload,created_at FROM autopsy_records WHERE case_id=? AND kind='analysis' AND (json_extract(payload,'$.method') IN ('eml_static_v1', 'email_static_triage') OR json_extract(payload,'$.method') GLOB 'v[0-9]*_email_static_triage') AND id<? ORDER BY id DESC LIMIT 11",
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


def _email_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""


def inspect_email_with_attachment_triage(content: bytes) -> dict:
    from .autopsy_static_analysis import inspect_static_bytes

    max_eml_bytes = 5 * 1024 * 1024
    if not content or len(content) > max_eml_bytes:
        raise ValueError("حجم رسالة EML يجب ألا يتجاوز 5MiB")
    try:
        message = BytesParser(policy=policy.default).parsebytes(content)
    except RecursionError as exc:
        raise ValueError("تداخل أجزاء MIME يتجاوز الحد المسموح") from exc
    if not any(message.get(key) for key in ("From", "To", "Subject", "Message-ID")):
        raise ValueError("الملف لا يحتوي رؤوس رسالة EML معروفة")
    headers = {}
    for key in ("From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID", "Return-Path", "Authentication-Results", "Received-SPF"):
        headers[key] = "\n".join(str(value) for value in message.get_all(key, []))[:4096]

    sender_email = parseaddr(headers.get("From", ""))[1].strip().lower()
    reply_to_email = parseaddr(headers.get("Reply-To", ""))[1].strip().lower()
    return_path_email = parseaddr(headers.get("Return-Path", ""))[1].strip().lower()

    header_flags: list[dict] = []
    email_risk = 0

    def add_header_flag(code: str, severity: str, points: int, detail: str) -> None:
        nonlocal email_risk
        if not any(f["code"] == code for f in header_flags):
            header_flags.append({"code": code, "severity": severity, "detail": detail})
            email_risk = min(100, email_risk + points)

    sender_dom = _email_domain(sender_email)
    reply_dom = _email_domain(reply_to_email)
    return_dom = _email_domain(return_path_email)
    if sender_dom and reply_dom and sender_dom != reply_dom:
        add_header_flag("reply_to_domain_mismatch", "high", 35, f"نطاق Reply-To ({reply_dom}) يختلف عن نطاق المرسل From ({sender_dom}).")
    if sender_dom and return_dom and sender_dom != return_dom:
        add_header_flag("return_path_domain_mismatch", "medium", 20, f"نطاق Return-Path ({return_dom}) يختلف عن نطاق المرسل ({sender_dom}).")

    auth_blob = f"{headers.get('Authentication-Results', '')}\n{headers.get('Received-SPF', '')}".lower()
    if any(tok in auth_blob for tok in ("spf=fail", "spf=softfail", "dkim=fail", "dmarc=fail")):
        add_header_flag("auth_failure_claimed", "high", 35, "رؤوس المصادقة تسجل فشل SPF أو DKIM أو DMARC.")

    subj_lower = headers.get("Subject", "").lower()
    if any(tok in subj_lower for tok in ("urgent", "wire", "invoice", "password", "suspended", "عاجل", "حوالة", "تحديث كلمة المرور")):
        add_header_flag("urgent_lure_subject", "low", 10, "عنوان الرسالة يستخدم صياغة استعجال شائعة في التصيد.")

    pending = [(message, 0)]
    leaves = []
    part_count, header_count, attachment_count = 0, 0, 0
    while pending:
        part, depth = pending.pop()
        if depth > MAX_MIME_DEPTH:
            raise ValueError("تداخل أجزاء MIME يتجاوز الحد المسموح")
        part_count += 1
        header_count += len(part.keys())
        if part_count > MAX_MIME_PARTS or header_count > 200:
            raise ValueError("عدد أجزاء MIME أو رؤوس الرسالة يتجاوز الحد المسموح")
        is_attachment = (
            bool(part.get_filename())
            or part.get_content_disposition() == "attachment"
            or (not part.is_multipart() and part.get_content_type() not in {"text/plain", "text/html"})
        )
        if is_attachment:
            attachment_count += 1
            if attachment_count > MAX_ATTACHMENTS:
                raise ValueError("عدد المرفقات يتجاوز الحد المسموح")
        if part.is_multipart():
            children = part.get_payload()
            if not isinstance(children, list):
                raise ValueError("بنية MIME غير صالحة")
            if len(children) + len(pending) + part_count > MAX_MIME_PARTS:
                raise ValueError("عدد أجزاء MIME أو رؤوس الرسالة يتجاوز الحد المسموح")
            pending.extend((child, depth + 1) for child in reversed(children))
            continue
        leaves.append((part, is_attachment))

    attachments: list[dict] = []
    plain, html_text, links = [], [], []
    for part, is_attachment in leaves:
        data = part.get_payload(decode=True) or b""
        if not isinstance(data, bytes):
            raise ValueError("محتوى جزء MIME ليس بيانات ثنائية صالحة")
        raw_filename = str(part.get_filename() or "")
        if is_attachment:
            digest = hashlib.sha256(data).hexdigest()
            triage = (
                inspect_static_bytes(raw_filename or "attachment.bin", data, part.get_content_type())
                if data
                else {
                    "filename": raw_filename or "empty.bin",
                    "size": 0,
                    "sha256": digest,
                    "verdict": "low_signal_static_only",
                    "risk_score": 0,
                    "flags": [],
                    "execution": "never executed",
                }
            )
            email_risk = max(email_risk, min(100, email_risk // 2 + int(triage.get("risk_score", 0))))
            attachments.append(
                {
                    "filename": evidence_filename(raw_filename, data, "attachment"),
                    "original_filename": raw_filename or "attachment.bin",
                    "content_type": part.get_content_type()[:100],
                    "size": len(data),
                    "sha256": digest,
                    "triage": triage,
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

    urls = list(dict.fromkeys(value.rstrip(".,);]")[:2048] for value in links))[:100]
    if any("xn--" in u.lower() or re.match(r"^https?://(?:\d{1,3}\.){3}\d{1,3}", u) for u in urls):
        add_header_flag("suspicious_url_host", "high", 30, "تحتوي الرسالة على رابط IP مباشر أو نطاق Punycode.")

    email_verdict = "high_risk" if email_risk >= 65 else "suspicious" if email_risk >= 30 else "low_signal_static_only"
    body = "\n".join(plain or html_text)
    return {
        "headers": headers,
        "sender_email": sender_email or None,
        "reply_to_email": reply_to_email or None,
        "return_path_email": return_path_email or None,
        "header_flags": header_flags,
        "email_risk_score": email_risk,
        "email_verdict": email_verdict,
        "body": body[:16384],
        "body_truncated": len(body) > 16384,
        "urls": urls,
        "attachments": attachments,
        "mime_parts": part_count,
        "execution": "never executed",
        "limitations": LIMITATION,
    }


@autopsy_email_api.post("/api/cases/<int:case_id>/email-triage")
@require_permission("evidence.add")
def quick_email_triage(case_id: int):
    from .autopsy_domain import canonical, custody, text_value
    from .autopsy_samples import quarantine_or_get_sample

    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if case["status"] == "closed":
        return error_response("CASE_CLOSED", "القضية مغلقة", 409)

    upload = request.files.get("file")
    try:
        if upload:
            original_name = text_value(upload.filename or "message.eml", 255, True)
            if any(ch in original_name for ch in ("/", "\\")):
                raise ValueError("أرسل اسم ملف دون مسار")
            content = upload.stream.read(5 * 1024 * 1024 + 1)
        else:
            body = request.get_json(silent=True) or {}
            if not isinstance(body, dict) or not isinstance(body.get("raw_eml"), str):
                raise ValueError("أرفق ملف .eml في حقل file أو أرسل raw_eml نصيًا")
            original_name = text_value(str(body.get("filename") or "message.eml"), 255, True)
            content = body["raw_eml"].encode("utf-8")
        if not original_name.lower().endswith(".eml"):
            original_name = f"{original_name}.eml"
        parsed = inspect_email_with_attachment_triage(content)
    except (ValueError, UnicodeError, RecursionError) as exc:
        return error_response("INVALID_EMAIL_FILE", str(exc)[:200], 422)

    with transaction():
        case = _case_row(case_id)
        if not case or not case_full_access(case_id):
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة ضمن النطاق الحالي", 404)
        if case["status"] == "closed":
            return error_response("CASE_CLOSED", "القضية مغلقة", 409)
        sample_id, evidence_id, digest, duplicate_sample = quarantine_or_get_sample(case_id, original_name, content, "email_static_triage")
        payload = {
            "title": parsed["headers"]["Subject"][:255] or get_db().execute("SELECT filename FROM autopsy_samples WHERE id=?", (sample_id,)).fetchone()[0],
            "method": "email_static_triage",
            "sample_id": sample_id,
            "evidence_id": evidence_id,
            "sha256": digest,
            **parsed,
        }
        prior = (
            get_db()
            .execute(
                "SELECT id FROM autopsy_records WHERE case_id=? AND kind='analysis' AND payload=? ORDER BY id DESC LIMIT 1",
                (case_id, canonical(payload)),
            )
            .fetchone()
        )
        if prior:
            return jsonify(
                {"id": prior["id"], "sample_id": sample_id, "evidence_id": evidence_id, "duplicate_sample": True, "duplicate": True, "payload": payload}
            )
        analysis_id = insert_record(case_id, "analysis", payload)
        custody(
            case_id,
            "quick_email_triage_completed",
            {
                "sample_id": sample_id,
                "analysis_id": analysis_id,
                "sha256": digest,
                "verdict": parsed["email_verdict"],
                "attachments": len(parsed["attachments"]),
            },
        )
    return jsonify({"id": analysis_id, "sample_id": sample_id, "evidence_id": evidence_id, "duplicate_sample": duplicate_sample, "payload": payload}), 201
