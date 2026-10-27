"""Provision a small, isolated, synthetic V4 workspace; never alter an existing database."""

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import secrets
from datetime import timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from socify import create_app
from socify.autopsy_worker import run_autopsy_worker_once
from socify.db import get_db
from socify.seeding import _seed_rules, _user
from socify.timeutils import iso_now, utc_now

TEAM = [
    ("manager", "نورة · مدير التجربة", "soc_manager"),
    ("analyst", "عمر · محلل التجربة", "l1_analyst"),
    ("responder", "ريم · مستجيب التجربة", "l2_responder"),
    ("reviewer", "سلمان · مراجع التجربة", "reviewer"),
]
MARKER = b"SOCIFY-DEMO-INVOICE\nInert synthetic evidence, never executable.\nhttps://invoice-update.test/review\n198.51.100.42\n"


def provision(directory: Path):
    if os.environ.get("SOCIFY_ENV", "development").lower() != "development":
        raise RuntimeError("Synthetic demo provisioning is restricted to development")
    if directory.exists():
        raise RuntimeError("Destination already exists; choose a new directory to preserve existing data")
    directory.mkdir(parents=True, mode=0o700)
    keys = {"SOCIFY_SECRET_KEY": secrets.token_urlsafe(48), "SOCIFY_CREDENTIAL_KEY": secrets.token_urlsafe(48)}
    environment = directory / "runtime.env"
    environment.write_text("\n".join(f"{key}={value}" for key, value in keys.items()) + "\n")
    environment.chmod(0o600)
    app = create_app(
        {
            "DATABASE": str(directory / "socify.db"),
            "ENV_NAME": "development",
            "DEMO_MODE": True,
            "SECRET_KEY": keys["SOCIFY_SECRET_KEY"],
            "CREDENTIAL_KEY": keys["SOCIFY_CREDENTIAL_KEY"],
            "IMPORT_INLINE_EXECUTION": True,
        }
    )
    users: list[dict[str, Any]] = []
    with app.app_context():
        db = get_db()
        for handle, name, role in TEAM:
            password = secrets.token_urlsafe(20) + "!7aA"
            email = f"{handle}@demo.socify.test"
            identifier = _user(db, email, name, role, "وحدة الاستجابة التجريبية", password)
            db.execute("INSERT INTO demo_accounts(user_id) VALUES (?)", (identifier,))
            users.append({"id": identifier, "email": email, "name": name, "role": role, "password": password})
        _seed_rules(db, users[0]["id"])
    credentials = directory / "accounts.json"
    credentials.write_text(json.dumps(users, ensure_ascii=False, indent=2) + "\n")
    credentials.chmod(0o600)
    client = app.test_client()

    def call(path, method="GET", body=None, data=None):
        token = client.get("/api/auth/csrf").get_json()["csrf_token"]
        response = client.open(path, method=method, json=body, data=data, headers={"X-CSRFToken": token})
        if response.status_code not in {200, 201, 202}:
            error = (response.json or {}).get("error", {})
            raise RuntimeError(f"Synthetic setup failed at {method} {path}: {response.status_code} {error.get('code')}: {error.get('message')}")
        return response.json

    call("/api/auth/login", "POST", {"email": users[0]["email"], "password": users[0]["password"]})
    expires = (utc_now() + timedelta(days=365)).isoformat().replace("+00:00", "Z")
    feed = call(
        "/api/autopsy/intelligence",
        "POST",
        {
            "name": "SOCify synthetic invoice campaign",
            "version": "1",
            "source": "Local fictional QA scenario; no external reputation claims",
            "license": "CC0 synthetic fixture",
            "expires_at": expires,
            "format": "flat",
            "content": [
                {"type": kind, "value": value, "verdict": "malicious", "confidence": 90, "notes": "Synthetic training classification only"}
                for kind, value in [("ip", "198.51.100.42"), ("domain", "invoice-update.test"), ("sha256", hashlib.sha256(MARKER).hexdigest())]
            ],
        },
    )
    call(f"/api/autopsy/intelligence/{feed['id']}/activate", "POST", {})
    sigma = "title: Synthetic invoice campaign\ndescription: Synthetic fixture detector, no real-world coverage claim\nlogsource:\n  category: socify_normalized\ndetection:\n  selected:\n    title|contains: Invoice\n  condition: selected\nlevel: high\ntags: [attack.t1566]\n"
    call(
        "/api/autopsy/sigma/publish",
        "POST",
        {
            "source": sigma,
            "fixtures": {"positive": [{"title": "Invoice link clicked"}], "negative": [{"title": "Routine backup"}]},
            "reason": "Publish synthetic invoice detector",
        },
    )
    yara = call(
        "/api/autopsy/yara",
        "POST",
        {
            "name": "Synthetic invoice marker",
            "version": 1,
            "license": "CC0",
            "origin": "SOCify isolated demo",
            "source": 'rule SOCify_Demo_Invoice { strings: $a = "SOCIFY-DEMO-INVOICE" condition: $a }',
            "fixtures": {"positive": [base64.b64encode(MARKER).decode()], "negative": [base64.b64encode(b"Routine synthetic document").decode()]},
        },
    )
    cases = []
    titles = [
        "رسالة الفاتورة المشبوهة · INV-042",
        "نشاط حساب مرتبط بحملة الفواتير",
        "طلب فحص بوابة البريد · بانتظار المدير",
        "مراجعة نسخ احتياطي مستقلة · نطاق المدير",
    ]
    for index, title in enumerate(titles):
        case = call(
            "/api/cases",
            "POST",
            {
                "title": title,
                "reason": "user_report" if index == 0 else "alert_review",
                "objective": "ربط البريد وسجلات الشبكة والجهاز وتحديد الأثر والاستجابة اعتمادًا على أدلة وهمية محفوظة",
                "severity": "high" if index < 2 else "low",
                "assignee": users[1]["id"] if index < 3 else users[0]["id"],
                "classification": "confidential",
            },
        )
        cases.append(case["id"])
        if index == 2:
            continue
        call(f"/api/cases/{case['id']}/approval", "POST", {"decision": "approved", "version": 1, "reason": "نطاق تجربة وهمي معتمد؛ يسمح ببدء التحقيق"})
        call("/api/investigation-selection", "POST", {"case_ids": [case["id"]]})
        if index < 2:
            for user in users[1:]:
                call(
                    f"/api/cases/{case['id']}/members",
                    "POST",
                    {"user_id": user["id"], "responsibility": "reviewer" if user["role"] == "reviewer" else "l2" if user["role"] == "l2_responder" else "l1"},
                )
    call(
        f"/api/cases/{cases[0]}/relationships",
        "POST",
        {"related_case_id": cases[1], "reason": "نفس عنوان الوجهة ونفس الحساب الوهمي؛ تحقق من انتقال النشاط بين القضيتين"},
    )
    fixtures = directory / "fixtures"
    fixtures.mkdir()
    (fixtures / "invoice-marker.txt").write_bytes(MARKER)
    mail = EmailMessage()
    mail["From"], mail["To"], mail["Subject"] = "billing@invoice-update.test", "omar@company.test", "Invoice INV-042 needs review"
    mail["Date"] = utc_now().strftime("%a, %d %b %Y %H:%M:%S +0000")
    mail["Authentication-Results"] = "gateway.company.test; spf=fail; dkim=none; dmarc=fail"
    mail.set_content("Synthetic exercise only. Review link: https://invoice-update.test/review?id=INV-042\nAttachment is inert text.")
    mail.add_attachment(MARKER, maintype="text", subtype="plain", filename="invoice-marker.txt")
    (fixtures / "invoice.eml").write_bytes(mail.as_bytes())
    events = []
    observations = [
        ("email_gateway", "Invoice received with failed authentication", "email_delivered", "192.0.2.10"),
        ("proxy", "Invoice link clicked", "http_request", "198.51.100.42"),
        ("dns", "Invoice domain lookup", "dns_query", "198.51.100.42"),
        ("endpoint", "Invoice attachment retained; not executed", "file_created", "192.0.2.20"),
        ("firewall", "Invoice outbound connection blocked", "connection_blocked", "198.51.100.42"),
        ("identity", "Routine authenticated session", "successful_login", "192.0.2.20"),
        ("backup", "Routine backup completed", "backup_completed", "192.0.2.30"),
    ]
    for index, (source, title, kind, ip) in enumerate(observations):
        events.append(
            {
                "title": title,
                "event_time": (utc_now() - timedelta(minutes=40 - index * 3)).isoformat().replace("+00:00", "Z"),
                "source": source,
                "source_type": source,
                "event_type": kind,
                "category": "network" if source in {"proxy", "dns", "firewall"} else "authentication" if source == "identity" else "system",
                "severity": "high" if "Invoice" in title else "low",
                "source_ip": ip,
                "destination_ip": "192.0.2.20",
                "hostname": "invoice-update.test" if source in {"dns", "proxy"} else "ws-finance-07.company.test",
                "username": "omar.demo",
                "description": "Synthetic retained evidence only; URL https://invoice-update.test/review?id=INV-042",
                "file_hash": hashlib.sha256(MARKER).hexdigest() if source == "endpoint" else "",
                "action": kind,
                "outcome": "blocked" if source == "firewall" else "observed",
            }
        )
    baseline = [
        {
            **events[-1],
            "title": f"Routine baseline connection {index + 1:02d}",
            "event_time": (utc_now() - timedelta(hours=3, minutes=-index * 3)).isoformat().replace("+00:00", "Z"),
            "source": "proxy",
            "source_ip": "192.0.2.20",
            "hostname": "portal.company.test",
            "description": "Routine synthetic baseline; https://portal.company.test/home",
            "event_type": "http_request",
            "category": "network",
            "file_hash": "",
        }
        for index in range(24)
    ]
    retained_events = baseline + events
    (fixtures / "case1-logs.json").write_text(json.dumps(retained_events, ensure_ascii=False, indent=2) + "\n")
    csv_output = io.StringIO()
    writer = csv.DictWriter(csv_output, fieldnames=list(events[0]))
    writer.writeheader()
    writer.writerows(retained_events)
    (fixtures / "case1-logs.csv").write_text(csv_output.getvalue())
    import_jobs = []
    for index, case in enumerate(cases):
        if index == 2:
            continue
        call("/api/investigation-selection", "POST", {"case_ids": [case]})
        logs = (
            retained_events
            if index == 0
            else [{**events[1], "title": "Invoice related identity review"}]
            if index == 1
            else [
                {
                    **events[-1],
                    "title": "PRIVATE-UNRELATED-BACKUP",
                    "source_ip": "203.0.113.99",
                    "hostname": "private-backup.company.test",
                    "description": "Unrelated manager-only retained fixture",
                }
            ]
        )
        import_jobs.append(call(f"/api/cases/{case}/imports", "POST", {"filename": f"demo-case{index + 1}.json", "content": json.dumps(logs)})["id"])
    base = f"/api/cases/{cases[0]}"
    call("/api/investigation-selection", "POST", {"case_ids": cases[:2]})
    call(
        "/api/team/assignments",
        "POST",
        {
            "job_id": import_jobs[0],
            "case_id": cases[0],
            "assignee": users[1]["id"],
            "instructions": "ابحث عن 198.51.100.42 والرابط invoice-update.test واربط النتائج بالبريد",
        },
    )
    current = call(base)
    call(
        base + "/sla",
        "POST",
        {"version": current["version"], "minutes": 240, "calendar": {"mode": "24x7", "timezone": "Asia/Riyadh"}, "reason": "هدف استجابة تجريبي أربع ساعات"},
    )
    ids = []
    for name, kind, address, os_name, assessment in [
        ("FINANCE-07", "workstation", "192.0.2.20", "Windows 11", "suspected"),
        ("MAIL-GW-01", "email_gateway", "192.0.2.10", "Linux", "checked_clear"),
        ("IDP-01", "identity_provider", "192.0.2.40", "Linux", "unexamined"),
    ]:
        ids.append(
            call(
                base + "/records/asset",
                "POST",
                {
                    "name": name,
                    "type": kind,
                    "role": "defender",
                    "address": address,
                    "operating_system": os_name,
                    "owner": "قسم المالية الوهمي",
                    "importance": "high",
                    "assessment": assessment,
                },
            )["id"]
        )
    event_evidence = {}
    event_ids = {}
    for event in events[:5]:
        matching = call(base + "/logs?" + urlencode({"q": event["title"]}))["items"]
        log = next(row for row in matching if row["title"] == event["title"])
        event_ids[event["title"]] = log["id"]
        event_evidence[event["title"]] = call(base + f"/logs/{log['id']}/exhibit", "POST", {})["id"]
    evidence = event_evidence[events[0]["title"]]
    for kind, value in [
        ("ip", "198.51.100.42"),
        ("domain", "invoice-update.test"),
        ("url", "https://invoice-update.test/review?id=INV-042"),
        ("sha256", hashlib.sha256(MARKER).hexdigest()),
    ]:
        indicator_evidence = event_evidence[events[3 if kind == "sha256" else 1]["title"]]
        call(
            base + "/records/indicator",
            "POST",
            {
                "type": kind,
                "value": value,
                "classification": "ioc",
                "source": "سيناريو تجربة وهمي / دليل محفوظ",
                "confidence": 90,
                "evidence_id": indicator_evidence,
            },
        )
    call(
        base + "/records/hypothesis",
        "POST",
        {
            "title": "احتمال سرقة جلسة مستخدم",
            "statement": "قد يرتبط فتح الرابط بنشاط الهوية؛ لا دليل يثبت سرقة الجلسة بعد",
            "assessment": "open",
            "confidence": 45,
        },
    )
    call(
        base + "/records/foothold",
        "POST",
        {
            "title": "أقدم نشاط محفوظ",
            "asset_id": ids[0],
            "first_observed_at": events[0]["event_time"],
            "confidence": 70,
            "limitations": "سجلات التجربة لا تثبت بداية اختراق حقيقي",
            "evidence_id": evidence,
        },
    )
    for event in events[:5]:
        call(
            base + "/records/timeline",
            "POST",
            {
                "title": event["title"],
                "event_time": event["event_time"],
                "category": "observed",
                "source": event["source"],
                "confidence": 80,
                "tags": ["synthetic", "INV-042"],
                "evidence_id": event_evidence[event["title"]],
            },
        )
    call(
        base + "/attack",
        "POST",
        {
            "technique_id": "T1566",
            "assessment": "verified",
            "event_id": event_ids[events[0]["title"]],
            "reason": "رسالة تصيد ضمن السيناريو الوهمي، مدعومة بسجل البوابة المحفوظ",
        },
    )
    cause = call(
        base + "/records/root_cause",
        "POST",
        {
            "category": "phishing",
            "conclusion": "رسالة وهمية اجتازت البوابة رغم إخفاق المصادقة؛ إعادة ضبط السياسة تحتاج تحققًا",
            "confidence": 75,
            "evidence_id": evidence,
            "whys": [
                {
                    "id": "mail-policy",
                    "question": "لماذا وصلت الرسالة؟",
                    "answer": "السجل الوهمي يوضح التسليم رغم إخفاق DMARC",
                    "assessment": "supported",
                    "evidence_id": evidence,
                },
                {
                    "id": "policy-review",
                    "parent_id": "mail-policy",
                    "question": "لماذا لم تمنعها السياسة؟",
                    "answer": "نحتاج مراجعة الإعداد، هذا افتراض لم يثبت بعد",
                    "assessment": "hypothesis",
                },
            ],
        },
    )
    call(
        base + "/records/corrective",
        "POST",
        {
            "title": "مراجعة سياسة DMARC والتحقق من فعاليتها",
            "owner_id": users[2]["id"],
            "due_at": (utc_now() + timedelta(days=3)).isoformat(),
            "status": "open",
            "root_cause_id": cause["id"],
            "why_id": "policy-review",
        },
    )
    call(
        base + "/records/response",
        "POST",
        {
            "title": "قرار احتواء موثق",
            "phase": "containment",
            "status": "planned",
            "performed_by": users[2]["id"],
            "details": "مراجعة المنع في الجدار وتوثيق أثره، دون إرسال أوامر حية",
        },
    )
    call(
        base + "/records/war_room",
        "POST",
        {
            "title": "قرار فريق التحقيق",
            "body": "اربط البريد بالسجلات، ثم تحقق من النشاط المرتبط في القضية الثانية",
            "decision": "لا إغلاق قبل تحقق الاحتواء ومراجعة التقرير",
            "visibility": "team",
            "evidence_id": evidence,
        },
    )
    call(
        base + "/records/escalation",
        "POST",
        {
            "to_user": users[2]["id"],
            "from_level": "l1",
            "to_level": "l2",
            "reason": "فحص الاتصال الخارجي وربطه بنشاط الحساب",
            "priority": "high",
            "status": "raised",
        },
    )
    call(f"/api/incidents/{cases[0]}/tasks", "POST", {"title": "ربط رأس البريد بنتائج بحث IP", "assignee": users[1]["id"], "required": True})
    call(f"/api/incidents/{cases[0]}/tasks", "POST", {"title": "التحقق من الاحتواء وإرفاق القرار", "assignee": users[2]["id"], "required": True})
    call("/api/autopsy/procedures/seed", "POST", {})
    templates = call("/api/autopsy/procedures")["items"]
    if templates:
        call(f"/api/autopsy/procedures/{templates[0]['id']}/publish", "POST", {})
        call(base + "/procedures", "POST", {"template_id": templates[0]["id"]})
    sample = call(base + "/samples", "POST", data={"file": (io.BytesIO(MARKER), "invoice-marker.txt")})
    job = call(base + f"/samples/{sample['id']}/analyze", "POST", {"yara_pack_id": yara["id"]})
    with app.app_context():
        run_autopsy_worker_once("v4-demo-analysis")
    if call(base + f"/jobs/{job['id']}")["state"] != "completed":
        raise RuntimeError("Real isolated sample analysis did not complete; demo is not ready")
    results = call(base + "/records?kind=analysis")["items"]
    if not any(any(match["rule"] == "SOCify_Demo_Invoice" for match in item["payload"].get("yara_matches", [])) for item in results):
        raise RuntimeError("Expected synthetic YARA marker did not match")
    sample_mail = call(base + "/samples", "POST", data={"file": (io.BytesIO(mail.as_bytes()), "invoice.eml")})
    call(base + f"/samples/{sample_mail['id']}/email-review", "POST", {})
    baseline_after_id = max(row["id"] for row in call(base + "/logs?limit=100&q=Routine%20baseline")["items"])
    detection_jobs = []
    for mode, after in [("anomaly", baseline_after_id), ("rules", 0)]:
        current = call(base)
        detection = call(base + "/detection", "POST", {"version": current["version"], "mode": mode, "after_id": after})
        with app.app_context():
            run_autopsy_worker_once("v4-demo-detection")
        if call(base + f"/jobs/{detection['id']}")["state"] != "completed":
            raise RuntimeError("Synthetic detection did not complete")
        detection_jobs.append(detection["id"])
    current = call(base)
    call(base + "/transitions", "POST", {"status": "investigating", "version": current["version"], "reason": "بدء التحقيق التجريبي بعد اعتماد المدير"})
    current = call(base)
    report = call(base + "/reports", "POST", {"version": current["version"], "profile": "full"})
    with app.app_context():
        run_autopsy_worker_once("v4-demo-report")
    if call(base + f"/jobs/{report['job_id']}")["state"] != "completed":
        raise RuntimeError("Real isolated report generation did not complete; demo is not ready")
    call("/api/auth/logout", "POST", {})
    manifest = {
        "synthetic": True,
        "created_at": iso_now(),
        "cases": cases,
        "primary_case": cases[0],
        "related_case": cases[1],
        "pending_case": cases[2],
        "unrelated_private_case": cases[3],
        "sample_sha256": hashlib.sha256(MARKER).hexdigest(),
        "sample_analysis_job": job["id"],
        "detection_jobs": detection_jobs,
        "anomaly_after_id": baseline_after_id,
        "report": report["id"],
        "credentials_file": "accounts.json",
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    (directory / "README.txt").write_text(
        "Private synthetic demonstration. Keep runtime.env with socify.db to preserve encrypted evidence.\nFrom the V4 checkout run: python -m scripts.run_v4_demo --directory <this directory>\nRequires the isolated analysis service for new analyses and report exports; existing analysis and generated report files are retained.\nCredentials: accounts.json. Do not upload this directory to Git.\n"
    )
    print(f"Synthetic demo ready: {directory}; 4 accounts, 4 compact cases, real analysis and report. Credentials saved privately, not printed.")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("instance/v4-demo"))
    args = parser.parse_args()
    provision(args.directory.resolve())


if __name__ == "__main__":
    main()
