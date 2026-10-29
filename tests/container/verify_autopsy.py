import base64
import hashlib
import http.client
import json
import os
import secrets
import tempfile
import time
from http.cookies import SimpleCookie

from scripts.bootstrap_team import create_manager
from socify import create_app


def main():
    if os.environ.get("SOCIFY_CONTAINER_ACCEPTANCE") != "synthetic":
        raise SystemExit("Run only against an isolated synthetic acceptance volume with SOCIFY_CONTAINER_ACCEPTANCE=synthetic")
    password = secrets.token_urlsafe(28) + "Aa9!"
    email = "container-" + secrets.token_hex(6) + "@example.test"
    create_manager(create_app(), email, "Synthetic investigator", "Synthetic acceptance team", password)
    cookie = ""

    def call(path, body=None, content_type="application/json", raw=False):
        nonlocal cookie
        headers = {"Content-Type": content_type, "Host": "localhost"}
        if body is not None:
            headers["X-CSRFToken"] = call("/api/auth/csrf")["csrf_token"]
        if cookie:
            headers["Cookie"] = cookie
        data = body if isinstance(body, bytes) else None if body is None else json.dumps(body).encode()
        connection = http.client.HTTPConnection("ingress", 5000, timeout=55)
        try:
            connection.request("GET" if body is None else "POST", path, body=data, headers=headers)
            response = connection.getresponse()
            content = response.read()
            if response.getheader("Set-Cookie"):
                parsed = SimpleCookie(response.getheader("Set-Cookie"))
                if "session" in parsed:
                    cookie = "session=" + parsed["session"].value
            assert response.status < 400, (path, response.status)
            return (content, dict(response.getheaders())) if raw else json.loads(content)
        finally:
            connection.close()

    def wait(path, field, pending):
        deadline = time.monotonic() + 50
        while True:
            result = call(path)
            state = result[field]
            if state not in pending:
                return result
            if time.monotonic() >= deadline:
                raise TimeoutError("Synthetic local worker did not finish within the acceptance deadline")
            time.sleep(0.2)

    call("/api/auth/login", {"email": email, "password": password})
    case = call(
        "/api/cases",
        {
            "title": "تحقيق اصطناعي — Synthetic Incident Review",
            "reason": "forensic_review",
            "objective": "التحقق من حفظ الأدلة والتحليل المحلي وتقرير عربي وإنجليزي داخل الحاويات",
        },
    )
    base = "/api/cases/" + str(case["id"])
    call(base + "/approval", {"decision": "approved", "version": case["approval"]["version"], "reason": "Synthetic container acceptance scope"})
    call("/api/investigation-selection", {"case_ids": [case["id"]]})
    imported = call(
        base + "/imports", {"filename": "synthetic.jsonl", "content": '{"title":"Synthetic incident evidence","event_time":"2026-10-24T10:00:00Z"}\n'}
    )
    import_status = wait(base + "/imports/" + str(imported["id"]), "status", {"queued", "processing", "interrupted"})
    assert import_status["status"] == "completed", import_status["status"]
    sample = b"Synthetic EICAR-STANDARD-ANTIVIRUS-TEST-FILE acceptance marker"
    boundary = "SOCifyAcceptance" + secrets.token_hex(12)
    multipart = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="synthetic.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
        + sample
        + f"\r\n--{boundary}--\r\n".encode()
    )
    quarantined = call(base + "/samples", multipart, "multipart/form-data; boundary=" + boundary)
    assert quarantined["sha256"] == hashlib.sha256(sample).hexdigest()
    analysis = call(base + "/samples/" + str(quarantined["id"]) + "/analyze", {})
    analysis_status = wait(base + "/jobs/" + str(analysis["id"]), "state", {"queued", "processing"})
    assert analysis_status["state"] == "completed", analysis_status
    findings = call(base + "/records?kind=analysis")["items"]
    assert findings[0]["payload"]["execution"] == "never executed"
    assert findings[0]["payload"]["yara_matches"][0]["rule"] == "SOCify_EICAR_Test_Marker"
    pack = call(
        "/api/autopsy/yara",
        {
            "name": "Synthetic production pack",
            "version": 1,
            "origin": "Internal synthetic acceptance",
            "license": "Synthetic test permission",
            "source": 'rule Production_Test { strings: $a = "SOCify-production-fixture" condition: $a }',
            "fixtures": {"positive": [base64.b64encode(b"SOCify-production-fixture").decode()], "negative": [base64.b64encode(b"unrelated bytes").decode()]},
        },
    )
    assert pack["validation"]["valid"] and pack["validation"]["isolation"]["syscalls"] == "linux-seccomp"
    custom = call(base + "/samples/" + str(quarantined["id"]) + "/analyze", {"yara_pack_id": pack["id"]})
    assert wait(base + "/jobs/" + str(custom["id"]), "state", {"queued", "processing"})["state"] == "completed"
    result = call(base + "/records?kind=analysis")["items"][0]["payload"]
    assert result["yara_pack"]["id"] == pack["id"] and not result["yara_matches"]
    archived, _ = call(base + "/capsule?profile=backup", raw=True)
    restore_boundary = "SOCifyRestore" + secrets.token_hex(12)
    restore_body = (
        f'--{restore_boundary}\r\nContent-Disposition: form-data; name="file"; filename="case.zip"\r\nContent-Type: application/zip\r\n\r\n'.encode()
        + archived
        + f"\r\n--{restore_boundary}--\r\n".encode()
    )
    restored = call("/api/cases/import-capsule", restore_body, "multipart/form-data; boundary=" + restore_boundary)
    assert restored["case_id"] != case["id"]
    restored_base = "/api/cases/" + str(restored["case_id"])
    restored_case = call(restored_base)
    call(restored_base + "/approval", {"decision": "approved", "version": restored_case["approval"]["version"], "reason": "Review restored synthetic evidence"})
    call("/api/investigation-selection", {"case_ids": [restored["case_id"]]})
    assert call("/api/cases/" + str(restored["case_id"]) + "/logs")["total"] == 1
    call("/api/investigation-selection", {"case_ids": [case["id"]]})
    report = call(base + "/reports", {"version": call(base)["version"]})
    state = wait(base + "/jobs/" + str(report["job_id"]), "state", {"queued", "processing"})
    assert state["state"] == "completed", state
    ready = call(base + "/reports/" + str(report["id"]))
    content, headers = call(base + "/reports/" + str(report["id"]) + "/files/pdf", raw=True)
    assert content.startswith(b"%PDF-")
    assert hashlib.sha256(content).hexdigest() == headers["X-Content-SHA256"]
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    descriptor, artifact = tempfile.mkstemp(prefix="socify-acceptance-", suffix=".pdf")
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)
    print(
        json.dumps(
            {
                "production_http_login_csrf": True,
                "fixed_internal_ingress": True,
                "import_state": import_status["status"],
                "static_analysis": analysis_status["state"],
                "sample_executed": False,
                "custom_yara_validation_and_versioned_scan": True,
                "case_archive_restore": True,
                "report_state": state["state"],
                "formats": ready["formats"],
                "pdf_sha256_verified": True,
                "pdf_artifact": artifact,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
