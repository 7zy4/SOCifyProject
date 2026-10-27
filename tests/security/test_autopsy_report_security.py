import io
import socket
import zipfile

import pytest

from socify.autopsy_domain import canonical
from socify.autopsy_report_render import FORMATS, lines, render_files
from socify.autopsy_worker import deny_network, run_autopsy_worker_once


def test_only_bundled_brand_image_can_be_resolved_in_reports():
    from weasyprint.urls import URLFetchingError

    from socify.autopsy_report_render import bundled_report_asset_fetcher, render_docx, render_html
    from socify.report_brand import report_logo

    payload = {"case": {"title": "Retained case evidence", "reference": "CASE-BRAND"}, "revision": 1}
    document = render_html(payload)
    assert report_logo() in document
    assert bundled_report_asset_fetcher(report_logo()).content_type == "image/png"
    for destination in ("https://example.test/logo.png", "file:///etc/passwd", "data:image/png;base64,dW50cnVzdGVk"):
        with pytest.raises(URLFetchingError):
            bundled_report_asset_fetcher(destination)
    with zipfile.ZipFile(io.BytesIO(render_docx(payload))) as archive:
        assert any(name.startswith("word/media/") for name in archive.namelist())


def test_rendered_reports_escape_active_content_and_never_resolve_network(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "font-cache"))
    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    payload = {
        "case": {"title": '<script src="https://evil.test/a"></script> ``` \u202etxt', "reference": "SOC-CASE-42"},
        "revision": 1,
        "context": {"objective": '<img src="file:///etc/passwd">'},
        "records": {"war_room": [{"payload": {"body": "```\n<script>alert(1)</script>\nhttps://evil.test/exfil"}}]},
        "summary": {"counts": {"evidence": 1}},
        "limitations": ["Synthetic security acceptance fixture"],
    }
    files = render_files(payload)
    assert set(files) == set(FORMATS)
    assert files["pdf"].startswith(b"%PDF-")
    assert files["json"] == canonical(payload).encode()
    assert b"<script" not in files["html"] and b"<img src=" not in files["html"]
    assert b"&lt;script" in files["html"]
    assert b"\\u202e" in files["html"]
    assert files["md"].count(b"```") == 2 * sum(1 for line in files["md"].splitlines() if line.startswith(b"## "))
    assert not files["md"].startswith(b"# SOCify Digital Autopsy\n\n<script")
    with zipfile.ZipFile(io.BytesIO(files["docx"])) as archive:
        assert b"&lt;script" in archive.read("word/document.xml")
        assert b'TargetMode="External"' not in archive.read("word/_rels/document.xml.rels")
        assert b'w:cs="IBM Plex Sans Arabic"' in archive.read("word/styles.xml")
        assert b'w:cs="IBM Plex Sans Arabic"' in archive.read("word/styles.xml")
    assert list(lines(None)) == [(0, "غير مسجل")]
    assert list(lines([])) == [(0, "لا توجد عناصر مسجلة")]
    with pytest.raises(PermissionError):
        deny_network("https://evil.test")


def test_job_failure_retry_cancellation_and_revoked_access(autopsy_case, app, client, login_as, database, monkeypatch, user_ids):
    from socify import autopsy_worker

    base = f"/api/cases/{autopsy_case}"

    def create():
        return client.post(base + "/reports", json={"version": client.get(base).json["version"]}).json

    job = create()
    assert client.get(base + f"/jobs/{job['job_id']}").json["state"] == "queued"
    assert client.post(base + f"/jobs/{job['job_id']}/wrong").status_code == 404
    monkeypatch.setattr(autopsy_worker, "compute_report", lambda payload: (_ for _ in ()).throw(TimeoutError("Fixture limit")))
    with app.app_context():
        assert run_autopsy_worker_once("security-worker") == job["job_id"]
    assert client.get(base + f"/jobs/{job['job_id']}").json["error_code"] == "RESOURCE_LIMIT"
    assert client.post(base + f"/jobs/{job['job_id']}/cancel").status_code == 409
    assert client.post(base + f"/jobs/{job['job_id']}/retry").status_code == 200
    database.execute("DELETE FROM autopsy_case_members WHERE case_id = ? AND user_id = ?", (autopsy_case, user_ids["analyst"]))
    with app.app_context():
        run_autopsy_worker_once("security-worker")
    login_as("soc_manager")
    assert client.get(base + f"/jobs/{job['job_id']}").json["error_code"] == "ACCESS_REVOKED"
    assert client.get(base + f"/reports/{job['id']}").json["formats"] == []
    assert client.post(base + f"/jobs/{job['job_id']}/retry").status_code == 200
    assert client.post(base + f"/jobs/{job['job_id']}/cancel").status_code == 200
    assert client.get(base + f"/jobs/{job['job_id']}").json["state"] == "cancelled"
    newer = create()
    database.execute(
        "UPDATE autopsy_jobs SET state = 'processing', worker_id = 'dead-worker', attempts = 3, lease_expires_at = '2000-01-01T00:00:00Z' WHERE id = ?",
        (newer["job_id"],),
    )
    with app.app_context():
        assert run_autopsy_worker_once("replacement") is None
    assert client.get(base + f"/jobs/{newer['job_id']}").json["error_code"] == "LEASE_EXPIRED"
    assert client.post(base + f"/jobs/{newer['job_id']}/retry").status_code == 409
    assert client.get(base + "/jobs/999999").status_code == 404
    assert client.post(base + "/jobs/999999/cancel").status_code == 404
    assert client.get(base + "/reports/999999").status_code == 404
    assert client.post(base + "/reports/999999/approve", json={"version": 1}).status_code == 404
    count = database.execute("SELECT COUNT(*) FROM autopsy_report_files").fetchone()[0]
    assert count == 0
