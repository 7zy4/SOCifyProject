import json
import socket

from socify.db import get_db
from socify.import_worker import run_import_worker_once


def test_import_quota_cancel_then_resume_after_worker_restart_preserves_evidence(autopsy_case, app, client):
    app.config.update(IMPORT_INLINE_EXECUTION=False, MAX_PENDING_IMPORT_JOBS=1)
    base = f"/api/cases/{autopsy_case}"
    first = client.post(base + "/imports", json={"filename": "first.json", "content": '[{"title":"Cancelled original still retained"}]'})
    assert first.status_code == 202
    content = json.dumps([{"title": "Recovered bounded queue event", "source_ip": "192.0.2.80"}])
    assert client.post(base + "/imports", json={"filename": "second.json", "content": content}).status_code == 429
    assert client.get(base + "/logs").status_code == 200
    assert client.post(base + f"/imports/{first.json['id']}/cancel").status_code == 200
    second = client.post(base + "/imports", json={"filename": "second.json", "content": content})
    assert second.status_code == 202
    with app.app_context():
        assert run_import_worker_once(get_db(), "new-worker-after-interruption") is not None
    state = client.get(base + f"/imports/{second.json['id']}").json
    assert state["status"] == "completed" and state["accepted"] == 1
    assert client.get(base + "/logs").json["total"] == 1
    assert client.get(base + "/custody").json["integrity_valid"] is True
    assert client.get(base + f"/imports/{first.json['id']}").json["raw_evidence"]["available"] is True


def test_observable_url_is_preserved_as_data_without_network_or_dns(autopsy_case, client, monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("User-controlled observable triggered network or DNS")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    base = f"/api/cases/{autopsy_case}"
    url = "https://malicious.invalid/collect?case=synthetic"
    created = client.post(
        base + "/records/indicator",
        json={
            "type": "url",
            "value": url,
            "classification": "observable",
            "confidence": 20,
            "source": "Retained synthetic log",
            "description": "Unvisited URL",
        },
    )
    assert created.status_code == 201, created.json
    assert client.get(base + "/records?kind=indicator").json["items"][0]["payload"]["value"] == url
