"""Exact IP identity lookup must preserve evidence, pagination and access scope."""

import hashlib
import json
from pathlib import Path
from time import perf_counter

import pytest

from socify import autopsy_ingestion

COMPRESSED = "2001:db8::1"
EXPANDED = "2001:0db8:0000:0000:0000:0000:0000:0001"
MIXED = "2001:DB8:0:0::01"


def upload(client, case_id, records, **options):
    content = json.dumps(records)
    response = client.post(f"/api/cases/{case_id}/imports", json={"filename": "identities.json", "content": content, **options})
    assert response.status_code == 201, response.json
    return response.json, content


def identities():
    return [
        {"title": "Compressed source", "source_ip": COMPRESSED},
        {"title": "Expanded destination", "destination_ip": EXPANDED},
        {"title": "Mixed source", "source_ip": MIXED},
        {"title": "Adjacent address", "source_ip": "2001:db8::2"},
        {"title": "Shared prefix", "source_ip": "2001:db8::10"},
        {"title": "Unrelated address with incidental number 1", "source_ip": "2001:db8::3"},
        {"title": "Malformed address", "source_ip": "2001:db8:::1"},
    ]


@pytest.mark.parametrize("query", [COMPRESSED, EXPANDED, MIXED])
def test_ipv6_equivalent_identity_excludes_neighbor_and_keeps_original_values(autopsy_case, client, query):
    job, content = upload(client, autopsy_case, identities())
    base = f"/api/cases/{autopsy_case}"
    response = client.get(base + "/logs", query_string={"q": query, "limit": 1})
    assert response.status_code == 200, response.json
    assert response.json["total"] == 3
    assert response.json["has_next"] is True
    found = []
    for page in (1, 2, 3):
        result = client.get(base + "/logs", query_string={"q": query, "limit": 1, "page": page}).json
        assert result["total"] == 3
        assert result["has_next"] is (page < 3)
        found.extend(result["items"])
    assert len({row["id"] for row in found}) == 3
    assert {row["source_ip"] or row["destination_ip"] for row in found} == {COMPRESSED, EXPANDED, MIXED}
    for row in found:
        detail = client.get(base + f"/logs/{row['id']}").json
        retained = row["source_ip"] or row["destination_ip"]
        assert retained in json.dumps(detail["raw_payload"])
    original = client.get(base + f"/imports/{job['id']}/original")
    assert original.data == content.encode()
    assert original.headers["X-Evidence-SHA256"] == hashlib.sha256(content.encode()).hexdigest()


@pytest.mark.parametrize("format_name", ["json", "jsonl", "csv"])
def test_ip_filtered_export_reuses_identity_selection_and_redaction(autopsy_case, client, format_name):
    upload(client, autopsy_case, identities())
    base = f"/api/cases/{autopsy_case}/logs/export"
    result = client.get(base, query_string={"q": COMPRESSED, "format": format_name, "redacted": "0"})
    assert result.status_code == 200
    for address in (COMPRESSED, EXPANDED, MIXED):
        assert address in result.text
    assert "Adjacent address" not in result.text and "Malformed address" not in result.text
    redacted = client.get(base, query_string={"q": EXPANDED, "format": format_name, "redacted": "1"})
    assert redacted.status_code == 200
    assert redacted.headers["X-Redaction-Policy"] == "metadata_only_v1"
    assert all(address not in redacted.text for address in (COMPRESSED, EXPANDED, MIXED))


def test_ipv4_is_exact_and_invalid_ip_keeps_text_search(autopsy_case, client):
    upload(
        client,
        autopsy_case,
        [
            {"title": "Source match", "source_ip": "192.0.2.1"},
            {"title": "Destination match", "destination_ip": "192.0.2.1"},
            {"title": "Prefix neighbor", "source_ip": "192.0.2.10"},
            {"title": "Malformed collector value 192.0.2.999", "source_ip": "192.0.2.999"},
        ],
    )
    base = f"/api/cases/{autopsy_case}/logs"
    exact = client.get(base, query_string={"q": "192.0.2.1"}).json
    assert {row["title"] for row in exact["items"]} == {"Source match", "Destination match"}
    malformed = client.get(base, query_string={"q": "192.0.2.999"})
    assert malformed.status_code == 200
    assert malformed.json["total"] == 1
    assert malformed.json["items"][0]["source_ip"] == "192.0.2.999"


def test_ip_query_preserves_restricted_batch_case_and_job_scope(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    upload(client, autopsy_case, [{"title": "Visible match", "source_ip": COMPRESSED}])
    login_as("soc_manager")
    hidden, _ = upload(client, autopsy_case, [{"title": "Restricted match", "destination_ip": EXPANDED}])
    policy = {"restricted": True, "members": [], "reason": "Need-to-know evidence"}
    assert client.put(base + f"/imports/{hidden['id']}/access", json=policy).status_code == 200
    private = client.post(
        "/api/cases", json={"title": "Unrelated private investigation", "reason": "alert_review", "objective": "Retain unrelated evidence"}
    ).json["id"]
    upload(client, private, [{"title": "Other case match", "source_ip": COMPRESSED}])
    login_as("analyst")
    visible = client.get(base + "/logs", query_string={"q": EXPANDED}).json
    assert visible["total"] == 1 and visible["items"][0]["title"] == "Visible match"
    assert client.get(base + "/logs", query_string={"q": COMPRESSED, "job_id": hidden["id"]}).status_code == 422
    exported = client.get(base + "/logs/export", query_string={"q": EXPANDED, "format": "json", "redacted": "0"})
    assert [row["title"] for row in exported.json] == ["Visible match"]
    assert client.get(f"/api/cases/{private}/logs", query_string={"q": COMPRESSED}).status_code == 404
    login_as("soc_manager")
    assert client.put(base + f"/imports/{hidden['id']}/access", json={**policy, "members": [user_ids["analyst"]]}).status_code == 200
    login_as("analyst")
    assert client.get(base + "/logs", query_string={"q": COMPRESSED}).json["total"] == 2


def test_ip_search_historical_jobs_time_severity_and_bounded_count(autopsy_case, client, monkeypatch):
    records = [{"title": "Retained observation", "source_ip": EXPANDED, "event_time": "2021-07-08T06:15:00Z", "severity": "high"}]
    old, _ = upload(client, autopsy_case, records)
    new, _ = upload(client, autopsy_case, records, source_timezone="Asia/Riyadh")
    base = f"/api/cases/{autopsy_case}/logs"
    active = client.get(base, query_string={"q": COMPRESSED}).json
    historical = client.get(base, query_string={"q": COMPRESSED, "job_id": old["id"]}).json
    assert active["total"] == historical["total"] == 1
    assert active["items"][0]["id"] != historical["items"][0]["id"]
    assert new["id"] != old["id"]
    assert client.get(base, query_string={"q": COMPRESSED, "start": "2022-01-01T00:00:00Z"}).json["total"] == 0
    assert client.get(base, query_string={"q": COMPRESSED, "severity": "low"}).json["total"] == 0
    upload(client, autopsy_case, identities())
    monkeypatch.setattr(autopsy_ingestion, "SEARCH_COUNT_LIMIT", 2)
    capped = client.get(base, query_string={"q": COMPRESSED, "limit": 1}).json
    assert capped["total"] == 2 and capped["total_relation"] == "gte" and capped["has_next"] is True


def test_sparse_ip_lookup_with_ten_thousand_case_records(autopsy_case, client, database, user_ids):
    # Prepare a bounded isolated corpus directly; measure the actual scoped API.
    database.execute("BEGIN")
    database.executemany(
        "INSERT INTO security_events(event_id,source,severity,category,title,event_time,ingested_at,source_ip,owner_case_id) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (
                f"ip-scale-{i}",
                "test-corpus",
                "low",
                "network",
                f"Observation {i}",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                EXPANDED if i in {0, 9999} else "2001:db8::2",
                autopsy_case,
            )
            for i in range(10000)
        ],
    )
    database.execute(
        "INSERT INTO case_events(case_id,event_id,attached_by,attached_at) SELECT ?,id,?,? FROM security_events WHERE owner_case_id=?",
        (autopsy_case, user_ids["analyst"], "2026-01-01T00:00:00Z", autopsy_case),
    )
    database.commit()
    measurements = []
    for query, total in ((COMPRESSED, 2), ("2001:db8::ffff", 0), ("2001:db8::2", 9998)):
        started = perf_counter()
        result = client.get(f"/api/cases/{autopsy_case}/logs", query_string={"q": query, "limit": 1})
        elapsed = perf_counter() - started
        assert result.status_code == 200 and result.json["total"] == total
        measurements.append({"query": query, "expected_matches": total, "elapsed_seconds": round(elapsed, 4)})
    target = Path("artifacts/usability_campaign/blue-team-decisions/ip-query-measurements.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "case_records": 10000,
                "human_participants": 0,
                "measurement": "Flask test-client requests, local SQLite, concurrent development suites; not production load",
                "requests": measurements,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
