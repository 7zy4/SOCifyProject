import json

import pytest

from socify.chronology_time import record_clock, sql_utc_key, utc_key
from socify.timeutils import parse_timestamp


def add(client, base, kind, payload):
    result = client.post(base + "/records/" + kind, json=payload)
    assert result.status_code == 201, result.json
    return result.json


def test_combined_chronology_preserves_microseconds_provenance_pagination_and_unknown_time(autopsy_case, client, user_ids):
    base = f"/api/cases/{autopsy_case}"
    content = json.dumps(
        [
            {"title": "Chronology one microsecond", "event_time": "2026-10-20T10:00:00.000001Z"},
            {"title": "Chronology whole second", "event_time": "2026-10-20T10:00:00Z"},
            {"title": "Chronology half second", "event_time": "2026-10-20T10:00:00.5Z"},
            {"title": "Chronology unknown source time"},
        ]
    )
    assert client.post(base + "/imports", json={"filename": "chronology.json", "content": content}).status_code == 201
    logs = client.get(base + "/logs").json["items"]
    first = next(row for row in logs if row["title"] == "Chronology whole second")
    exhibit = client.post(base + f"/logs/{first['id']}/exhibit", json={}).json["id"]
    add(
        client,
        base,
        "timeline",
        {
            "title": "Chronology investigator observation",
            "event_time": "2026-10-20T10:00:00.000002Z",
            "category": "observed",
            "source": "Retained exhibit",
            "evidence_id": exhibit,
        },
    )
    add(
        client,
        base,
        "timeline",
        {"title": "Chronology hypothesis", "event_time": "2026-10-20T10:00:00.000003Z", "category": "hypothesis", "source": "Investigator hypothesis only"},
    )
    add(
        client,
        base,
        "response",
        {
            "title": "Chronology containment",
            "phase": "containment",
            "status": "succeeded",
            "performed_at": "2026-10-20T10:00:00.000004Z",
            "performed_by": user_ids["analyst"],
            "evidence_id": exhibit,
            "details": "Documented authorized action, no remote execution",
        },
    )
    add(client, base, "war_room", {"title": "Chronology team decision", "body": "Use retained evidence before attribution", "visibility": "team"})
    assert client.post(f"/api/incidents/{autopsy_case}/notes", json={"body": "Chronology shared legacy note", "visibility": "team"}).status_code == 201
    result = client.get(base + "/chronology?limit=100")
    assert result.status_code == 200, result.json
    data = result.json
    assert data["total"] == 9 and data["total_relation"] == "eq" and not data["has_next"]
    assert [row["title"] for row in data["items"][:6]] == [
        "Chronology whole second",
        "Chronology one microsecond",
        "Chronology investigator observation",
        "Chronology hypothesis",
        "Chronology containment",
        "Chronology half second",
    ]
    assert data["items"][3]["time_basis"] == "hypothesis_time"
    assert data["items"][4]["time_basis"] == "reported_action_time"
    assert data["items"][-1]["event_time"] is None
    assert data["items"][-1]["observed_time_known"] is False
    notes = [row for row in data["items"] if row["entry_type"] == "note" or row.get("kind") == "war_room"]
    assert all(row["time_basis"] == "documentation_time" for row in notes)
    keys = []
    for page in range(1, 6):
        batch = client.get(base + f"/chronology?limit=2&page={page}").json
        keys.extend(row["key"] for row in batch["items"])
        assert batch["has_next"] is (page < 5)
    assert keys == [row["key"] for row in data["items"]]
    assert len(keys) == len(set(keys))
    exact = client.get(base + "/chronology?start=2026-10-20T10:00:00.000001Z&end=2026-10-20T10:00:00.000003Z").json
    assert [row["title"] for row in exact["items"]] == ["Chronology one microsecond", "Chronology investigator observation", "Chronology hypothesis"]
    filtered = client.get(base + "/logs?start=2026-10-20T10:00:00.000001Z&end=2026-10-20T10:00:00.000003Z").json
    assert [row["title"] for row in filtered["items"]] == ["Chronology one microsecond"]
    report = client.post(base + "/reports", json={"version": client.get(base).json["version"]})
    assert report.status_code == 202
    snapshot = client.get(base + f"/reports/{report.json['id']}").json["payload"]
    assert snapshot["chronology"]["entries"][0]["title"] == "Chronology whole second"
    assert sum(row["entry_type"] == "log" for row in snapshot["chronology"]["entries"]) == 1
    assert any(row["time_basis"] == "reported_action_time" for row in snapshot["chronology"]["entries"])


def test_combined_chronology_search_and_private_counts_obey_actor_and_batch_scope(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    assert client.post(base + "/imports", json={"filename": "scope.json", "content": '[{"title":"shared literal_key observation"}]'}).status_code == 201
    for visibility in ("team", "private"):
        add(client, base, "war_room", {"title": visibility + " literal_key", "body": "literal_key retained context", "visibility": visibility})
        assert (
            client.post(f"/api/incidents/{autopsy_case}/notes", json={"body": visibility + " literal_key legacy note", "visibility": visibility}).status_code
            == 201
        )
    assert client.get(base + "/chronology?q=literal_key").json["total"] == 5
    login_as("soc_manager")
    assert client.post(base + "/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer"}).status_code == 200
    login_as("auditor")
    visible = client.get(base + "/chronology?q=literal_key").json
    assert visible["total"] == 3
    assert "private literal_key" not in json.dumps(visible)
    assert client.get(base + "/chronology?q=non_matching_token").json["total"] == 0
    login_as("soc_manager")
    restricted = client.post(base + "/imports", json={"filename": "restricted.json", "content": '[{"title":"Hidden chronology batch"}]'}).json
    assert (
        client.put(
            base + f"/imports/{restricted['id']}/access", json={"restricted": True, "members": [], "reason": "Chronology full-scope boundary"}
        ).status_code
        == 200
    )
    login_as("auditor")
    assert client.get(base + "/chronology").status_code == 403
    assert client.get(base + "/timeline").status_code == 200
    assert client.get("/api/cases/999999/chronology").status_code == 404


@pytest.mark.parametrize(
    "query",
    [
        "page=0",
        "limit=101",
        "page=NaN",
        "unknown=1",
        "job_id=1",
        "severity=unknown",
        "q=" + "a" * 201,
        "start=invalid",
        "start=2026-10-21T00:00:00Z&end=2026-10-20T00:00:00Z",
    ],
)
def test_chronology_rejects_invalid_filters_before_querying_evidence(autopsy_case, client, query):
    result = client.get(f"/api/cases/{autopsy_case}/chronology?{query}")
    assert result.status_code == 422, result.json


def test_timeline_clock_expressions_are_closed_and_preserve_fractional_precision():
    assert utc_key("2026-10-20T13:00:00.000001+03:00") == "2026-10-20T10:00:00.000001Z"
    assert parse_timestamp(utc_key("2026-10-20T10:00:00Z")) == parse_timestamp("2026-10-20T10:00:00Z")
    with pytest.raises(ValueError):
        sql_utc_key("event_time); DROP TABLE users; --")
    with pytest.raises(ValueError):
        record_clock("untrusted")


def test_streamed_chronology_keeps_cross_source_equal_time_ties_stable_across_pages(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    assert (
        client.post(
            base + "/imports",
            json={
                "filename": "ties.json",
                "content": json.dumps([{"title": title, "event_time": "2026-10-20T10:00:00Z"} for title in ("Tie first log", "Tie second log")]),
            },
        ).status_code
        == 201
    )
    for index in range(2):
        add(
            client,
            base,
            "timeline",
            {"title": f"Tie observation {index}", "event_time": "2026-10-20T10:00:00Z", "category": "observed", "source": "Synthetic timing tie"},
        )
        assert client.post(f"/api/incidents/{autopsy_case}/notes", json={"body": f"Tie shared note {index}", "visibility": "team"}).status_code == 201
    database.execute("UPDATE case_notes SET created_at='2026-10-20T10:00:00Z' WHERE case_id=?", (autopsy_case,))
    all_items = client.get(base + "/chronology?limit=100").json["items"]
    assert [row["entry_type"] for row in all_items] == ["log", "log", "note", "note", "record", "record"]
    pages = [client.get(base + f"/chronology?limit=2&page={page}").json for page in range(1, 4)]
    assert [row["key"] for page in pages for row in page["items"]] == [row["key"] for row in all_items]
    assert [page["has_next"] for page in pages] == [True, True, False]
    assert client.get(base + "/chronology?limit=100&page=1000000").json["items"] == []
