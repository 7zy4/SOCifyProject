"""Completed-work navigation uses the same authorized data as its counters."""

from datetime import timedelta

import pytest

from socify.timeutils import iso_now, utc_now
from tests.integration.test_performance_review_queue import escalate


def close(database, case_id, stamp=None):
    database.execute("UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", (stamp or iso_now(), case_id))


def test_closed_case_pagination_is_complete_stable_and_keeps_totals(autopsy_case, client, database):
    identifiers = [autopsy_case]
    for index in range(54):
        result = client.post("/api/cases", json={"title": f"Completed scope review {index}"})
        assert result.status_code == 201
        identifiers.append(result.json["id"])
    stamp = iso_now()
    for case_id in identifiers:
        close(database, case_id, stamp)
    first = client.get("/api/soc/performance?queue=closed").json
    second = client.get("/api/soc/performance?queue=closed&page=2").json
    assert first["counts"]["closed"] == second["counts"]["closed"] == 55
    assert first["queue_total"] == second["queue_total"] == 55
    assert first["queue_pages"] == 2 and first["queue_page_size"] == 50
    actual = [row["id"] for row in first["queue"] + second["queue"]]
    assert actual == sorted(identifiers, reverse=True)
    assert len(set(actual)) == 55
    assert all(row["closed_at"] == stamp and row["status"] == "closed" for row in first["queue"])
    end = client.get("/api/soc/performance?queue=closed&page=999").json
    assert end["queue_page"] == 2 and end["queue"] == second["queue"]


def test_closed_queue_obeys_period_and_reopened_state(autopsy_case, client, database):
    close(database, autopsy_case, (utc_now() - timedelta(days=8)).isoformat())
    recent = client.get("/api/soc/performance?queue=closed&days=7").json
    assert recent["queue"] == [] and recent["counts"]["closed"] == 0
    assert recent["queue_page"] == recent["queue_pages"] == 1
    month = client.get("/api/soc/performance?queue=closed&days=30").json
    assert month["queue"][0]["id"] == autopsy_case and month["counts"]["closed"] == 1
    database.execute("UPDATE incident_cases SET status='reopened' WHERE id=?", (autopsy_case,))
    assert client.get("/api/soc/performance?queue=closed&days=all").json["queue"] == []
    assert client.get("/api/soc/performance?queue=open").json["queue"][0]["id"] == autopsy_case


def test_review_queue_matches_the_review_counter_without_closed_cases(autopsy_case, client, database):
    escalate(client, autopsy_case)
    review = client.get("/api/soc/performance?queue=awaiting_review").json
    assert review["queue_total"] == review["counts"]["awaiting_review"] == 1
    assert review["queue"][0]["id"] == autopsy_case
    close(database, autopsy_case)
    review = client.get("/api/soc/performance?queue=awaiting_review").json
    assert review["queue"] == [] and review["counts"]["awaiting_review"] == 0


def test_closed_queue_retains_member_authorization(autopsy_case, client, database, login_as, user_ids):
    close(database, autopsy_case)
    assert client.get("/api/soc/performance?queue=closed&member=team").status_code == 403
    assert client.get(f"/api/soc/performance?queue=closed&member={user_ids['soc_manager']}").status_code == 403
    login_as("soc_manager")
    analyst = client.get(f"/api/soc/performance?queue=closed&member={user_ids['analyst']}").json
    assert analyst["queue"][0]["id"] == autopsy_case
    own = client.get("/api/soc/performance?queue=closed&member=me").json
    assert own["queue"] == []


@pytest.mark.parametrize("query", ["queue=unknown", "queue=open&queue=closed", "page=0", "page=-1", "page=x", "page=1000001", "page=1&page=2"])
def test_queue_filters_are_validated_before_any_results(autopsy_case, client, query):
    result = client.get("/api/soc/performance?" + query)
    assert result.status_code == 422 and result.json["error"]["code"] == "INVALID_PERFORMANCE_FILTER"
