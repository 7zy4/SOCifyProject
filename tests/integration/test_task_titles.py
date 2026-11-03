"""System task labels, searches and immutable report content keep provenance."""

import copy

import pytest

from socify.autopsy_report_render import report_table, sections
from socify.autopsy_reports import build_snapshot
from socify.cases import _case_row
from socify.db import get_db
from socify.schema import ensure_schema
from socify.task_titles import TITLES, task_title


@pytest.fixture
def case(app, client, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("analyst")
    response = client.post("/api/cases", json={"title": "Language investigation"})
    assert response.status_code == 201
    return response.json["id"]


@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("key", list(TITLES))
def test_system_title_and_search_use_active_language(case, client, language, key):
    headers = {"X-SOCify-Language": language}
    title = TITLES[key][0 if language == "en" else 1]
    task = next(item for item in client.get(f"/api/cases/{case}", headers=headers).json["tasks"] if item["system_key"] == key)
    assert task["display_title"] == title and task["title"] == TITLES[key][0]
    for query in [title, TITLES[key][0]]:
        response = client.get(f"/api/cases/{case}/tasks", query_string={"q": query}, headers=headers)
        assert response.status_code == 200 and response.json["total"] == 1
        assert response.json["items"][0]["id"] == task["id"]
    assert client.get(f"/api/incidents/{case}", headers=headers).json["tasks"][0]["display_title"]


@pytest.mark.parametrize("title", [TITLES["validate_evidence"][0], TITLES["document_response"][1], "Analyst original wording"])
def test_authored_title_cannot_claim_system_origin(case, client, title):
    response = client.post(f"/api/incidents/{case}/tasks", json={"title": title, "system_key": "validate_evidence"})
    assert response.status_code == 201
    for language in ["ar", "en"]:
        rows = client.get(f"/api/cases/{case}/tasks", headers={"X-SOCify-Language": language}).json["items"]
        task = next(item for item in rows if item["id"] == response.json["id"])
        assert task["system_key"] is None and task["display_title"] == title


def test_title_language_header_overrides_cookie(case, client):
    client.set_cookie("socify-language", "en")
    assert client.get(f"/api/cases/{case}/tasks").json["items"][0]["display_title"] == TITLES["document_response"][0]
    assert client.get(f"/api/cases/{case}/tasks", headers={"X-SOCify-Language": "ar"}).json["items"][0]["display_title"] == TITLES["document_response"][1]


def test_schema_upgrade_preserves_unknown_historical_authorship(case, database):
    original = [tuple(row) for row in database.execute("SELECT id,title,status FROM case_tasks WHERE case_id=?", (case,))]
    database.execute("ALTER TABLE case_tasks DROP COLUMN system_key")
    ensure_schema(database)
    rows = database.execute("SELECT id,title,status,system_key FROM case_tasks WHERE case_id=?", (case,)).fetchall()
    assert [tuple(row)[:3] for row in rows] == original
    assert all(row["system_key"] is None for row in rows)


@pytest.mark.parametrize(
    "title,key", [("Unmodified author text", "validate_evidence"), ("Validate primary evidence", "unknown"), ("Validate primary evidence", None)]
)
def test_unrecognized_or_changed_titles_are_not_translated(title, key):
    assert task_title(title, key, "ar") == title


def test_snapshot_carries_origin_without_mutation_or_user_translation(case, client, app):
    client.post(f"/api/incidents/{case}/tasks", json={"title": "Validate primary evidence"})
    with client.session_transaction() as session:
        context_session = dict(session)
    with app.test_request_context():
        from flask import session

        session.update(context_session)
        snapshot = build_snapshot(_case_row(case), 1, "full")
        before = copy.deepcopy(snapshot)
        task_section = next(value for heading, value in sections(snapshot) if heading == "المهام")
        markup = report_table(task_section, localize=True)
        assert "التحقق من الدليل الأساسي" in markup and "Validate primary evidence" in markup
        assert '<bdi dir="auto" data-ui-copy>التحقق من الدليل الأساسي</bdi>' in markup
        assert '<bdi dir="auto">Validate primary evidence</bdi>' in markup
        assert "system_key" not in markup and "display_title" not in markup
        assert snapshot == before
        get_db().execute("UPDATE case_tasks SET status='completed' WHERE case_id=?", (case,))
        assert snapshot == before
