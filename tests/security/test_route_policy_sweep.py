"""Every URL rule under the production request policy: CSRF, authentication and retired legacy routes.

The sweep walks the whole URL map, so a new route is checked without being listed. The exceptions below are
written out on purpose: changing any of them should be a visible decision in review.
"""

from urllib.parse import urlsplit

from werkzeug.routing import IntegerConverter

from socify import OPERATIONAL_BLUEPRINT_PREFIX, OPERATIONAL_BLUEPRINTS, OPERATIONAL_LEGACY_ENDPOINTS, RETIRED_API_PREFIXES
from socify.autopsy_pipeline import PARTIAL_SCOPE_BLUEPRINT, PARTIAL_SCOPE_READ_ENDPOINTS, PARTIAL_SCOPE_TIMELINE_ENDPOINT
from socify.autopsy_workspace import ASSIGN_LOGS_ENDPOINT, CASE_GATE_BLUEPRINT, CASE_READ_ENDPOINTS, PAGE_BLUEPRINT, UPDATE_ASSIGNMENT_ENDPOINT
from tests.conftest import issue_session

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# State-changing requests accepted without a CSRF token; each authenticates with its own credential instead.
CSRF_EXEMPT = {("POST", "/api/sources/<int:source_id>/ingest")}  # per-source ingestion key

# Rules an anonymous browser may use, and the answer it gets to an empty request (status, error code or redirect path).
PUBLIC = {
    ("GET", "/login"): (200, None),
    ("POST", "/login"): (401, "INVALID_CREDENTIALS"),
    ("GET", "/register"): (200, None),
    ("POST", "/register"): (403, "REGISTRATION_DISABLED"),
    ("POST", "/logout"): (200, None),
    ("POST", "/api/auth/login"): (401, "INVALID_CREDENTIALS"),
    ("POST", "/api/auth/register"): (403, "REGISTRATION_DISABLED"),
    ("POST", "/api/auth/logout"): (200, None),
    ("GET", "/api/auth/csrf"): (200, None),
    ("GET", "/health/live"): (200, None),
    ("GET", "/health/ready"): (200, None),
    ("POST", "/api/sources/<int:source_id>/ingest"): (401, "INVALID_SOURCE_KEY"),
    ("GET", "/"): (302, "/login"),
    ("GET", "/test"): (302, "/analysis-library"),  # redirect only; the target page requires an account
}

# Legacy training-platform API retired in operational mode: answered 410 before any view runs.
RETIRED = {
    ("GET", "/api/alerts"),
    ("GET", "/api/alerts/<int:alert_id>"),
    ("POST", "/api/alerts/<int:alert_id>/triage"),
    ("GET", "/api/assessments/<int:assessment_id>"),
    ("POST", "/api/assessments/<int:assessment_id>"),
    ("GET", "/api/assessments/<int:assessment_id>/report"),
    ("GET", "/api/attack/catalogs"),
    ("POST", "/api/attack/catalogs/<version>/activate"),
    ("GET", "/api/attack/coverage"),
    ("GET", "/api/attack/matrix"),
    ("GET", "/api/attack/navigator-layer"),
    ("GET", "/api/attack/techniques"),
    ("GET", "/api/attack/techniques/<path:technique_id>"),
    ("GET", "/api/dashboard"),
    ("GET", "/api/events"),
    ("POST", "/api/events"),
    ("DELETE", "/api/events/<int:event_id>"),
    ("GET", "/api/events/<int:event_id>"),
    ("PUT", "/api/events/<int:event_id>"),
    ("GET", "/api/events/<int:event_id>/raw"),
    ("GET", "/api/events/export"),
    ("POST", "/api/hunt/query"),
    ("GET", "/api/hunt/saved-queries"),
    ("POST", "/api/hunt/saved-queries"),
    ("DELETE", "/api/hunt/saved-queries/<int:query_id>"),
    ("GET", "/api/imports"),
    ("POST", "/api/imports"),
    ("GET", "/api/imports/<int:job_id>"),
    ("POST", "/api/imports/<int:job_id>/cancel"),
    ("GET", "/api/imports/<int:job_id>/evidence"),
    ("POST", "/api/imports/<int:job_id>/resume"),
    ("POST", "/api/imports/preview"),
    ("GET", "/api/iocs"),
    ("POST", "/api/iocs/<int:ioc_id>/enrich"),
    ("POST", "/api/iocs/extract"),
    ("POST", "/api/lab/event"),
    ("GET", "/api/leaderboards"),
    ("POST", "/api/playbook-runs"),
    ("GET", "/api/playbook-runs/<int:run_id>"),
    ("POST", "/api/playbook-runs/<int:run_id>/approve"),
    ("POST", "/api/playbook-runs/<int:run_id>/cancel"),
    ("POST", "/api/playbook-runs/<int:run_id>/retry"),
    ("POST", "/api/playbook-runs/<int:run_id>/rollback"),
    ("GET", "/api/playbooks"),
    ("POST", "/api/playbooks"),
    ("POST", "/api/playbooks/<int:playbook_id>/preview"),
    ("POST", "/api/playbooks/<int:playbook_id>/versions"),
    ("GET", "/api/profile"),
    ("PUT", "/api/profile/leaderboard"),
    ("GET", "/api/rules"),
    ("POST", "/api/rules"),
    ("DELETE", "/api/rules/<int:rule_id>"),
    ("GET", "/api/rules/<int:rule_id>"),
    ("PUT", "/api/rules/<int:rule_id>"),
    ("POST", "/api/rules/<int:rule_id>/backfill"),
    ("POST", "/api/rules/<int:rule_id>/clone"),
    ("POST", "/api/rules/<int:rule_id>/rollback"),
    ("POST", "/api/rules/<int:rule_id>/test"),
    ("POST", "/api/rules/<int:rule_id>/toggle"),
    ("GET", "/api/rules/<int:rule_id>/versions"),
    ("GET", "/api/scenarios"),
    ("POST", "/api/scenarios"),
    ("GET", "/api/scenarios/<int:scenario_id>"),
    ("POST", "/api/scenarios/<int:scenario_id>/clone"),
    ("POST", "/api/scenarios/<int:scenario_id>/transition"),
    ("POST", "/api/scenarios/<int:scenario_id>/versions"),
    ("GET", "/api/scores/me"),
    ("GET", "/api/settings"),
    ("GET", "/api/stats"),
    ("GET", "/api/stream/events"),
    ("GET", "/api/training/runs"),
    ("POST", "/api/training/runs"),
    ("GET", "/api/training/runs/<int:run_id>"),
    ("GET", "/api/training/runs/<int:run_id>/ground-truth"),
    ("POST", "/api/training/runs/<int:run_id>/ground-truth"),
    ("POST", "/api/training/runs/<int:run_id>/hints"),
    ("POST", "/api/training/runs/<int:run_id>/pause"),
    ("POST", "/api/training/runs/<int:run_id>/play"),
    ("POST", "/api/training/runs/<int:run_id>/restart"),
    ("POST", "/api/training/runs/<int:run_id>/resume"),
    ("GET", "/api/training/runs/<int:run_id>/score"),
    ("POST", "/api/training/runs/<int:run_id>/submit"),
    ("GET", "/api/visualizations/graph"),
    ("GET", "/api/visualizations/graph/export"),
    ("GET", "/api/visualizations/timeline"),
}


def _requests(app):
    for rule in sorted(app.url_map.iter_rules(), key=lambda item: item.rule):
        if rule.endpoint == "static":
            continue
        path = rule.build({name: 1 if isinstance(converter, IntegerConverter) else "x" for name, converter in rule._converters.items()}, append_unknown=False)[
            1
        ]
        for method in sorted((rule.methods or set()) - {"HEAD", "OPTIONS"}):
            yield method, rule.rule, path


def _outcome(client, method, path):
    try:
        response = client.open(path, method=method, json=None if method in SAFE_METHODS else {})
    except Exception as error:  # a crash is a finding, reported with every other mismatch
        return f"raised {type(error).__name__}", None, ""
    body = response.get_json(silent=True)
    code = body.get("error", {}).get("code") if isinstance(body, dict) else None
    return response.status_code, code, urlsplit(response.headers.get("Location", "")).path


def _operational(app, *, csrf):
    app.config.update(LEGACY_TRAINING_TESTS=False, WTF_CSRF_ENABLED=csrf)


def test_every_state_changing_request_requires_a_csrf_token(app):
    _operational(app, csrf=True)
    accepted = {}
    for method, rule, path in _requests(app):
        if method in SAFE_METHODS:
            continue
        status, code, _ = _outcome(app.test_client(), method, path)
        if status != 400 or (path.startswith("/api/") and code != "CSRF_VALIDATION_FAILED"):
            accepted[(method, rule)] = (status, code)
    assert set(accepted) == CSRF_EXEMPT, accepted


def test_anonymous_requests_are_refused_outside_the_public_list(app):
    _operational(app, csrf=False)  # CSRF is covered above; this isolates authentication
    mismatches = []
    for method, rule, path in _requests(app):
        status, code, location = _outcome(app.test_client(), method, path)
        if (method, rule) in PUBLIC:
            expected = PUBLIC[(method, rule)]
            actual = (status, location if status == 302 else code)
        elif (method, rule) in RETIRED:
            expected, actual = (410, "CASE_CONTEXT_REQUIRED"), (status, code)
        elif path.startswith("/api/") or status == 401:  # pages guarded by a permission check refuse like the API
            expected, actual = (401, "AUTHENTICATION_REQUIRED"), (status, code)
        else:
            expected, actual = (302, "/login"), (status, location)
        if actual != expected:
            mismatches.append((method, rule, actual, expected))
    assert not mismatches, mismatches


def test_retired_legacy_routes_are_exactly_the_documented_set(app, user_ids):
    _operational(app, csrf=False)
    for endpoint in list(app.view_functions):
        if endpoint != "static":
            app.view_functions[endpoint] = lambda **_: ("", 299)  # reached the view: not blocked by request policy
    client = app.test_client()
    blocked, other = set(), []
    for method, rule, path in _requests(app):
        with client.session_transaction() as state:
            state.update(user_id=user_ids["admin"], workspace_id=1, user_role="admin", session_id=issue_session(app, user_ids["admin"]))
        status, code, _ = _outcome(client, method, path)
        if (status, code) == (410, "CASE_CONTEXT_REQUIRED"):
            blocked.add((method, rule))
        elif status != 299:
            other.append((method, rule, status, code))
    assert blocked == RETIRED, {"unexpectedly retired": sorted(blocked - RETIRED), "unexpectedly open": sorted(RETIRED - blocked)}
    assert not other, other


def test_policy_names_used_by_request_guards_exist(app):
    endpoints = set(app.view_functions)
    rules = {rule.endpoint: rule for rule in app.url_map.iter_rules()}
    named = set(OPERATIONAL_LEGACY_ENDPOINTS) | {ASSIGN_LOGS_ENDPOINT, UPDATE_ASSIGNMENT_ENDPOINT, PARTIAL_SCOPE_TIMELINE_ENDPOINT}
    named |= set(CASE_READ_ENDPOINTS) | set(PARTIAL_SCOPE_READ_ENDPOINTS)
    assert named <= endpoints, sorted(named - endpoints)
    blueprints = set(OPERATIONAL_BLUEPRINTS) | {PAGE_BLUEPRINT, CASE_GATE_BLUEPRINT, PARTIAL_SCOPE_BLUEPRINT}
    assert blueprints <= set(app.blueprints), sorted(blueprints - set(app.blueprints))
    assert any(name.startswith(OPERATIONAL_BLUEPRINT_PREFIX) for name in app.blueprints)
    segments = {rule.rule.split("/")[2] for rule in app.url_map.iter_rules() if rule.rule.startswith("/api/")}
    assert set(RETIRED_API_PREFIXES) <= segments, sorted(set(RETIRED_API_PREFIXES) - segments)
    # guard_workspace reads these request details; a renamed argument would silently skip the case check.
    assert "assignment_id" in rules[UPDATE_ASSIGNMENT_ENDPOINT].arguments
    assert all(
        "GET" in (rules[name].methods or set()) for name in set(CASE_READ_ENDPOINTS) | set(PARTIAL_SCOPE_READ_ENDPOINTS) | {PARTIAL_SCOPE_TIMELINE_ENDPOINT}
    )


def test_anonymous_assignment_update_is_refused_without_a_server_error(app):
    _operational(app, csrf=False)
    app.config["TESTING"] = False  # production error handling: an exception here would become a 500
    response = app.test_client().patch("/api/team/assignments/1", json={"status": "completed"})
    assert response.status_code == 401 and response.json["error"]["code"] == "AUTHENTICATION_REQUIRED"
