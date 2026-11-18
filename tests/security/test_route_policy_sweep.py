"""Every URL rule under the production request policy: CSRF, authentication and the removed training API.

The sweep walks the whole URL map, so a new route is checked without being listed. The exceptions below are
written out on purpose: changing any of them should be a visible decision in review.
"""

import inspect
from urllib.parse import urlsplit

from werkzeug.routing import IntegerConverter

from socify import RETIRED_API_PREFIXES
from socify.case_policy import ANY_METHOD, CasePolicy
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
    # Aggregate counts for operators: absent until SOCIFY_METRICS_TOKEN is set, then bearer-token only (and refused by the ingress).
    ("GET", "/health/metrics"): (404, None),
    ("POST", "/api/sources/<int:source_id>/ingest"): (401, "INVALID_SOURCE_KEY"),
    ("GET", "/"): (302, "/login"),
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


def test_every_state_changing_request_requires_a_csrf_token(app):
    app.config.update(WTF_CSRF_ENABLED=True)
    accepted = {}
    for method, rule, path in _requests(app):
        if method in SAFE_METHODS:
            continue
        status, code, _ = _outcome(app.test_client(), method, path)
        if status != 400 or (path.startswith("/api/") and code != "CSRF_VALIDATION_FAILED"):
            accepted[(method, rule)] = (status, code)
    assert set(accepted) == CSRF_EXEMPT, accepted


def test_anonymous_requests_are_refused_outside_the_public_list(app):
    # CSRF is covered above and is off in the test configuration; this isolates authentication.
    mismatches = []
    for method, rule, path in _requests(app):
        status, code, location = _outcome(app.test_client(), method, path)
        if (method, rule) in PUBLIC:
            expected = PUBLIC[(method, rule)]
            actual = (status, location if status == 302 else code)
        elif path.startswith("/api/") or status == 401:  # pages guarded by a permission check refuse like the API
            expected, actual = (401, "AUTHENTICATION_REQUIRED"), (status, code)
        else:
            expected, actual = (302, "/login"), (status, location)
        if actual != expected:
            mismatches.append((method, rule, actual, expected))
    assert not mismatches, mismatches


def test_no_registered_route_is_refused_as_retired(app, user_ids):
    # The training platform's routes were deleted; a registered route answering 410 would be a view nobody can reach.
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
    assert not blocked, sorted(blocked)
    assert not other, other


def test_removed_legacy_paths_still_answer_gone(app, user_ids):
    # The training platform's API was deleted, not hidden: old clients get a stable 410 instead of a bare 404.
    client = app.test_client()
    for anonymous in (True, False):
        if not anonymous:
            with client.session_transaction() as state:
                state.update(user_id=user_ids["admin"], workspace_id=1, user_role="admin", session_id=issue_session(app, user_ids["admin"]))
        for prefix in sorted(RETIRED_API_PREFIXES):
            for method, path in (("GET", f"/api/{prefix}"), ("POST", f"/api/{prefix}/1/anything"), ("GET", f"/api/{prefix}/runs/1")):
                assert _outcome(client, method, path)[:2] == (410, "CASE_CONTEXT_REQUIRED"), (anonymous, method, path)


# Views exempt from part of the case guards (socify.case_policy). Every other view that names a case is strict: the case
# must be approved, selected and fully accessible. Adding a row here is the visible decision to relax a view.
BATCH_MEMBER_ANY = CasePolicy(batch_member=ANY_METHOD)
RELAXED_CASE_VIEWS = {
    "ui.dashboard": CasePolicy(before_approval=ANY_METHOD, batch_member=frozenset({"GET"})),  # the page shows the approval state itself
    "autopsy_workspace.review_case": CasePolicy(before_approval=ANY_METHOD),  # creates the approval
    "autopsy_workspace.link_cases": CasePolicy(before_approval=ANY_METHOD),
    "autopsy.case_get": CasePolicy(before_approval=frozenset({"GET"}), batch_member=frozenset({"GET"})),
    "cases.case_detail": CasePolicy(before_approval=frozenset({"GET"}), batch_member=frozenset({"GET"})),
    "autopsy_investigation.case_timeline": CasePolicy(batch_member=frozenset({"GET"})),
    # Import and log views filter by batch themselves, so a batch-scoped member may use them.
    **{
        f"autopsy_ingestion.{name}": BATCH_MEMBER_ANY
        for name in (
            "case_import_access",
            "case_import_activate",
            "case_import_cancel",
            "case_import_create",
            "case_import_detail",
            "case_import_list",
            "case_import_preview",
            "case_import_resume",
            "case_log_detail",
            "case_logs",
            "export_case_logs",
            "original_import",
            "select_log_exhibit",
        )
    },
    # The case is not in the URL: it comes from the JSON body or from the stored assignment.
    "teams.assign_logs": CasePolicy(case_from="body"),
    "teams.update_assignment": CasePolicy(case_from="assignment"),
}


def test_relaxed_case_views_are_exactly_the_reviewed_set(app):
    declared = {endpoint: view.case_policy for endpoint, view in app.view_functions.items() if hasattr(view, "case_policy")}
    assert declared == RELAXED_CASE_VIEWS
    rules = {rule.endpoint: rule for rule in app.url_map.iter_rules()}
    for endpoint, policy in declared.items():
        methods = rules[endpoint].methods or set()
        # A relaxation for a method the route does not answer would be dead text that looks like a rule.
        named = (policy.before_approval | policy.batch_member) - ANY_METHOD if ANY_METHOD in (policy.before_approval, policy.batch_member) else set()
        assert not named
        for relaxed in (policy.before_approval, policy.batch_member):
            assert relaxed == ANY_METHOD or relaxed <= methods, (endpoint, sorted(relaxed - methods))
        if policy.case_from == "url":
            assert any("case_id" in rule.arguments for rule in app.url_map.iter_rules() if rule.endpoint == endpoint), endpoint
        else:
            assert "case_id" not in rules[endpoint].arguments, endpoint
    assert "assignment_id" in rules["teams.update_assignment"].arguments


def test_a_view_declared_under_another_decorator_is_not_silently_strict(app):
    # The declaration must reach the function Flask dispatches; a decorator that does not copy attributes would hide it.
    undeclared = {
        endpoint for endpoint, view in app.view_functions.items() if not hasattr(view, "case_policy") and hasattr(inspect.unwrap(view), "case_policy")
    }
    assert not undeclared, sorted(undeclared)


def test_anonymous_assignment_update_is_refused_without_a_server_error(app):
    app.config["TESTING"] = False  # production error handling: an exception here would become a 500
    response = app.test_client().patch("/api/team/assignments/1", json={"status": "completed"})
    assert response.status_code == 401 and response.json["error"]["code"] == "AUTHENTICATION_REQUIRED"
