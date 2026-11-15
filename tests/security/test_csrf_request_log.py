"""A request refused for a missing CSRF token is logged like any other request, plus the csrf_rejected reason."""

import logging
import re


def test_csrf_rejection_writes_the_request_line_and_the_reason(app, client, caplog):
    app.config.update(WTF_CSRF_ENABLED=True, LEGACY_TRAINING_TESTS=False)
    with caplog.at_level(logging.INFO):
        response = client.post("/api/cases?q=private-search-term", json={"title": "No token"})
    assert response.status_code == 400 and response.json["error"]["code"] == "CSRF_VALIDATION_FAILED"
    identifier = response.headers["X-Correlation-ID"]
    messages = [record.getMessage() for record in caplog.records if record.name == "socify"]
    assert f"csrf_rejected reason=TOKEN_MISSING correlation_id={identifier}" in messages
    request_lines = [message for message in messages if message.startswith("request ")]
    assert len(request_lines) == 1, request_lines
    assert re.fullmatch(rf"request method=POST path=/api/cases status=400 duration_ms=\d+\.\d correlation_id={identifier} user_id=-", request_lines[0])
    assert all("private-search-term" not in record.getMessage() for record in caplog.records)
