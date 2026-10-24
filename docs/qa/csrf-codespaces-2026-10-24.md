# Codespaces login CSRF recovery

The reported correlation ID belongs to the user's runtime; that runtime's logs were not available here. Repository inspection establishes a concrete failure mode: starting multiple Gunicorn workers without exporting `SOCIFY_SECRET_KEY` lets each worker obtain a different random development key, invalidating a session/CSRF token signed by another worker. A stale cached login form or blocked cookies can produce the same public error.

The new Codespaces launcher loads persistent session/encryption keys before starting Gunicorn, validates missing saved keys instead of silently replacing an existing file, and retains explicit environment overrides. It initializes schema without deleting existing data. Production configuration is explicitly rejected by this development launcher. The development container now uses the same launcher.

All HTML responses use no-store caching. Invalid login/registration form CSRF still returns HTTP 400, but now renders a fresh protected form and explains that no manual token is needed. JSON/API errors retain their existing error contract. CSRF remains enabled.

Evidence: 25 focused security tests passed; a Chromium journey with CSRF explicitly enabled rejects an invalid form token, retries using the refreshed form, logs in, and creates a protected case. Live Gunicorn 26.2.0 started with two workers through the new launcher; 20 cookie/token form round trips succeeded, while a missing-token API request remained rejected. Separate application instances also accept the same session/token using the saved Codespaces keys. See `tests/security/test_csrf_login_recovery.py` and `test_browser_login_recovers_from_invalid_csrf_with_protection_enabled`.

Users should stop the previous server, pull `socify-version-2`, run `SOCIFY_HOST=0.0.0.0 python -m scripts.start_codespace`, and open the private port in a standalone browser tab. Do not delete the saved keys, disable CSRF or expose the port publicly to work around a login error.

Final regression results: 387 tests passed in 63.76 seconds, combined branch coverage 92.74%; all eight Chromium journeys passed in 42.60 seconds. Ruff lint/format, mypy, Bandit and the existing reviewed secret-scanning gate passed.

## Follow-up: repeated error in the user's runtime

The user reported the recovery message again. Their subsequent terminal output contained a master shutdown and an empty log tail; it did not establish why CSRF validation failed. `flask_wtf.csrf` was mistakenly entered as a shell command. The earlier change therefore remains a verified mitigation for worker key inconsistency, not a confirmed resolution of the user's runtime issue.

The CSRF handler now logs an allowlisted reason code and correlation ID for every rejection, including HTTPS referrer failures that Flask-WTF does not log through its validation logger. Login and registration forms display the same diagnostic references and cause-specific recovery guidance. API errors preserve their code/status and add `error.details.reason`. No submitted credentials, token values, cookie values, raw exception descriptions or referrer URLs are included in the new diagnostic log. No CSRF, session or HTTPS referrer checks are relaxed.

Seven real rejection scenarios are exercised over HTTPS: absent token, absent session, expired token, invalid signature, different session token, absent referrer and cross-origin referrer. A matching-origin HTTPS login succeeds with protection enabled. Tests verify correlation across response/log, no-store responses and absence of credentials/tokens from the diagnostic log. See `docs/troubleshooting.md` for foreground logging instructions if the problem recurs.

The user subsequently confirmed that login works when the application is started with `python run.py`. This is recorded as the successful runtime workaround. Inspection confirms that this command uses a single-process development server, whereas the earlier launcher uses multiple Gunicorn workers. That difference is consistent with the previously identified key-sharing failure mode, but the exact reason for the earlier failed requests remains unconfirmed without their runtime rejection details. No additional runtime evidence is required from the user while login works. `run.py` is documented for development only and is not modified by this follow-up.

Follow-up verification: 395 tests passed in 75.88 seconds with 92.76% combined branch coverage; all eight Chromium journeys passed in 45.09 seconds. The 11 focused CSRF tests also passed after replacing a synthetic test password literal with an ephemeral generated value. Ruff lint/format, mypy and Bandit passed. The diagnostics change does not claim that the overall project meets final acceptance.
