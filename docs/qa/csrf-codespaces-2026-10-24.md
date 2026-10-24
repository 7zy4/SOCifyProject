# Codespaces login CSRF recovery

The reported correlation ID belongs to the user's runtime; that runtime's logs were not available here. Repository inspection establishes a concrete failure mode: starting multiple Gunicorn workers without exporting `SOCIFY_SECRET_KEY` lets each worker obtain a different random development key, invalidating a session/CSRF token signed by another worker. A stale cached login form or blocked cookies can produce the same public error.

The new Codespaces launcher loads persistent session/encryption keys before starting Gunicorn, validates missing saved keys instead of silently replacing an existing file, and retains explicit environment overrides. It initializes schema without deleting existing data. Production configuration is explicitly rejected by this development launcher. The development container now uses the same launcher.

All HTML responses use no-store caching. Invalid login/registration form CSRF still returns HTTP 400, but now renders a fresh protected form and explains that no manual token is needed. JSON/API errors retain their existing error contract. CSRF remains enabled.

Evidence: 25 focused security tests passed; a Chromium journey with CSRF explicitly enabled rejects an invalid form token, retries using the refreshed form, logs in, and creates a protected case. Live Gunicorn 26.2.0 started with two workers through the new launcher; 20 cookie/token form round trips succeeded, while a missing-token API request remained rejected. Separate application instances also accept the same session/token using the saved Codespaces keys. See `tests/security/test_csrf_login_recovery.py` and `test_browser_login_recovers_from_invalid_csrf_with_protection_enabled`.

Users should stop the previous server, pull `socify-version-2`, run `SOCIFY_HOST=0.0.0.0 python -m scripts.start_codespace`, and open the private port in a standalone browser tab. Do not delete the saved keys, disable CSRF or expose the port publicly to work around a login error.

Final regression results: 387 tests passed in 63.76 seconds, combined branch coverage 92.74%; all eight Chromium journeys passed in 42.60 seconds. Ruff lint/format, mypy, Bandit and the existing reviewed secret-scanning gate passed.
