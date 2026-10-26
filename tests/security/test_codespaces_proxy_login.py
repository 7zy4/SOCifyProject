import re
import secrets

import pytest

from scripts.bootstrap_team import create_manager
from socify import create_app

PUBLIC_HOST = "socify-login-fixture-5000.app.github.dev"
UPSTREAM = "https://localhost:5000"


@pytest.fixture
def forwarded_login(app, monkeypatch):
    monkeypatch.setenv("CODESPACE_NAME", "socify-login-fixture")
    monkeypatch.setenv("SOCIFY_PORT", "5000")
    configuration = {key: app.config[key] for key in ("DATABASE", "TESTING", "SECRET_KEY", "CREDENTIAL_KEY")}
    configuration.update(WTF_CSRF_ENABLED=True, LEGACY_TRAINING_TESTS=False)
    application = create_app(configuration)
    password = secrets.token_urlsafe(24)
    create_manager(application, "manager@example.test", "Local manager", "Private team", password)
    return application, password


def submit(application, password, *, headers=None, address="127.0.0.1", invalid_token=False):
    client = application.test_client()
    forwarding = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": PUBLIC_HOST}
    page = client.get("/login", base_url=UPSTREAM, headers=forwarding, environ_overrides={"REMOTE_ADDR": address})
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert csrf is not None, page.status_code
    response = client.post(
        "/login",
        base_url=UPSTREAM,
        headers={"Referer": f"https://{PUBLIC_HOST}/login", **forwarding, **(headers or {})},
        environ_overrides={"REMOTE_ADDR": address},
        data={"email": "manager@example.test", "password": password, "csrf_token": "invalid" if invalid_token else csrf[1]},
    )
    return client, response


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "::ffff:127.0.0.1"])
def test_codespaces_https_login_uses_configured_public_origin_from_loopback(forwarded_login, address):
    application, password = forwarded_login
    client, response = submit(application, password, address=address)
    assert response.status_code == 302, response.text
    assert response.headers["Location"] == "/dashboard"
    dashboard = client.get("/dashboard", base_url=UPSTREAM)
    assert dashboard.status_code == 302
    assert dashboard.headers["Location"] == "/cases"
    assert client.get("/api/auth/me", base_url=UPSTREAM).status_code == 200


def test_codespaces_https_without_forwarded_host_retains_the_configured_authority(forwarded_login):
    application, password = forwarded_login
    _, response = submit(application, password, headers={"X-Forwarded-Host": ""})
    assert response.status_code == 302, response.text


def test_direct_local_https_login_is_not_rewritten(forwarded_login):
    application, password = forwarded_login
    client = application.test_client()
    page = client.get("/login", base_url=UPSTREAM)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert csrf is not None
    response = client.post(
        "/login",
        base_url=UPSTREAM,
        headers={"Referer": UPSTREAM + "/login"},
        data={"email": "manager@example.test", "password": password, "csrf_token": csrf[1]},
    )
    assert response.status_code == 302


def test_codespaces_uses_https_authority_instead_of_the_upstream_port(forwarded_login):
    application, password = forwarded_login
    _, response = submit(application, password, headers={"X-Forwarded-Host": PUBLIC_HOST + ":443", "X-Forwarded-Port": "5000"})
    assert response.status_code == 302, response.text


def test_trusted_gunicorn_ssl_marker_is_supported(forwarded_login):
    application, password = forwarded_login
    _, response = submit(application, password, headers={"X-Forwarded-Proto": "", "X-Forwarded-SSL": "on"})
    assert response.status_code == 302, response.text


def test_forwarded_metadata_cannot_replace_an_untrusted_host(forwarded_login):
    application, password = forwarded_login
    _, response = submit(application, password, headers={"Host": "attacker.example"})
    assert response.status_code == 400


def test_invalid_proxy_address_is_not_trusted(forwarded_login):
    application, password = forwarded_login
    _, response = submit(application, password, address="not-an-ip-address")
    assert response.status_code == 400
    assert "CSRF: REFERRER_MISMATCH" in response.text


@pytest.mark.parametrize("referrer", ["https://attacker.example/login", "https://other-codespace-5000.app.github.dev/login", ""])
def test_forwarded_login_still_rejects_foreign_or_missing_referrer(forwarded_login, referrer):
    application, password = forwarded_login
    _, response = submit(application, password, headers={"Referer": referrer})
    assert response.status_code == 400
    assert "CSRF: REFERRER_" in response.text


def test_forwarded_login_still_requires_a_valid_session_bound_token(forwarded_login):
    application, password = forwarded_login
    _, response = submit(application, password, invalid_token=True)
    assert response.status_code == 400
    assert "CSRF: TOKEN_INVALID" in response.text


def test_untrusted_client_cannot_claim_the_codespaces_proxy_identity(forwarded_login):
    application, password = forwarded_login
    _, response = submit(application, password, address="198.51.100.20", headers={"X-Forwarded-For": "127.0.0.1"})
    assert response.status_code == 400
    assert "CSRF: REFERRER_MISMATCH" in response.text


@pytest.mark.parametrize("host", ["attacker.example", "other-codespace-5000.app.github.dev", PUBLIC_HOST + ", attacker.example"])
def test_conflicting_forwarded_authority_is_rejected(forwarded_login, host):
    application, password = forwarded_login
    _, response = submit(application, password, headers={"X-Forwarded-Host": host})
    assert response.status_code == 400


def test_production_does_not_implicitly_trust_codespaces_forwarding(forwarded_login):
    application, password = forwarded_login
    production = create_app({**{key: application.config[key] for key in ("DATABASE", "TESTING", "SECRET_KEY", "CREDENTIAL_KEY")}, "ENV_NAME": "production"})
    _, response = submit(production, password)
    assert response.status_code == 400
    assert "CSRF: REFERRER_MISMATCH" in response.text
