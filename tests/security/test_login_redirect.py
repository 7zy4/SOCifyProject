"""Sign-in returns only to a page of this site, whatever the next parameter holds."""

import pytest

from socify.auth import safe_next_path


@pytest.mark.parametrize("value", ["/cases", "/cases/7?tab=logs", "/monitoring?channel=intake&status=open", "/reports?case_id=3"])
def test_same_site_pages_are_kept(value):
    assert safe_next_path(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "//evil.example",
        "/\evil.example",
        "/\t/evil.example",
        "/\n/evil.example",
        "/ /evil.example",
        "/%2F%2Fevil.example",
        "/%2f/evil.example",
        "/%5Cevil.example",
        "https://evil.example",
        "javascript:alert(1)",
        "/login?next=/x",
        "/api/auth/me",
        "/cases ",
        None,
        "/" + "a" * 3000,
    ],
)
def test_other_sites_control_characters_and_sign_in_pages_fall_back_to_cases(value):
    assert safe_next_path(value) == "/cases"


def test_a_signed_in_visit_to_the_login_page_never_leaves_the_site(client, login_as):
    login_as("analyst")
    response = client.get("/login?next=/%09/evil.example")
    assert response.status_code == 302 and response.location == "/cases"
