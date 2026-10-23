import shutil
import sqlite3
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

from socify import create_app
from socify.db import connect_path
from socify.schema import ensure_schema
from socify.seeding import seed_demo_data

DEMO_LOGIN_VALUE = "Training-Safe-Password-2026!"


@pytest.fixture(scope="session")
def template_database(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("socify-template") / "template.db"
    connection = connect_path(str(path), True)
    try:
        ensure_schema(connection)
        seed_demo_data(connection, DEMO_LOGIN_VALUE)
    finally:
        connection.close()
    return path


@pytest.fixture
def app(tmp_path: Path, template_database: Path) -> Iterator[Flask]:
    database = tmp_path / "test.db"
    shutil.copy2(template_database, database)
    application = create_app(
        {
            "DATABASE": str(database),
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SECRET_KEY": "test-session-key",
            "CREDENTIAL_KEY": "test-credential-key",
            "ALLOW_REGISTRATION": True,
            "RATE_LIMIT_LOGIN_ATTEMPTS": 3,
            "MAX_CONTENT_LENGTH": 2 * 1024 * 1024,
            "MAX_IMPORT_ROWS": 10000,
        }
    )
    yield application


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


@pytest.fixture
def database(app: Flask) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(app.config["DATABASE"], isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    yield connection
    connection.close()


@pytest.fixture
def user_ids(database: sqlite3.Connection) -> dict[str, int]:
    rows = database.execute("SELECT id, role FROM users").fetchall()
    return {str(row["role"]): int(row["id"]) for row in rows}


@pytest.fixture
def login_as(client: FlaskClient, user_ids: dict[str, int]) -> Callable[[str], None]:
    def authenticate(role: str) -> None:
        with client.session_transaction() as browser_session:
            browser_session.clear()
            browser_session["user_id"] = user_ids[role]
            browser_session["workspace_id"] = 1
            browser_session["user_role"] = role

    return authenticate


@pytest.fixture
def event_payload() -> dict[str, object]:
    return {
        "source": "acceptance-fixture",
        "source_type": "training",
        "severity": "medium",
        "category": "authentication",
        "event_type": "failed_login",
        "title": "Synthetic failed login",
        "description": "Isolated acceptance event",
        "source_ip": "198.51.100.20",
        "username": "amina",
        "hostname": "idp-training-01",
        "action": "login",
        "outcome": "failed",
        "raw_payload": {"synthetic": True, "outcome": "failed", "action": "login"},
    }
