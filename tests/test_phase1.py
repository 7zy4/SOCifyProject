"""Focused phase-one integration checks; run with python -m unittest discover -s tests."""
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import bcrypt
from app import app, ensure_phase1_schema


class PhaseOneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_database = app.config["DATABASE"]
        self.old_testing = app.config.get("TESTING")
        self.old_csrf = app.config.get("WTF_CSRF_ENABLED")
        app.config.update(DATABASE=os.path.join(self.temp.name, "test.db"),
                          TESTING=True, WTF_CSRF_ENABLED=False)
        with sqlite3.connect(app.config["DATABASE"]) as db:
            # Test fixtures avoid seeded credentials from the demo initializer.
            db.executescript("""
            CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, name TEXT,
                password_hash TEXT, role TEXT, is_active INTEGER DEFAULT 1);
            CREATE TABLE security_events (id INTEGER PRIMARY KEY,
                event_id TEXT UNIQUE, source TEXT, severity TEXT, category TEXT,
                title TEXT, description TEXT, raw_data TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'open', assigned_to INTEGER, created_by INTEGER);
            CREATE TABLE rules (id INTEGER PRIMARY KEY, name TEXT, description TEXT,
                condition_type TEXT, condition_value TEXT, action_type TEXT,
                action_value TEXT, is_active INTEGER DEFAULT 1, created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, user_id INTEGER,
                action TEXT, table_name TEXT, record_id INTEGER, old_values TEXT,
                new_values TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT, user_agent TEXT);
            CREATE TABLE event_sources (id INTEGER PRIMARY KEY, name TEXT,
                type TEXT, endpoint TEXT, api_key TEXT, is_active INTEGER,
                last_sync TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            """)
            db.execute("INSERT INTO users (id, email, name, password_hash, role) VALUES (1, 'admin@test', 'Admin', ?, 'admin')",
                       (bcrypt.hashpw(b'testpassword', bcrypt.gensalt()).decode(),))
            db.execute("INSERT INTO users (id, email, name, password_hash, role) VALUES (2, 'analyst@test', 'Analyst', ?, 'analyst')",
                       (bcrypt.hashpw(b'testpassword', bcrypt.gensalt()).decode(),))
            db.execute("""INSERT INTO rules (name, condition_type, condition_value,
                action_type, action_value, created_by) VALUES
                ('Brute force', 'failed_login_count', '{"threshold": 2, "timeframe": "10m"}',
                 'create_event', '{"severity":"high","category":"authentication"}', 1)""")
            db.execute("""INSERT INTO event_sources
                (name, type, endpoint, api_key, is_active) VALUES
                ('test', 'syslog', 'localhost', 'private-token', 1)""")
        with app.app_context():
            ensure_phase1_schema()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(DATABASE=self.old_database, TESTING=self.old_testing,
                          WTF_CSRF_ENABLED=self.old_csrf)
        self.temp.cleanup()

    def auth(self, uid):
        with self.client.session_transaction() as s:
            s["user_id"] = uid

    def event(self):
        return self.client.post("/api/lab/event", json={
            "source": "lab", "severity": "medium", "category": "Brute Force",
            "title": "Failed login", "description": "Simulated failure",
            "raw_data": '{"source_ip":"192.0.2.9","username":"training"}'
        })

    def test_rule_triggers_on_threshold_only(self):
        self.auth(2)
        one = self.event()
        self.assertEqual(one.status_code, 200)
        self.assertEqual(one.json["detections"], [])
        two = self.event()
        self.assertEqual(two.status_code, 200)
        self.assertEqual(len(two.json["detections"]), 1)
        with sqlite3.connect(app.config["DATABASE"]) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM detection_matches").fetchone()[0], 1)

    def test_analyst_cannot_delete_security_events(self):
        self.auth(2)
        event = self.event()
        response = self.client.delete("/api/events/" + str(event.json["id"]))
        self.assertEqual(response.status_code, 403)

    def test_case_workflow_and_notes(self):
        self.auth(2)
        event = self.event()
        case = self.client.post("/api/incidents", json={
            "title": "Investigate failed login",
            "event_ids": [event.json["id"]]})
        self.assertEqual(case.status_code, 201)
        case_id = case.json["id"]
        note = self.client.post(f"/api/incidents/{case_id}/notes",
                                json={"note": "Checked IP and username"})
        self.assertEqual(note.status_code, 201)
        detail = self.client.get(f"/api/incidents/{case_id}").json
        self.assertEqual(len(detail["events"]), 1)
        self.assertEqual(detail["notes"][0]["note"], "Checked IP and username")
        self.assertEqual(self.client.patch(f"/api/incidents/{case_id}",
            json={"status": "investigating"}).status_code, 200)

    def test_source_secret_redaction(self):
        self.auth(2)
        response = self.client.get("/api/sources")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("private-token", response.get_data(as_text=True))
        self.assertNotIn("api_key", response.json[0])

    def test_password_change_rejects_wrong_password_and_accepts_correct(self):
        self.auth(2)
        rejected = self.client.post("/api/profile/password", json={
            "current_password": "incorrect",
            "new_password": "updated-strong-password"})
        self.assertEqual(rejected.status_code, 403)
        accepted = self.client.post("/api/profile/password", json={
            "current_password": "testpassword",
            "new_password": "updated-strong-password"})
        self.assertEqual(accepted.status_code, 200)
        with sqlite3.connect(app.config["DATABASE"]) as db:
            password_hash = db.execute(
                "SELECT password_hash FROM users WHERE id = 2").fetchone()[0]
        self.assertTrue(bcrypt.checkpw(b"updated-strong-password",
                                       password_hash.encode()))

    def test_anonymous_incidents_returns_401(self):
        self.assertEqual(self.client.get("/api/incidents").status_code, 401)


if __name__ == "__main__":
    unittest.main()
