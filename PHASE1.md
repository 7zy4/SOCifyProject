# Phase 1 — Security, Detection, Incident Cases

This branch implements the initial foundation of SOCify's first delivery phase.

## Run locally

```bash
pip install -r requirements.txt
export SOCIFY_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python run.py
```

Visit `http://127.0.0.1:5000` and select **التحقيقات الأمنية** from the dashboard, or visit `/incidents`. The bundled demo accounts are **strictly for local training**.

- `SOCIFY_SECRET_KEY`: set a strong persistent session-signing secret in real deployments. With no value, one is generated at startup, invalidating existing sessions after a restart.
- `SOCIFY_HOST`: defaults to `127.0.0.1`.
- `SOCIFY_DEBUG`: disabled by default; setting `1` enables debug and **must only be used locally**.
- `SOCIFY_HTTPS=1`: set when HTTPS is correctly deployed to secure session cookies.
- `python run.py` creates the demo database if absent, then applies phase-one tables to an existing database without deleting it. Back up your database before upgrades.

## Detection workflow

`POST /api/lab/event` and `POST /api/events` store an event and evaluate active `rules` before committing. Matching `create_event` actions write a second event with `source='rules_engine'`, and `detection_matches` records the rule/event pair for deduplication. Each response includes a `detections` array of created alert database IDs. The detection engine supports:

- `failed_login_count`: threshold and timeframe (for example `{"threshold":5,"timeframe":"10m"}`), grouped by source IP and username when included in `raw_data`. The simulator's `Brute Force` category is included.
- `network_anomaly`: numeric `raw_data.anomaly_score` compared with `condition_value.threshold`.
- `error_level`: matching `raw_data.level` against `condition_value.level`.

Other rule conditions remain configurable but are **not yet evaluated**, and action types beyond `create_event` remain unsupported. This is an initial detection implementation, not a full SIEM engine.

## Investigation API

All endpoints require login and pass CSRF protection on writes:

| Endpoint | Use |
| --- | --- |
| `GET /api/incidents` | List investigation cases |
| `POST /api/incidents` | Create a case with optional `event_ids` |
| `GET /api/incidents/:id` | Case details, evidence, notes |
| `PATCH /api/incidents/:id` | Update status, severity, title, assignment |
| `POST /api/incidents/:id/events` | Link an existing security event |
| `POST /api/incidents/:id/notes` | Add investigation note |
| `POST /api/profile/password` | Change own password after checking current password |

Cases, linked events, and notes have durable SQL storage and an audit trail.

## Security notes and current boundaries

- Analysts can update events but only managers/admins can delete them.
- The event-source list no longer returns stored API keys, and audit messages for source edits redact them.
- The profile password form now updates the server, rather than claiming a simulated successful change.
- Login is still designed for a local demonstration. Before an Internet-facing deployment, also implement brute-force throttling, stronger password policy, real 2FA/session management, CSP/output escaping, secret-at-rest encryption, and operational database backups.
- Legacy frontend screens for source connection tests and some rule actions still contain mock behavior; they should be wired to APIs in the next iteration.

## Tests

```bash
python -m unittest discover -s tests -v
```

The GitHub Actions workflow `.github/workflows/phase-one-tests.yml` runs the tests on branch updates and pull requests to `main`.
