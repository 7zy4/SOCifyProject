# Release notes

## Enterprise platform release candidate

- Rebuilt the repository around an application factory, idempotent schema migrations, workspace scoping, secure sessions, RBAC, MFA, audit, and encrypted source credentials.
- Added normalized ingestion for CSV, JSON, JSONL, Syslog, Linux auth, web logs, Sysmon XML, and EVTX.
- Added typed detection DSL, event-time windows, ordered sequences, deduplicated alerts, rule versions, preview, rollback, clone, health, and bounded backfill.
- Added investigation lifecycle, evidence hashing, tasks, notes, optimistic concurrency, closure gates, report revisions, and reopen support.
- Added deterministic attack-chain simulation, ATT&CK coverage, hunting, IoCs, graph/timeline/SSE, simulated SOAR, and deterministic scoring.
- Replaced legacy fake interactions with an RTL responsive interface backed by real APIs.
- Added Docker, Compose, Codespaces, health checks, backup/restore, OpenAPI, security documentation, fixtures, and CI quality gates.

Release status and measured acceptance are recorded in `docs/qa/final-acceptance-report.md` and must not be inferred from this change list.
