# Adversarial final audit

## Open findings

| ID | Severity | Finding | Required resolution |
|---|---|---|---|
| AUD-001 | Resolved locally; remote verification pending | Aggregate coverage is 93.18%, with 285 passing tests after adding 172 boundary and lifecycle cases. | Verify both push and pull-request quality jobs on the published correction; the threshold remains 90%. |
| AUD-002 | High gate blocker | Chromium cannot start in the restricted local container. | Pass the mandatory GitHub Actions Chromium job on the final head SHA. |
| AUD-003 | High gate blocker | SCA and remote CI evidence are not yet attached to the final SHA. | Pass pip-audit and every required workflow job. |
| AUD-004 | Medium | Bandit reports B608 for server-constructed SQL fragments. | Keep server-owned allowlists and parameterized values, retain injection tests, and document the configuration exclusion. |

## Verified controls

- RBAC and cross-workspace IDOR denial are covered by negative integration tests.
- CSRF, authentication throttling, MFA lifecycle, session invalidation, source-secret encryption and redaction, SSRF default denial, XXE rejection, immutable event evidence, CSV formula neutralization, deterministic scoring, and training-run isolation have executable tests.
- ATT&CK Enterprise 20.0 is bundled as an offline catalog with 706 active techniques and sub-techniques.
- Backup, restore, integrity verification, migration dry-run, and fresh schema creation have executable tests.

The audit remains open until all blocker rows are closed on the final pull-request head.
