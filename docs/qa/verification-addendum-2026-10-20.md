# SOCify — Verification Addendum (20 October 2026)

## Scope and mandatory release gate

This addendum follows the attached `SOCify_Enterprise_Master_Implementation_Prompt_AR(4).md`, including F01–F10, 132 traceable requirements, 60 E2E journeys, and the owner's stricter requirement for 100% verified compliance. The configured CI checks are **necessary but not sufficient** for that gate.

**Current release decision: NO-GO. Do not merge the development branch into main or publish it as complete.** The prior weighted acceptance figure (30.29%) is a historical audit baseline, not a recalculated acceptance score for this new code. No new 100% percentage can be honestly asserted until all 132 requirements and 60 journeys are retested and evidenced.

## New implementation and verified changes

1. MITRE ATT&CK version integrity: `socify/schema.py` and `socify/attack_snapshot.py` preserve immutable catalogs, SHA-256 source provenance, versioned technique data and transition history. Activation and rollback atomically rebuild the current read model while retaining deprecated/revoked records. `tests/integration/test_attack_catalog_upgrade.py` checks repeated startup, upgrade deltas, rollback and same-version content collision rejection. **OPEN-04 is resolved for the implemented offline catalog lifecycle.**
2. Training lifecycle: `socify/training.py` now distinguishes completed **playback** (`awaiting_submission`) from the trainee's explicit `POST /api/training/runs/{id}/submit`. Attempts are listed via `GET /api/training/runs`, scoped to the owner. A completed playback alone never produces a new assessment. The `submitted_at` column is migrated additively without erasing prior data.
3. Score semantics: `socify/scoring.py` uses immutable `socify-score-v4` snapshots after submission and compares recorded analyst triage decisions, evidence attachments, and successful simulated response actions against the scenario's stored ground-truth expectations and step timing. Detection TP/FP/FN, precision/recall, machine detection latency, learner decision latency, MTTA, MTTR, classification accuracy, evidence completeness, response quality, elapsed time, hints, and dimension weights are recorded separately. The downloadable report derives missed targets and recommendations from the same immutable inputs. **This materially improves OPEN-03 but does not replace independent educational validation.**
4. Frontend: `static/app.js` shows ongoing and awaiting-submission runs with an explicit submission button; score tables read actual API fields and label unavailable timing metrics rather than displaying `undefined` or `NaN`.
5. API and tests: Updated `docs/api/openapi.yaml` matches Flask's generated API route and method ordering. Existing API tests were adapted to explicit submission, `tests/integration/test_training_submission.py` verifies no premature scores, decision-based credit, idempotency, and ownership; `tests/e2e/test_browser.py` exercises the relevant browser path.
6. Durable simulated response: production requests enqueue playbook runs for `scripts/run_playbook_worker.py`. The worker uses persisted leases, atomic step effects, unique effect identities, retry backoff, timeout rollback, cancellation and queue bounds. `tests/integration/test_playbook_worker.py` covers concurrent claims, interruption recovery, exact internal effects, pinned versions, timeout, cancellation and monitoring.

## Evidence at last tested source revision

Commit `04c45e46ffafb9f4ef15fe20cd4092117f93adc9` passed the configured jobs `quality`, `security` and `browser` in GitHub Actions run [39460706748](https://github.com/7zy4/SOCifyProject/actions/runs/39460706748). The Phase One Tests PR workflow passed in run [39460706692](https://github.com/7zy4/SOCifyProject/actions/runs/39460706692). Results from older revisions must not be treated as evidence for newer commits.

## Explicit unresolved acceptance

- OPEN-01 historical case/event/report confidentiality audit and quarantine/repair migration.
- OPEN-02 bounded import worker and black-box process kill/restart evidence; the simulated response worker lifecycle is implemented and integration-tested.
- OPEN-03 remaining fidelity to ground truth across complete learner decisions and validated timing definitions, false-positive judgments, fairness and report accuracy.
- OPEN-05 full security evidence: secret scanning, SAST review including dynamic SQL, license/SBOM, DAST and standards mapping.
- OPEN-06 complete F01–F10 visual workflows, accessibility and all 60 browser/operational journeys.
- OPEN-07 fresh Codespaces/Docker startup, load/soak, recovery and reference performance proof.
- OPEN-08 complete OpenAPI successful response/request schema contracts, not just generator synchronization.

All original requirements remain mandatory. Nothing is removed or marked complete merely because the repository's configured CI is green. `main` remains unchanged; PR #3 remains draft.
