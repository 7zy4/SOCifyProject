# V3 case-first foundation verification

Scope: first implementation checkpoint on `socify-version-3`; not final V3 acceptance.

Implemented: case purpose/objective/classification, case membership enforcement, structured investigation records and optimistic versions, evidence-referenced IOC/response validation, escalation sender/recipient/acknowledgement/response, a hash-chained custody journal, operational navigation, invitation-only joining and a local team bootstrap command. Training and unscoped legacy data APIs are retired in operational mode. Old data and training tests remain; their compatibility flag is effective only with TESTING.

Validation:

- Full non-browser regression: **424 passed**, coverage **91.75%** combined statement/branch, in 86.04 seconds. Two subsequently added bootstrap integration tests passed independently, covering private-team creation, password hashing, duplicate refusal and preservation of existing accounts.
- All **nine Chromium journeys passed** in 51.39 seconds, including the new V3 journey with actual CSRF protection, case creation and a structured defender asset.
- New V3 core integration file: **29 passed**, including same-workspace case isolation, retired endpoints, unknown/invalid inputs, optimistic conflicts, private notes, immutable custody entries and separate escalation acknowledgement/response.
- New browser journey ran axe with no serious/critical violations in its observed investigation page and checked no document overflow at 360, 390, 768 and 1440 pixels. This is a bounded check, not a complete design audit.
- Ruff lint/format, mypy, Bandit and JavaScript syntax checks passed. The existing coverage threshold and security rules remain enabled.

Initial full regression exposed four failures in standalone legacy `PhaseOneTests`, which used a custom app rather than the shared fixture. The class now explicitly opts into the same legacy test-only mode and restores it in teardown. Its assertions remain intact. Operational retirement has separate negative tests; no test was deleted or skipped to address those failures.

Remaining work includes case-bound ingestion/export, packet analysis, local intelligence/Sigma/anomaly workflows, complete response/template/report lifecycles, operations and deployment isolation, extended migration/access tests and the remaining acceptance journeys. See `v3-acceptance.csv`. Do not treat this checkpoint as a final release.
