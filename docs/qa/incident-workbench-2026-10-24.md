# Incident log workbench

The existing case workspace now supports this journey without replacing existing features:

1. Create a case and upload logs through the existing preview/commit import flow.
2. Use the completed import job ID in the case's log-linking form. The API attaches at most 200 records per transaction and returns a continuation cursor. The UI follows the pages sequentially. Repeating a page adds no duplicate case-event or evidence associations.
3. Open the case graph/timeline. Existing case/time/severity filters apply to the graph, timeline and export.
4. Record an ATT&CK technique as suggested, verified or rejected, with an explanation. The server checks the current catalog and records its version. A verified conclusion requires a specific event already attached to this case. An unrelated event, invalid catalog ID or malformed JSON is rejected.
5. Complete investigation tasks and closure fields. The immutable report revision now includes ordered event metadata and digests, technique assessments with authors/evidence, shared notes, tasks, alert/rule versions, response execution metadata, case activity and the evidence inventory. HTML uses escaped tables; JSON preserves structured fields. Private notes and response parameter payloads are excluded from the shared report.

New import-link and technique-write endpoints enforce both workspace and training-run access, and reject writes to closed cases. Case severity, note visibility and task-state endpoints now explicitly validate string types before enum membership checks, correcting malformed-list server errors.

The regression suite exercises 205 imported records across two pages, replay, timeline/report content, report escaping, private-note exclusion, closed-case locking and cross-trainee/scope denial. Chromium exercises the new forms and verifies persisted results. New tables are created additively during schema startup; old report revisions are preserved.

Final local verification for this change: 380 unit/integration/security tests passed in 65.59 seconds, with six browser tests deselected from that command. Combined branch coverage was 92.85%. All six Chromium journeys passed separately in 43.40 seconds, including axe-core checks. Ruff lint/format, mypy, Bandit and JavaScript syntax checks passed. These results establish the exercised workflow, not all 132 original requirements.

The user-selected REA fork was built and actually executed; see [source comparison, runtime details and retained evidence](../research/incident-workbench-top10-2026-10-24.md). This delivery does not declare the original 132-requirement release accepted. Remaining limitations include direct case assignment during asynchronous upload, richer observables/response-detail sections in reports, final hosted CI, independent security review, and the previously recorded acceptance gaps.
