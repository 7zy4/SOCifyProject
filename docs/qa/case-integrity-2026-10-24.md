# Case closure and custody verification — 2026-10-24

Branch: `socify-version-2`. Release decision remains NO-GO.

Closure now requires evidence summary and validation alongside disposition, root cause, impact, response summary and lessons learned. Server limits match the form limits. Managers may use the existing explicit override policy; its reason is retained in the security audit. All seven fields appear in escaped HTML and JSON reports.

The closure transition, history, audit, training action, outbox notification and both report formats commit in one transaction. A fault injected after report creation proves that neither a closed case nor a partial report survives failure. Reopening and closing again creates revision 2 while revision 1 remains byte-identical and downloadable using `?revision=1`.

Database triggers prevent replacing or deleting immutable evidence metadata. An authorized evidence-detail request records actor, time, digest and case in the audit and case history. The case UI exposes that view. Another trainee cannot read the private case, its evidence or reports, find it in the list, or mutate it.

Verification:

- Full API/unit/security suite: 362 passed, four browser tests deselected, 47.86 seconds; combined branch coverage 92.53%.
- Existing Chromium suite: four passed, 23.71 seconds.
- New Chromium closure journey: one passed, 8.37 seconds. It rejects an incomplete report, submits all fields, downloads HTML, reads evidence custody metadata and passes axe-core serious/critical checks. Fixture API calls prepare the recovered case before the browser closure journey.
- Ruff lint/format, mypy, Bandit and JavaScript syntax checks passed. OpenAPI regenerated for the new evidence-detail route.

Remaining limitations: user-submitted raw-log/training-artifact evidence currently retains a digest and metadata but not the original submitted content. Existing historical contamination is not repaired by the new immutability triggers. F04-R07 therefore remains unaccepted. Authenticated DAST, independent review and final hosted CI evidence remain release gates.
