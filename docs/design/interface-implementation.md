# SOCify V3 — SOC workbench implementation

The latest user direction replaces the retro desktop with a LetsDefend-inspired SOC application. A stable top bar, sidebar, three monitoring channels and an expandable alert table now organize the product. There are no draggable windows, taskbar or folder view. SOCify remains a text wordmark with the same two local font families and a unified blue/navy identity across operational pages, public templates and new reports.

- [Corrective implementation prompt, written before application changes](soc-workbench-corrective-prompt.md)
- [Research and design rationale](soc-workbench-research.md)

## Navigation and role boundaries

The primary workflow is Monitoring → linked case investigation → review/closure. Main Channel maps to new/open/triaged cases; Closed Alerts maps to closed/cancelled cases; Investigation Channel covers the remaining operational case states. These are views of existing state, not new closure shortcuts. The existing `/dashboard` compatibility redirect to `/cases` remains intact.

Top-level tools are `/monitoring`, `/log-management`, `/cases`, `/endpoint-security`, `/threat-intel`, `/email-security`, `/sandbox` and `/reports`. Tasks, playbooks, analysis libraries and team management remain available. A tool requiring case context presents a searchable, paginated authorized case selector. It does not silently pick the latest case. `case_id` in the URL preserves context when moving between tools. Saves return to the corresponding existing case tab when appropriate.

Navigation uses the effective permissions returned by the server, including role overrides. Editing uses the case's server-computed `can_update`; administrative responsibility assignment retains `cases.assign`; report approval retains `reports.approve`. Read-only reviewers can inspect existing evidence summaries but cannot upload, edit or run the new email inspection. Full report creation requires `evidence.download`; other authorized readers receive the existing metadata-only profile. Original quarantined downloads still require `samples.download`, which is not granted by the new inspection endpoint.

L1, L2 and investigator retain their existing permission sets and differ by assigned responsibilities and workflow. This iteration does not silently narrow or expand default roles. Team managers control available role permissions through the retained team interface. Restricted batch users can use authorized logs; full-context tools display an explanation and a link to those logs.

## Actual features and contracts

`GET /api/soc/monitoring` returns only real alerts with an owning case in the current workspace and authorized case/batch scope. Filtering, sorting, channel counts and pagination are server-side. Counts use the same authorization and filters as rows. Query arguments are validated, sort identifiers are allowlisted and values use SQL bindings. Read snapshots keep counts and rows consistent. The new owner/date index supports case alert lookup. Tests cover cross-workspace isolation, removed membership, custom role permissions and restricted imports, including channel counts.

`static/soc-workbench.js` composes the retained case tools. Endpoint Security presents a paginated inventory of retained asset records, their address, OS, assessment and importance, with an accessible detail dialog and links to response documentation. Threat Intel separates authored indicators from paginated log observables and local enrichment sources. Record panels can load further pages. These views do not claim a live EDR connection or automatic device isolation. Sample Analysis reuses encrypted quarantine and the existing isolated static-analysis workflow; dynamic malware execution is not introduced.

Email Security uploads EML through the existing encrypted sample/evidence API. `POST /api/cases/{case_id}/samples/{sample_id}/email-review` checks the case, effective permissions, scope, state, sample type, size and SHA-256 before static MIME inspection. Limits are 2 MiB, 100 MIME parts, 200 headers, 50 attachments, 100 displayed URLs and 16 KiB of displayed body text. The original remains unchanged and encrypted. HTML-only bodies become text; scripts and styles are excluded, remote resources are not fetched, and URLs are shown as inert text. Attachment bytes are hashed without execution or archive extraction. Authentication-Results and SPF/DKIM claims are explicitly untrusted header text, not independent verification.

The result is a retained `analysis` record linked to the original evidence and included in subsequent report snapshots. Repeating inspection returns the existing result without duplication. Closed cases reject new analysis. `GET /api/cases/{case_id}/email-reviews` provides ten records per cursor page, under the same case/batch guard. OpenAPI documents the new routes and bounds.

The Quick Report action creates one immediate versioned snapshot through the existing API, disables repeated clicks during the request and opens the report workflow. It does not claim that a PDF is ready while its job is queued. PDF, DOCX, HTML, Markdown and JSON rendering, source versions, digests, sharing profiles, retry, approval and closure requirements remain in place. Stored historical reports are not regenerated.

## Shared design system

`static/design-tokens.json` remains the source for generated `static/tokens.css`. Dark uses #0D101B / #171E2A surfaces, light uses #F4F6FA / #FFFFFF, and blue is the single action accent. Red and amber communicate severity with written labels. Compact controls use 6px corners and panels 8px; decorative grid textures, dossier paper and window chrome are removed. The desktop shell has a 76px header, 240px sidebar and 24–32px content padding. Below 1100px the sidebar becomes a keyboard-operable drawer; mobile uses a two-row header and internally scrollable tables.

Arabic uses Almarai 400/700; English and technical Latin text use IBM Plex Sans. Both are local, licensed WOFF2 assets. User names, evidence and file content retain their source language. System/Light/Dark preferences still resolve before CSS, persist across pages and language changes, respond to system changes and tolerate unavailable storage. Printed reports remain light. The product's old image logo remains deleted.

## Verification and limitations

The browser matrix covers all existing operational routes plus seven new entry points in Arabic/English and light/dark, local fonts, edit/save, responsive widths, system/persisted preferences, storage failure and axe serious/critical checks. The new journey covers real server-side triage pagination/filtering, alert expansion, context links, asset detail, EML upload/inspection, safe URL display, a single immediate report snapshot containing the email result, mobile navigation and read-only reviewer controls. Existing navigation/draft, dropdown and CSS/native 200% zoom tests remain included.

Agent-browser 0.39.4 was loaded through the exact requested skills command and used with a named session for snapshots, interactions, screenshots, console inspection and its embedded axe audit. The skill and supporting files stayed under `work/`; no runtime dependency on this CLI was added to SOCify. The Vercel web interface guidelines informed the final UI review.

During review, Sample Analysis initially overflowed at 390px because a nested grid inherited its content's minimum width. The tool grid now uses `minmax(0,1fr)` with constrained items and wrapped upload controls. Both the browser matrix and manual check verify the corrected width. The monitoring table's disclosure column was also sized independently so desktop actions remain visible. The automated audit of the populated monitoring view reports zero violations; some contrast checks are incomplete on pseudo-element channel backgrounds and non-text disclosure glyphs. Token contrast is checked separately; this is not a full manual accessibility certification.

The runtime used here does not implement the pre-existing Landlock syscall required for isolated worker execution. Two worker-dependent report integration cases remain excluded from the focused backend run; three older worker-dependent browser journeys are not counted as passing. Direct rendering/security tests validate the five formats, and the browser validates creation of a real queued report snapshot. The worker isolation boundary was not weakened. Run the full worker journeys in the project's supported Linux/container deployment before release.

Visual previews are retained locally under docs/design/previews and use synthetic test accounts/evidence. Screenshots are not included in this commit. The supplied screenshot is the composition reference. No claim is made that third-party websites never used AI or that a Figma file was updated in this iteration. The final work is committed directly to `socify-version-3` without a new branch or PR.

## Final recorded results — 2026-10-27

- **11 browser tests passed in 84.77s**, including the new SOC/email/report journey and the expanded theme/locale/viewport matrix.
- **67 backend/security/contract tests passed in 13.46s; 2 Landlock-dependent report cases deselected.** One expected duplicate-ZIP-member warning comes from a malicious archive rejection fixture.
- Agent-browser's populated-monitoring audit: **0 violations**, with incomplete contrast checks documented above. Browser console/page-error checks found no application errors in the reviewed flows.
- Ruff lint/format, generated-token consistency, JS syntax, six CSS parse checks and git whitespace checks pass.

Commands:

```sh
.venv/bin/pytest -q -m e2e tests/e2e/test_soc_workbench.py tests/e2e/test_interface_theme.py tests/e2e/test_autopsy_zoom_keyboard.py tests/e2e/test_autopsy_navigation_state.py tests/e2e/test_interface_languages.py tests/e2e/test_investigation_dropdowns.py
.venv/bin/pytest -q tests/integration/test_soc_workbench.py tests/integration/test_autopsy_core.py tests/integration/test_autopsy_capsules_pipeline.py tests/security/test_autopsy_report_security.py tests/unit/test_interface_translation_catalog.py tests/test_openapi.py tests/integration/test_autopsy_reports.py -k 'not local_report_formats_snapshot_review_and_closure and not report_bola_redaction_and_revoked_worker_access'
.venv/bin/python -m scripts.generate_interface_tokens --check
```

After these runs, a control caption was clarified to “Sort by” and unused desktop-only translation entries were removed; neither changes application behavior. The control-outline contrast adjustment to 3.49:1 was also checked in the final light-theme browser audit. Translation-catalog and syntax checks were repeated for those edits.

Manual token contrast checks: channel text is 4.85:1 (light) / 5.96:1 (dark), muted text on secondary surfaces 5.58:1 / 7.34:1, and primary text on panels 14.27:1 / 15.03:1. The light input/control outline was darkened to #7D8AA0 to exceed 3:1 against a white surface.

[Browser review and fixed responsive finding](soc-workbench-review.md).
