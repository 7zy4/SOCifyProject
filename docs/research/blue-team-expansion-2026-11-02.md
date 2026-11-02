# Blue-team feature review — 2 November 2026

Goal: a user uploads their own logs, obtains rule-backed alerts, investigates retained evidence, records explicit decisions, and produces a report representing that case. Managers and analysts can inspect actual workload and evidenced performance while retaining SOCify's existing visual identity.

## Primary sources reviewed

This is feature and workflow research, not imported third-party code or copied screens. No external project was executed against user data, and no new runtime dependency was added.

| Project / source | Relevant capability | SOCify decision |
|---|---|---|
| [CarterPerez-dev SIEM Dashboard README](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/PROJECTS/intermediate/siem-dashboard/README.md) | Log correlation, lifecycle states, filtering, MITRE mapping; also contains an attack simulator | Keep the real ingestion/rules workflow and improve investigation disclosure. Exclude simulator output from operations. The repository lists AGPL-3.0; no implementation was copied. |
| [DFIR-IRIS](https://github.com/dfir-iris/iris-web), [task documentation](https://docs.dfir-iris.org/latest/operations/cases/tasks/) | Collaborative cases, assigned tasks and investigation records | Add team/personal workload, completion attribution, queue links, and task visibility in alert context. Existing case membership remains authoritative. |
| [Timesketch](https://github.com/google/timesketch), [sketch overview](https://github.com/google/timesketch/blob/master/docs/guides/user/sketch-overview.md) | Collaborative timelines, event annotations and saved investigative views | Existing chronology already covers evidence timelines. Preserve source-time uncertainty and expose actual linked events from the alert. Do not reinterpret import time as incident time. |
| [MISP](https://github.com/MISP/MISP) | Indicator correlation, structured threat information and sharing controls | Existing watchlist, local intelligence bundles and observable links already cover a useful offline subset. Retain provenance and case scope; do not add network enrichment disguised as local analysis. |
| [Wazuh dashboard documentation](https://github.com/wazuh/wazuh-documentation/blob/main/source/user-manual/wazuh-dashboard/navigating-the-wazuh-dashboard.rst) | Endpoint and process context, incident response views and reports | Add hosts observed in uploaded logs, first/last known source timestamps, process/parent/command line and network observations. This view does not require or impersonate an installed endpoint agent. |
| [Velociraptor](https://github.com/Velocidex/velociraptor), [offline collector reference](https://docs.velociraptor.app/artifact_references/pages/server.utils.createcollector/) | Artifact-based endpoint collection and offline workflows | Keep SOCify on the retained-artifact side: imported host observations and existing collection requests. Live collection would require a separately configured, authenticated integration. |
| [SigmaHQ](https://github.com/SigmaHQ/sigma), [official specification](https://github.com/SigmaHQ/sigma-specification) | Portable log detections with log-source constraints | Existing validated Sigma subset and published rules remain the detection engine. Do not claim all upstream rules are supported or bulk-enable unvalidated detections. The rule repository specifies DRL 1.1. |
| [TheHive repository](https://github.com/TheHive-Project/TheHive) | Incident response case-management lineage | Reviewed as context only. The current repository explicitly describes commercial distribution; it is not represented as a current open-source component being integrated. |

## Changes implemented

- `/performance`: manager team view and individual drilldown; each analyst gets their own view. Current open/awaiting-review/unassigned cases, unreviewed alerts, pending tasks, severity distribution and actionable case links.
- Completion period: 7, 30, 90 days or all time. Current backlog remains visible regardless of its creation date. Daily case activity is available on demand.
- Durations: medians of successful response timestamps backed by evidence, for cases closed in the period. Each metric includes measured/excluded denominators. Missing, future and negative intervals do not become zero. No invented accuracy score or leaderboard.
- Alert dossier: retained source events, source-time availability, analyst verdict/outcome/reason, case assessment answers, reviewer comment, MITRE annotations, investigation tasks and shared notes.
- Observed hosts: case-scoped, searchable/paginated projection of active uploaded events; process details come from those events. Historical replaced imports do not appear as current observations.
- Full immutable report snapshots now include saved guided assessment answers and management review, alongside existing evidence, chronology, responses, tasks and custody. Later edits do not mutate earlier snapshots.
- New assessments start unanswered. Printing a guided report requires saved answers. Removed the prior unsaved preview that printed assumed decisions.
- Removed repeated feature descriptions from operational page headings and explanatory tool paragraphs. Calculation documentation lives here, not as instructional copy in the interface. Dynamic error/state information and necessary scope limits remain.
- Fixed account switching outside demo mode to submit the current account-menu logout form, and removed a stale mobile rule hiding that action.

## Scope and metric contract

All new endpoints enforce workspace, case membership, investigation selection when enabled, approval when enabled, and full batch visibility. Training-run and archived cases are excluded. Private notes are excluded. Managers alone can view another member or the whole team. A personal case scope means membership or current assignment; task completion credit belongs to the recorded completer. The workload table attributes cases to their current assignee, not necessarily their historical closer.

The case-deadline count uses `sla_due_at`, excluding paused cases. It is deliberately labelled **case deadline**, not business-calendar SLA compliance. Existing workflow SLA configuration and pause history remain on the case. Dashboard scope above 2,000 cases is rejected explicitly instead of silently sampling. Queues show their total and the first 50 actionable records. Hosts page in groups of 25; a selected host shows its latest 50 retained events. Alert source text is bounded with a link to logs when truncated.

## Existing capabilities and remaining operational dependencies

| Journey | Current implementation | Verification focus |
|---|---|---|
| Upload → normalize → detect | Import preview/commit, format mapping, source timezone, deduplication, published rules and case-owned alerts | New tests upload process evidence and assert generated alerts; a second case begins empty. |
| Investigate → decide | Alert reviews, shared/private notes, assets, chronology, hypotheses, MITRE, playbooks and response records | Dossier and report decisions are queried from retained case data, not mock arrays. |
| Decide → report | Guided assessment and versioned report snapshots | Explicit choices, HTML escaping, snapshot immutability and restricted sharing profile. |
| Team management | Roles, membership, assignments and invitations | Personal/team access, restricted cases, selection, approval and task attribution. |
| Host investigation | Retained events plus manually documented assets | No simulated live EDR state, host isolation or remote shell. |
| Native sample analysis / PDF | Isolated Linux analysis worker | Requires the configured worker. Windows-only checks cannot substitute for this integration; CI validates it. |
| Fresh deployment | Normal startup creates schema/reference catalog/rules, not operational cases/logs/reports | Repeated clean startup must keep evidence tables empty. Demo scripts remain explicit developer test utilities. |

URL reconnaissance, port scanning, offensive tools, automatic containment, unsourced feeds and fabricated training scores were excluded because they do not improve this retained-evidence investigation workflow.

## CarterPerez source inspection and additional implementation

The follow-up review opened the repository tree and actual implementation files, not only its README. The inspected `main` tree was `ee0a9c92c95f801cc34fad19ba8ebc05dc73d82d`. These are independently implemented capabilities in SOCify, not bundled upstream programs or copied AGPL source. Upstream projects were read; SOCify's implementations were executed and tested.

| Reviewed implementation | New SOCify capability | Connected workflow |
|---|---|---|
| [base64-tool peeler.py](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/ee0a9c92c95f801cc34fad19ba8ebc05dc73d82d/PROJECTS/beginner/base64-tool/src/base64_tool/peeler.py), blob `919723089577684930da67d355165f4c5b8aebd3` | Layered decoding of Base64/Base64URL, Base32, hexadecimal and percent-encoded text; PowerShell encoded-command UTF-16LE handling | Upload → inspection → retained decoded layers → suspicious decoded-content rule → alert dossier and report |
| [secrets-scanner entropy.go](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/ee0a9c92c95f801cc34fad19ba8ebc05dc73d82d/PROJECTS/intermediate/secrets-scanner/internal/rules/entropy.go), blob `464039025011df79dba45d15b4085d62b1f26fb7`, and its README | Contextual detection of credential assignments, bearer tokens and private-key blocks, with redacted findings | Upload → credential-exposure rule → exact event/field/character location → analyst review |
| [dlp-scanner financial.py](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/ee0a9c92c95f801cc34fad19ba8ebc05dc73d82d/PROJECTS/intermediate/dlp-scanner/src/dlp_scanner/detectors/rules/financial.py), blob `835580187dc0d4ca8da1c3b0410ab4e6fc9decce`, and [redaction.py](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/ee0a9c92c95f801cc34fad19ba8ebc05dc73d82d/PROJECTS/intermediate/dlp-scanner/src/dlp_scanner/redaction.py), blob `2982866b9ae7046c51bf1638627f82592e150b53` | Payment-card Luhn and IBAN mod-97 checks, with masked results | Upload → financial-data exposure rule → case analysis and report |

The SIEM project's `backend/app/engine/correlation.py` was also reviewed. Threshold, sequence and aggregation support already exist in SOCify; these are not presented as newly added capabilities. Other offensive/scanning projects were excluded from this change.

### Behavior and boundaries

- `socify/content_inspection.py` is a deterministic standard-library implementation. It never executes decoded text, contacts observed addresses, validates credentials remotely or installs endpoint agents.
- Inspection runs on case ingestion, before rule evaluation. Re-running case rules also inspects older retained events. Original text and its hash remain unchanged. Repeated rule runs retain alert deduplication.
- Three published built-in rules consume engine-owned counts. Uploaded normalized fields cannot forge these counts or retained inspection objects. A decoding match alone does not imply malicious activity; the decoded-content rule requires a suspicious pattern.
- Findings retain field paths, character offsets, layer numbers and masked values. A later discovered secret also masks its earlier encoded layers; private-key blocks are masked as a whole. Original evidence remains available to authorized investigators in the existing raw-log view. This is pattern detection, not a guarantee that every possible secret has been recognized.
- Financial matches prove a format/checksum match, not a valid bank account, active payment card or exfiltration. Credential heuristics are deliberately narrower than the upstream scanner's full rule collection. No claims of importing its 150+ rules or benchmark accuracy are made.
- Bounds per event: 32,768 source characters, 64 fields, 12 candidate tokens, 4 layers, 40 retained findings. Partial inspection and layer limits are explicit results. The API pages 25 matching events; reports reject more than 2,000 matching events or 4 MiB of inspection data rather than silently omitting results.
- Results are wired to the case's analysis page, the same single alert-details table, immutable full reports and the guided printable report. Metadata-only sharing excludes them. Scope checks cover workspace, membership, investigation selection, approval and full import visibility.
- Alert rows start collapsed. Clicking their name or arrow expands one vertical property table containing metadata, decisions, source events, inspection results, tasks and notes. List pagination sits outside the disclosure and is absent for a single page.

### Validation artifacts

`tests/unit/test_content_inspection.py` exercises decoding, checksums, masking, invalid input and limits. `tests/integration/test_content_inspection_workflow.py` exercises real uploads, new rule alerts, source preservation, re-scanning, deduplication, access boundaries, pagination and both report paths. `tests/e2e/test_soc_insights_browser.py` exercises disclosure, decisions, pagination, new analysis results and printable reports in Arabic/English, light/dark, desktop/mobile, with accessibility and page-overflow assertions. Screenshots are generated under `artifacts/soc-insights/`; the CI run for the final commit is the acceptance record.
