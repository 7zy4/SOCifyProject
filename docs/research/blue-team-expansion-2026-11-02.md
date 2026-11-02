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
- Fixed account switching outside demo mode to submit the current account-menu logout form.

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
