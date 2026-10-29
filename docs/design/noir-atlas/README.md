# SOCify V4 design atlas

Open `index.html` from this checkout. The catalogue contains 32 distinct views and 128 language/edition combinations. Switch Arabic/English and Midnight Noir/Aged Pulp in the review bar; resize the viewport for the mobile layout. Content is synthetic design material, never application metrics. Fonts load from `../../../static/fonts/` and require no third-party network request.

The first 24 compositions were created and reviewed before application styling changed. Eight detail compositions expand the intake, scope, response and dialog families. `all-screens.png` records the original 24-view review; `details-contact-sheet.png` records those eight additions. These static composition renders do not replace browser accessibility or runtime acceptance.

| View | Application surface |
| --- | --- |
| Dashboard | Retained training dashboard; operational `/dashboard` intentionally redirects to `/cases` |
| Monitoring | `/monitoring`, three scoped alert channels |
| Log management | `/log-management`, import preview and retained logs |
| Cases, scope selection | `/cases`, manager approval and related-case selection |
| Endpoint security | `/endpoint-security`, retained asset inventory |
| Threat intelligence | `/threat-intel`, indicators and local enrichment |
| Email security | `/email-security`, quarantined EML inspection |
| Sandbox | `/sandbox`, isolated static analysis |
| Reports, printed report | `/reports`, immutable report snapshots and exports |
| My tasks | `/my-tasks`, assigned case work |
| Playbooks | `/playbooks`, documented response procedures |
| Analysis library | `/analysis-library`, locally managed rules and sources |
| Team | `/team`, effective roles and assignments |
| Profile | `/profile`, profile and session security |
| Audit | `/audit`, authorized workspace audit records |
| Administration | `/admin`, authorized users and role matrix |
| Case dossier, investigation, response, activity | `/cases/{id}` summary, investigation, response and activity tabs |
| Login, registration, public overview | `/login`, `/register`, retained landing template; operational registration remains policy controlled |
| Forms, import, approval, account switch, confirmation | Existing dialogs and intake flows; no simulated server actions in this catalogue |
| System states, foundations | Shared loading, empty, failed, unavailable, success, approval, denied and disabled states; type and palette |

`screen-manifest.json` records the base revision and all variants. `static/design-tokens.json` is the application/report token source; catalogue examples are design specimens. Application widgets retain server permission gates, case boundaries and data semantics.

Figma file creation succeeded, but the Starter MCP call limit blocked subsequent writes. Zero frames were uploaded. This catalogue is the reviewable design fallback; it is not represented as a populated Figma file.
