# V4 noir workspace implementation and verification

Base: `V4@53f739c3372b85fff3fd9682ddbffcc2f40868d3`. Implementation branch: `codex/v4-noir-workspace`. This record distinguishes design review, implementation and verified execution. It does not certify a production deployment.

## Design and implementation

The initial 24-view atlas preceded application styling; eight detail compositions complete scope selection, intake and case workflows. The [atlas](../design/noir-atlas/index.html) contains 32 views, Arabic/English, two editions and responsive layouts. The [mapping](../design/noir-atlas/README.md) describes their actual routes. Operational `/dashboard` retains its compatibility redirect to `/cases`; the retained training dashboard receives the common theme. Registration remains policy controlled.

A new Figma file was created (`AMxY6mcybMcfG2M4YiZHvD`), but Starter MCP quota prevented subsequent reads/writes. No frames/components were uploaded. Local design sources are the available deliverable. The enhanced execution prompt is maintained outside this repository.

The shared token source now governs application and report palettes, local fonts, sharp borders, hard shadows, amber actions and dark/paper editions. Semantic foreground colors are distinct from raw severity pigments. Arabic display text uses Cairo, body IBM Plex Sans Arabic and voice Tajawal; English uses Bangers, IBM Plex Sans and Comic Neue; code uses JetBrains Mono. Licenses and provenance accompany the fonts. Decorative treatments do not distort evidence text. Reduced motion, focus, RTL and print treatments remain explicit.

Audit and administration now invoke their existing authorized renderers in operational mode instead of falling through to the case list. Their navigation respects `audit.read` and `users.read`. API permissions remain unchanged.

## Engineering changes

- IPC socket mode is explicitly `0660`. Connections retry only before a request is sent, at 100/200/400ms; permission errors and interrupted responses are not replayed. Clients retain the read-only IPC volume, and the service retains its locked directory and isolated process boundary.
- Compose and the local supervisor run import, autopsy and playbook workers against the same database. Tests verify local execution and single-owner claims from simultaneous database connections.
- File-backed SQLite databases use WAL in tests and normal operation, a 15s lock timeout, foreign keys, bounded mmap and short existing immediate transactions.
- MIME depth is capped at 5, attachments at 25 and parts at 100 before payload decoding. Unicode display names preserve safe extensions with a digest fallback. Original sample bytes remain encrypted and hashed; client names are not storage paths. XML DTD/entities are explicitly forbidden, including late and UTF-16 declarations.
- Unsupported analysis hosts fail closed with a Linux/Docker diagnostic. No weaker sandbox or automatic unisolated fallback was added.
- V4 launchers, CI and documentation use the supported entry points. Necessary operations/backup/recovery instructions were merged before retiring old launchers, initializer shims and planning/identity files. Historical security/research evidence is retained and labeled.

## Verification ledger

- Before changes: 850 passed, 17 failed in the local backend suite. Failures involved missing procfs, denied pathname UNIX sockets and dependent isolated analysis/report setup.
- Focused regressions: 49 passed, including the new transport, MIME, Unicode filename, concurrent claim and local worker cases.
- Ruff format/check, mypy (86 source files), Bandit, generated-token consistency, OpenAPI drift and 24 WCAG AA foreground/background pairs passed locally.
- Full real-page brand audit was attempted. Synthetic provisioning stopped at `503 YARA_VALIDATION_UNAVAILABLE` because this runtime cannot start the isolated analysis process. It did not produce a false browser pass.
- Chromium download returned an unavailable response; Docker and procfs are absent. Kernel isolation and full browser checks require the Linux CI environment. No tests were removed or security assertions relaxed to conceal this limitation.
- Full post-change backend run: 889 tests, 871 passed and 18 failed. Seventeen failures match the environment-dependent baseline; the additional migration failure exposed writable inspection/backup connections changing the source journal header. Verification, backup sources, restore sources and fixture inspection now use read-only connections, retaining the byte-for-byte preservation assertion. The focused migration/backup regression passed after the fix. The first full GitHub results and follow-up findings are recorded below.

- GitHub CI on `a22f694`: **889 passed**, 27 browser tests deselected, **90.98%** branch coverage. The native isolated renderer produced all five formats; the bilingual 23-page PDF passed geometry checks (2,931 words, zero clipped words, zero blank pages).
- The first CI run identified acceptance scripts omitting V4 case approval/selection, a Playwright/Ubuntu 26.04 incompatibility and secret-scanner false positives for public font digests. Follow-up changes exercise approval/selection through the real API, use the supported Ubuntu 24.04 browser runner, and individually baseline verified public hashes. Follow-up CI results are pending.
- Dependency review reports that it is unavailable and asks for Dependency graph to be enabled in repository settings. That check remains blocked until repository configuration is resolved; the separate runtime dependency audit passed with no known vulnerabilities. No security gate was skipped or weakened.

- The second CI run (`6a08072`) passed security, container and million-event performance gates. Browser acceptance passed 25 cases and exposed two defects: the legacy-route guard blocked the authorized governance endpoints, and a more specific email CSS rule broke light-mode contrast. A narrow endpoint exception retains the existing permission decorators and workspace filters; an added regression checks anonymous/analyst denial, tenant isolation and continued retirement of training APIs. The terminal palette now wins the email selector cascade. All 66 focused governance/case tests and 26 contrast pairs passed locally; final browser results are recorded on the PR.

`python -m scripts.audit_brand --tokens-only` explicitly reports `browser_verified:false`. The default audit requires real V4 provisioning, authenticates an ephemeral synthetic administrator, and checks 17 operational URLs in two languages, two editions and two widths, recording redirects rather than claiming distinct dashboards. CI also runs the existing public/auth/role/browser accessibility journeys and uploads screenshots.

## Reproduce

Follow [operations-v4.md](../operations-v4.md) to start the isolated service. Then run `python -m scripts.generate_interface_tokens --check`, `python -m scripts.audit_brand`, and the checks declared in `.github/workflows/enterprise-quality.yml`. Never enable an isolation-container marker on an ordinary host. Use only synthetic data for development/CI.
