# V6 readiness and design review — 2 November 2026

## Scope and design direction

Reviewed the existing V6 workbench changes, including bilingual navigation, theme tokens, safe static triage, watchlists and printable quick reports.

The design review followed **unslop by Damir Sokolovsky ([@heydamir](https://x.com/heydamir)), CC BY 4.0**, in polish mode:

- **Product:** a SOC analyst's workspace for triage, investigation and evidence-based reporting.
- **Character:** calm, precise, operational.
- **World:** security monitoring instruments and long analyst shifts.
- **Moments:** meaningful alert severity and the investigation report; navigation stays quiet.
- **Signature:** monospaced case references and an understated selected-navigation indicator.

Kept the existing IBM Plex/JetBrains fonts, neutral surfaces, cobalt accent, feature set and section order.

## Findings corrected

- English sign-in expanded a 390px viewport to 482px because long decorative badges imposed an intrinsic minimum width. Replaced them with wrapping neutral descriptions and constrained the grid tracks and children.
- Monitoring actions broke the word “investigation” across lines. Gave the action column room, preserved word boundaries and allowed timestamps to wrap at spaces.
- Reduced heavy headings, tight tracking on small text, repeated decorative dots and coloured feature-icon backgrounds.
- Normalized the spacing of case-selection cards, account choices and feature groups.
- Quick reports now use a compact mobile layout, a two-column metadata grid and wrapping table cells, while retaining the A4 print layout.
- Removed redundant accessible labels from textual brand links; decorative version stamps are hidden from assistive technology.
- Corrected `high_risk` static-triage results using the low-severity report colour. The existing report workflow test now checks the high-severity badge.
- Corrected optional-value narrowing in SIEM ingestion and formatted the files rejected by the repository's formatter.

## Local verification

Environment: Windows, Python 3.13.7, Microsoft Edge through Playwright, synthetic data in isolated temporary databases.

- 130 unit and V6 workflow tests passed before the final SIEM type-narrowing fix; all 12 V6 workflow tests passed again afterwards.
- Ruff formatting and lint checks passed.
- Mypy with the deployment target `--platform linux` passed for 89 source files.
- Bandit passed; the tracked-file secret scan passed using the same two fixture exclusions as CI.
- The dependency audit reported no known vulnerabilities; `pip check` reported no broken requirements.
- Generated design tokens matched their source; all 26 checked colour pairs met the 4.5:1 contrast threshold.
- OpenAPI regeneration produced no specification differences; all JavaScript files passed Node syntax checks.
- Browser design review covered sign-in, cases, monitoring, quick reports and the retained landing page at desktop and 390px widths, in Arabic/English and light/dark combinations. The corrected pages fit their viewport and emitted no JavaScript page errors. Dense monitoring tables scroll within their container on mobile.
- All 13 browser tests in `test_interface_theme.py`, `test_interface_languages.py` and `test_browser.py` passed (428.62 seconds). The public-page typography, responsiveness and accessibility test also passed independently after the final accessible-label correction.

Local visual evidence is stored in ignored `artifacts/unslop-before`, `artifacts/unslop-after` and `artifacts/unslop-final` directories. Machine-readable test results are in the ignored `artifacts/readiness-v6-*.xml` files.

## Deployment acceptance

The complete suite requires the isolated Linux analysis service (Landlock/seccomp, Unix sockets and native report rendering). A Windows-only run is not evidence of Linux deployment acceptance; the attempted complete local run hit these platform dependencies and was stopped. No security isolation was disabled to make tests pass.

The Enterprise Quality Gates workflow now covers V5, V6 and `feat/v6-*` pushes as well as pull requests, and supports manual dispatch. Verify its quality, security, browser, container and performance jobs on the exact uploaded commit before promoting the branch to a production release.
