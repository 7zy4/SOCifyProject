# SOCify reference desktop implementation

The current website follows the user's supplied front-facing 1600×1200 security desktop screenshot: five overlapping, square-edged windows, a paper dossier, two terminal surfaces, an upper-right folder strip and a bottom taskbar. SOCify's blue/ink palette replaces the reference colors. The old PNG logo and SVG symbol are removed; all four site templates and new reports use a live text **SOCify** wordmark.

- [Revised Arabic/English implementation prompt, dimensions and full color table](interface-redesign-prompt.md)
- [English dark desktop](previews/desktop-en-dark-1600.png)
- [English light desktop](previews/desktop-en-light-1600.png)
- [Arabic dark desktop](previews/desktop-ar-dark-1600.png)
- [Arabic mobile](previews/desktop-ar-dark-mobile.png)

## Behavior and scope

`static/desktop.js` enhances the retained operational workspace, preserving its DOM, route handlers, forms and API. It provides drag, resize, minimize, maximize/restore, close/reopen, taskbar switching, layout reset and keyboard move/resize. Scrollable window bodies can receive keyboard focus. Closing a window hides its view; it does not delete records. Desktop positions are session-local and resettable. The focus preference persists in sessionStorage; positions do not.

At 1600×1200, the five initial window bounds are tested against the screenshot-derived target within 4 CSS pixels. RTL changes internal content direction while retaining the reference's composition. The exact source portrait/fingerprints are replaced by authorized case evidence. Case data, import hashes, history and access context come from existing authenticated APIs. Empty states remain empty; no operational records or encryption claims are invented. The directory previews the first 25 authorized cases. Case list folder/table preference is retained during the session.

The case list initially shows the reference desktop. Internal operational routes default to a focused workspace unless a session preference exists; Focus workspace or Escape switches views. Below 1100px, one active window fills the workspace and the taskbar switches views. This preserves readable forms on mobile. Existing search, pagination, case tabs, context editing, roles, CSRF and server authorization remain in place.

The shared styles cover cases, the seven case tabs, tasks, team, playbooks, analysis library, profile/security, login, registration and the retained public landing page. The operational root keeps its redirect behavior; retired training features are not reintroduced.

## Design system

`static/design-tokens.json` is the color/spacing/typography source; `python -m scripts.generate_interface_tokens` emits `static/tokens.css`, with `--check` to detect drift. `static/design-system.css` provides the retro window styling over the retained page styles. `static/theme.js` resolves System/Light/Dark before CSS, persists the preference, responds to system and cross-tab changes, and tolerates unavailable browser storage.

Only Almarai (Arabic 400/700) and IBM Plex Sans (Latin variable) are loaded by the active interface. Local WOFF2 files, OFL licenses, source URLs and digests are under `static/fonts/`. Arabic text has no added letter spacing, technical identifiers retain LTR direction and user/evidence content is preserved. The paper dossier remains light in both themes. Printed reports use light surfaces independent of the website setting. New HTML/PDF reports embed the fonts and a text wordmark; DOCX names the same two font families without a logo image. Previously stored reports are not rewritten.

## Verification

The reference-desktop browser test exercises real case/import APIs, initial geometry, taskbar restore, maximize/restore, folder/table switching, pointer drag/resize, keyboard movement, closing without data loss, reset, focus, RTL, light/dark, mobile overflow, browser errors and old-logo network requests. The broader browser matrix exercises all operational routes in both languages/themes, local font loads, storage failure, system theme changes, edit/save, responsive layouts and automated axe serious/critical checks. Public templates, search/draft preservation, dropdown interactions and CSS/native 200% zoom have separate coverage. Automated checks do not constitute a complete manual accessibility audit.

Report security tests check escaped content, blocked image/network asset requests, font assignments and absence of media in new DOCX output. Token consistency, JS syntax, CSS parsing, Ruff and whitespace checks are also run. Screenshots use synthetic test records/accounts only; names and evidence content are not translated by the product.

**Known environment limit:** existing isolated report/analysis worker journeys require Landlock. The provided runtime returns `OSError: [Errno 38] Function not implemented` for syscall 444, before rendering/analysis. This was reproduced independently of the interface and outside the nested sandbox. The isolation boundary remains intact. Two worker-dependent report tests are excluded from the focused report run, and three longer worker-dependent browser journeys are not counted as passing. Run those checks on the project's supported Linux/container runtime before deployment.

**Figma:** the screenshot is the final visual reference for this iteration. Riffs could not be read directly. A previous Figma design explored an earlier direction; it was not updated to this final desktop composition, and should not be treated as its source of truth.

Implementation is delivered directly to `socify-version-3`, as requested, without creating a branch or pull request.

## Recorded final results — 2026-10-27

- Browser run: **11 passed in 70.61s** across reference desktop, full interface theme matrix, language, navigation, dropdowns and two zoom checks.
- Focused report/security/catalog run: **10 passed, 2 worker-dependent cases deselected in 4.01s**.

```sh
.venv/bin/pytest -q -m e2e tests/e2e/test_desktop_windows.py tests/e2e/test_interface_theme.py tests/e2e/test_interface_languages.py tests/e2e/test_autopsy_navigation_state.py tests/e2e/test_investigation_dropdowns.py tests/e2e/test_autopsy_zoom_keyboard.py
.venv/bin/pytest -q tests/security/test_autopsy_report_security.py tests/unit/test_interface_translation_catalog.py tests/integration/test_autopsy_reports.py -k 'not local_report_formats_snapshot_review_and_closure and not report_bola_redaction_and_revoked_worker_access'
```

Formatting-only changes to the desktop test after this run do not change its assertions or behavior.
