# SOCify interface redesign — implementation and verification

The operational interface now shares a light/dark palette, a two-family Arabic/English typography system and responsive investigation surfaces. Case context is readable before opening its edit controls. Existing API, authorization, evidence handling, CSRF and report snapshots remain the source of behavior.

- [Expanded implementation prompt and complete color codes](interface-redesign-prompt.md)
- [Figma design](https://www.figma.com/design/Ytucm3oFTuZRB3SrxVGRCX?node-id=6-6)
- [Figma state ledger](figma-state.json)

## Shared implementation

`static/design-tokens.json` defines 25 semantic color roles in Light and Dark, spacing, radii and typography. `python -m scripts.generate_interface_tokens` regenerates `static/tokens.css`; `--check` detects drift. `static/design-system.css` applies the hierarchy to the retained application styles. `static/theme.js` resolves the initial theme in the document head and provides System/Light/Dark controls on all four templates, with local persistence, system changes and cross-tab synchronization.

The active interface uses only Almarai for Arabic and IBM Plex Sans for Latin. Three local WOFF2 assets provide real Arabic Regular/Bold and a variable English weight axis. Licenses, source URLs, sizes and digests are included under `static/fonts/`. The previous fonts remain available for historical compatibility but are not loaded by the active interface. New HTML/PDF reports embed the new fonts; DOCX names IBM Plex Sans for Latin and Almarai for complex script. Report output remains light regardless of the application preference.

Operational views include cases, all seven case tabs, tasks, team, playbooks, local analysis library and profile/security. Case titles are links, severity and workflow status have separate treatments, the active navigation and reports tab expose `aria-current`, the case reference replaces the repeated long top-bar title, and editable context/responsibility/handover forms open on demand. Form saving exposes a busy state and translated progress text. The retained landing page is redesigned while the operational root keeps its existing redirect behavior.

## Figma deliverable and remaining limits

The file contains 76 native editable screen frames: 16 desktop compositions in each language/theme combination, plus mobile cases, summary and login examples in all four combinations. Six component families contain 104 variants. Sixteen text styles use the two chosen families. Semantic variables alias 44 color primitives; Light and Dark use separate collections because this Starter account supports only one mode per collection.

These are representative design compositions of the existing product, not a claim that every administrative form and backend state has a separate Figma frame. The website retains its original PNG logo; the Figma lockup uses the repository SVG symbol with an editable wordmark. Screens are native text, vector, frame and component-instance nodes, with no complete-screen raster backgrounds.

**Unfinished in Figma:** the Starter MCP call quota was reached before the final prototype connections and foundations specimen could be completed, and before a screenshot of the last mobile alignment refinement could be taken. Screens, component variants, tokens and typography were created successfully. The quota error explicitly requires an upgraded plan or renewed quota for more calls. `figma-finalize.js` contains the corrected, retry-safe navigation linking pass; supply `figma-state.json` as `LEDGER` and load the Figma use/generate-design skills before running it. Active links deliberately do not navigate to their own frame.

## Verification

The browser matrix checks every operational route and case tab in Arabic/English and Light/Dark. It checks loaded fonts, persisted/system preferences, storage failure, direction, context editing and saving, page overflow at 390/768/1280px and axe serious/critical violations. Separate public-page checks cover landing, login and registration in both languages/themes. Existing navigation/search/draft-retry and choice-menu journeys and both CSS/native 200% zoom checks are included.

Direct report rendering produced PDF, DOCX, HTML, Markdown and JSON from a synthetic case. `pdffonts` confirmed embedded IBM Plex Sans, Almarai and Almarai Bold subsets, with Unicode mapping. The report security test verifies escaped evidence, no external relationships and the updated Latin/complex-script font assignments. Token generation consistency, JavaScript syntax, CSS parsing, Ruff lint/format and whitespace checks pass.

**Environment-blocked checks:** two report-worker integration tests and three longer analysis/report browser journeys fail because the selected runtime does not implement the Landlock syscall required by the pre-existing isolation boundary. A standalone `harden()` probe returns `OSError: [Errno 38] Function not implemented` from syscall 444 before analysis or report rendering. This was reproduced outside the nested execution sandbox. The isolation controls were not removed or weakened. Run those existing worker journeys in the project's supported Linux/container environment before merging or deployment.

Screenshots in `previews/` use synthetic test records and test accounts only.

Latest focused results: **10 browser tests passed** (including the full theme/language matrix, public pages, draft/navigation preservation, choice interaction and two zoom modes); **10 report/security/catalog tests passed, 2 worker cases excluded after their isolation failure was documented**. The broader pre-exclusion browser run returned **8 passed, 3 worker-dependent failures**.
