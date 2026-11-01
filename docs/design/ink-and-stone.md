# Ink & Stone — 2 November 2026

The revised direction follows the owner's supplied references: printed ink, angular lettering, warm paper, charcoal, slate and aged gold. The interface communicates this through its materials and shapes, with no character branding, neon colours or decorative genre labels in product copy.

## Applied across the product

- Sign-in and registration use one focused form below a large wordmark. The verification field expands when needed; password, invitation and CSRF protections remain in place.
- Cairo provides bold, angular Arabic lettering; Bangers supplies English headings and the wordmark; IBM Plex Sans and JetBrains Mono keep body copy and evidence readable. All fonts are bundled locally.
- Shared light/dark tokens set opaque text colours, hand-inked edges, solid offset shadows, hatching and halftone backgrounds. An original SVG architectural backdrop frames authentication without using licensed character artwork.
- Redundant introductions are removed. Important scope, safety, evidence, timestamps and approval explanations remain readable.
- The header contains the wordmark, an appearance switch, language and account. Account actions are grouped in a keyboard-accessible disclosure.
- The appearance control has light/system/dark states, persistent preferences, immediate feedback, interruptible spring motion and reduced-motion support.
- Severity uses distinct brick, ochre, slate and olive fills with visible text labels. Mobile monitoring uses labelled cards and expandable details.
- Printable quick reports and native report styles use the same palette and typography. Native A4 safety margins are retained.
- Product version stamps and current built-in rule labels no longer carry a release number. Existing rules retain their IDs, detection logic and immutable history during the label refresh.

## Review evidence

The user's explicit typography, texture and detail requirements take precedence over the restrained weight/radius defaults in unslop. Its review workflow was used to check layout, unnecessary copy, consistency, contrast and actual browser output.

Local Windows/Edge verification:

- Five theme, operational UI, accessibility and public-page browser tests passed, including Arabic/English, light/dark and widths 390, 768, 1280 and 1440.
- Twenty-seven authentication, security and built-in rule integration tests passed, including MFA form continuation and preservation of rule identity/history.
- Eleven quick-report and password-integrity tests passed.
- Twenty-six token contrast pairs passed the 4.5:1 threshold. Eleven representative screenshots produced no serious/critical axe violations or JavaScript errors; page widths stayed within their viewport. Visually hidden mobile table headings are retained for assistive technology.
- Ruff formatting/lint, Bandit and Mypy for the Linux deployment target passed.
- Additional legacy-browser checks caught the fixed header covering investigation actions. The training shell now keeps its header in the layout; both affected action/CSRF workflows passed again.
- The secret scan found no new secrets. Only two existing synthetic test-fixture line numbers changed in the baseline.

Screenshots and measurement output are local, ignored artifacts under `artifacts/unslop-ink-*`. Full Linux service, native PDF, browser, container and performance acceptance is enforced by the Enterprise Quality Gates workflow on the uploaded commit.

Figma was opened and a reference file was created, but the connected Starter plan reached its MCP call limit before canvas construction. The blank file is not presented as a completed design. Application screenshots are the implemented source of truth and can be imported into Figma.

Review references: **unslop by Damir Sokolovsky ([@heydamir](https://x.com/heydamir)), CC BY 4.0**; Anthropic frontend-design; [Apple Design by Emil Kowalski](https://github.com/emilkowalski/skills/tree/main/skills/apple-design), applied to control motion and interaction feedback. The latter was installed locally as requested.
