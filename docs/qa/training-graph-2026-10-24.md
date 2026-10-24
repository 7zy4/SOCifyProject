# Training reproducibility and interactive graph

Training restarts now pin the original scenario version, seed, difficulty and rate even after a new version is published. Creating the replacement and cancelling the original share a transaction; injected audit failure leaves the original running with no partial replacement. Analyst scenario reads no longer disclose hint text without consumption. Hint counts and action history commit atomically, and completed assessments reject further hint consumption.

The graph UI now passes case/run/time/severity filters to graph, timeline and export consistently. The API validates case and severity filters and returns no results for inaccessible cases. Timeline timestamps use `event_time`, correcting the previous incorrect field names. Controls provide zoom, fit, keyboard panning, node selection and neighbor navigation, plus an accessible table. Selecting a timeline event selects its graph node. Truncated responses display a refine-query notice.

Chromium at 390px verifies zoom/reset, keyboard node selection, real UTC timestamps, severity filtering, JSON download and axe-core accessibility. The six browser tests passed in 35.65 seconds. Focused training tests passed (35); graph filter API tests passed (1). Ruff format/lint and mypy passed.

REA was rerun on the modified browser files using the pinned CLI. [Full compressed evidence](../research/rea-graph-evidence-2026-10-24.json.gz):

- Evidence `ev_218dfaf7df7c2f102fa03a7742f1b0261cac6ea46c1fab3ce3f733bcf6c608df`
- Target `58891086a7ad9360e6c1687a02eaa437db8b586fa5e29db52a9eebebd173b178`
- Semantic graph `jsrg_d947e711f1324d8a84453b84182de23b833882b967ac0dd1c9094986b66851cf`
- Uncompressed evidence SHA-256 `e15488737c784e4a1302ce8a7f912c77696655f6cad896a2c0d2abfb2d42e853`

REA parsed two files totaling 71,282 text bytes, visited 10,263 AST nodes and reported zero parse failures. Its 1,658 explicit unknown relationships remain unknown; static analysis does not prove runtime correctness. Clustering, complete path highlighting, comprehensive graph types, live reconnect behavior and final acceptance remain open.
