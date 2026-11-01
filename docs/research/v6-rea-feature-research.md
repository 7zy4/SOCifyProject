# SOCify V6 — Reference Tool Research & REA Mechanism Analysis

This document records the reference tools studied for **SOCify Tactical Workbench (`SOC / V6`)**, separates **sealed static artifact analysis performed with `REA` (`rea@6.8.0`)** from **external specification and open-source architecture research**, and maps each recovered mechanism to concrete V6 upgrades.

---

## 1. Methodology & Epistemic Boundaries

To adhere strictly to evidence-backed engineering:

1. **REA Static Artifact Analysis (`rea@6.8.0`):**
   - Executed against actual downloaded/shipped npm tarball artifacts (`file-type@22.3.0`, `postal-mime@4.2.0`, `ipaddr.js@2.5.0`, `cyberchef@11.5.0`) and SOCify's shipped frontend JavaScript (`static/*.js`).
   - Every REA claim below cites its sealed **Parent Evidence ID (`ev_...`)**, **Summary View ID (`ev_...`)**, **Root Artifact SHA-256**, **Application Graph ID (`jag_...`)**, and **Semantic Graph ID (`jsrg_...`)**.
   - Static analysis limitations (such as unselected files in large packages or runtime-only browser print behavior) are explicitly noted.
2. **External Reference Architecture & Standards Research:**
   - Used for domain-standard log schemas, SIEM HTTP push conventions, SOC case ownership models, and incident taxonomy frameworks (**Splunk HEC**, **Elastic Bulk/Ingest**, **ArcSight CEF**, **Chainsaw**, **Hayabusa**, **Sublime Security**, **DFIR-IRIS / TheHive**, **NIST SP 800-61r2 / VERIS**). These are cited as architectural/specification references rather than REA artifact claims.

---

## 2. REA Static Artifact Analysis (`rea@6.8.0`)

### 2.1 Summary of Sealed REA Evidence Bundles

| Target Artifact | Version | Root Artifact SHA-256 | Parent Evidence ID | Summary View ID | App Graph (`jag_...`) | Semantic Graph (`jsrg_...`) |
| --- | --- | --- | --- | --- | --- | --- |
| **`file-type`** | `22.3.0` | `b55dfbb99e51ad118b6955a6f0786b9ea328a4326ddf78c24fdd1cb831e184da` | `ev_f82f429e9220c98452ce66c8cb70a2e5090dcccf4606158fcfb17b9b8d11eefc` | `ev_aef27e314bfa68fe1f88f8533330b311eab769b0e5e0c6f74c9320900e3b5d13` | `jag_986f4b4c3562c1c57f686b138d6d59816434bb73f05f098d3b88b36e6d9347b6` (86 nodes, 140 edges) | `jsrg_99e2c6a449000545b72c21355ccf12e1f200b664174936f6e561da67acb2e5f8` (5,281 nodes, 3,874 relations) |
| **`postal-mime`** | `4.2.0` | `103b4cacdf60fada7884f6dd81cfccf3e081a3f8a2987c43d56f0f03ccfa85a5` | `ev_7b6bbc902dbf9af5dea7b34640b1ea86e92f2e05ce9652d4126fd1a35a96f1ab` | `ev_26621ad16fdde75be131742489900510112c55d58c158659f22bb90824888de9` | `jag_8f12277b51e89c6a2b7c025152cd9e8b1ac36fa7bb628aa9cf196a0592039322` (446 nodes, 737 edges) | `jsrg_24c1faaa9aca5da017ee08c44385e194eef919ddb06a620c9184d50f837028d3` (37,287 nodes, 34,538 relations) |
| **`ipaddr.js`** | `2.5.0` | `36d5b0012fbd9bd3f8f91f4570a7f1f3224fb2d1aea33eb959460c6ad1b67e8b` | `ev_a6b2ee3bbdf47273533640f0ebd3b192a240ac827959a0b4e329ce0a2e818e94` | `ev_cb6456cd66833e68cc323d15bdb492b432854ad329d07af2584c5f8b31382302` | `jag_7a92ef2239660a9ca585755fa414440122aa9e3cf180720a1dc95d5bee4d8f26` (11 nodes, 11 edges) | `jsrg_78533bba5faae961d3ba448ae9fd56ca44935984577686121112258c2ddd6963` (2,526 nodes, 2,192 relations) |
| **`cyberchef`** (10 triage modules) | `11.5.0` | `ea302b2ce5925988a013d121875a9864894049cb8b4a8f22e7e0e63f26c5fd28` | `ev_70e04f0c99d00cbb73c18f492a0cd30216a96bf500ec6003e956b0cdf2061b63` | `ev_780fe8b8d4e3216066656f6b71ae45b720cc0f03fd5b5c15943bf90fafb17a96` | `jag_231956a0a79f20002aab13760d232e31f509a6f5fc958129043ed872b2d0f3e4` (1,891 nodes, 1,951 edges) | `jsrg_429e6a1990f169d8c13e1ad8b73f88eebd8e162ad685bfe2f8dfd1759e4c8544` (4,634 nodes, 3,427 relations) |
| **`socify-frontend`** (`static/*.js`) | `V5->V6` | `2db46799c31ddeb1393a0218b97e4844a7e68698cb9a1ca5b1a2ac3e5a284e42` | `ev_48ca4f2634d0d4d04a1bd0b985da6d7a6bc430a215f614432addf913a521c0af` | `ev_26c404dd820d384544df228bba866c20db8dc86f0d384544df228bba866c20db`* | `jag_9d78faf9ce72faebff3295ac24b1fe5a278186c713098dbd21fe43d020ac3939` (85 nodes, 90 edges) | `jsrg_8a487dbee792f6b05e6e7e57ab0c926a614dbdff14dd0aba8733a162b72520c1` (32,884 nodes, 32,474 relations) |

*\*Exact `socify-frontend` summary view ID: `ev_26c404dd820d384544df228bba866c20db8dc86f0d3334f3eaa814399016c569`.*

---

### 2.2 Recovered Mechanisms & Design Invariants

#### A. Magic-Byte Disambiguation & Anti-Zip-Bomb Central Directory Inspection (`file-type@22.3.0`)
- **REA Evidence:** `ev_f82f429e9220c98452ce66c8cb70a2e5090dcccf4606158fcfb17b9b8d11eefc` (`source/core.js`, `source/parser.js`, `source/detectors/zip.js`).
- **Recovered Exports & Call Graph:**
  - `source/parser.js` exports `safeReadBuffer`, `getSafeBound`, `maximumUntrustedSkipSizeInBytes`, `ParserHardLimitError`, `hasExceededUnknownSizeScanBudget`.
  - `source/detectors/zip.js` exports `detectZip` and invokes `ZipHandler` bounded by `maximumZipEntryCount` (`1024`) and `canReadZipEntryForDetection` (verifying both `compressedSize` and `uncompressedSize` stay within `1 MiB` before inspecting entry content).
- **Why It Matters for SOCify V6:**
  - Checking only the first 4 bytes (`PK\x03\x04`) conflates benign `.zip`, `.docx`, `.xlsx`, `.pptx` files with macro-bearing `.docm`, `.xlsm`, `.pptm`, `.jar`, `.apk`, or disguised double-extension executables inside archives.
  - Extracting untrusted archives on disk risks zip bombs and path traversal (`../`).
  - **V6 Implementation:** `socify/autopsy_static_analysis.py` inspects the ZIP central directory (`zipfile.ZipFile` over `io.BytesIO`, capped at `1,024` entries, zero disk extraction, bounded per-entry read only for tiny metadata files like `[Content_Types].xml` or `vbaProject.bin` up to bounded byte budgets) to detect OOXML macro projects (`vbaProject.bin`), embedded executables inside archives (`.exe`, `.scr`, `.hta`, `.js`, `.vbs`, `.ps1`, `.lnk`, `.iso`), and compression-ratio anomalies (`uncompressed / compressed > 100` with large uncompressed size).

#### B. Shared-Budget MIME Tree Traversal & Nested `message/rfc822` Containment (`postal-mime@4.2.0`)
- **REA Evidence:** `ev_7b6bbc902dbf9af5dea7b34640b1ea86e92f2e05ce9652d4126fd1a35a96f1ab` (`dist/node/postal-mime.js` / `src/postal-mime.ts`).
- **Recovered Mechanism:**
  - `PostalMime` passes a single shared `LimitCounters` state across the root message and all nested `message/rfc822` parts rather than resetting counters per sub-message.
  - Enforces explicit hard bounds on total MIME nesting depth, total MIME part count, header byte size, and nested `message/rfc822` recursion depth (deeper nested RFC822 messages are treated as opaque attachments rather than recursively parsed forever).
- **Why It Matters for SOCify V6:**
  - Phishing emails frequently nest `.eml` inside `.eml` or include malformed multipart trees to evade naive attachment scanners or exhaust memory.
  - **V6 Implementation:** `POST /api/cases/<id>/email-triage` (`socify/autopsy_email.py`) walks MIME trees with a shared counter budget (max MIME parts, max nesting depth, max attachment count, and bounded total attachment bytes), extracts authentication signals (`SPF`, `DKIM`, `DMARC`, `From` vs `Reply-To` vs `Return-Path`), extracts protocol-anchored URLs, and runs `inspect_static_bytes()` on every attachment in one click without ever executing or writing unencrypted attachment bytes to disk.

#### C. Dual Entropy (Whole-File + 256-Byte Sliding Window), Offset Signatures & Protocol-Anchored IOCs (`cyberchef@11.5.0`)
- **REA Evidence:** `ev_70e04f0c99d00cbb73c18f492a0cd30216a96bf500ec6003e956b0cdf2061b63` (selected 10 modules from `cyberchef@11.5.0`; REA coverage note: 924 unrelated cipher/encoding operations were intentionally excluded from static selection).
- **Recovered Mechanisms:**
  - `Entropy.mjs`: Computes whole-buffer Shannon entropy ($H \in [0, 8]$, flagging $> 7.5$ as likely encrypted/packed/compressed) **and** sliding-window 256-byte block entropy so high-entropy encrypted payloads embedded inside low-entropy HTML/JS wrappers (**HTML smuggling**) are caught even when overall file entropy is moderate ($5.2 - 6.3$).
  - `FileType.mjs` & `ScanForEmbeddedFiles.mjs`: Uses offset-aware magic signatures (`MZ`, `\x7fELF`, `%PDF-`, `\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1`, `PK\x03\x04`, `Rar!`, `7z\xbc\xaf'\x1c`, `LNK` `\x4c\x00\x00\x00\x01\x14\x02\x00`, `ISO`/`UDF`, `RTF` `{\rtf`) and scans non-zero offsets for polyglot/appended payloads.
  - `ExtractURLs.mjs`, `ExtractIPAddresses.mjs`, `ExtractEmailAddresses.mjs`: Anchors URLs on explicit scheme (`https?://`, `ftp://`) so dotted filenames (`invoice.pdf.exe` or `WScript.Shell`) are never misclassified as domains/URLs.
- **Why It Matters for SOCify V6:**
  - Directly powers `inspect_static_bytes()` in `socify/autopsy_static_analysis.py` so analysts get high-signal verdicts (`low_observation`, `suspicious`, `high_risk`) with zero false-positive URL noise from code identifiers.

#### D. IPv4 / IPv6 / CIDR & IPv4-Mapped IPv6 Normalization (`ipaddr.js@2.5.0`)
- **REA Evidence:** `ev_a6b2ee3bbdf47273533640f0ebd3b192a240ac827959a0b4e329ce0a2e818e94` (`lib/ipaddr.js`).
- **Recovered Mechanism:**
  - `ipaddr.process()` normalizes IPv4-mapped IPv6 addresses (`::ffff:192.0.2.25` -> `192.0.2.25`) prior to `match` / `subnetMatch` CIDR checks.
- **Why It Matters for SOCify V6:**
  - Dual-stack Linux/Windows proxies and SIEM forwarders often emit `::ffff:203.0.113.50`. Without unwrapping `addr.ipv4_mapped`, an analyst's watchlist entry for `203.0.113.50` or `203.0.113.0/24` misses IPv4-mapped IPv6 logs!
  - **V6 Implementation:** `socify/watchlist.py` normalizes both IPv4/IPv6 literals and `ip_address(...).ipv4_mapped` before matching exact IPs and CIDR subnets.

#### E. SOCify Frontend Architecture Audit (`socify-frontend`)
- **REA Evidence:** `ev_48ca4f2634d0d4d04a1bd0b985da6d7a6bc430a215f614432addf913a521c0af` (`static/*.js`, 20 scripts, 85 application graph nodes, 32,884 semantic graph nodes).
- **Recovered Structure & Upgrade Opportunities:**
  - `static/soc-workbench.js` drives 7 operational workspace views (`monitoring`, `triage`, `cases`, `email`, `sandbox`, `threat-intel`, `reports`), while `static/autopsy*.js` drives deep per-case tabs (`overview`, `data`, `events`, `analysis`, `reports`, `audit`).
  - Both layers route localized strings through `SOCifyLocale.text(...)` (`static/localization.js`), validated by `tests/unit/test_interface_translation_catalog.py`.
  - **Identified Friction Fixed in V6:**
    1. Case creation previously assumed manager approval/selection workflows; V6 adds direct creation with tactical defaults and a 1-click **Claimable Team Cases (`استلام الملكية`)** queue.
    2. Log import required a 2-step preview-then-commit dance even for urgent single-file triage; V6 adds 1-click **Quick Import & Scan (`استيراد وفحص فوري`)** plus direct SIEM webhook/pull management.
    3. File/sandbox analysis required an external Linux Docker worker socket (`503` on standalone Windows/macOS); V6 adds 1-click cross-platform static file & `.eml` attachment triage directly in the coordinator.
    4. Threat intelligence was read-only admin bundles; V6 adds an interactive **Suspicious Emails & IPs Watchlist** with 1-click `+ قائمة المراقبة` buttons across views.
    5. Reporting required free-text writing and background WeasyPrint PDF workers; V6 adds a **9-Question Dropdown Triage Report** with instant browser A4 printing (`@media print`) and 1-click **Escalate to Manager**.

---

## 3. External Architecture & Specification Research (Non-REA)

| Capability Area | Reference Tools / Standards | Adopted Pattern in SOCify V6 |
| --- | --- | --- |
| **Fast EVTX / Windows Event Triage & Built-in Rules** | **Chainsaw**, **Hayabusa**, **SigmaHQ** | Extract high-value Sysmon & Windows Security `EventData` keys (`CommandLine`, `Image`/`NewProcessName`, `ParentImage`/`ParentProcessName`, `IpAddress`, `TargetUserName`) during XML/EVTX normalization and ship **16+ built-in SOC detection rules** auto-seeded into every workspace so uploaded logs generate alerts immediately. |
| **Direct SIEM Push & Pull Ingestion** | **Splunk HEC** (`Authorization: Splunk <token>`), **Elastic HTTP Bulk**, **ArcSight CEF** | Add `POST /api/sources/<id>/ingest` accepting `X-SOCify-Source-Key` or `Authorization: Bearer/Splunk <key>` (verified via `hmac.compare_digest`) supporting JSON, JSONL, Syslog, and **CEF (`CEF:0|...`)**, plus `POST /api/sources/<id>/pull` honoring `SOCIFY_SOURCE_ALLOWLIST`. |
| **Email & Attachment Triage** | **Sublime Security**, **EMLDump / oletools** concepts | Combine header auth checks (`SPF`/`DKIM`/`DMARC`, Reply-To mismatch), link inspection, and static attachment triage (`vbaProject.bin`, PDF `/JS` & `/OpenAction`, double extensions, RLO `\u202e`, LNK/ISO/HTML smuggling indicators) in a single non-executing pass. |
| **Collaborative Case Claiming** | **DFIR-IRIS**, **TheHive** | Any analyst can open a case immediately or claim unassigned workspace cases via `GET /api/cases/claimable` and `POST /api/cases/<id>/claim`, escalating only the completed report to the SOC Manager. |
| **Structured Dropdown Incident Reporting** | **NIST SP 800-61r2**, **VERIS Framework** | Replace blank-page report writing with 9 structured dropdown taxonomy questions (Classification, Verdict, Severity, Attack Vector, Impact Scope, Containment Action, IOC Disposition, Escalation Priority, Recommended Next Step) + auto-attached alerts, watchlist hits, and static file/email triage evidence. |

---

## 4. Existing Platform Bugs & Cross-Platform Friction Discovered & Upgraded

During baseline verification on Windows (`Python 3.13`), several existing platform limitations were identified and resolved alongside V6 features:

1. **Missing `tzdata` Dependency & `ZoneInfo("UTC")` Failure on Windows:**
   - Windows Python installations do not ship system IANA `/usr/share/zoneinfo` files; `ZoneInfo("UTC")` in `socify/ingestion.py` raised `ZoneInfoNotFoundError` (`422 source timezone is not available locally`) on every log import unless `tzdata` was installed.
   - **Upgrade:** Added `tzdata` to `requirements.txt` and added a native `datetime.timezone.utc` fallback for `"UTC"` in `socify/ingestion.py` and `socify/autopsy_workflow.py`.
2. **Unix-Only Module Imports Blocking Windows CLI/Test Collection:**
   - `socify/analysis_sandbox.py` (`import resource`), `scripts/start_v4_demo.py` (`import fcntl`), `scripts/run_analysis_service.py` (`import fcntl`), and `scripts/start_codespace.py` (`import gunicorn.app.base`) failed at import time on Windows, and `socify/analysis_transport.py` / `socify/autopsy_worker.py` referenced `socket.AF_UNIX` / `os.O_NOFOLLOW` unconditionally.
   - **Upgrade:** Added clean platform guards so modules import cleanly across Windows, macOS, and Linux while keeping every Linux fail-closed sandbox security invariant intact.
3. **WeasyPrint Native GTK (`libgobject-2.0-0`) & Linux Landlock Dependency for Basic Triage:**
   - Standalone analysts on Windows/macOS laptops could not run sample analysis or print PDF reports without Docker/GTK.
   - **Upgrade:** V6's pure-Python static file/email triage and self-contained `@media print` A4 quick report run natively in `<50 ms` on Windows, macOS, and Linux with zero native daemon dependencies.
4. **Windows Exclusive File-Handle Locking on `.evtx` Imports & Startup Key Generation (`socify/ingestion.py`, `scripts/prepare_codespace.py`):**
   - **Finding:** `_evtx_records` opened `Evtx(temporary.name)` while `tempfile.NamedTemporaryFile` still held an open handle (`PermissionError: [Errno 13]`), and `prepare_codespace.py` called `temporary.unlink()` inside `with NamedTemporaryFile(..., delete=False)` (`PermissionError: [WinError 32]`).
   - **Upgrade:** Closed temporary descriptors prior to reopening/unlinking (`TemporaryDirectory` for `.evtx`, closed handle before `os.link`/`unlink` in `prepare_codespace.py`), enabling native `.evtx` ingestion and clean first-boot key initialization on Windows.
