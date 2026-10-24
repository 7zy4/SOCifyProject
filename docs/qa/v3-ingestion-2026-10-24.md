# V3 case-bound ingestion and export checkpoint

This checkpoint extends the case-first foundation; it is not final V3 acceptance.

Implemented:

- Case-scoped preview/import/list/detail/cancel/resume/original-download endpoints, retaining raw bytes encrypted with a verified SHA-256 and a separate original filename.
- Explicit CSV delimiters, encodings, source timezone and validated field mappings; DST ambiguity/gaps are quarantined instead of silently choosing an offset. Missing event times are marked as ingestion-time fallbacks, not observed attack times.
- JSONL quarantine continues after malformed records. Import jobs attach normalized events and derived alerts to their authorized case. Job retries recheck the creator's active permission and case access.
- Detection windows and watermarks use a trusted owner-case field. A negative test proves that two different private cases cannot jointly trigger a two-event threshold, while two events in the same case can.
- PCAP/PCAPNG metadata parsing in the import worker: Ethernet/raw IP, IPv4/IPv6, ports/protocol, bounded uncompressed DNS questions, visible single-frame TLS ClientHello SNI and HTTP method/path without query strings. Originals remain unchanged; no traffic acquisition, TCP reassembly, decryption or URL fetch occurs.
- SQLite FTS5 indexing, bounded case search/pagination, explicit selection of important log records as exhibits, and streamed CSV/JSON/JSONL export with CSV formula neutralization and an independently permissioned unredacted mode.
- Original-file evidence is the default forensic exhibit. Raw log rows remain accessible with source/row provenance; selecting a key log adds its own exhibit. This avoids multiplying full exhibit metadata for every routine imported row.

Evidence: **447 non-browser tests passed**, combined statement/branch coverage **90.89%**, in 102.23 seconds; **10 Chromium journeys passed** in 59.21 seconds. The V3 ingestion file has **21 passing integration tests**, including real offline TLS ClientHello generation, IPv6, PCAPNG, DNS, encoding/timezone, raw-byte comparison, case/detection isolation, role revocation and redaction. The browser import journey previews/commits a file with CSRF enabled, downloads byte-identical evidence and verifies normalized JSON export; axe found no serious/critical violations in its observed page.

Ruff, mypy, Bandit, JavaScript syntax checks and the runtime dependency audit passed. Dependency audit reported no known vulnerabilities; this is not proof of absence of vulnerabilities. A final targeted regression also covers Unicode JSON-upload filenames; the full regression totals above precede that filename-helper cleanup.

Limitations to retain for subsequent work: parser-option reprocessing preserves multiple derived versions and still needs a clear active-version/filter policy; packet decoding remains deliberately bounded; the operating-system/container egress boundary has not yet been proven here; new report/procedure/intelligence features remain pending. The report engine dependencies are installed and pinned, but that alone does not implement reports or malware analysis.
