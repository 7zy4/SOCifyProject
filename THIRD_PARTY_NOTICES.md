# Third-party notices

## Internal deployment ingress

The optional container ingress uses the Debian security-maintained NGINX package under its upstream BSD-style terms. Source and license: `https://nginx.org/LICENSE`. The ingress proxies only to the fixed internal SOCify service, has no database or encryption-key mount, and does not run investigative processing. It must be deployed inside the organization with the organization's inbound TLS and outbound firewall policy.

## MITRE ATT&CK

The bundled ATT&CK reference records and optional STIX snapshot loader use material from MITRE ATT&CK. ATT&CK is a registered trademark of The MITRE Corporation. Source: `https://attack.mitre.org/` and `https://github.com/mitre-attack/attack-stix-data`. Use and redistribution remain subject to MITRE's Terms of Use.

## python-evtx fixture

`fixtures/windows/sysmon-sample.evtx.b64` is derived from `tests/data/issue_38.evtx` in `williballenthin/python-evtx`, distributed under the Apache License 2.0. The fixture is used solely to verify defensive parsing.

## Python dependencies

Runtime dependencies and pinned versions are listed in `requirements.txt`. CI generates a CycloneDX SBOM and performs vulnerability review with `pip-audit`. Each dependency remains under its own upstream license.

V3 adds local defensive processing/reporting dependencies: WeasyPrint (BSD, `https://github.com/Kozea/WeasyPrint`), python-docx (MIT, `https://github.com/python-openxml/python-docx`), dpkt (BSD, `https://github.com/kbandla/dpkt`), PyYAML (MIT, `https://github.com/yaml/pyyaml`), yara-python (Apache 2.0 binding with the upstream YARA engine's own notices, `https://github.com/VirusTotal/yara-python`), and maxminddb (Apache 2.0, `https://github.com/maxmind/MaxMind-DB-Reader-python`). These libraries do not imply an installed GeoIP database, threat feed, YARA rule collection, sandbox, or external VirusTotal integration. Any separately imported intelligence, GeoIP or rule data retains its own license and version requirements.

## Brand fonts

Baloo Bhaijaan 2 and IBM Plex Sans Arabic are self-hosted from the Google Fonts repository under the SIL Open Font License 1.1. Copyright notices and complete license terms are retained beside the original fonts in `static/fonts/`. WOFF2 files are lossless format conversions using fonttools 4.60.1 and Brotli 1.2.1; glyph content is unchanged. Printable HTML embeds the WOFF2 fonts for offline use.

## Interface fonts (previous 2026 redesign)

The previous interface used Almarai and IBM Plex Sans. Sources: https://github.com/google/fonts/tree/main/ofl/almarai and https://github.com/google/fonts/tree/main/ofl/ibmplexsans. Both are distributed under SIL OFL 1.1; licenses are in `static/fonts/Almarai-OFL.txt` and `static/fonts/IBMPlexSans-OFL.txt`. Original WOFF2 builds are recorded in `static/fonts/interface-manifest.json`. IBM Plex Sans fixes the width axis at 100 and retains the variable weight axis. Earlier font assets remain for historical report compatibility.

## V4 noir interface and reports

The current type system uses Bangers, Comic Neue, Cairo, Tajawal, IBM Plex Sans Arabic, IBM Plex Sans and JetBrains Mono. Fonts are bundled locally under SIL OFL 1.1 with the corresponding license beside each family. The added upstream sources, input hashes and converted WOFF2 hashes are recorded in `static/fonts/sources.json`; the retained IBM Plex Sans face uses the preceding interface manifest. The new faces were converted with fontTools without changing glyph designs. `static/design-tokens.json` selects the active families. No runtime request to a font provider is required.
