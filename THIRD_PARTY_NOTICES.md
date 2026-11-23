# Third-party notices

## Internal deployment ingress

The container ingress, the entry point Docker Compose publishes on loopback, uses the Debian security-maintained NGINX package under its upstream BSD-style terms. Source and license: `https://nginx.org/LICENSE`. The ingress proxies only to the fixed internal SOCify service, has no database or encryption-key mount, and does not run investigative processing. It must be deployed inside the organization with the organization's inbound TLS and outbound firewall policy.

## MITRE ATT&CK

The bundled ATT&CK reference records and optional STIX snapshot loader use material from MITRE ATT&CK. ATT&CK is a registered trademark of The MITRE Corporation. Source: `https://attack.mitre.org/` and `https://github.com/mitre-attack/attack-stix-data`. Use and redistribution remain subject to MITRE's Terms of Use.

## python-evtx fixture

`fixtures/windows/sysmon-sample.evtx.b64` is derived from `tests/data/issue_38.evtx` in `williballenthin/python-evtx`, distributed under the Apache License 2.0. The fixture is used solely to verify defensive parsing.

## Python dependencies

Direct runtime dependencies are listed in `requirements.in`; `requirements.txt` pins every runtime package, including transitive ones, with its hashes. Each dependency remains under its own upstream license.

Local defensive processing/reporting dependencies: WeasyPrint (BSD, `https://github.com/Kozea/WeasyPrint`), python-docx (MIT, `https://github.com/python-openxml/python-docx`), dpkt (BSD, `https://github.com/kbandla/dpkt`), PyYAML (MIT, `https://github.com/yaml/pyyaml`), yara-python (Apache 2.0 binding with the upstream YARA engine's own notices, `https://github.com/VirusTotal/yara-python`), and maxminddb (Apache 2.0, `https://github.com/maxmind/MaxMind-DB-Reader-python`). These libraries do not imply an installed GeoIP database, threat feed, YARA rule collection, sandbox, or external VirusTotal integration. Any separately imported intelligence, GeoIP or rule data retains its own license and version requirements.

## Fonts

SOCify ships two font families, self-hosted under the SIL Open Font License 1.1: Kufam for headings and IBM Plex Sans Arabic for all other text. Both come from the Google Fonts repository (`https://github.com/google/fonts/tree/main/ofl/kufam` and `https://github.com/google/fonts/tree/main/ofl/ibmplexsansarabic`). Each license sits beside its font in `static/fonts/`, and the upstream sources and file hashes are recorded in `static/fonts/sources.json` and `static/fonts/manifest.json`. Word reports embed the TrueType instances in `static/fonts/report/`; printable HTML embeds the WOFF2 files. No request to a font provider is made at runtime.
