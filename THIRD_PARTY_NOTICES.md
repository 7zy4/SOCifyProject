# Third-party notices

## MITRE ATT&CK

The bundled ATT&CK reference records and optional STIX snapshot loader use material from MITRE ATT&CK. ATT&CK is a registered trademark of The MITRE Corporation. Source: `https://attack.mitre.org/` and `https://github.com/mitre-attack/attack-stix-data`. Use and redistribution remain subject to MITRE's Terms of Use.

## python-evtx fixture

`fixtures/windows/sysmon-sample.evtx.b64` is derived from `tests/data/issue_38.evtx` in `williballenthin/python-evtx`, distributed under the Apache License 2.0. The fixture is used solely to verify defensive parsing.

## Python dependencies

Runtime dependencies and pinned versions are listed in `requirements.txt`. CI generates a CycloneDX SBOM and performs vulnerability review with `pip-audit`. Each dependency remains under its own upstream license.

## Brand fonts

Baloo Bhaijaan 2 and IBM Plex Sans Arabic are self-hosted from the Google Fonts repository under the SIL Open Font License 1.1. Copyright notices and complete license terms are retained beside the original fonts in `static/fonts/`. WOFF2 files are lossless format conversions using fonttools 4.60.1 and Brotli 1.2.1; glyph content is unchanged. Printable HTML embeds the WOFF2 fonts for offline use.
