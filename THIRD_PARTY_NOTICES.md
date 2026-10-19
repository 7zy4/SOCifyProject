# Third-party notices

## MITRE ATT&CK

The bundled ATT&CK reference records and optional STIX snapshot loader use material from MITRE ATT&CK. ATT&CK is a registered trademark of The MITRE Corporation. Source: `https://attack.mitre.org/` and `https://github.com/mitre-attack/attack-stix-data`. Use and redistribution remain subject to MITRE's Terms of Use.

## python-evtx fixture

`fixtures/windows/sysmon-sample.evtx.b64` is derived from `tests/data/issue_38.evtx` in `williballenthin/python-evtx`, distributed under the Apache License 2.0. The fixture is used solely to verify defensive parsing.

## Python dependencies

Runtime dependencies and pinned versions are listed in `requirements.txt`. CI generates a CycloneDX SBOM and performs vulnerability review with `pip-audit`. Each dependency remains under its own upstream license.
