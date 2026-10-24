# Incident workbench: ten reference platforms and executed REA

This is a deliberately selected comparison of ten SIEM, SOAR and incident-response platforms, not an independently measured market ranking. Public publisher repositories were fetched on 24 October 2026; URLs, response sizes and SHA-256 digests are retained in [the source manifest](top10-source-manifest-2026-10-24.json). Commercial services were not logged into or probed. No external detection content or application code was copied into SOCify.

| Platform / publisher source | Observed public capability | SOCify design consequence |
|---|---|---|
| [Splunk Security Content](https://github.com/splunk/security_content) | Analytic stories combine TTP context, searches and available playbooks | Keep detection explanations and ATT&CK evidence in the case report |
| [Microsoft Sentinel](https://github.com/Azure/Azure-Sentinel) | Detections, exploration/hunting queries, workbooks and playbooks | Preserve a joined investigation journey rather than separate unlinked screens |
| [Elastic Security detection rules](https://github.com/elastic/detection-rules) | Rule development, testing, validation and release tooling | Test normalized imports and preserve rule versions in reports |
| [Wazuh](https://github.com/wazuh/wazuh) | Agents, centralized log analysis and security alerts | Preserve original sources and provenance; SOCify does not claim Wazuh agent capabilities |
| [Security Onion](https://github.com/Security-Onion-Solutions/securityonion) | Published views for alerts, dashboards, hunt, detections and PCAP | Pivot case-linked events into a filtered graph/timeline; no PCAP support is claimed |
| [OpenSearch Security Analytics](https://github.com/opensearch-project/security-analytics) | Customizable detection rules, findings and event correlation | Keep bounded server-side filtering and evidence relationships |
| [Cortex XSOAR content](https://github.com/demisto/content) | Playbooks, automation scripts and report templates | Include response execution metadata in the incident report |
| [Shuffle](https://github.com/Shuffle/Shuffle) | Security automation workflows and integration ecosystem | Retain existing simulated response workflows and approval boundaries |
| [TheHive](https://github.com/TheHive-Project/TheHive) | Current README states old public releases are retired and directs users to commercial documentation | The earlier case/observable comparison remains historical; this source does not prove current commercial implementation behavior |
| [DFIR-IRIS](https://github.com/dfir-iris/iris-web) | Collaborative incident investigation; current public README distinguishes beta from production stable | Collect shared notes, tasks, case evidence and incident history in a versioned report |

## Executed user-selected REA fork

Cloned and built `https://github.com/7zy4/rea` at `2250e67bc271c83f9e200ee298aa04a2457438a6`. Its package is `rea-agents` 6.7.0 and provides a local CLI. No Claude-only dependency or source translation was needed for static JavaScript analysis.

`npm ci --ignore-scripts` initially rejected the package's Node engine range: the environment provides Node 24.19.0 whereas the manifest requests 24.22.1 or later on that line. Dependencies were installed with `--engine-strict=false`, then the fork's actual `npm run compile` succeeded and its `scripts/rea.mjs analyze-javascript-application ... --json` command ran successfully. This proves the exercised static workflow, not compatibility of all REA providers with the older Node runtime. No system Node upgrade or client MCP configuration was performed.

[Complete compressed evidence](rea-fork-incident-evidence-2026-10-24.json.gz):

- Evidence `ev_d7ac5898feb9627128b167a1511badaaca4d01b6aea02d398c7d8d1580865a03`
- Target digest `68b675f68e198ebc117780f8cdb0850932842b78e1a794ccc3148cc55021e9b9`
- Semantic graph `jsrg_a779cba11e787b453c7e00dbef8046fbb04548c0c7da3d89807a6ca736a1e87e`
- Uncompressed evidence SHA-256 `4f9a27a249d747447cfcdd545645821cde7cd084d6917b2aa83045cbd1f156db`

The fork parsed two files totaling 74,249 text bytes, visited 10,676 AST nodes, and reported zero parse failures. It retained 1,839 unknown relationships. Those unknowns do not establish errors or correctness. It did not execute Python, validate database authorization or run any of the third-party platforms. API and Chromium tests supply the behavioral evidence for SOCify.

Reproduce against a separately built checkout using `SOCIFY_REA_CLI=/absolute/path/to/rea/scripts/rea.mjs bash scripts/run_rea_analysis.sh /tmp/rea-evidence.json`. The default pinned npm workflow remains available when the override is absent.
