# Performance SLO and measured baseline

The reference profile is the isolated Codex Linux container, Python 3.12, SQLite, one client, and synthetic training data. Results are not claims about production infrastructure.

| Measure | Target | Latest measured result | Status |
|---|---:|---:|---|
| Import 10,000 small events | at most 60 seconds | No reproducible current-head artifact | Unverified |
| Detection latency | P95 at most 150 ms | No reproducible current-head artifact | Unverified |
| Ground truth | no false positives or false negatives | No reproducible current-head artifact | Unverified |
| Basic hunt on 100,000 events | P95 at most 1.5 seconds | No reproducible current-head artifact | Unverified |

Previously quoted numbers are withdrawn as acceptance evidence because their raw artifacts and exact source revision are unavailable. Availability, load, soak, and recovery gates remain open.

Every release-candidate benchmark must record the commit SHA, CPU, memory, operating system, fixture generator seed, command, P50, P95, P99, throughput, RSS, error rate, and raw results. A result measured before the final code change is not release evidence.
