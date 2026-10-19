# Performance SLO and measured baseline

The reference profile is the isolated Codex Linux container, Python 3.12, SQLite, one client, and synthetic training data. Results are not claims about production infrastructure.

| Measure | Target | Latest measured result | Status |
|---|---:|---:|---|
| Import 10,000 small events | at most 60 seconds | 1.402 seconds | Pass |
| Detection latency | P95 at most 150 ms | 1.986 ms | Pass |
| Ground truth | no false positives or false negatives | 100 TP, 0 FP, 0 FN | Pass |
| Basic hunt on 100,000 events | P95 at most 1.5 seconds | Passed in the local benchmark run; raw artifact must be regenerated on final SHA | Pending final evidence |

Every release-candidate benchmark must record the commit SHA, CPU, memory, operating system, fixture generator seed, command, P50, P95, P99, throughput, RSS, error rate, and raw results. A result measured before the final code change is not release evidence.
