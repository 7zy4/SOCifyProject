# Performance SLO and measured baseline

The reference profile is the isolated Codex Linux container, Python 3.12, SQLite, one client, and synthetic training data. Results are not claims about production infrastructure.

| Measure | Target | Latest measured result | Status |
|---|---:|---:|---|
| Import 10,000 small events | at most 60 seconds | 4.358 seconds; 2,294.45 events/second | Pass |
| Detection latency | P95 at most 150 ms | P50 2.249 ms; P95 2.734 ms; P99 2.744 ms | Pass |
| Ground truth | no false positives or false negatives | No reproducible current-head artifact | Unverified |
| Basic hunt on 100,000 events | P95 at most 1.5 seconds | P50 254.560 ms; P95 403.709 ms; P99 427.140 ms | Pass |

The raw result is [performance-reference-2026-10-23.json](performance-reference-2026-10-23.json). It was produced from commit `6d09371a709bef27508a7ffc87f389a4f971ae83` on the isolated reference profile with Python 3.12.14, 5 available CPUs, 35,743,760,384 bytes of memory, and fixture seed 20261023. The run completed in 13.506 seconds with zero request errors and a maximum RSS of 82,936 KiB. Availability, soak, worker backpressure, and recovery gates remain open.

Every release-candidate benchmark records the commit SHA, CPU, memory, operating system, fixture generator seed, command, P50, P95, P99, throughput, RSS, error rate, and raw results. CI repeats `python -m scripts.benchmark_reference` on its exact checkout and uploads the JSON artifact.
