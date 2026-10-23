# Performance SLO and measured baseline

The reference profile is the isolated Codex Linux container, Python 3.12, SQLite, one client, and synthetic training data. Results are not claims about production infrastructure.

| Measure | Target | Latest measured result | Status |
|---|---:|---:|---|
| Import 10,000 small events | at most 60 seconds | 4.695 seconds; 2,129.89 events/second | Pass |
| Detection latency | P95 at most 150 ms | P50 2.186 ms; P95 2.560 ms; P99 2.725 ms | Pass |
| Ground truth | no false positives or false negatives | No reproducible current-head artifact | Unverified |
| Basic hunt on 100,000 events | P95 at most 1.5 seconds | P50 229.803 ms; P95 302.983 ms; P99 332.693 ms | Pass |

The raw result is [performance-reference-2026-10-23.json](performance-reference-2026-10-23.json). It was produced from commit `b024f04b774e8400ac598cbbbd59f9786a4f585c` on the isolated reference profile with Python 3.12.14, 5 available CPUs, 35,743,760,384 bytes of memory, and fixture seed 20261023. The run completed in 12.460 seconds with zero request errors and a maximum RSS of 82,380 KiB. Availability, soak, worker backpressure, and recovery gates remain open.

Every release-candidate benchmark records the commit SHA, CPU, memory, operating system, fixture generator seed, command, P50, P95, P99, throughput, RSS, error rate, and raw results. CI repeats `python -m scripts.benchmark_reference` on its exact checkout and uploads the JSON artifact.
