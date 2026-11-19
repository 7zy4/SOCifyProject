"""Measurement helpers shared by the benchmark and container verification scripts."""

import math
from pathlib import Path


def percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    return ordered[min(math.ceil(len(ordered) * percent) - 1, len(ordered) - 1)]


def git_revision() -> str:
    git_path = Path(".git")
    if git_path.is_file():
        git_path = Path(git_path.read_text().strip().removeprefix("gitdir: "))
    head = (git_path / "HEAD").read_text().strip()
    if not head.startswith("ref: "):
        return head
    reference = head.removeprefix("ref: ")
    loose = git_path / reference
    if loose.exists():
        return loose.read_text().strip()
    packed = (git_path / "packed-refs").read_text().splitlines()
    return next(line.split()[0] for line in packed if line.endswith(f" {reference}"))


def memory_total_bytes() -> int | None:
    try:
        line = next(item for item in Path("/proc/meminfo").read_text().splitlines() if item.startswith("MemTotal:"))
        return int(line.split()[1]) * 1024
    except (OSError, StopIteration, ValueError):
        return None


def distribution(values: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(values, 0.50) * 1000, 3),
        "p95_ms": round(percentile(values, 0.95) * 1000, 3),
        "p99_ms": round(percentile(values, 0.99) * 1000, 3),
    }
