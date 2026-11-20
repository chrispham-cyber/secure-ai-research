"""build_benchmark_service generator param stays deterministic by default (Slice 1a, Task 5).

Hermetic. The new ``generator`` parameter must not disturb the deterministic benchmark: the
no-arg default and an explicit JoinGenerator both reproduce the same aggregate, so the Phase-4
1.0 regression gate is unaffected.
"""

from __future__ import annotations

from secure_ai_research.evaluation.benchmark import build_benchmark_service, run_benchmark
from secure_ai_research.evaluation.benchmark_items import benchmark_items
from secure_ai_research.evaluation.metrics import aggregate
from secure_ai_research.generation.join import JoinGenerator


def test_build_benchmark_service_default_is_deterministic(tmp_path):
    items = benchmark_items()
    a = aggregate(run_benchmark(build_benchmark_service(tmp_path / "a.jsonl"), items))
    b = aggregate(run_benchmark(build_benchmark_service(tmp_path / "b.jsonl"), items))
    assert a == b


def test_build_benchmark_service_accepts_generator(tmp_path):
    items = benchmark_items()
    explicit = aggregate(
        run_benchmark(
            build_benchmark_service(tmp_path / "a.jsonl", generator=JoinGenerator()), items
        )
    )
    default = aggregate(run_benchmark(build_benchmark_service(tmp_path / "b.jsonl"), items))
    assert explicit == default
