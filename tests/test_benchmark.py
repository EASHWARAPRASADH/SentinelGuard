"""
Test suite for CloudGuard-Bench runner.
Ensures that the 120-scenario dataset generates cleanly and that
all 4 baselines execute without exceptions.
"""

from sentinelguard.benchmark.dataset_generator import generate_benchmark_scenarios
from sentinelguard.benchmark.runner import BenchmarkRunner


def test_scenario_generation_count():
    scenarios = generate_benchmark_scenarios()
    assert len(scenarios) == 120

    cat_a = [s for s in scenarios if s.id.startswith("A-")]
    cat_b = [s for s in scenarios if s.id.startswith("B-")]
    cat_c = [s for s in scenarios if s.id.startswith("C-")]

    assert len(cat_a) == 40
    assert len(cat_b) == 40
    assert len(cat_c) == 40


def test_benchmark_runner_execution():
    runner = BenchmarkRunner()
    results = runner.run_all()

    assert "Config 1: Unchecked LLM" in results
    assert "Config 2: Static Policy Gate" in results
    assert "Config 3: Static Policy + Dependency" in results
    assert "Config 4: SentinelGuard (Proposed)" in results

    sg = results["Config 4: SentinelGuard (Proposed)"]
    assert sg["UAER"] == 0.0
    assert sg["PVPR"] == 100.0
    assert sg["LAAR"] == 100.0
    assert sg["FBR"] == 0.0
    assert sg["MSR"] > 50.0
    assert sg["Mean_Latency_ms"] < 50.0  # Well below 50ms requirement
