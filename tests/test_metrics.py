"""
Unit Tests for Benchmark Metric Calculations.
Tests:
- Zero denominator handling for all rates.
- Correct computation of UAER, PVPR, LAAR, FBR, MSR.
- Latency statistical calculations (mean, median, std, p95).
- DetectionMetrics calculations (Precision, Recall, F1, FPR).
"""

import pytest
from sentinelguard.benchmark.metrics import (
    DetectionMetrics,
    LatencyStats,
    MetricCalculator,
)


def test_safe_percent_zero_denominator():
    assert MetricCalculator.safe_percent(10, 0) == 0.0
    assert MetricCalculator.safe_percent(0, 0) == 0.0
    assert MetricCalculator.safe_percent(5, 10) == 50.0


def test_latency_stats_edge_cases():
    # Empty latencies
    stats_empty = LatencyStats.compute([])
    assert stats_empty.sample_count == 0
    assert stats_empty.mean_ms == 0.0
    assert stats_empty.median_ms == 0.0
    assert stats_empty.p95_ms == 0.0

    # Single element
    stats_single = LatencyStats.compute([12.5])
    assert stats_single.sample_count == 1
    assert stats_single.mean_ms == 12.5
    assert stats_single.median_ms == 12.5
    assert stats_single.std_ms == 0.0
    assert stats_single.p95_ms == 12.5

    # Known distribution
    lats = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    stats = LatencyStats.compute(lats)
    assert stats.sample_count == 10
    assert stats.mean_ms == 5.5
    assert stats.median_ms == 5.5
    assert stats.min_ms == 1.0
    assert stats.max_ms == 10.0
    assert stats.p95_ms == 10.0


def test_benchmark_metrics_computation():
    # Simulate Config 4 (SentinelGuard)
    metrics_sg = MetricCalculator.compute_benchmark_metrics(
        configuration_name="Config 4: SentinelGuard",
        cat_a_allowed=40,
        cat_a_total=40,
        cat_b_blocked=40,
        cat_b_total=40,
        cat_c_unsafe_allowed=0,
        cat_c_mitigated=25,
        cat_c_traps_prevented=40,
        cat_c_total=40,
        latencies_ms=[0.1, 0.12, 0.09, 0.11],
        cat_b_allowed=0,
    )

    assert metrics_sg.total_scenarios == 120
    assert metrics_sg.laar_percent == 100.0
    assert metrics_sg.fbr_percent == 0.0
    assert metrics_sg.pvpr_percent == 100.0
    assert metrics_sg.uaer_percent == 0.0
    assert metrics_sg.msr_percent == 62.5
    assert metrics_sg.trap_prevention_percent == 100.0
    assert metrics_sg.latency.mean_ms > 0.0

    # Simulate Config 1 (Unchecked LLM)
    metrics_unc = MetricCalculator.compute_benchmark_metrics(
        configuration_name="Config 1: Unchecked LLM",
        cat_a_allowed=40,
        cat_a_total=40,
        cat_b_blocked=0,
        cat_b_total=40,
        cat_c_unsafe_allowed=40,
        cat_c_mitigated=0,
        cat_c_traps_prevented=0,
        cat_c_total=40,
        latencies_ms=[0.01, 0.01],
        cat_b_allowed=40,
    )

    assert metrics_unc.laar_percent == 100.0
    assert metrics_unc.pvpr_percent == 0.0
    assert metrics_unc.uaer_percent == 100.0
    assert metrics_unc.msr_percent == 0.0


def test_detection_metrics_zero_division():
    det = DetectionMetrics.compute(
        detector_name="TestDetector",
        telemetry_source="CloudTrail",
        total_events=100,
        tp=0,
        fp=0,
        tn=100,
        fn=0,
        inference_latency_ms=5.0,
    )
    assert det.precision == 0.0
    assert det.recall == 0.0
    assert det.f1_score == 0.0
    assert det.false_positive_rate == 0.0
    assert det.accuracy == 1.0


def test_detection_metrics_valid_values():
    det = DetectionMetrics.compute(
        detector_name="IsolationForest",
        telemetry_source="VPC_Flow",
        total_events=1000,
        tp=50,
        fp=10,
        tn=930,
        fn=10,
        inference_latency_ms=8.5,
    )
    # Precision: 50 / (50 + 10) = 50/60 = 0.8333
    assert det.precision == 0.8333
    # Recall: 50 / (50 + 10) = 50/60 = 0.8333
    assert det.recall == 0.8333
    # FPR: 10 / (10 + 930) = 10 / 940 = 0.0106
    assert det.false_positive_rate == 0.0106
