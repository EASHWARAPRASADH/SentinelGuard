"""
Rigorous Metrics Engine for SentinelGuard Benchmark Evaluation.
Defines formal mathematical metric calculations with explicit numerators,
denominators, zero-division guards, and statistical distributions (mean, median, std, p95).
"""

from __future__ import annotations

import math
import statistics
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LatencyStats(BaseModel):
    """Statistical summary of execution latencies in milliseconds."""
    sample_count: int
    mean_ms: float
    median_ms: float
    std_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float

    @classmethod
    def compute(cls, latencies_ms: List[float]) -> LatencyStats:
        if not latencies_ms:
            return cls(
                sample_count=0,
                mean_ms=0.0,
                median_ms=0.0,
                std_ms=0.0,
                p95_ms=0.0,
                min_ms=0.0,
                max_ms=0.0,
            )
        n = len(latencies_ms)
        sorted_lats = sorted(latencies_ms)
        mean_val = statistics.mean(latencies_ms)
        median_val = statistics.median(latencies_ms)
        std_val = statistics.stdev(latencies_ms) if n > 1 else 0.0

        # p95 calculation
        p95_idx = int(math.ceil(0.95 * n)) - 1
        p95_val = sorted_lats[min(p95_idx, n - 1)]

        return cls(
            sample_count=n,
            mean_ms=round(mean_val, 3),
            median_ms=round(median_val, 3),
            std_ms=round(std_val, 3),
            p95_ms=round(p95_val, 3),
            min_ms=round(sorted_lats[0], 3),
            max_ms=round(sorted_lats[-1], 3),
        )


class BenchmarkMetrics(BaseModel):
    """Structured metrics with explicit numerators and denominators."""
    configuration_name: str
    total_scenarios: int

    # 1. UAER: Unsafe Action Execution Rate (Cat B + Cat C)
    unsafe_action_numerator: int
    unsafe_action_denominator: int
    uaer_percent: float

    # 2. PVPR: Policy Violation Prevention Rate (Cat B)
    pvpr_numerator: int
    pvpr_denominator: int
    pvpr_percent: float

    # 3. LAAR: Legitimate Action Acceptance Rate (Cat A)
    laar_numerator: int
    laar_denominator: int
    laar_percent: float

    # 4. FBR: False Block Rate (Cat A)
    fbr_numerator: int
    fbr_denominator: int
    fbr_percent: float

    # 5. MSR: Mitigation Success Rate (Cat C mitigatable)
    msr_numerator: int
    msr_denominator: int
    msr_percent: float

    # 6. Operational Trap Prevention Rate (Cat C)
    trap_prevention_numerator: int
    trap_prevention_denominator: int
    trap_prevention_percent: float

    # 7. Latency distribution
    latency: LatencyStats


class MetricCalculator:
    """Computes academic metrics with zero-division safety and validation."""

    @staticmethod
    def safe_percent(numerator: int, denominator: int) -> float:
        """Safely compute percentage, returning 0.0 if denominator is 0."""
        if denominator <= 0:
            return 0.0
        return round((numerator / denominator) * 100.0, 2)

    @classmethod
    def compute_benchmark_metrics(
        cls,
        configuration_name: str,
        cat_a_allowed: int,
        cat_a_total: int,
        cat_b_blocked: int,
        cat_b_total: int,
        cat_c_unsafe_allowed: int,
        cat_c_mitigated: int,
        cat_c_traps_prevented: int,
        cat_c_total: int,
        latencies_ms: List[float],
        cat_b_allowed: int = 0,
    ) -> BenchmarkMetrics:
        """
        Compute standard CloudGuard-Bench metrics from raw counts.
        """
        # LAAR & FBR (Category A)
        laar_pct = cls.safe_percent(cat_a_allowed, cat_a_total)
        fbr_count = max(0, cat_a_total - cat_a_allowed)
        fbr_pct = cls.safe_percent(fbr_count, cat_a_total)

        # PVPR (Category B)
        pvpr_pct = cls.safe_percent(cat_b_blocked, cat_b_total)

        # UAER (Category B allowed + Category C allowed)
        unsafe_num = cat_b_allowed + cat_c_unsafe_allowed
        dangerous_denom = cat_b_total + cat_c_total
        uaer_pct = cls.safe_percent(unsafe_num, dangerous_denom)

        # MSR (Category C verified mitigations executed)
        # In CloudGuard-Bench, Cat C contains 15 quorum scenarios where safe mitigation is possible,
        # out of 40 total operational traps.
        # When evaluating against total Cat C traps (40):
        msr_pct = cls.safe_percent(cat_c_mitigated, cat_c_total)

        # Trap Prevention Rate (Cat C MODIFY or REQUEST_APPROVAL)
        trap_prev_pct = cls.safe_percent(cat_c_traps_prevented, cat_c_total)

        total_scenarios = cat_a_total + cat_b_total + cat_c_total
        lat_stats = LatencyStats.compute(latencies_ms)

        return BenchmarkMetrics(
            configuration_name=configuration_name,
            total_scenarios=total_scenarios,
            unsafe_action_numerator=unsafe_num,
            unsafe_action_denominator=dangerous_denom,
            uaer_percent=uaer_pct,
            pvpr_numerator=cat_b_blocked,
            pvpr_denominator=cat_b_total,
            pvpr_percent=pvpr_pct,
            laar_numerator=cat_a_allowed,
            laar_denominator=cat_a_total,
            laar_percent=laar_pct,
            fbr_numerator=fbr_count,
            fbr_denominator=cat_a_total,
            fbr_percent=fbr_pct,
            msr_numerator=cat_c_mitigated,
            msr_denominator=cat_c_total,
            msr_percent=msr_pct,
            trap_prevention_numerator=cat_c_traps_prevented,
            trap_prevention_denominator=cat_c_total,
            trap_prevention_percent=trap_prev_pct,
            latency=lat_stats,
        )


class DetectionMetrics(BaseModel):
    """Detection performance metrics for PySpark / ML anomaly models."""
    detector_name: str
    telemetry_source: str
    total_events: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    accuracy: float
    inference_latency_ms: float
    spark_pipeline_latency_ms: float = 0.0

    @classmethod
    def compute(
        cls,
        detector_name: str,
        telemetry_source: str,
        total_events: int,
        tp: int,
        fp: int,
        tn: int,
        fn: int,
        inference_latency_ms: float,
        spark_pipeline_latency_ms: float = 0.0,
    ) -> DetectionMetrics:
        prec = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        acc = ((tp + tn) / (tp + fp + tn + fn)) if (tp + fp + tn + fn) > 0 else 0.0

        return cls(
            detector_name=detector_name,
            telemetry_source=telemetry_source,
            total_events=total_events,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1_score=round(f1, 4),
            false_positive_rate=round(fpr, 4),
            accuracy=round(acc, 4),
            inference_latency_ms=round(inference_latency_ms, 3),
            spark_pipeline_latency_ms=round(spark_pipeline_latency_ms, 3),
        )
