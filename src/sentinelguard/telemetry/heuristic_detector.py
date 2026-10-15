"""
Heuristic Threshold Baseline Detector for SentinelGuard Telemetry.
Implements a conventional rule-based security threshold detector (SIEM baseline)
to compare against the Isolation Forest unsupervised machine learning model on identical datasets.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple
import numpy as np
import pandas as pd

from sentinelguard.benchmark.metrics import DetectionMetrics


class HeuristicThresholdDetector:
    """
    Fixed-threshold baseline detector representing standard static SIEM rules.
    """

    def __init__(
        self,
        cloudtrail_error_rate_threshold: float = 0.5,
        cloudtrail_sensitive_api_threshold: int = 1,
        vpc_c2_port_threshold: int = 1,
        vpc_bytes_threshold: int = 20_000_000,  # 20 MB
    ) -> None:
        self.ct_error_rate_th = cloudtrail_error_rate_threshold
        self.ct_sensitive_th = cloudtrail_sensitive_api_threshold
        self.vpc_c2_port_th = vpc_c2_port_threshold
        self.vpc_bytes_th = vpc_bytes_threshold

    def predict_cloudtrail(self, df: pd.DataFrame) -> Tuple[np.ndarray, float]:
        """Flag rows exceeding fixed CloudTrail thresholds."""
        t0 = time.perf_counter()
        flags = np.zeros(len(df), dtype=bool)

        for i, (_, row) in enumerate(df.iterrows()):
            is_flagged = False
            if row.get("error_rate", 0.0) >= self.ct_error_rate_th and row.get("event_count", 0) >= 5:
                is_flagged = True
            elif row.get("sensitive_api_count", 0) >= self.ct_sensitive_th:
                is_flagged = True
            elif row.get("distinct_ip_count", 0) >= 10:
                is_flagged = True
            flags[i] = is_flagged

        latency_ms = (time.perf_counter() - t0) * 1000.0
        return flags, latency_ms

    def predict_vpc(self, df: pd.DataFrame) -> Tuple[np.ndarray, float]:
        """Flag rows exceeding fixed VPC Flow thresholds."""
        t0 = time.perf_counter()
        flags = np.zeros(len(df), dtype=bool)

        for i, (_, row) in enumerate(df.iterrows()):
            is_flagged = False
            if row.get("c2_port_count", 0) >= self.vpc_c2_port_th:
                is_flagged = True
            elif row.get("bytes_total", 0) >= self.vpc_bytes_th:
                is_flagged = True
            flags[i] = is_flagged

        latency_ms = (time.perf_counter() - t0) * 1000.0
        return flags, latency_ms

    def evaluate_cloudtrail(self, df: pd.DataFrame) -> DetectionMetrics:
        """Evaluate fixed threshold performance on CloudTrail."""
        flags, latency_ms = self.predict_cloudtrail(df)
        y_true = df["is_anomaly"].values.astype(bool) if "is_anomaly" in df else np.zeros(len(df), dtype=bool)

        tp = int(np.sum(flags & y_true))
        fp = int(np.sum(flags & ~y_true))
        tn = int(np.sum(~flags & ~y_true))
        fn = int(np.sum(~flags & y_true))

        return DetectionMetrics.compute(
            detector_name="Heuristic Thresholds (SIEM Baseline)",
            telemetry_source="CloudTrail API",
            total_events=len(df),
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            inference_latency_ms=latency_ms,
        )

    def evaluate_vpc(self, df: pd.DataFrame) -> DetectionMetrics:
        """Evaluate fixed threshold performance on VPC Flow."""
        flags, latency_ms = self.predict_vpc(df)
        y_true = df["is_anomaly"].values.astype(bool) if "is_anomaly" in df else np.zeros(len(df), dtype=bool)

        tp = int(np.sum(flags & y_true))
        fp = int(np.sum(flags & ~y_true))
        tn = int(np.sum(~flags & ~y_true))
        fn = int(np.sum(~flags & y_true))

        return DetectionMetrics.compute(
            detector_name="Heuristic Thresholds (SIEM Baseline)",
            telemetry_source="VPC Flow Logs",
            total_events=len(df),
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            inference_latency_ms=latency_ms,
        )
