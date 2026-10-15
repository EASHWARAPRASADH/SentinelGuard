"""
Unit tests for extended Adversarial Suite and Heuristic Baseline Detector (Phase 8).
"""

import pandas as pd
import pytest

from sentinelguard.benchmark.adversarial_suite import generate_adversarial_suite
from sentinelguard.telemetry.heuristic_detector import HeuristicThresholdDetector


def test_adversarial_suite_structure_and_coverage():
    scenarios = generate_adversarial_suite()
    assert len(scenarios) == 24

    classes = set(s.vulnerability_class for s in scenarios)
    assert len(classes) == 12

    expected_classes = {
        "Prompt Injection",
        "Malformed Proposal",
        "Unknown Action",
        "Missing Parameters",
        "Invalid Resource ID",
        "Stale State Snapshot",
        "Missing Dependency Information",
        "Concurrent State Change",
        "Simulated API Failure",
        "Telemetry Severance",
        "Sole Admin Lockout",
        "Quorum Breach",
    }
    assert classes == expected_classes

    # Ensure every scenario has an expected outcome and valid ID
    for sc in scenarios:
        assert sc.id.startswith("ADV-")
        assert sc.expected_decision is not None
        assert sc.expected_outcome is not None


def test_heuristic_detector_cloudtrail():
    detector = HeuristicThresholdDetector()
    df = pd.DataFrame([
        # Normal row
        {"error_rate": 0.05, "event_count": 20, "sensitive_api_count": 0, "distinct_ip_count": 1, "is_anomaly": 0},
        # Anomaly 1: High error rate
        {"error_rate": 0.85, "event_count": 25, "sensitive_api_count": 0, "distinct_ip_count": 1, "is_anomaly": 1},
        # Anomaly 2: Sensitive API calls
        {"error_rate": 0.0, "event_count": 10, "sensitive_api_count": 3, "distinct_ip_count": 1, "is_anomaly": 1},
    ])

    metrics = detector.evaluate_cloudtrail(df)
    assert metrics.total_events == 3
    assert metrics.true_positives == 2
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0


def test_heuristic_detector_vpc():
    detector = HeuristicThresholdDetector()
    df = pd.DataFrame([
        # Normal row
        {"c2_port_count": 0, "bytes_total": 500_000, "is_anomaly": 0},
        # Anomaly: C2 port
        {"c2_port_count": 2, "bytes_total": 1_000_000, "is_anomaly": 1},
        # Anomaly: Massive byte exfiltration
        {"c2_port_count": 0, "bytes_total": 80_000_000, "is_anomaly": 1},
    ])

    metrics = detector.evaluate_vpc(df)
    assert metrics.total_events == 3
    assert metrics.true_positives == 2
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
