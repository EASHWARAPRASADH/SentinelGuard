"""
Unit Tests for MLAnomalyDetector.
Tests:
- Isolation Forest training on aggregated features.
- Binary predictions and continuous anomaly scores.
- Unfitted model error handling.
- Evaluation metrics calculation (Precision, Recall, F1, FPR).
"""

import pandas as pd
import pytest

from sentinelguard.telemetry.anomaly_detector import MLAnomalyDetector


@pytest.fixture
def sample_feature_data() -> pd.DataFrame:
    # 20 normal rows and 2 anomaly rows
    data = []
    for i in range(20):
        data.append({
            "event_count": 50 + (i % 5),
            "error_count": 0 if i % 4 != 0 else 1,
            "distinct_api_count": 4,
            "distinct_ip_count": 1,
            "sensitive_api_count": 0,
            "external_ip_count": 0,
            "error_rate": 0.02,
            "external_ip_ratio": 0.0,
            "is_anomaly": 0,
        })
    # 2 high-anomaly rows
    for j in range(2):
        data.append({
            "event_count": 500,
            "error_count": 45,
            "distinct_api_count": 25,
            "distinct_ip_count": 8,
            "sensitive_api_count": 15,
            "external_ip_count": 500,
            "error_rate": 0.9,
            "external_ip_ratio": 1.0,
            "is_anomaly": 1,
        })
    return pd.DataFrame(data)


def test_detector_fit_and_predict(sample_feature_data: pd.DataFrame):
    detector = MLAnomalyDetector(contamination=0.1, random_state=42)
    feature_cols = MLAnomalyDetector.DEFAULT_CLOUDTRAIL_FEATURES

    detector.fit(sample_feature_data, feature_cols)
    assert detector.is_fitted is True

    is_anom, scores = detector.predict(sample_feature_data, feature_cols)
    assert len(is_anom) == len(sample_feature_data)
    assert len(scores) == len(sample_feature_data)

    # Anomaly rows should receive higher anomaly scores
    assert scores[-1] > scores[0]


def test_detector_unfitted_raises():
    detector = MLAnomalyDetector()
    df = pd.DataFrame({"col1": [1, 2]})
    with pytest.raises(RuntimeError, match="must be fitted before predict"):
        detector.predict(df, ["col1"])


def test_detector_evaluate_metrics(sample_feature_data: pd.DataFrame):
    detector = MLAnomalyDetector(contamination=0.1, random_state=42)
    feature_cols = MLAnomalyDetector.DEFAULT_CLOUDTRAIL_FEATURES
    detector.fit(sample_feature_data, feature_cols)

    metrics = detector.evaluate(sample_feature_data, feature_cols)
    assert "Precision" in metrics
    assert "Recall" in metrics
    assert "F1_Score" in metrics
    assert "False_Positive_Rate" in metrics
    assert metrics["Recall"] >= 0.5
    assert metrics["Inference_Latency_ms"] < 50.0
