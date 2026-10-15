"""
Machine Learning Anomaly Detection Engine for SentinelGuard.
Utilizes an Isolation Forest model to detect anomalous behavioral feature vectors
extracted by the PySpark pipeline.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler


class MLAnomalyDetector:
    """
    Unsupervised ML Anomaly Detector using Isolation Forest on aggregated telemetry features.
    """

    DEFAULT_CLOUDTRAIL_FEATURES = [
        "event_count",
        "error_count",
        "distinct_api_count",
        "distinct_ip_count",
        "sensitive_api_count",
        "external_ip_count",
        "error_rate",
        "external_ip_ratio",
    ]

    DEFAULT_VPC_FEATURES = [
        "flow_count",
        "bytes_total",
        "bytes_mean",
        "bytes_max",
        "packets_total",
        "c2_port_count",
        "external_dst_count",
    ]

    def __init__(
        self,
        contamination: float | str = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        self.is_fitted = False


    def fit(self, df: pd.DataFrame, feature_cols: List[str]) -> MLAnomalyDetector:
        """
        Fit the Isolation Forest model on numerical feature columns.
        """
        X = df[feature_cols].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
        )
        self.model.fit(X_scaled)
        self.is_fitted = True
        return self

    def predict(
        self, df: pd.DataFrame, feature_cols: List[str]
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict binary anomaly flags and raw decision scores.
        Returns:
            is_anomaly: boolean array (True = anomaly, False = normal)
            scores: float array (higher score = more anomalous)
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError("MLAnomalyDetector must be fitted before predict.")

        X = df[feature_cols].fillna(0).values
        X_scaled = self.scaler.transform(X)

        # IsolationForest: -1 for outlier, 1 for inlier
        raw_preds = self.model.predict(X_scaled)
        is_anomaly = raw_preds == -1

        # Decision function: lower values represent greater anomaly degree
        # Invert so higher score represents higher anomaly confidence
        raw_scores = self.model.decision_function(X_scaled)
        normalized_anomaly_scores = -raw_scores

        return is_anomaly, normalized_anomaly_scores

    def evaluate(
        self,
        df: pd.DataFrame,
        feature_cols: List[str],
        ground_truth_col: str = "is_anomaly",
    ) -> Dict[str, float]:
        """
        Compute detection precision, recall, F1, false positive rate, and latency.
        """
        t0 = time.perf_counter()
        is_anomaly_pred, scores = self.predict(df, feature_cols)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        y_true = df[ground_truth_col].astype(int).values
        y_pred = is_anomaly_pred.astype(int)

        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))

        # Confusion Matrix for False Positive Rate
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        accuracy = float((tp + tn) / (tp + tn + fp + fn))

        return {
            "Precision": round(precision, 4),
            "Recall": round(recall, 4),
            "F1_Score": round(f1, 4),
            "False_Positive_Rate": round(fpr, 4),
            "Accuracy": round(accuracy, 4),
            "True_Positives": int(tp),
            "False_Positives": int(fp),
            "True_Negatives": int(tn),
            "False_Negatives": int(fn),
            "Inference_Latency_ms": round(latency_ms, 3),
        }
