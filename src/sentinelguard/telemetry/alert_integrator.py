"""
Alert Integrator for SentinelGuard.
Converts ML anomaly detections into structured SecurityIncident envelopes and
dispatches them into the Phase 5 Investigation & Governor Pipeline.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd

from sentinelguard.agent.schemas import InvestigationReport, SecurityIncident
from sentinelguard.orchestration.pipeline import IncidentResponsePipeline


class AlertIntegrator:
    """
    Translates ML-detected telemetry anomalies into structured SecurityIncident envelopes.
    """

    @classmethod
    def convert_features_to_incidents(
        cls,
        features_df: pd.DataFrame,
        is_anomaly_mask: np.ndarray,
        anomaly_scores: np.ndarray,
        raw_events: Optional[List[Dict[str, Any]]] = None,
    ) -> List[SecurityIncident]:
        """
        Convert anomalous rows from the aggregated feature DataFrame into SecurityIncident envelopes.
        """
        incidents: List[SecurityIncident] = []
        raw_events = raw_events or []

        # Find rows flagged as anomalous
        anom_indices = np.where(is_anomaly_mask)[0]

        for idx in anom_indices:
            row = features_df.iloc[idx]
            score = float(anomaly_scores[idx])

            # Determine resource ID and incident type based on features present
            if "accessKeyId" in row and row["accessKeyId"]:
                resource_id = str(row["accessKeyId"])
                default_type = "credential_abuse"
            elif "instance_id" in row and row["instance_id"]:
                resource_id = str(row["instance_id"])
                default_type = "c2_beacon"
            elif "principalArn" in row and row["principalArn"]:
                resource_id = str(row["principalArn"])
                default_type = "privilege_escalation"
            else:
                resource_id = "res-unknown-anomaly"
                default_type = "security_anomaly"

            # Use labeled incident_type if present in row, otherwise inferred
            incident_type = str(row.get("incident_type") or default_type)
            if not incident_type or incident_type == "nan":
                incident_type = default_type

            # Find matching raw events for forensic grounding
            matching_events = []
            for e in raw_events:
                user_id = e.get("userIdentity", {})
                if (
                    e.get("target_resource_id") == resource_id
                    or user_id.get("accessKeyId") == resource_id
                    or user_id.get("arn") == resource_id
                    or e.get("instance_id") == resource_id
                ):
                    matching_events.append({
                        "event_name": e.get("eventName") or "FlowRecord",
                        "source_ip": e.get("sourceIPAddress") or e.get("srcaddr"),
                        "destination": e.get("dstaddr"),
                        "error_code": e.get("errorCode"),
                    })
                    if len(matching_events) >= 5:
                        break

            # Build detection evidence from feature values
            evidence: Dict[str, Any] = {
                "ml_anomaly_score": round(score, 4),
                "model_type": "IsolationForest",
            }
            for col in [
                "error_rate",
                "sensitive_api_count",
                "external_ip_count",
                "bytes_total",
                "c2_port_count",
                "distinct_api_count",
            ]:
                if col in row:
                    val = row[col]
                    if pd.notna(val):
                        if hasattr(val, "item"):
                            val = val.item()
                        evidence[col] = val

            # Determine severity
            severity = "HIGH"
            if row.get("sensitive_api_count", 0) > 0 or row.get("c2_port_count", 0) > 0 or score > 0.2:
                severity = "CRITICAL"

            inc_id = f"INC-ML-{int(time.time())}-{idx:03d}"
            incident = SecurityIncident(
                incident_id=inc_id,
                alert_type=incident_type,
                severity=severity,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                affected_resource_ids=[resource_id],
                observed_events=matching_events,
                detection_evidence=evidence,
                cloud_metadata={"account_id": "123456789012"},
            )
            incidents.append(incident)

        return incidents

    @classmethod
    def dispatch_to_pipeline(
        cls,
        pipeline: IncidentResponsePipeline,
        incidents: List[SecurityIncident],
    ) -> List[InvestigationReport]:
        """
        Process a batch of ML-generated incidents through the investigation and governor pipeline.
        """
        reports: List[InvestigationReport] = []
        for inc in incidents:
            report = pipeline.process_incident(inc)
            reports.append(report)
        return reports
