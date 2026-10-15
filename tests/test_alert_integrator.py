"""
Test suite for AlertIntegrator.
Verifies translation of ML feature anomalies into SecurityIncident envelopes
and seamless dispatch into the Phase 5 IncidentResponsePipeline and Governor.
"""

import numpy as np
import pandas as pd
import pytest

from sentinelguard.benchmark.agent_eval import build_evaluation_odg
from sentinelguard.core.engine import SentinelGuardGovernor
from sentinelguard.core.schemas import DecisionType
from sentinelguard.orchestration.pipeline import IncidentResponsePipeline
from sentinelguard.telemetry.alert_integrator import AlertIntegrator


def test_convert_features_to_incidents_basic():
    features_data = {
        "accessKeyId": ["AKIAIOSFODNN7EXAMPLE", "AKIASECUREKEY001"],
        "principalArn": ["arn:aws:iam::123456789012:user/attacker", "arn:aws:iam::123456789012:user/alice"],
        "error_rate": [0.85, 0.0],
        "sensitive_api_count": [4, 0],
        "external_ip_count": [12, 1],
        "distinct_api_count": [15, 3],
        "incident_type": ["credential_abuse", "normal"],
    }
    df = pd.DataFrame(features_data)
    is_anomaly_mask = np.array([True, False])
    anomaly_scores = np.array([0.28, -0.15])

    raw_events = [
        {
            "eventName": "GetCallerIdentity",
            "sourceIPAddress": "198.51.100.22",
            "userIdentity": {"accessKeyId": "AKIAIOSFODNN7EXAMPLE", "arn": "arn:aws:iam::123456789012:user/attacker"},
            "errorCode": "Client.UnauthorizedOperation",
        },
        {
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": "198.51.100.22",
            "userIdentity": {"accessKeyId": "AKIAIOSFODNN7EXAMPLE", "arn": "arn:aws:iam::123456789012:user/attacker"},
            "errorCode": None,
        },
    ]

    incidents = AlertIntegrator.convert_features_to_incidents(
        features_df=df,
        is_anomaly_mask=is_anomaly_mask,
        anomaly_scores=anomaly_scores,
        raw_events=raw_events,
    )

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.incident_id.startswith("INC-ML-")
    assert inc.alert_type == "credential_abuse"
    assert inc.severity == "CRITICAL"
    assert "AKIAIOSFODNN7EXAMPLE" in inc.affected_resource_ids
    assert inc.detection_evidence["model_type"] == "IsolationForest"
    assert inc.detection_evidence["sensitive_api_count"] == 4
    assert inc.detection_evidence["error_rate"] == 0.85
    assert len(inc.observed_events) == 2
    assert inc.observed_events[0]["event_name"] == "GetCallerIdentity"


def test_convert_features_to_incidents_vpc_flow():
    features_data = {
        "instance_id": ["i-0abcdef1234567890"],
        "bytes_total": [85000000],
        "c2_port_count": [8],
        "incident_type": ["c2_beacon"],
    }
    df = pd.DataFrame(features_data)
    is_anomaly_mask = np.array([True])
    anomaly_scores = np.array([0.31])

    raw_events = [
        {
            "instance_id": "i-0abcdef1234567890",
            "srcaddr": "10.0.1.50",
            "dstaddr": "203.0.113.88",
            "dstport": 4444,
        }
    ]

    incidents = AlertIntegrator.convert_features_to_incidents(
        features_df=df,
        is_anomaly_mask=is_anomaly_mask,
        anomaly_scores=anomaly_scores,
        raw_events=raw_events,
    )

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.alert_type == "c2_beacon"
    assert inc.severity == "CRITICAL"
    assert "i-0abcdef1234567890" in inc.affected_resource_ids
    assert inc.detection_evidence["c2_port_count"] == 8
    assert len(inc.observed_events) == 1
    assert inc.observed_events[0]["destination"] == "203.0.113.88"


def test_dispatch_to_pipeline_end_to_end():
    features_data = {
        "accessKeyId": ["AKIAIOSFODNN7EXAMPLE"],
        "principalArn": ["arn:aws:iam::123456789012:user/compromised_developer"],
        "error_rate": [0.6],
        "sensitive_api_count": [2],
        "incident_type": ["credential_abuse"],
    }
    df = pd.DataFrame(features_data)
    is_anomaly_mask = np.array([True])
    anomaly_scores = np.array([0.22])

    incidents = AlertIntegrator.convert_features_to_incidents(
        features_df=df,
        is_anomaly_mask=is_anomaly_mask,
        anomaly_scores=anomaly_scores,
    )

    odg = build_evaluation_odg()
    governor = SentinelGuardGovernor(odg)
    pipeline = IncidentResponsePipeline(governor=governor)

    reports = AlertIntegrator.dispatch_to_pipeline(pipeline, incidents)

    assert len(reports) == 1
    report = reports[0]
    assert report.incident_id == incidents[0].incident_id
    assert report.assessment.recommended_action is not None
    assert report.governor_decision is not None
    assert report.governor_decision.decision in {
        DecisionType.ALLOW,
        DecisionType.BLOCK,
        DecisionType.MODIFY,
        DecisionType.REQUEST_APPROVAL,
    }
    assert report.audit_hash is not None
    assert len(report.audit_hash) == 64  # SHA-256 hash length

