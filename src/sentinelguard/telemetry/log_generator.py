"""
Synthetic Cloud Security Log Generator for SentinelGuard.
Generates realistic normal baseline and labeled anomalous telemetry for:
- AWS CloudTrail API events
- Amazon VPC Flow Logs
"""

from __future__ import annotations

import json
import random
import time
from typing import Any, Dict, List, Optional, Tuple


class SyntheticLogGenerator:
    """
    Generates realistic CloudTrail and VPC Flow Log events with ground-truth labels.
    """

    BENIGN_PRINCIPALS = [
        {"arn": "arn:aws:iam::123456789012:user/dev-bob", "name": "dev-bob", "key": "ak-bob-01"},
        {"arn": "arn:aws:iam::123456789012:user/analyst-charlie", "name": "analyst-charlie", "key": "ak-charlie-01"},
        {"arn": "arn:aws:iam::123456789012:role/ci-deployer", "name": "ci-deployer", "key": "ak-ci-01"},
        {"arn": "arn:aws:iam::123456789012:role/lambda-worker", "name": "lambda-worker", "key": "ak-lambda-01"},
    ]

    BENIGN_READ_APIS = [
        "DescribeInstances",
        "DescribeSecurityGroups",
        "DescribeSubnets",
        "ListBuckets",
        "GetCallerIdentity",
        "DescribeVolumes",
        "GetItem",
        "ListObjectsV2",
    ]

    INTERNAL_IPS = [
        "10.0.1.15", "10.0.1.42", "10.0.2.100", "10.0.2.155", "172.16.0.22"
    ]

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def generate_cloudtrail_events(
        self,
        normal_count: int = 1000,
        anomaly_count: int = 50,
        base_timestamp: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate a mixed dataset of benign CloudTrail events and labeled anomaly sequences.
        """
        t_base = base_timestamp or (time.time() - 3600)
        events: List[Dict[str, Any]] = []

        # 1. Generate Benign Events
        for i in range(normal_count):
            principal = self.rng.choice(self.BENIGN_PRINCIPALS)
            api_name = self.rng.choice(self.BENIGN_READ_APIS)
            src_ip = self.rng.choice(self.INTERNAL_IPS)
            ts = t_base + (i * 2.5) + self.rng.uniform(-0.5, 0.5)

            # Rare benign error rate (~2%)
            is_error = self.rng.random() < 0.02
            error_code = "AccessDenied" if is_error else None

            event = {
                "eventID": f"evt-normal-{i:06d}",
                "eventTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
                "eventSource": "ec2.amazonaws.com" if "Describe" in api_name else "iam.amazonaws.com",
                "eventName": api_name,
                "awsRegion": "us-east-1",
                "sourceIPAddress": src_ip,
                "userAgent": "aws-sdk-go/v1.38.0",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": principal["name"],
                    "arn": principal["arn"],
                    "userName": principal["name"],
                    "accessKeyId": principal["key"],
                },
                "requestParameters": {"maxResults": 50},
                "responseElements": None,
                "errorCode": error_code,
                "errorMessage": "Access denied" if error_code else None,
                "is_anomaly": False,
                "label": "benign",
                "incident_type": None,
                "target_resource_id": None,
            }
            events.append(event)

        # 2. Inject Anomaly Sequences
        # Anomaly Type 1: Credential Abuse / Impossible Travel
        target_admin_key = "ak-alice-01"
        for j in range(anomaly_count // 3):
            ts = t_base + 1800 + (j * 0.5)  # rapid burst
            events.append({
                "eventID": f"evt-anom-cred-{j:04d}",
                "eventTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
                "eventSource": "iam.amazonaws.com",
                "eventName": "GetCallerIdentity" if j % 2 == 0 else "ListUsers",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "198.51.100.222",  # Anomalous foreign IP
                "userAgent": "python-requests/2.28.1 (KaliLinux)",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "usr-alice",
                    "arn": "arn:aws:iam::123456789012:user/AliceAdmin",
                    "userName": "AliceAdmin",
                    "accessKeyId": target_admin_key,
                },
                "requestParameters": {},
                "responseElements": None,
                "errorCode": "UnauthorizedOperation" if j == 0 else None,
                "errorMessage": None,
                "is_anomaly": True,
                "label": "credential_abuse",
                "incident_type": "credential_abuse",
                "target_resource_id": target_admin_key,
            })

        # Anomaly Type 2: Privilege Escalation
        for k in range(anomaly_count // 3):
            ts = t_base + 2400 + (k * 1.0)
            events.append({
                "eventID": f"evt-anom-priv-{k:04d}",
                "eventTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
                "eventSource": "iam.amazonaws.com",
                "eventName": "AttachUserPolicy",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.45",
                "userAgent": "aws-cli/2.11.0",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "usr-intern",
                    "arn": "arn:aws:iam::123456789012:user/intern-eve",
                    "userName": "intern-eve",
                    "accessKeyId": "ak-eve-01",
                },
                "requestParameters": {
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "userName": "intern-eve",
                },
                "responseElements": None,
                "errorCode": "AccessDenied" if k < 2 else None,
                "errorMessage": None,
                "is_anomaly": True,
                "label": "privilege_escalation",
                "incident_type": "privilege_escalation",
                "target_resource_id": "arn:aws:iam::123456789012:user/intern-eve",
            })

        # Anomaly Type 3: Telemetry Evasion / Audit Tampering
        for m in range(anomaly_count - (2 * (anomaly_count // 3))):
            ts = t_base + 3000 + (m * 2.0)
            events.append({
                "eventID": f"evt-anom-audit-{m:04d}",
                "eventTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketPolicy",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "198.51.100.99",
                "userAgent": "boto3/1.26.0",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "usr-rogue",
                    "arn": "arn:aws:iam::123456789012:user/rogue-user",
                    "userName": "rogue-user",
                    "accessKeyId": "ak-rogue-01",
                },
                "requestParameters": {
                    "bucketName": "s3-audit-logs",
                    "policy": '{"Effect": "Deny", "Principal": "*"}',
                },
                "responseElements": None,
                "errorCode": None,
                "errorMessage": None,
                "is_anomaly": True,
                "label": "audit_tampering",
                "incident_type": "audit_tampering",
                "target_resource_id": "s3-audit-logs",
            })

        # Sort chronologically by eventTime
        events.sort(key=lambda x: x["eventTime"])
        return events

    def generate_vpc_flow_logs(
        self,
        normal_count: int = 1000,
        anomaly_count: int = 50,
        base_timestamp: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate a mixed dataset of benign VPC Flow Logs and labeled C2 network anomalies.
        """
        t_base = int(base_timestamp or (time.time() - 3600))
        flows: List[Dict[str, Any]] = []

        BENIGN_INSTANCES = [
            "i-web-02", "i-web-03", "i-app-01", "i-app-02", "i-worker-01", "i-worker-02", "i-db-01", "i-cache-01"
        ]

        # 1. Benign Internal & Web Traffic
        for i in range(normal_count):
            inst_id = self.rng.choice(BENIGN_INSTANCES)
            src_ip = self.rng.choice(self.INTERNAL_IPS)
            dst_ip = self.rng.choice(["10.0.1.5", "10.0.2.8", "172.16.1.1"])
            bytes_sent = self.rng.randint(200, 15000)
            packets = max(1, bytes_sent // 1200)
            start_ts = t_base + (i * 3)
            end_ts = start_ts + 60

            flows.append({
                "version": 2,
                "account_id": "123456789012",
                "interface_id": f"eni-{inst_id[-6:]}",
                "instance_id": inst_id,
                "srcaddr": src_ip,
                "dstaddr": dst_ip,
                "srcport": self.rng.choice([80, 443, 3306, 5432]),
                "dstport": self.rng.randint(30000, 65000),
                "protocol": 6,  # TCP
                "packets": packets,
                "bytes": bytes_sent,
                "start": start_ts,
                "end": end_ts,
                "action": "ACCEPT",
                "log_status": "OK",
                "is_anomaly": False,
                "label": "benign",
                "incident_type": None,
                "target_resource_id": None,
            })

        # 2. C2 Beaconing & Data Exfiltration Anomaly on target instance i-web-01
        target_inst = "i-web-01"
        c2_ip = "203.0.113.195"
        for j in range(anomaly_count):
            start_ts = t_base + 1200 + (j * 15)  # Periodic beacon every 15s
            end_ts = start_ts + 5
            # Heavy exfiltration / beacon payload
            bytes_sent = self.rng.randint(500000, 5000000)
            packets = bytes_sent // 1400

            flows.append({
                "version": 2,
                "account_id": "123456789012",
                "interface_id": "eni-c2-compromised",
                "instance_id": target_inst,
                "srcaddr": "10.0.1.50",  # Private IP of i-web-01
                "dstaddr": c2_ip,
                "srcport": self.rng.randint(40000, 60000),
                "dstport": 4444,  # Classic C2 port
                "protocol": 6,
                "packets": packets,
                "bytes": bytes_sent,
                "start": start_ts,
                "end": end_ts,
                "action": "ACCEPT",
                "log_status": "OK",
                "is_anomaly": True,
                "label": "c2_beacon",
                "incident_type": "c2_beacon",
                "target_resource_id": target_inst,
            })

        flows.sort(key=lambda x: x["start"])
        return flows
