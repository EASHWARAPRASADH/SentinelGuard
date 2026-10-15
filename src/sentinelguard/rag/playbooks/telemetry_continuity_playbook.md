# SentinelGuard Playbook: Security Telemetry & Audit Pipeline Protection
<!-- category: telemetry_and_audit -->
<!-- version: 1.0 -->

## 1. Overview and Scope
This playbook establishes safeguards for maintaining CloudTrail logging, VPC Flow Logs, and CloudWatch agent telemetry during active security incidents.

## 2. Core Operational Constraints
- Audit telemetry is critical for SOC visibility and forensic investigation.
- Under NO circumstances should remediation actions disable CloudTrail trails, delete or block write access to audit S3 buckets, or disable KMS encryption keys used for log storage.
- The security governor enforces the Telemetry Continuity invariant ($I_{\text{Telem}}$).
- Any candidate action that interrupts CloudTrail delivery, VPC Flow log ingestion, or host CloudWatch log forwarding will be rejected or modified by the governor.
