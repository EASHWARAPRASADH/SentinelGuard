# SentinelGuard Playbook: EC2 Compute Host Containment & C2 Isolation
<!-- category: compute_isolation -->
<!-- version: 1.0 -->

## 1. Overview and Scope
This playbook provides guidance for containing compromised Amazon EC2 compute instances exhibiting command-and-control (C2) communication, cryptomining, or malware execution.

## 2. Detection Criteria
- VPC Flow Logs indicating outbound connections to known malicious IP addresses or unexpected high-bandwidth data transfers.
- GuardDuty alerts for unauthorized crypto-mining or backdoor beacons.

## 3. Recommended Remediation Procedures
- **Primary Remediation Action**: `isolate_instance`.
- **Target Parameter**: `target_resource_id` must match the affected EC2 Instance ID.
- **Safety Invariant Verification**:
  - The security governor enforces the Service Availability invariant ($I_{\text{Avail}}$).
  - If the affected instance belongs to a production target group, the governor checks whether isolating it would reduce healthy replica count below the required `min_healthy_replicas`.
  - When direct isolation would collapse service quorum or drop health checks, the governor automatically synthesizes a verified mitigation (`attach_scoped_egress_filter`) that blocks external attacker egress while preserving internal health-check ingress.
