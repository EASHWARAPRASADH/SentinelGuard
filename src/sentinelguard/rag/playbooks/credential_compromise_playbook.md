# SentinelGuard Playbook: IAM Access Key & Credential Compromise Response
<!-- category: identity_and_access -->
<!-- version: 1.0 -->

## 1. Overview and Scope
This playbook provides guidance for responding to compromised AWS IAM access keys, leaked credentials, and unauthorized programmatic API usage.

## 2. Detection Criteria
- CloudTrail events showing impossible travel, anomalous API calling patterns, or reconnaissance calls (e.g., `iam:ListUsers`, `sts:GetCallerIdentity` from untrusted IPs).
- Credential leak alerts on external repositories or public forums.

## 3. Recommended Remediation Procedures
- **Primary Remediation Action**: `revoke_access_key`.
- **Target Parameter**: `target_resource_id` must match the specific compromised Access Key ID.
- **Safety Invariant Verification**:
  - The security governor enforces the Administrative Recovery invariant ($I_{\text{Admin}}$).
  - Prior to credential revocation, the system must verify that at least one independent, reachable administrator recovery path remains active for the account.
  - If the target access key belongs to the sole reachable administrator and no verified emergency break-glass role exists, the action must NOT execute automatically. It must be escalated to a human operator for emergency verification.
