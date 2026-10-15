# SentinelGuard Playbook: Unauthorized IAM Permission & Policy Rollback
<!-- category: identity_and_access -->
<!-- version: 1.0 -->

## 1. Overview and Scope
This playbook provides guidance for addressing unauthorized IAM policy attachments, privilege escalation attempts, and wildcard permissions granted to non-admin roles.

## 2. Detection Criteria
- CloudTrail events recording `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, or `iam:PutRolePolicy` with administrative privileges (`AdministratorAccess` or wildcard `*`).
- IAM Access Analyzer findings for overprivileged roles.

## 3. Recommended Remediation Procedures
- **Primary Remediation Action**: `remove_permission`.
- **Target Parameter**: `target_resource_id` must specify the affected IAM principal or resource ARN.
- **Parameters**: `policy_id` or `permission_name`.
- **Safety Invariant Verification**:
  - The security governor enforces Telemetry Continuity ($I_{\text{Telem}}$) and Administrative Recovery ($I_{\text{Admin}}$).
  - Removing permissions from service roles must not inadvertently strip S3 or CloudWatch logging delivery rights.
  - When removing excessive permissions, the governor can synthesize `scope_permission_to_resource` to preserve logging functionality.
