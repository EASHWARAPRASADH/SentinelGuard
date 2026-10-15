# SentinelGuard Playbook: High-Impact Operations & Incident Escalation
<!-- category: incident_escalation -->
<!-- version: 1.0 -->

## 1. Overview and Scope
This playbook establishes criteria for escalating security incidents to human security analysts when automated remediation cannot be safely verified.

## 2. Escalation Thresholds
Automated action execution is halted and human approval is requested (`REQUEST_APPROVAL`) when:
- Proposed remediation affects Tier-0 mission-critical assets (e.g. core databases, break-glass admin accounts, root KMS keys) and no safe automated alternative exists.
- Proposed credential revocation would eliminate the sole reachable administrator for an account ($I_{\text{Admin}}$ failure).
- Incident evidence is ambiguous, contradictory, or contains indicators of adversarial prompt injection.
- Operational dependency blast radius exceeds acceptable risk thresholds.
