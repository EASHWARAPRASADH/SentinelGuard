# SentinelGuard

**State-Aware Policy Verification for Safe AI-Driven Cloud Incident Response**

SentinelGuard is a research-grade security governor designed for autonomous AI security agents. Rather than blindly trusting LLM-generated cloud remediation recommendations or evaluating actions using static permission rules, SentinelGuard models live cloud infrastructure topologies, runs speculative counterfactual simulations, and enforces system-wide operational invariants before executing actions.

---

## The Core Problem

When an autonomous AI security agent detects an active compromise in a cloud environment, its proposed remediation actions may be syntactically valid and well-intentioned, but operationally catastrophic:
- **Sole Administrator Lockout**: Revoking an anomalous access key when it is the sole reachable administrator during an active outage.
- **Service Quorum Collapse**: Isolating an infected compute node behind a load balancer when doing so drops healthy replica capacity below minimum quorum.
- **Telemetry Blindness**: Altering bucket policies or route tables in a way that severs CloudTrail, VPC Flow log delivery, or CloudWatch host agents.

---

## Foundational Operational Invariants

SentinelGuard evaluates candidate actions against three explicit invariants:
1. **$I_{\text{Admin}}$ (Administrative Recovery)**: At least one independent, reachable administrator recovery path remains operational.
2. **$I_{\text{Avail}}$ (Service Availability)**: Required healthy capacity and health-check network connectivity remain above configured thresholds for all Tier-0/Tier-1 services.
3. **$I_{\text{Telem}}$ (Security Telemetry Continuity)**: Resource-specific logging pipelines (CloudTrail, VPC Flow Logs, CloudWatch agents) and their encryption keys remain functional.

---

## The Four-Way Decision Taxonomy

SentinelGuard enforces a 10-step verified remediation lifecycle:
- **`ALLOW`**: Action verified safe; all operational invariants satisfied in the projected post-action state $S' = f(S_0, a)$.
- **`BLOCK`**: Overt policy breach, unauthorized action, or prompt-injected payload.
- **`MODIFY`**: Original action would breach an invariant, but the governor identifies and verifies a non-disruptive mitigation (e.g. `AttachScopedEgressFilter` to block attacker C2 while keeping health-checks open).
- **`REQUEST_APPROVAL`**: Irreversible or catastrophic risk with no safely verifiable automated mitigation (escalates to human analyst with blast-radius report).

---

## Experimental Benchmark (CloudGuard-Bench)

Evaluated across **120 reproducible scenarios** (40 Safe, 40 Overt Violations, 40 Operational Traps) against four configurations:

| Configuration | UAER (%) ↓ | PVPR (%) ↑ | LAAR (%) ↑ | FBR (%) ↓ | MSR (%) ↑ | Decision Latency (ms) ↓ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config 1: Unchecked LLM** | 100.0% | 0.0% | 100.0% | 0.0% | 0.0% | 0.00 ± 0.00 |
| **Config 2: Static Policy Gate** | 50.0% | 100.0% | 100.0% | 0.0% | 0.0% | 0.00 ± 0.00 |
| **Config 3: Static Policy + Dependency** | 12.5% | 100.0% | 50.0% | 50.0% | 0.0% | 0.00 ± 0.00 |
| **Config 4: SentinelGuard (Proposed)** | **0.0%** | **100.0%** | **100.0%** | **0.0%** | **62.5%** | **0.09 ± 0.07** |

---

## Quickstart

### Prerequisites
- Python 3.11+
- `uv` (recommended)

### Run the Demo
```bash
uv run python main.py
```

### Run Tests
```bash
uv run pytest -v
```

### Run Benchmark Suite
```bash
uv run python -m sentinelguard.benchmark.runner
```
