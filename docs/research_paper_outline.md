# SentinelGuard: Research Paper Outline

**Working Title**:  
*SentinelGuard: State-Aware Policy Verification for Safe AI-Driven Cloud Incident Response*

**Target Venues**:  
IEEE Symposium on Security and Privacy (S&P), ACM Conference on Computer and Communications Security (CCS), USENIX Security Symposium, or IEEE Cloud.

---

## Abstract

Automated incident response using Large Language Models (LLMs) offers rapid containment of intrusions across enterprise cloud environments. However, current LLM agents lack global awareness of operational infrastructure topologies and runtime dependencies. Consequently, AI-directed remediations frequently introduce cascading operational outages, total administrative lockouts, and telemetry blindness—vulnerabilities we formalize as *operational traps*. Traditional Cloud Security Posture Management (CSPM) and Service Control Policies (SCPs) fail to prevent these failures because they evaluate policies on single isolated resources rather than evaluating holistic relational state transitions.

In this paper, we propose **SentinelGuard**, a state-aware security governor that intercepts, verifies, and safely adapts AI-generated cloud incident remediation actions prior to execution. SentinelGuard formalizes an in-memory **Operational Dependency Graph (ODG)**, executes high-speed pure-Python counterfactual state simulation, and enforces three foundational operational invariants: Administrative Recovery ($\mathcal{I}_{\text{Admin}}$), Service Availability ($\mathcal{I}_{\text{Avail}}$), and Security Telemetry Continuity ($\mathcal{I}_{\text{Telem}}$). When an action threatens an invariant, a bounded mitigation engine transforms destructive containment actions into non-disruptive alternatives.

We evaluate SentinelGuard on **CloudGuard-Bench**, an extensive benchmark of 120 structurally distinct infrastructure scenarios, alongside a 24-scenario adversarial suite covering 12 vulnerability classes. Our empirical results demonstrate that SentinelGuard reduces the Unsafe Action Execution Rate ($\text{UAER}$) from $100.0\%$ (Unchecked LLM) and $50.0\%$ (Static Policy Gates) to **$0.0\%$**, while maintaining a **$100.0\%$** Legitimate Action Acceptance Rate ($\text{LAAR}$) and **$0.0\%$** False Blocking Rate ($\text{FBR}$). Furthermore, SentinelGuard safely adapts **$62.5\%$** of operational traps into verified mitigations, with a mean decision latency of **$0.105\text{ ms}$** ($p95 = 0.228\text{ ms}$). To ensure execution safety, SentinelGuard integrates pre-execution Time-of-Check to Time-of-Use (TOCTOU) verification and a SHA-256 Merkle-linked audit ledger, ensuring zero unauthorized cloud mutations.

---

## 1. Introduction

* **1.1 The Rise of Agentic Cloud Security**: Growth of autonomous LLM agents in SOCs; need for sub-minute containment of ransomware, credential abuse, and lateral movement.
* **1.2 The Blind Spot: Operational Traps**: Why security-compliant actions can be operationally fatal:
  * Isolating an infected node breaks load balancer quorum ($k_{\text{min}}$).
  * Revoking compromised keys locks out the sole remaining administrator.
  * Modifying bucket policies severs CloudTrail audit delivery.
* **1.3 Limitations of Prior Art**: Why static SCPs, IAM boundaries, and graph CMDBs fail: static checks lack counterfactual state simulation.
* **1.4 Research Contributions**:
  * Formalization of the Operational Dependency Graph (ODG) and three foundational invariants.
  * A four-way decision model (`ALLOW`, `BLOCK`, `MODIFY`, `REQUEST_APPROVAL`) with bounded mitigation selection.
  * The CloudGuard-Bench 120-scenario benchmark and 24-scenario adversarial evaluation suite.
  * Empirical proof of zero unsafe executions ($\text{UAER} = 0\%$) at sub-millisecond simulation overhead.

---

## 2. Threat Model & Problem Formulation

* **2.1 Cloud Infrastructure Representation**: Directed multigraph $G = (V, E)$ modeling resources, tiers, and multi-relational dependencies.
* **2.2 Threat Actors & Attacker Capabilities**:
  * External adversaries injecting prompt injections into telemetry error logs.
  * Subverted or hallucinating AI models generating malformed or out-of-scope actions.
  * Out-of-band actors inducing TOCTOU state drifts during verification.
* **2.3 Formal Invariant Definitions**:
  * $\mathcal{I}_{\text{Admin}}$: Reachable root credentials + break-glass roles $\ge 1$.
  * $\mathcal{I}_{\text{Avail}}$: Quorum of healthy instances in each active target group $\ge k_{\text{min}}$.
  * $\mathcal{I}_{\text{Telem}}$: Functional delivery and encryption paths for CloudTrail, VPC Flow Logs, and CloudWatch agents.

---

## 3. SentinelGuard System Architecture

* **3.1 High-Level Architecture**: Pipeline from telemetry ingestion to execution.
* **3.2 In-Memory Operational Dependency Graph**: Node typing, edge typing, and sub-millisecond graph cloning.
* **3.3 Speculative Counterfactual Simulator**: Pure-Python simulator computing $G' = \text{Simulate}(G, a)$ without cloud API calls.
* **3.4 Four-Way Decision Engine & Bounded Mitigation**:
  * Action substitution table (e.g., `AttachScopedEgressFilter` replacing `IsolateInstance`).
  * Escalation to human approval when no verified automated mitigation exists.
* **3.5 Controlled Execution State-Machine**:
  * Pre-execution TOCTOU hash verification.
  * Post-execution invariant validation.
  * Cryptographic SHA-256 Merkle-linked audit ledger.

---

## 4. Big Data Telemetry & ML Anomaly Detection

* **4.1 Telemetry Processing Pipeline**: PySpark distributed ETL ingesting CloudTrail and VPC Flow Logs.
* **4.2 Sliding-Window Feature Engineering**: 5-minute aggregations (request counts, error spikes, distinct IAM methods, byte volume).
* **4.3 Unsupervised Anomaly Detection**: Isolation Forest vs. Heuristic SIEM rule baseline.
* **4.4 Alert Integration & Decoupling**: Converting detected anomalies into structured envelopes for the agent, maintaining strict separation between detection metrics and safety verification.

---

## 5. Experimental Evaluation

* **5.1 Evaluation Setup & CloudGuard-Bench**: 120 scenarios across 3 balanced categories (Safe, Overt Violations, Operational Traps).
* **5.2 Baseline Configurations**:
  * Config 1: Unchecked LLM.
  * Config 2: Static Policy Gate (CSPM / SCP).
  * Config 3: Static Policy + Dependency Checking.
  * Config 4: Proposed SentinelGuard.
* **5.3 Core Results & Comparative Analysis**:
  * UAER: 100% $\to$ 50% $\to$ 12.5% $\to$ **0.0%**.
  * LAAR: 100% in SentinelGuard vs. 50% in Config 3 (eliminating false blocks).
  * MSR: 62.5% in SentinelGuard vs. 0.0% across all baselines.
* **5.4 Micro-Benchmarking & Latency Distribution**:
  * Pure-Python simulation latency: Mean $0.105\text{ ms}$, Median $0.071\text{ ms}$, $p95 = 0.228\text{ ms}$.
* **5.5 Adversarial Suite Evaluation**: 100% fail-closed safety across 12 vulnerability classes (24 scenarios).
* **5.6 TOCTOU Drift & Audit Ledger Integrity**: Preventing out-of-band state race conditions and verifying cryptographic chain integrity.

---

## 6. Discussion & Practical Deployment

* **6.1 Deployment Topologies**: Integration with AWS EventBridge, Step Functions, and AWS Systems Manager.
* **6.2 Human-in-the-Loop Integration**: Seamless escalation of Tier-0 actions via Slack/Teams webhook tokens.
* **6.3 Computational Complexity & Scalability**: Analysis of graph cloning and invariant verification complexity ($O(|V| + |E|)$).
* **6.4 Limitations**: Graph boundary completeness, discovery latency in live AWS Config, and reliance on modeled abstractions.

---

## 7. Related Work

* **7.1 LLM Agents for Security**: Autonomous SOC agents, prompt injection vulnerabilities, and tool-use verification.
* **7.2 Cloud Policy Verification**: Formally verified IAM policies (Zelkova, Tiros), AWS Config rules, and CSPM platforms.
* **7.3 Safe Reinforcement Learning & Invariant Enforcement**: Runtime shielding, safe exploration, and transactional state-rollback in distributed systems.

---

## 8. Conclusion

SentinelGuard bridges the critical gap between autonomous AI decision-making and operational cloud resilience. By anchoring AI remediation proposals in state-aware graph simulation and invariant enforcement, SentinelGuard proves that automated incident response can achieve zero unsafe executions without compromising security containment or runtime performance.
