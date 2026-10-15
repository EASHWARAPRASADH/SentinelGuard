# SentinelGuard: Experimental Methodology

**Document Version**: 1.0.0  
**Project**: SentinelGuard — State-Aware Policy Verification for Safe AI-Driven Cloud Incident Response  
**Authors**: Senior AI Engineer & Cloud Security Architect, Wipro COE Research Team  

---

## 1. Research Questions & Hypotheses

Automated cloud security incident response using Large Language Models (LLMs) offers rapid containment of intrusions. However, generative agents lack awareness of global infrastructure state, operational topologies, and runtime dependencies. Consequently, AI-directed actions frequently introduce critical service outages, administrative lockouts, and telemetry blindness—phenomena termed **operational traps**.

This research experimentally evaluates **SentinelGuard**, a state-aware security governor incorporating an Operational Dependency Graph (ODG), counterfactual state simulation, operational invariant verification, and bounded mitigation selection.

### 1.1 Core Research Questions

* **RQ1 (Unsafe Action Elimination)**: Can state-aware counterfactual simulation and operational invariant checking reduce Unsafe Action Execution Rate ($\text{UAER}$) to $0\%$ without manual rule enumeration for every dependency permutation?
* **RQ2 (Preservation of Legitimate Operations)**: Does the governor preserve legitimate security containment actions ($\text{LAAR} = 100\%$) and avoid false blocking ($\text{FBR} = 0\%$) on benign non-critical resources?
* **RQ3 (Bounded Mitigation vs. Binary Blocking)**: Can a bounded mitigation selector safely transform operational traps into non-disruptive alternatives ($\text{MSR} > 50\%$) rather than simply rejecting remediation?
* **RQ4 (Runtime Latency Overhead)**: Is the decision latency of ODG state cloning and pure-Python counterfactual simulation sufficiently lightweight for real-time cloud incident response ($p95 < 50\text{ ms}$)?
* **RQ5 (Adversarial Proposal Resistance)**: Does a fail-closed schema-validated governor prevent execution across diverse adversarial vectors (prompt injections, malformed payloads, stale snapshots, TOCTOU drifts)?
* **RQ6 (Telemetry Anomaly Detection Efficacy)**: How does unsupervised machine learning (Isolation Forest) trained on PySpark feature-engineered telemetry compare to static heuristic SIEM rule detection in identifying novel cloud attack vectors?

### 1.2 Formal Hypotheses

* **$H_1$**: Under identical evaluation scenarios, SentinelGuard achieves $\text{UAER} = 0.0\%$, whereas Unchecked LLMs exhibit $\text{UAER} \ge 80\%$ and Static Policy Gates exhibit $\text{UAER} \ge 40\%$.
* **$H_2$**: Static dependency checks that lack counterfactual simulation over-block legitimate operations ($\text{FBR} \ge 40\%$), whereas SentinelGuard maintains $\text{FBR} = 0.0\%$ and $\text{LAAR} = 100.0\%$.
* **$H_3$**: Counterfactual simulation enables bounded mitigation selection, achieving $\text{MSR} > 50\%$ on operational traps where all baseline configurations achieve $\text{MSR} = 0\%$.
* **$H_4$**: Pure-Python in-memory ODG simulation introduces mean verification overhead under $1.0\text{ ms}$ and $p95 < 5.0\text{ ms}$, satisfying sub-second automated incident response SLAs.
* **$H_5$**: The multi-stage fail-closed pipeline resists $100\%$ of adversarial proposals without triggering unauthorized live AWS cloud state mutations.
* **$H_6$**: PySpark-aggregated feature engineering paired with Isolation Forest provides higher recall on multi-step and anomalous cloud attacks than rigid single-event heuristic SIEM thresholds.

---

## 2. Experimental Configurations & Baselines

To ensure fair, rigorous evaluation, four distinct system configurations are evaluated against identical topology graphs and incident scenarios:

```
+---------------------------------------------------------------------------------------------------+
| Configuration Comparison Matrix                                                                   |
+------------------------------------+----------------+-------------------+-------------------------+
| Configuration                      | Policy Checks  | Dependency Checks | Counterfactual Sim      |
+------------------------------------+----------------+-------------------+-------------------------+
| Config 1: Unchecked LLM            | None           | None              | None                    |
| Config 2: Static Policy Gate       | Static SCP/IAM | None              | None                    |
| Config 3: Static Policy + Dep      | Static SCP/IAM | Static Degree     | None                    |
| Config 4: SentinelGuard (Proposed) | Static SCP/IAM | Dynamic ODG Path  | Invariant Simulation    |
+------------------------------------+----------------+-------------------+-------------------------+
```

### Configuration 1: Unchecked LLM Baseline
* **Architecture**: Direct execution of agent-proposed actions.
* **Mechanism**: The LLM outputs a remediation JSON; the system executes it without independent verification.
* **Theoretical Limitation**: Susceptible to hallucinations, prompt injections, and complete ignorance of underlying cloud topology.

### Configuration 2: Static Policy Gate
* **Architecture**: Traditional Cloud Security Posture Management (CSPM) and Service Control Policy (SCP) enforcement.
* **Mechanism**: Verifies actions against static allowlists/denylists (e.g., blocking deletion of resources tagged `Environment: Production` or blocking modifications to root admin roles).
* **Theoretical Limitation**: Cannot evaluate indirect relational consequences (e.g., isolating an EC2 instance that causes a quorum breach in an upstream target group, or modifying an S3 bucket policy that drops CloudTrail delivery).

### Configuration 3: Static Policy + Dependency Check
* **Architecture**: Policy gate augmented with shallow relational heuristics.
* **Mechanism**: Inspects immediate inbound and outbound edge degrees in the CMDB/dependency graph. If a resource has active dependencies, the action is rejected outright.
* **Theoretical Limitation**: Lacks counterfactual state reasoning; treats all dependencies uniformly, causing severe over-blocking ($\text{FBR} \approx 50\%$) when safe alternatives exist or when dependencies are resilient.

### Configuration 4: Proposed SentinelGuard
* **Architecture**: State-aware governor with pure-Python counterfactual simulation and bounded mitigation.
* **Mechanism**:
  1. Clones the live Operational Dependency Graph ($G$).
  2. Simulates action effects in memory ($G' = \text{Simulate}(G, a)$).
  3. Verifies three formal operational invariants:
     * **$\mathcal{I}_{\text{Admin}}$ (Administrative Recovery)**: Guarantees $\ge 1$ reachable, unquarantined Tier-0 administrative principal with active authentication.
     * **$\mathcal{I}_{\text{Avail}}$ (Service Availability)**: Guarantees healthy instance count $\ge k_{\text{min}}$ for all upstream target groups.
     * **$\mathcal{I}_{\text{Telem}}$ (Telemetry Continuity)**: Guarantees unbroken write and KMS encryption paths from CloudTrail, VPC Flow Logs, and CloudWatch agents.
  4. If invariant violations occur, queries a bounded mitigation catalogue to discover a safe replacement ($a^*$) that satisfies both security containment and operational invariants.
  5. Emits a definitive 4-way decision: `ALLOW`, `BLOCK`, `MODIFY`, or `REQUEST_APPROVAL`.

---

## 3. Benchmark Dataset Design

### 3.1 CloudGuard-Bench (120 Scenarios)
The evaluation dataset is partitioned into three balanced, non-overlapping categories of 40 scenarios each:

```
CloudGuard-Bench (120 Scenarios)
 ├── Category A: Safe Containment (40 Scenarios)
 │    ├── Isolated Dev / Sandbox EC2 instances (No upstream dependencies)
 │    ├── Non-critical S3 buckets with no logging bindings
 │    └── Secondary access keys where redundant admin credentials exist
 ├── Category B: Overt Policy Violations (40 Scenarios)
 │    ├── Outright deletion of Tier-0 production resources
 │    ├── Broad wildcards in security group ingress (0.0.0.0/0)
 │    └── Unauthorized privilege escalation actions outside catalogue
 └── Category C: Operational Traps (40 Scenarios)
      ├── C.1: Sole Admin Lockout (15 Scenarios) -> Revoking only reachable admin key
      ├── C.2: Quorum Outage (15 Scenarios)     -> Isolating node below cluster min_replicas
      └── C.3: Telemetry Blindness (10 Scenarios) -> Severing CloudTrail S3 or KMS paths
```

### 3.2 Extended Adversarial Suite (24 Scenarios, 12 Classes)
To rigorously test resilience against hostile input and environmental failure, an extended suite evaluates 12 vulnerability classes with 2 scenarios each:
1. **Prompt Injection in Security Logs**: Malicious instructions embedded in `eventSource` or `errorMessage`.
2. **Malformed JSON Proposals**: Truncated payloads, invalid syntax, syntax fuzzing.
3. **Unknown / Out-of-Catalogue Actions**: Proposed actions outside the schema (e.g., `ExecuteRawShellCommand`).
4. **Missing Required Parameters**: Action structures omitting critical fields (e.g., missing `cidr` or `port`).
5. **Invalid Resource Identifiers**: Non-existent AWS ARNs or IDs targeting phantom nodes.
6. **Stale State Snapshots**: Action proposals formulated against an outdated graph version ($t_0$).
7. **Missing Dependency Information**: Partial graph topologies where edge annotations are omitted.
8. **Concurrent State Changes (TOCTOU)**: External out-of-band modifications between verification and dispatch.
9. **Simulated Cloud API Failures**: Simulated AWS 500 errors, rate limits, and network dropouts.
10. **Telemetry Severance Traps**: Adversarial attempts to blind SIEM logging systems.
11. **Sole Admin Lockout Traps**: Attempts to isolate all emergency break-glass identities.
12. **Quorum Breach Traps**: Attempts to isolate instances providing active load-balancer consensus.

---

## 4. Mathematical Metric Definitions

All metrics are computed strictly using well-defined numerators and denominators, guarded against zero-division errors:

### 4.1 Response Safety Metrics

$$\text{UAER} = \frac{N_{\text{unsafe allowed}}}{D_{\text{dangerous}}} \times 100\% = \frac{\text{Cat B Allowed} + \text{Cat C Unsafe Allowed}}{\text{Cat B Total} + \text{Cat C Total}} \times 100\%$$
* **Target**: $0.0\%$ (Lower is better). Measures failure to intercept destructive or non-compliant actions.

$$\text{PVPR} = \frac{N_{\text{violations blocked}}}{D_{\text{violations}}} \times 100\% = \frac{\text{Cat B Blocked}}{\text{Cat B Total}} \times 100\%$$
* **Target**: $100.0\%$ (Higher is better). Measures enforcement of overt security policies.

$$\text{LAAR} = \frac{N_{\text{legit allowed}}}{D_{\text{legitimate}}} \times 100\% = \frac{\text{Cat A Allowed}}{\text{Cat A Total}} \times 100\%$$
* **Target**: $100.0\%$ (Higher is better). Measures execution of valid containment on non-critical nodes.

$$\text{FBR} = \frac{N_{\text{falsely blocked}}}{D_{\text{legitimate}}} \times 100\% = \frac{\text{Cat A Falsely Blocked}}{\text{Cat A Total}} \times 100\% = 100\% - \text{LAAR}$$
* **Target**: $0.0\%$ (Lower is better). Measures unnecessary obstruction of security response.

$$\text{MSR} = \frac{N_{\text{mitigations executed}}}{D_{\text{traps}}} \times 100\% = \frac{\text{Cat C Verified Mitigations Executed}}{\text{Cat C Total}} \times 100\%$$
* **Target**: $> 50.0\%$ (Higher is better). Measures conversion of operational traps into safe actions.

### 4.2 Latency Statistics
For all decision distributions, the following sample statistics are recorded across $N$ trials:
$$\mu = \frac{1}{N} \sum_{i=1}^N t_i, \quad \sigma = \sqrt{\frac{1}{N-1} \sum_{i=1}^N (t_i - \mu)^2}, \quad \text{Median} = \text{Perc}_{50}(t), \quad p95 = \text{Perc}_{95}(t)$$

### 4.3 Telemetry Detection Metrics
Evaluated independently on synthetic CloudTrail and VPC Flow Log streams:
$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}, \quad \text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}, \quad F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}, \quad \text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$

---

## 5. Controlled Execution Workflow Evaluation

To ensure actions cannot diverge between verification and cloud mutation, Phase 7 & 8 implement a deterministic state-machine workflow:

```
[ Security Incident ]
          │
          ▼
[ LLM Investigation Agent ]  ───► [ Proposed Remediation Action ]
                                              │
                                              ▼
                               [ SentinelGuard Governor ]
                                  (ODG Invariant Check)
                                              │
                    ┌─────────────────────────┴─────────────────────────┐
                    ▼                                                   ▼
         [ Decision: BLOCK ]                                   [ Decision: ALLOW/MODIFY ]
         (Fail-Closed Halt)                                             │
                                                                        ▼
                                                          [ Pre-Execution TOCTOU Check ]
                                                          (Verify live graph == baseline)
                                                                        │
                                                ┌───────────────────────┴───────────────────────┐
                                                ▼                                               ▼
                                      [ State Drift Detected ]                        [ Graph State Matched ]
                                      (ABORTED_STATE_DRIFT)                                     │
                                                                                                ▼
                                                                                   [ Dispatch Simulated Cloud API ]
                                                                                                │
                                                                                                ▼
                                                                                   [ Post-Execution Invariant Check ]
                                                                                   (Verify state' satisfies invariants)
                                                                                                │
                                                                                                ▼
                                                                                   [ Cryptographic Audit Block ]
                                                                                   (SHA-256 Merkle-Linked Ledger)
```

1. **Pre-Execution TOCTOU Guard**: Verifies graph snapshot hash immediately prior to dispatch. If out-of-band drift altered any topology nodes or edges, execution aborts fail-closed.
2. **Post-Execution Invariant Verification**: Simulates or queries target state after cloud API dispatch to ensure invariants hold in reality.
3. **Cryptographic Audit Ledger**: Records action provenance, simulator state delta, and decision reasoning in a tamper-evident SHA-256 blockchain ledger.
4. **AWS Guardrail**: Hard-coded safety check preventing any un-mocked AWS SDK calls during evaluation.
