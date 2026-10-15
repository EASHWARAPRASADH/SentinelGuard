# SentinelGuard

**State-Aware Policy Verification for Safe AI-Driven Cloud Incident Response**

SentinelGuard is a research-grade security governor designed for autonomous AI security agents. Rather than blindly trusting LLM-generated cloud remediation recommendations or evaluating actions using static permission rules, SentinelGuard models live cloud infrastructure topologies, runs speculative counterfactual simulations, and enforces system-wide operational invariants before executing actions.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       Security Incident Envelope      |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |    RAG Subsystem (Knowledge Base)     |
                      |  - Curated Playbooks (.md)            |
                      |  - Vector Retriever (Cosine Search)   |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |     Incident Investigation Agent      |
                      |  - LLM Provider (Mock / OpenAI API)   |
                      |  - Action Parser (Schema & Injection) |
                      +---------------------------------------+
                                          |
                        Candidate Action  v (Bounded Catalogue)
                      +---------------------------------------+
                      |      SentinelGuard Governor Engine    |
                      |  - Operational Dependency Graph (ODG) |
                      |  - Counterfactual Simulation S' = f() |
                      |  - 3 Core Operational Invariants      |
                      |  - Bounded Mitigation Lattice         |
                      +---------------------------------------+
                                          |
                        Final Decision    v (ALLOW / BLOCK / MODIFY / APPROVAL)
                      +---------------------------------------+
                      |     Tamper-Evident Audit Ledger       |
                      |     (SHA-256 Cryptographic Chain)     |
                      +---------------------------------------+
```

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

## Phase 5: LLM Investigation Agent & RAG Pipeline

### 1. RAG Knowledge Base (`src/sentinelguard/rag/`)
- Curated markdown security playbooks stored in `src/sentinelguard/rag/playbooks/`:
  - `credential_compromise_playbook.md`: IAM key rotation, compromised API keys, break-glass protection.
  - `instance_isolation_playbook.md`: EC2 C2 containment, target group draining, scoped security groups.
  - `iam_privilege_escalation_playbook.md`: Unauthorized IAM permissions and policy rollback.
  - `telemetry_continuity_playbook.md`: Safeguards for CloudTrail, VPC Flow logs, and CloudWatch agents.
  - `incident_escalation_playbook.md`: Escalation criteria for Tier-0 assets and human approval gates.
- **Embeddings**: Deterministic feature-hash vectorizer (zero-cost offline testing) and `APIEmbeddingProvider` (OpenAI-compatible).
- **Retriever**: In-memory cosine-similarity vector store with relevance scoring and source attribution.

### 2. Investigation Agent (`src/sentinelguard/agent/`)
- Ingests structured `SecurityIncident` envelopes.
- Formulates queries and retrieves top-$k$ relevant playbook passages.
- Evaluates evidence and generates structured JSON assessments containing:
  - Incident summary and evidence grounding.
  - Playbook citations and source attribution.
  - Identified uncertainties or missing evidence.
  - Recommended action from the **bounded catalogue**: `isolate_instance`, `revoke_access_key`, `remove_permission`.
- **Action Parser**: Enforces strict JSON validation, rejects unapproved actions, rejects unexpected parameters, and neutralizes prompt-injection payloads fail-closed.

### 3. Orchestration Pipeline (`src/sentinelguard/orchestration/`)
- Connects `SecurityIncident` $\to$ RAG $\to$ Agent $\to$ Governor $\to$ Audit Ledger.
- **Zero Live Execution**: The agent never executes cloud commands directly. All proposals must pass governor verification before dispatch.

---

## Phase 6: Big Data Telemetry & ML Anomaly Detection

```
Raw CloudTrail / VPC Flow Logs (4,000+ Events)
                   |
                   v
       PySpark Feature Pipeline
  - 5-minute tumbling time windows
  - Error rates, sensitive APIs, external IPs, bytes, C2 ports
                   |
                   v
     Isolation Forest ML Detector
  - Multi-dimensional outlier scoring
  - 100% detection recall across credential abuse & C2 beacons
                   |
                   v
           Alert Integrator
  - Structured SecurityIncident envelopes with forensic evidence
                   |
                   v
    RAG Investigation Agent + Governor
  - Grounded assessment, proposal validation, invariant verification
```

### 1. Synthetic Telemetry Generator (`src/sentinelguard/telemetry/log_generator.py`)
- Generates high-volume multi-account cloud telemetry with ground-truth anomaly labels:
  - **CloudTrail Events**: Realistic administrative actions interspersed with `credential_abuse`, `privilege_escalation`, and `audit_tampering`.
  - **VPC Flow Logs**: Normal internal traffic mixed with `c2_beacon` network egress, unusual ports (4444, 1337, 8080), and exfiltration spikes.
  - Deterministic random seeds ensure 100% reproducible evaluation runs.

### 2. PySpark ETL & Feature Aggregation (`src/sentinelguard/telemetry/pyspark_pipeline.py`)
- Powered by Apache Spark 4.2 for distributed stream and batch aggregation:
  - Schema normalization, UTC timestamp conversion, and 5-minute tumbling time windows.
  - Groups CloudTrail by `[accessKeyId, principalArn, time_window]` and VPC Flow by `[instance_id, time_window]`.
  - Aggregated indicators: error rates, sensitive API frequencies, IP diversity, byte volume, and C2 port connections.

### 3. ML Anomaly Detection (`src/sentinelguard/telemetry/anomaly_detector.py`)
- Unsupervised **Isolation Forest** from `scikit-learn`:
  - Contamination-calibrated anomaly boundary scoring on multi-dimensional feature rows.
  - Generates binary anomaly masks and continuous anomaly scores.
  - Sub-10ms inference latency suitable for real-time alerting.

### 4. Alert Integration (`src/sentinelguard/telemetry/alert_integrator.py`)
- Converts anomalous feature records into structured `SecurityIncident` envelopes.
- Attaches observed forensic events and ML detection evidence.
- Bridges seamlessly into `IncidentResponsePipeline` for investigation and governor verification.

---

## Phase 7: Controlled Cloud Execution & Serverless Workflows

```
Incident Envelope (Telemetry / Integration)
                   |
                   v
     RAG Playbook Retrieval + Agent
                   |
                   v
     SentinelGuard Governor Engine
                   |
        +----------+----------+
        |                     |
     [ALLOW / MODIFY]    [REQUEST_APPROVAL / BLOCK]
        |                     |
     Approval Check       Human Operator Sign-Off
        |                     |
        +----------+----------+
                   |
                   v
   Pre-Execution TOCTOU Guard (Hash Recheck)
                   |
        +----------+----------+
        |                     |
     [Match]               [State Drift Detected]
        |                     |
        v                     v
   Controlled Dispatch     [Abort Fail-Closed]
   (Simulated Environment)
        |
        v
   Post-Execution Verifier
   - Target State Validation
   - Live Invariant Re-verification
        |
        v
   Cryptographic Execution Audit Ledger
```

### 1. Simulated Cloud Environment (`src/sentinelguard/execution/environment.py`)
- Authoritative in-memory model of cloud infrastructure, supporting state queries, controlled remediation dispatch, out-of-band state mutation, and transient API failure injection.
- Generates deterministic SHA-256 state fingerprints over all resources and topology edges.

### 2. Time-of-Check to Time-of-Use (TOCTOU) Guard (`src/sentinelguard/execution/toctou_guard.py`)
- Compares live cloud state fingerprints immediately prior to dispatch against the verification baseline.
- If an out-of-band change occurred (e.g. concurrent node failure, autoscaling event, or manual operator change), execution is aborted fail-closed (`ABORTED_STATE_DRIFT`).

### 3. Human Approval Gate (`src/sentinelguard/execution/approval_gate.py`)
- Enforces mandatory human approval tickets for `REQUEST_APPROVAL` decisions and Tier-0 mission-critical assets.
- Allows operators to review blast-radius reports and approve or reject proposed actions.

### 4. Post-Execution Verifier (`src/sentinelguard/execution/post_verifier.py`)
- Inspects the live post-execution environment to confirm that the target resource transitioned into the intended security posture and all operational invariants ($I_{\text{Admin}}, I_{\text{Avail}}, I_{\text{Telem}}$) remain satisfied.

### 5. Cryptographic Execution Ledger (`src/sentinelguard/execution/audit_trail.py`)
- Hash-chained immutable audit log capturing every workflow state transition (`INVESTIGATION`, `GOVERNOR_VERIFICATION`, `APPROVAL_GATE`, `TOCTOU_CHECK`, `DISPATCH`, `POST_VERIFICATION`).

### 6. AWS Execution Guardrails (`src/sentinelguard/execution/aws_guardrail.py`)
- Guarantees simulation-only mode by default. Live cloud dispatch requires explicit environment opt-in (`SENTINELGUARD_ALLOW_LIVE_AWS_EXECUTION=true`).

---

## Empirical Benchmark Results

SentinelGuard maintains strict separation between **Detection Evaluation** (measuring how well anomalies are identified from telemetry) and **Response-Safety Evaluation** (measuring whether remediation actions respect operational invariants).

### 1. Telemetry Detection Evaluation (PySpark + Isolation Forest across 4,150 Events)

| Metric / Indicator | CloudTrail API Telemetry | VPC Flow Network Telemetry | Target / Standard |
| :--- | :---: | :---: | :---: |
| **Raw Events Processed** | 2,100 | 2,050 | High-volume stream |
| **Spark Feature Latency** | ~1,030 ms | ~290 ms | Sub-second batch |
| **ML Model Architecture** | Isolation Forest | Isolation Forest | Unsupervised Outlier |
| **Detection Recall** | **100.0%** | **100.0%** | $\ge 80.0\%$ |
| **Detection Precision** | 50.0% | 50.0% | $\ge 50.0\%$ (unsupervised) |
| **Detection F1-Score** | 66.7% | 66.7% | $\ge 60.0\%$ |
| **False Positive Rate (FPR)** | **4.4%** | **1.8%** | $\le 10.0\%$ |
| **ML Inference Latency** | **6.8 ms** | **7.7 ms** | $< 10.0\text{ ms}$ |
| **Alerts Generated & Governed** | 12 | - | 100% Intercepted |

### 2. Response-Safety Evaluation: CloudGuard-Bench (120 Scenarios across 4 Governor Baselines)

| Configuration | UAER (%) ↓ | PVPR (%) ↑ | LAAR (%) ↑ | FBR (%) ↓ | MSR (%) ↑ | Decision Latency (ms) ↓ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config 1: Unchecked LLM** | 100.0% | 0.0% | 100.0% | 0.0% | 0.0% | 0.00 ± 0.00 |
| **Config 2: Static Policy Gate** | 50.0% | 100.0% | 100.0% | 0.0% | 0.0% | 0.00 ± 0.00 |
| **Config 3: Static Policy + Dependency** | 12.5% | 100.0% | 50.0% | 50.0% | 0.0% | 0.00 ± 0.00 |
| **Config 4: SentinelGuard (Proposed)** | **0.0%** | **100.0%** | **100.0%** | **0.0%** | **62.5%** | **0.10 ± 0.08** |

### 3. Agent & RAG Evaluation (30 Incident Envelopes)

| Metric | Result | Target / Standard |
| :--- | :---: | :---: |
| **Evaluation Provider** | MockLLMProvider (Deterministic Offline) | Reproducible baseline |
| **Retrieval Relevance Rate** | **100.0%** | $\ge 90.0\%$ |
| **Source Attribution Rate** | **100.0%** | 100.0% |
| **Structured-Action Validity Rate** | **100.0%** | 100.0% |
| **Prompt-Injection Resistance** | **100.0%** | 100.0% fail-closed |
| **Governor Alignment Rate** | **100.0%** | $\ge 95.0\%$ |
| **Mean Pipeline Latency** | **0.38 ± 0.10 ms** | $< 150\text{ ms}$ (local) |
| **Estimated Cost per Run** | **$0.0000** | Zero-cost offline baseline |

---

## Phase 8: Authoritative Academic Evaluation Results

SentinelGuard includes a unified, reproducible evaluation runner producing machine-readable JSON and Markdown reports (`benchmark_results/latest_evaluation.json` and `benchmark_results/latest_report.md`).

### 1. CloudGuard-Bench: Comparative Baseline Evaluation (120 Scenarios)

| Configuration | UAER (%) ↓ | PVPR (%) ↑ | LAAR (%) ↑ | FBR (%) ↓ | MSR (%) ↑ | Mean Latency (ms) | p95 Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config 1: Unchecked LLM** | **100.0%** (80/80) | **0.0%** (0/40) | **100.0%** (40/40) | **0.0%** (0/40) | **0.0%** (0/40) | 0.002 ± 0.002 | 0.003 |
| **Config 2: Static Policy Gate** | **50.0%** (40/80) | **100.0%** (40/40) | **100.0%** (40/40) | **0.0%** (0/40) | **0.0%** (0/40) | 0.002 ± 0.002 | 0.003 |
| **Config 3: Static Policy + Dependency** | **12.5%** (10/80) | **100.0%** (40/40) | **50.0%** (20/40) | **50.0%** (20/40) | **0.0%** (0/40) | 0.001 ± 0.003 | 0.003 |
| **Config 4: SentinelGuard (Proposed)** | **0.0%** (0/80) | **100.0%** (40/40) | **100.0%** (40/40) | **0.0%** (0/40) | **62.5%** (25/40) | 0.105 ± 0.103 | 0.228 |

### 2. Extended Adversarial Suite (24 Scenarios across 12 Vulnerability Classes)

- **Overall Fail-Closed Safety Rate**: **100.0%** (24/24 Scenarios safely neutralized)
- **Vulnerability Coverage**: Prompt injection in logs, malformed syntax payloads, unknown action injections, missing required parameters, invalid resource IDs, stale state snapshots, missing dependency edges, concurrent TOCTOU state mutations, simulated cloud API failures, audit telemetry severance traps, sole admin lockouts, and load-balancer quorum breaches.

### 3. Telemetry Anomaly Detection Benchmark: ML vs SIEM

| Detection Model | Telemetry Source | Precision | Recall | F1 Score | FPR | Inference Latency | Spark Batch Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest (Proposed ML)** | CloudTrail API | 66.7% | 100.0% | 80.0% | 2.8% | 7.62 ms | 3,345.75 ms |
| **Heuristic Thresholds (SIEM Baseline)** | CloudTrail API | 100.0% | 75.0% | 85.7% | 0.0% | 1.37 ms | 3,345.75 ms |
| **Isolation Forest (Proposed ML)** | VPC Flow Logs | 66.7% | 100.0% | 80.0% | 1.2% | 8.08 ms | 332.73 ms |
| **Heuristic Thresholds (SIEM Baseline)** | VPC Flow Logs | 100.0% | 100.0% | 100.0% | 0.0% | 2.72 ms | 332.73 ms |

### 4. Controlled Incident Response Workflow Verification

- **Pre-Execution TOCTOU Guard**: Verifies graph snapshot hash immediately prior to cloud dispatch. Confirmed aborts upon concurrent state drift (`ABORTED_STATE_DRIFT`).
- **Post-Execution Invariant Verification**: Simulates post-mutation state to verify invariants remain intact.
- **Cryptographic Audit Ledger**: Records all execution provenance across SHA-256 Merkle-linked blocks (`verify_integrity() = True`).
- **Execution Guardrail**: Hard-coded safety check ensuring zero unauthorized live AWS mutations.

---

## Formal Documentation Suite

Detailed technical, mathematical, and architectural documentation is available in the `docs/` directory:
- [Experimental Methodology](docs/experimental_methodology.md): Research questions, hypotheses, formal baseline specifications, metric formulas, and statistical methodology.
- [Evaluation Results](docs/evaluation_results.md): Complete empirical findings, numerators/denominators, latency distributions, trade-offs, and limitations.
- [System Architecture](docs/architecture.md): Multi-phase architectural design, state-machine transitions, component trust boundaries, and Mermaid diagrams.
- [Threat Model](docs/threat_model.md): Assets, attacker models, attack surfaces, STRIDE analysis, and fail-closed safety definitions.
- [Reproducibility Guide](docs/reproducibility.md): System dependencies, exact replication CLI commands, seeds, and JSON output schemas.
- [Research Paper Outline](docs/research_paper_outline.md): Complete academic publication structure for top systems security conferences.

---

## Configuration & Environment Variables

SentinelGuard runs completely offline by default using deterministic mock providers. To connect real LLM providers:

```bash
# Optional: OpenAI / OpenAI-compatible API credentials
export SENTINELGUARD_LLM_API_KEY="your-api-key"
# or
export OPENAI_API_KEY="your-api-key"
# or
export GEMINI_API_KEY="your-api-key"
```

---

## Quickstart & Replication Commands

### Prerequisites
- Python 3.12+ (tested on Python 3.13.13)
- Java 17+ (for Apache Spark local mode)
- `uv` (recommended)

### 1. Run Complete Reproducible Evaluation Suite (Phase 8)
```bash
uv run python run_experiments.py --seed 42 --results-dir benchmark_results
```

### 2. Run Automated Regression Test Suite (61+ Tests)
```bash
uv run pytest -v
```

### 3. Run the Interactive Demo
```bash
uv run python main.py
```

### 4. Run Subsystem Benchmarks Individually
```bash
# CloudGuard-Bench (120 Scenarios)
uv run python -m sentinelguard.benchmark.runner

# AI Investigation Agent Benchmark (30 Incidents)
uv run python -m sentinelguard.benchmark.agent_eval

# Telemetry Detection Benchmark
uv run python -m sentinelguard.benchmark.detection_eval
```

---

## Security Boundaries & Limitations
- **No Direct Live Cloud Execution**: The investigation agent has zero direct AWS credentials or live boto3 mutation permissions.
- **Model-Based Verification**: The governor verifies system safety against the modeled Operational Dependency Graph under explicit invariant definitions.
- **Strict Separation of Concerns**: Detection accuracy (identifying threats in logs) is evaluated independently of remediation safety (preventing operational outages).
- **Fail-Closed Guarantee**: Any model failure, timeout, unparseable JSON, invariant breach, or prompt injection automatically halts automated dispatch and records the incident in the tamper-evident audit ledger.

