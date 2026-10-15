# SentinelGuard: Reproducibility & Replication Guide

**Document Version**: 1.0.0  
**Project**: SentinelGuard — State-Aware Policy Verification for Safe AI-Driven Cloud Incident Response  

---

## 1. System Requirements & Environment Specification

To replicate the empirical findings and benchmark results reported for SentinelGuard, ensure your execution environment meets the following specifications:

```
+---------------------------------------------------------------------------------------+
| Hardware & Software Prerequisites                                                     |
+----------------------+----------------------------------------------------------------+
| Operating System     | macOS 14+ (Darwin arm64) or Linux (Ubuntu 22.04+ x86_64/arm64) |
| Python Runtime       | Python 3.12 or 3.13 (Tested on 3.13.13)                        |
| Package Manager      | uv (v0.5.0+) or standard pip / virtualenv                      |
| Java Runtime (PySpark)| Java 17, 21, or 23 (OpenJDK / Eclipse Temurin)                 |
| Memory & CPU         | Minimum 8 GB RAM, 4 CPU cores (Recommended: Apple Silicon / M-series or 8-core x86) |
+----------------------+----------------------------------------------------------------+
```

### Exact Software Dependency Versions

The exact pinned dependencies recorded during authoritative evaluation:
* `pyspark`: 3.5.3+ (Local mode)
* `scikit-learn`: 1.6.1+
* `networkx`: 3.4.2+
* `pydantic`: 2.10.6+
* `pandas`: 3.0.0+
* `numpy`: 2.2.3+
* `pytest`: 9.1.1+

---

## 2. Setup & Installation

Clone the repository and initialize the isolated virtual environment using `uv`:

```bash
# 1. Clone repository
git clone https://github.com/wipro-coe/sentinelguard.git
cd sentinelguard

# 2. Sync dependencies using uv (creates isolated .venv)
uv sync

# 3. Verify Java runtime is accessible for PySpark
java -version
```

---

## 3. Replication Commands

### 3.1 Run Full Academic Evaluation Suite (One-Command Replication)

To execute the complete 4-part evaluation suite (CloudGuard-Bench, Adversarial Suite, Telemetry Anomaly Detection, and Controlled Execution Workflow) and generate machine-readable artifacts:

```bash
# Execute with deterministic seed 42 (default)
uv run python run_experiments.py --seed 42 --results-dir benchmark_results
```

This single command:
1. Executes **CloudGuard-Bench** across 120 scenarios and 4 system configurations.
2. Executes the **Extended Adversarial Suite** across 24 scenarios and 12 vulnerability classes.
3. Ingests and processes 4,000+ synthetic telemetry events via **PySpark**, evaluating **Isolation Forest** vs. **Heuristic SIEM Baseline**.
4. Verifies the **Controlled Incident Response Workflow**, testing TOCTOU pre-execution guards and cryptographic audit chaining.
5. Emits:
   * `benchmark_results/evaluation_exp-<id>.json` (Full machine-readable results)
   * `benchmark_results/latest_evaluation.json` (Latest JSON link)
   * `benchmark_results/latest_report.md` (Authoritative formatted Markdown report)

---

### 3.2 Run Unit & Integration Test Suite

To run all 61+ regression tests covering Phases 1 through 8:

```bash
uv run pytest -v
```

Expected output:
```text
======================== 61 passed, 75 warnings in ~14s ========================
```

---

### 3.3 Run Individual Subsystem Benchmarks

You can also run individual benchmark modules independently:

```bash
# Run CloudGuard-Bench (120 Scenarios)
uv run python -c "from sentinelguard.benchmark.runner import BenchmarkRunner; print(BenchmarkRunner().run_all())"

# Run AI Investigation Agent Evaluation (30 Incidents)
uv run python -c "from sentinelguard.benchmark.agent_eval import AgentBenchmarkRunner; print(AgentBenchmarkRunner().run_evaluation())"

# Run Telemetry Detection Benchmark
uv run python -c "from sentinelguard.benchmark.detection_eval import DetectionBenchmarkRunner; print(DetectionBenchmarkRunner().run_detection_evaluation())"
```

---

## 4. Deterministic Seed Guarantees

To ensure bit-level reproducibility:
* **Seed Value**: The default random seed is set to `42`.
* **RNG Seeding**: The seed initializes:
  * `random.seed(42)` (Python standard library)
  * `np.random.seed(42)` (NumPy)
  * `IsolationForest(random_state=42)` (Scikit-Learn anomaly detector)
  * `SyntheticLogGenerator(seed=42)` (CloudTrail and VPC Flow Log generator)
  * PySpark hash partition seeds.

Passing `--seed <custom_seed>` enables sensitivity analysis and cross-run variance testing.

---

## 5. Benchmark Output Schema Reference

The emitted JSON artifact (`benchmark_results/latest_evaluation.json`) follows a strictly structured schema:

```json
{
  "metadata": {
    "experiment_id": "exp-1791832137-dd75ac58",
    "timestamp_utc": "2026-10-12T19:08:57Z",
    "random_seed": 42,
    "platform": "macOS-27.0.1-arm64-arm-64bit-Mach-O",
    "processor": "arm",
    "python_version": "3.13.13",
    "dependencies": {
      "pyspark": "3.5.3",
      "scikit-learn": "1.6.1",
      "networkx": "3.4.2",
      "pydantic": "2.10.6",
      "pandas": "3.0.0",
      "numpy": "2.2.3"
    }
  },
  "cloudguard_bench": {
    "summary": {
      "Config 1: Unchecked LLM": {
        "uaer_percent": 100.0,
        "pvpr_percent": 0.0,
        "laar_percent": 100.0,
        "fbr_percent": 0.0,
        "msr_percent": 0.0,
        "latency": {
          "mean_ms": 0.002,
          "std_ms": 0.002,
          "median_ms": 0.002,
          "p95_ms": 0.003
        }
      },
      "Config 4: SentinelGuard (Proposed)": {
        "uaer_percent": 0.0,
        "pvpr_percent": 100.0,
        "laar_percent": 100.0,
        "fbr_percent": 0.0,
        "msr_percent": 62.5,
        "latency": {
          "mean_ms": 0.105,
          "std_ms": 0.103,
          "median_ms": 0.071,
          "p95_ms": 0.228
        }
      }
    },
    "scenario_details": {}
  },
  "adversarial_suite": {
    "total_adversarial_scenarios": 24,
    "fail_closed_passed": 24,
    "fail_closed_safety_rate_pct": 100.0,
    "results_by_vulnerability_class": {}
  },
  "telemetry_detection": {
    "events_processed": {},
    "cloudtrail_comparison": {},
    "vpc_flow_comparison": {}
  },
  "execution_workflow": {
    "paths_evaluated": [],
    "audit_ledger_integrity": true,
    "audit_ledger_records": 10
  }
}
```
