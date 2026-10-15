#!/usr/bin/env python3
"""
SentinelGuard: State-Aware Policy Verification for Safe AI-Driven Cloud Incident Response

Phase 8 Experiment Runner Entry Point.
Executes the unified, reproducible academic evaluation suite:
  1. CloudGuard-Bench (120 Scenarios x 4 Configurations)
  2. Extended Adversarial Suite (24 Scenarios across 12 Vulnerability Classes)
  3. Telemetry Anomaly Detection Benchmark (Isolation Forest vs Heuristic SIEM Baseline)
  4. Controlled Incident Response Workflow Evaluation (TOCTOU, Human Approval, Post-Verification, Cryptographic Audit)

Generates:
  - benchmark_results/evaluation_<experiment_id>.json (Machine-readable)
  - benchmark_results/latest_evaluation.json (Latest machine-readable link)
  - benchmark_results/latest_report.md (Authoritative Markdown report)
"""

import sys
from sentinelguard.benchmark.reproducible_runner import main

if __name__ == "__main__":
    sys.exit(main())
