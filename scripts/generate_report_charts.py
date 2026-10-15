#!/usr/bin/env python3
"""
Generate publication-quality charts for the SentinelGuard College Report.
"""

import os
import matplotlib.pyplot as plt
import numpy as np

os.makedirs("report/images", exist_ok=True)
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "figure.titlesize": 14,
    "figure.dpi": 300,
})

# 1. Comparative Baselines Chart (UAER, LAAR, FBR, MSR)
def make_comparative_baselines():
    configs = [
        "Config 1\nUnchecked LLM",
        "Config 2\nStatic Policy",
        "Config 3\nStatic + Dep",
        "Config 4\nSentinelGuard",
    ]
    uaer = [100.0, 50.0, 12.5, 0.0]
    laar = [100.0, 100.0, 50.0, 100.0]
    fbr  = [0.0, 0.0, 50.0, 0.0]
    msr  = [0.0, 0.0, 0.0, 62.5]

    x = np.arange(len(configs))
    width = 0.20

    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    rects1 = ax.bar(x - 1.5*width, uaer, width, label="UAER (%) ↓", color="#dc2626")
    rects2 = ax.bar(x - 0.5*width, laar, width, label="LAAR (%) ↑", color="#16a34a")
    rects3 = ax.bar(x + 0.5*width, fbr,  width, label="FBR (%) ↓",  color="#f59e0b")
    rects4 = ax.bar(x + 1.5*width, msr,  width, label="MSR (%) ↑",  color="#2563eb")

    ax.set_ylabel("Metric Rate (%)")
    ax.set_title("CloudGuard-Bench: Comparative Performance Across 120 Scenarios")
    ax.set_xticks(x)
    ax.set_xticklabels(configs)
    ax.set_ylim(0, 115)
    ax.legend(loc="upper right", frameon=True)

    for rects in [rects1, rects2, rects3, rects4]:
        for rect in rects:
            h = rect.get_height()
            if h > 0:
                ax.annotate(f"{h:.1f}%",
                            xy=(rect.get_x() + rect.get_width() / 2, h),
                            xytext=(0, 3), textcoords="offset points",
                            ha="center", va="bottom", fontsize=8.5, rotation=0)

    plt.tight_layout()
    plt.savefig("report/images/comparative_baselines.png", dpi=300)
    plt.close()

# 2. Telemetry Detection ML vs SIEM Chart
def make_ml_vs_siem():
    categories = ["CloudTrail Recall", "CloudTrail Precision", "CloudTrail F1", "VPC Recall", "VPC Precision", "VPC F1"]
    ml_scores = [100.0, 66.7, 80.0, 100.0, 66.7, 80.0]
    siem_scores = [75.0, 100.0, 85.7, 100.0, 100.0, 100.0]

    x = np.arange(len(categories))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 4.6))
    r1 = ax.bar(x - width/2, ml_scores, width, label="Isolation Forest (Proposed ML)", color="#4f46e5")
    r2 = ax.bar(x + width/2, siem_scores, width, label="Heuristic SIEM Baseline", color="#059669")

    ax.set_ylabel("Detection Score (%)")
    ax.set_title("Telemetry Anomaly Detection: Unsupervised ML vs Rule-Based SIEM")
    ax.set_xticks(x)
    ax.set_xticklabels(categories, rotation=15, ha="right")
    ax.set_ylim(0, 118)
    ax.legend(loc="upper right", frameon=True)

    for rects in [r1, r2]:
        for rect in rects:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}%",
                        xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 3), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8.5)

    plt.tight_layout()
    plt.savefig("report/images/ml_vs_siem_detection.png", dpi=300)
    plt.close()

# 3. Decision Latency Comparison Chart
def make_latency_distribution():
    stages = ["Graph Cloning", "Counterfactual Sim", "Invariant Checks", "Total Governor", "PySpark VPC", "PySpark CloudTrail"]
    latencies = [0.08, 0.015, 0.01, 0.105, 332.7, 3345.8]  # ms

    fig, ax = plt.subplots(figsize=(8.5, 4.4))
    colors = ["#3b82f6", "#3b82f6", "#3b82f6", "#1d4ed8", "#10b981", "#059669"]
    bars = ax.bar(stages, latencies, color=colors, width=0.55)
    ax.set_yscale("log")
    ax.set_ylabel("Latency in Milliseconds (Log Scale)")
    ax.set_title("SentinelGuard Latency Breakdown: Microsecond Simulation vs Batch ETL")
    ax.set_xticklabels(stages, rotation=15, ha="right")

    for bar in bars:
        h = bar.get_height()
        if h < 1.0:
            text = f"{h*1000:.0f} µs"
        elif h < 1000:
            text = f"{h:.1f} ms"
        else:
            text = f"{h/1000:.2f} s"
        ax.annotate(text,
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", va="bottom", fontsize=9, fontweight="bold")

    plt.tight_layout()
    plt.savefig("report/images/latency_breakdown.png", dpi=300)
    plt.close()

# 4. Adversarial Fail-Closed Safety Chart
def make_adversarial_chart():
    classes = [
        "Prompt Injection", "Malformed JSON", "Unknown Action", "Missing Params",
        "Invalid Resource", "Stale Snapshot", "Missing Edge", "Concurrent TOCTOU",
        "API Failure", "Telemetry Trap", "Sole Admin Trap", "Quorum Breach"
    ]
    safety_rates = [100.0] * 12

    fig, ax = plt.subplots(figsize=(10, 4.8))
    bars = ax.barh(classes, safety_rates, color="#0284c7", height=0.6)
    ax.set_xlim(0, 115)
    ax.set_xlabel("Fail-Closed Safety Rate (%)")
    ax.set_title("Extended Adversarial Resilience: 100% Defense Across 12 Vulnerability Classes")

    for bar in bars:
        w = bar.get_width()
        ax.annotate(f"{w:.0f}% Safe",
                    xy=(w, bar.get_y() + bar.get_height() / 2),
                    xytext=(5, 0), textcoords="offset points",
                    ha="left", va="center", fontsize=8.5, fontweight="bold", color="#0369a1")

    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig("report/images/adversarial_fail_closed.png", dpi=300)
    plt.close()

if __name__ == "__main__":
    make_comparative_baselines()
    make_ml_vs_siem()
    make_latency_distribution()
    make_adversarial_chart()
    print("Generated all 4 report charts successfully in report/images/.")
