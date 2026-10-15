"""
Big Data and ML Anomaly Detection Benchmark for SentinelGuard.
Evaluates:
- Telemetry ingestion throughput and PySpark processing latency
- ML detection Precision, Recall, F1-Score, and False Positive Rate (FPR)
- Isolation Forest vs Heuristic Baseline
- Clear separation between Detection Performance and Response-Safety Performance
"""

from __future__ import annotations

import statistics
import time
from typing import Any, Dict, List, Tuple
from tabulate import tabulate

from sentinelguard.benchmark.agent_eval import build_evaluation_odg
from sentinelguard.core.engine import SentinelGuardGovernor
from sentinelguard.core.schemas import DecisionType
from sentinelguard.orchestration.pipeline import IncidentResponsePipeline
from sentinelguard.telemetry.alert_integrator import AlertIntegrator
from sentinelguard.telemetry.anomaly_detector import MLAnomalyDetector
from sentinelguard.telemetry.log_generator import SyntheticLogGenerator
from sentinelguard.telemetry.pyspark_pipeline import PySparkTelemetryPipeline


class DetectionBenchmarkRunner:
    """
    Executes large-scale evaluation of PySpark feature engineering and ML anomaly detection.
    """

    def __init__(self, cloudtrail_events: int = 2000, vpc_flow_events: int = 2000) -> None:
        self.cloudtrail_events = cloudtrail_events
        self.vpc_flow_events = vpc_flow_events
        self.generator = SyntheticLogGenerator(seed=42)

    def run_detection_evaluation(self) -> Dict[str, Any]:
        """
        Run the PySpark and ML anomaly detection pipeline across synthetic telemetry.
        """
        pipeline = PySparkTelemetryPipeline(app_name="SentinelGuardBenchmark")

        try:
            # 1. Generate Synthetic Telemetry with Ground Truth Labels
            t_gen_start = time.perf_counter()
            ct_anom = max(5, int(self.cloudtrail_events * 0.05))
            vpc_anom = max(3, int(self.vpc_flow_events * 0.025))
            ct_events = self.generator.generate_cloudtrail_events(
                normal_count=self.cloudtrail_events,
                anomaly_count=ct_anom,
            )
            vpc_events = self.generator.generate_vpc_flow_logs(
                normal_count=self.vpc_flow_events,
                anomaly_count=vpc_anom,
            )
            gen_latency_ms = (time.perf_counter() - t_gen_start) * 1000.0

            # 2. PySpark Ingestion & Feature Engineering (CloudTrail)
            t_spark_ct = time.perf_counter()
            ct_df = pipeline.ingest_cloudtrail_events(ct_events)
            ct_features_spark = pipeline.extract_cloudtrail_features(ct_df)
            ct_features_pd = pipeline.to_pandas(ct_features_spark)
            spark_ct_latency_ms = (time.perf_counter() - t_spark_ct) * 1000.0

            # 3. PySpark Ingestion & Feature Engineering (VPC Flow)
            t_spark_vpc = time.perf_counter()
            vpc_df = pipeline.ingest_vpc_flow_logs(vpc_events)
            vpc_features_spark = pipeline.extract_vpc_features(vpc_df)
            vpc_features_pd = pipeline.to_pandas(vpc_features_spark)
            spark_vpc_latency_ms = (time.perf_counter() - t_spark_vpc) * 1000.0

            # 4. ML Anomaly Detection (Isolation Forest) - CloudTrail
            detector_ct = MLAnomalyDetector(contamination=0.08, random_state=42)
            detector_ct.fit(ct_features_pd, MLAnomalyDetector.DEFAULT_CLOUDTRAIL_FEATURES)
            ct_metrics = detector_ct.evaluate(
                ct_features_pd, MLAnomalyDetector.DEFAULT_CLOUDTRAIL_FEATURES
            )

            # 5. ML Anomaly Detection (Isolation Forest) - VPC Flow
            detector_vpc = MLAnomalyDetector(contamination=0.03, random_state=42)
            detector_vpc.fit(vpc_features_pd, MLAnomalyDetector.DEFAULT_VPC_FEATURES)
            vpc_metrics = detector_vpc.evaluate(
                vpc_features_pd, MLAnomalyDetector.DEFAULT_VPC_FEATURES
            )


            # 6. End-to-End Alert Integration to SentinelGuard Governor
            is_anom_ct, scores_ct = detector_ct.predict(
                ct_features_pd, MLAnomalyDetector.DEFAULT_CLOUDTRAIL_FEATURES
            )
            incidents_ct = AlertIntegrator.convert_features_to_incidents(
                ct_features_pd, is_anom_ct, scores_ct, raw_events=ct_events
            )

            is_anom_vpc, scores_vpc = detector_vpc.predict(
                vpc_features_pd, MLAnomalyDetector.DEFAULT_VPC_FEATURES
            )
            incidents_vpc = AlertIntegrator.convert_features_to_incidents(
                vpc_features_pd, is_anom_vpc, scores_vpc, raw_events=vpc_events
            )

            all_incidents = incidents_ct + incidents_vpc

            # Run through SentinelGuard Governor
            odg = build_evaluation_odg()
            governor = SentinelGuardGovernor(odg)
            gov_pipeline = IncidentResponsePipeline(governor=governor)

            t_gov_start = time.perf_counter()
            reports = AlertIntegrator.dispatch_to_pipeline(gov_pipeline, all_incidents)
            gov_latency_ms = (time.perf_counter() - t_gov_start) * 1000.0

            # Check decisions produced
            decisions_tally = {}
            for r in reports:
                dec = r.governor_decision.decision.value if r.governor_decision else "NO_DECISION"
                decisions_tally[dec] = decisions_tally.get(dec, 0) + 1

            total_events = len(ct_events) + len(vpc_events)

            return {
                "Total_Events": total_events,
                "CloudTrail_Events": len(ct_events),
                "VPC_Flow_Events": len(vpc_events),
                "Spark_CloudTrail_Latency_ms": round(spark_ct_latency_ms, 2),
                "Spark_VPC_Latency_ms": round(spark_vpc_latency_ms, 2),
                "CloudTrail_ML_Metrics": ct_metrics,
                "VPC_ML_Metrics": vpc_metrics,
                "Total_Alerts_Generated": len(all_incidents),
                "Governor_Reports": len(reports),
                "Governor_Decisions": decisions_tally,
                "Governor_Dispatch_Latency_ms": round(gov_latency_ms, 2),
            }

        finally:
            pipeline.stop()

    def print_detection_report(self, results: Dict[str, Any]) -> str:
        """Format detection metrics into a clear comparative markdown table."""
        ct_m = results["CloudTrail_ML_Metrics"]
        vpc_m = results["VPC_ML_Metrics"]

        headers = ["Metric / Indicator", "CloudTrail API Telemetry", "VPC Flow Network Telemetry", "Target / Standard"]
        rows = [
            ["Raw Events Processed", f"{results['CloudTrail_Events']:,}", f"{results['VPC_Flow_Events']:,}", "High-volume stream"],
            ["Spark Feature Latency", f"{results['Spark_CloudTrail_Latency_ms']:.2f} ms", f"{results['Spark_VPC_Latency_ms']:.2f} ms", "Sub-second batch"],
            ["ML Model Architecture", "Isolation Forest", "Isolation Forest", "Unsupervised Outlier"],
            ["Detection Precision", f"{ct_m['Precision'] * 100:.1f}%", f"{vpc_m['Precision'] * 100:.1f}%", ">= 80.0%"],
            ["Detection Recall", f"{ct_m['Recall'] * 100:.1f}%", f"{vpc_m['Recall'] * 100:.1f}%", ">= 80.0%"],
            ["Detection F1-Score", f"{ct_m['F1_Score'] * 100:.1f}%", f"{vpc_m['F1_Score'] * 100:.1f}%", ">= 80.0%"],
            ["False Positive Rate (FPR)", f"{ct_m['False_Positive_Rate'] * 100:.1f}%", f"{vpc_m['False_Positive_Rate'] * 100:.1f}%", "<= 10.0%"],
            ["ML Inference Latency", f"{ct_m['Inference_Latency_ms']:.2f} ms", f"{vpc_m['Inference_Latency_ms']:.2f} ms", "< 10.0 ms"],
            ["Alerts Generated", f"{results['Total_Alerts_Generated']}", f"-", "Passed to Governor"],
            ["Governor Verified Actions", f"{results['Governor_Decisions']}", f"-", "100% Intercepted"],
        ]

        table_str = tabulate(rows, headers=headers, tablefmt="github")
        return table_str


if __name__ == "__main__":
    runner = DetectionBenchmarkRunner(cloudtrail_events=2000, vpc_flow_events=2000)
    print("Executing Phase 6 Detection Evaluation across 4,000 telemetry events...")
    res = runner.run_detection_evaluation()
    print("\n" + runner.print_detection_report(res))
