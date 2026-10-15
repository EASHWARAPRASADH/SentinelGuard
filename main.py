"""
SentinelGuard Demo Entrypoint.
Demonstrates:
1. Operational Trap Triage (Sole Admin Lockout, Service Quorum Breach, Telemetry Drop).
2. CloudGuard-Bench Comparative Benchmark across all 4 configurations.
3. Phase 5: End-to-End LLM Investigation Agent + RAG Pipeline.
4. Phase 5: Agent and RAG Benchmark Evaluation Report.
5. Phase 6: Big Data Telemetry Processing (PySpark) + ML Anomaly Detection (Isolation Forest).
6. Phase 6: Full Telemetry-to-Governor Pipeline & Detection Benchmark.
7. Phase 7: Controlled Cloud Execution Workflows (TOCTOU Guard, Approval Gate, Post-Verification).
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinelguard.agent.investigator import IncidentInvestigatorAgent
from sentinelguard.agent.llm_provider import MockLLMProvider
from sentinelguard.agent.schemas import SecurityIncident
from sentinelguard.benchmark.agent_eval import AgentBenchmarkRunner
from sentinelguard.benchmark.detection_eval import DetectionBenchmarkRunner
from sentinelguard.benchmark.runner import BenchmarkRunner
from sentinelguard.core.engine import SentinelGuardGovernor
from sentinelguard.core.graph import OperationalDependencyGraph
from sentinelguard.core.schemas import (
    ActionType,
    CloudResource,
    CriticalityTier,
    DecisionType,
    EdgeType,
    RemediationAction,
    ResourceType,
)
from sentinelguard.execution.approval_gate import HumanApprovalGate
from sentinelguard.execution.environment import SimulatedCloudEnvironment
from sentinelguard.execution.schemas import ApprovalStatus, WorkflowStatus
from sentinelguard.execution.workflow import ControlledIncidentResponseWorkflow
from sentinelguard.orchestration.pipeline import IncidentResponsePipeline
from sentinelguard.rag.knowledge_base import KnowledgeBase
from sentinelguard.telemetry.alert_integrator import AlertIntegrator
from sentinelguard.telemetry.anomaly_detector import MLAnomalyDetector
from sentinelguard.telemetry.log_generator import SyntheticLogGenerator
from sentinelguard.telemetry.pyspark_pipeline import PySparkTelemetryPipeline

console = Console()



def demo_operational_traps():
    console.print(
        Panel.fit(
            "[bold cyan]SentinelGuard: State-Aware Policy Verification for Safe AI Incident Response[/bold cyan]\n"
            "[dim]Phases 1-4: Demonstrating 3 Operational-Trap Scenarios before Cloud Dispatch[/dim]",
            border_style="cyan",
        )
    )

    # 1. Setup Base Topology
    odg = OperationalDependencyGraph()

    # Admin Alice
    alice = CloudResource(
        id="usr-alice",
        resource_type=ResourceType.IAM_USER,
        name="AliceAdmin",
        criticality=CriticalityTier.TIER_0,
        properties={"is_admin": True, "has_console_access": False},
    )
    alice_key = CloudResource(
        id="ak-alice-01",
        resource_type=ResourceType.ACCESS_KEY,
        name="AliceKey01",
        criticality=CriticalityTier.TIER_0,
        properties={"is_active": True},
    )
    odg.add_resource(alice)
    odg.add_resource(alice_key)
    odg.add_dependency(alice_key.id, alice.id, EdgeType.ATTACHED_TO)

    # Production Web Target Group (2 nodes, min_healthy = 2)
    tg = CloudResource(
        id="tg-prod-web",
        resource_type=ResourceType.TARGET_GROUP,
        name="ProductionWebCluster",
        criticality=CriticalityTier.TIER_0,
        properties={"min_healthy_replicas": 2, "health_check_port_open": True},
    )
    node1 = CloudResource(
        id="i-web-01",
        resource_type=ResourceType.EC2_INSTANCE,
        name="WebNode01",
        criticality=CriticalityTier.TIER_0,
        status="running",
    )
    node2 = CloudResource(
        id="i-web-02",
        resource_type=ResourceType.EC2_INSTANCE,
        name="WebNode02",
        criticality=CriticalityTier.TIER_0,
        status="running",
    )
    odg.add_resource(tg)
    odg.add_resource(node1)
    odg.add_resource(node2)
    odg.add_dependency(node1.id, tg.id, EdgeType.MEMBER_OF)
    odg.add_dependency(node2.id, tg.id, EdgeType.MEMBER_OF)

    # CloudTrail & S3 Audit Bucket
    trail = CloudResource(
        id="trail-audit",
        resource_type=ResourceType.CLOUDTRAIL_TRAIL,
        name="AuditTrail",
    )
    bucket = CloudResource(
        id="s3-audit-logs",
        resource_type=ResourceType.S3_BUCKET,
        name="AuditLogBucket",
        properties={"allows_cloudtrail_delivery": True},
    )
    kms = CloudResource(
        id="kms-audit-key",
        resource_type=ResourceType.KMS_KEY,
        name="AuditKMSKey",
        properties={"allows_cloudtrail_kms": True},
    )
    odg.add_resource(trail)
    odg.add_resource(bucket)
    odg.add_resource(kms)
    odg.add_dependency(trail.id, bucket.id, EdgeType.DELIVERS_TO)
    odg.add_dependency(trail.id, kms.id, EdgeType.ENCRYPTED_BY)

    governor = SentinelGuardGovernor(odg)

    # Trap 1: Sole Admin Lockout
    action_1 = RemediationAction(
        action_type=ActionType.REVOKE_ACCESS_KEY,
        target_resource_id="ak-alice-01",
        rationale="AI detected suspicious API calls on admin credentials",
    )
    dec_1 = governor.evaluate_action(action_1)

    # Trap 2: Service Quorum Breach
    action_2 = RemediationAction(
        action_type=ActionType.ISOLATE_INSTANCE,
        target_resource_id="i-web-01",
        rationale="AI detected anomalous egress beacon on web node",
    )
    dec_2 = governor.evaluate_action(action_2)

    # Trap 3: Telemetry Blindness
    action_3 = RemediationAction(
        action_type=ActionType.REMOVE_PERMISSION,
        target_resource_id="s3-audit-logs",
        parameters={"block_service_delivery": True},
        rationale="AI attempting to quarantine log bucket",
    )
    dec_3 = governor.evaluate_action(action_3)

    # Display in Rich Table
    table = Table(title="Live Demonstration of Operational Traps", show_lines=True)
    table.add_column("Scenario", style="bold yellow")
    table.add_column("AI Proposed Action", style="cyan")
    table.add_column("Invariant Violated", style="magenta")
    table.add_column("Governor Decision", style="bold green")
    table.add_column("Resolution Mechanism", style="white")

    table.add_row(
        "Trap 1: Sole Admin Lockout",
        "RevokeAccessKey(ak-alice-01)",
        "I_Admin (Zero recovery paths)",
        f"[{dec_1.decision.value}]",
        "Escalated to human approval gate; prevented total organizational lockout.",
    )
    table.add_row(
        "Trap 2: Quorum Service Outage",
        "IsolateInstance(i-web-01)",
        "I_Avail (Healthy count < 2)",
        f"[{dec_2.decision.value}]",
        f"Selected verified mitigation: {dec_2.executed_action.action_type.value} (preserves health checks).",
    )
    table.add_row(
        "Trap 3: Telemetry Severance",
        "RemovePermission(s3-audit-logs)",
        "I_Telem (CloudTrail bucket drop)",
        f"[{dec_3.decision.value}]",
        "Intercepted logging pipeline disruption; alerted operator.",
    )

    console.print(table)


def demo_benchmark():
    console.print("\n[bold cyan]Running CloudGuard-Bench across 120 Incident Scenarios...[/bold cyan]\n")
    runner = BenchmarkRunner()
    results = runner.run_all()
    console.print(runner.print_summary_table(results))


def demo_agent_pipeline():
    console.print(
        Panel.fit(
            "[bold green]Phase 5: LLM Investigation Agent & RAG Pipeline Demonstration[/bold green]\n"
            "[dim]Incident Envelope -> RAG Playbook Retrieval -> LLM Reasoning -> Governor Verification[/dim]",
            border_style="green",
        )
    )

    # Setup ODG
    odg = OperationalDependencyGraph()

    # Active Admin
    admin = CloudResource(
        id="usr-admin",
        resource_type=ResourceType.IAM_USER,
        name="SecurityAdmin",
        criticality=CriticalityTier.TIER_0,
        status="active",
        properties={"is_admin": True, "has_console_access": False},
    )
    admin_key = CloudResource(
        id="ak-admin-01",
        resource_type=ResourceType.ACCESS_KEY,
        name="SecurityAdminKey",
        criticality=CriticalityTier.TIER_0,
        status="active",
        properties={"is_active": True},
    )
    odg.add_resource(admin)
    odg.add_resource(admin_key)
    odg.add_dependency(admin_key.id, admin.id, EdgeType.ATTACHED_TO)

    tg = CloudResource(
        id="tg-prod-web",
        resource_type=ResourceType.TARGET_GROUP,
        name="ProductionWebCluster",
        criticality=CriticalityTier.TIER_0,
        properties={"min_healthy_replicas": 2, "health_check_port_open": True},
    )
    node1 = CloudResource(
        id="i-web-01",
        resource_type=ResourceType.EC2_INSTANCE,
        name="WebNode01",
        criticality=CriticalityTier.TIER_0,
        status="running",
    )
    node2 = CloudResource(
        id="i-web-02",
        resource_type=ResourceType.EC2_INSTANCE,
        name="WebNode02",
        criticality=CriticalityTier.TIER_0,
        status="running",
    )
    odg.add_resource(tg)
    odg.add_resource(node1)
    odg.add_resource(node2)
    odg.add_dependency(node1.id, tg.id, EdgeType.MEMBER_OF)
    odg.add_dependency(node2.id, tg.id, EdgeType.MEMBER_OF)

    governor = SentinelGuardGovernor(odg)
    pipeline = IncidentResponsePipeline(governor=governor)

    # 1. Real Investigation Scenario
    incident = SecurityIncident(
        incident_id="INC-2026-LIVE-C2",
        alert_type="c2_beacon",
        severity="HIGH",
        timestamp="2026-10-12T16:00:00Z",
        affected_resource_ids=["i-web-01"],
        observed_events=[
            {"event": "OutboundNetworkFlow", "destination_ip": "198.51.100.77", "bytes": 10485760}
        ],
        detection_evidence={"threat_intel_match": "Known C2 Beacon IP"},
    )

    report = pipeline.process_incident(incident)

    table = Table(title="Live Agent & Governor Execution Trace", show_lines=True)
    table.add_column("Pipeline Stage", style="bold cyan")
    table.add_column("Details & Artifacts", style="white")

    table.add_row("1. Input Incident", f"{incident.alert_type} on {incident.affected_resource_ids[0]} (Severity: {incident.severity})")
    table.add_row("2. RAG Retrieval", "\n".join(f"• {ref}" for ref in report.assessment.retrieved_references))
    table.add_row("3. Agent Assessment", report.assessment.summary)
    table.add_row("4. Agent Proposal", f"{report.assessment.recommended_action.action_type.value} on {report.assessment.recommended_action.target_resource_id}")
    table.add_row("5. Governor Verification", f"Result: [{report.governor_decision.decision.value}]\nReason: {report.governor_decision.reason}")
    table.add_row("6. Executed Action", report.governor_decision.executed_action.action_type.value if report.governor_decision.executed_action else "None")
    table.add_row("7. Audit Hash (SHA-256)", report.audit_hash[:32] + "...")
    table.add_row("8. Latency", f"{report.execution_time_ms:.2f} ms")

    console.print(table)


def demo_agent_benchmark():
    console.print("\n[bold green]Running Phase 5 Agent & RAG Evaluation (30 Incidents)...[/bold green]\n")
    runner = AgentBenchmarkRunner()
    results = runner.run_evaluation()
    console.print(runner.print_report_table(results))


def demo_telemetry_pipeline():
    console.print(
        Panel.fit(
            "[bold magenta]Phase 6: Big Data Telemetry & ML Anomaly Detection Pipeline[/bold magenta]\n"
            "[dim]Raw CloudTrail / VPC Logs -> PySpark Aggregation -> Isolation Forest -> Alert Integrator -> Governor[/dim]",
            border_style="magenta",
        )
    )

    generator = SyntheticLogGenerator(seed=42)
    ct_events = generator.generate_cloudtrail_events(normal_count=200, anomaly_count=10)

    spark_pipeline = PySparkTelemetryPipeline(app_name="SentinelGuardDemo")
    try:
        spark_df = spark_pipeline.ingest_cloudtrail_events(ct_events)
        features_spark = spark_pipeline.extract_cloudtrail_features(spark_df)
        features_df = spark_pipeline.to_pandas(features_spark)

        detector = MLAnomalyDetector(contamination=0.15, random_state=42)
        detector.fit(features_df, MLAnomalyDetector.DEFAULT_CLOUDTRAIL_FEATURES)
        is_anom, scores = detector.predict(features_df, MLAnomalyDetector.DEFAULT_CLOUDTRAIL_FEATURES)

        incidents = AlertIntegrator.convert_features_to_incidents(
            features_df=features_df,
            is_anomaly_mask=is_anom,
            anomaly_scores=scores,
            raw_events=ct_events,
        )

        from sentinelguard.benchmark.agent_eval import build_evaluation_odg

        odg = build_evaluation_odg()
        governor = SentinelGuardGovernor(odg)
        gov_pipeline = IncidentResponsePipeline(governor=governor)

        reports = AlertIntegrator.dispatch_to_pipeline(gov_pipeline, incidents[:3])

        table = Table(
            title="End-to-End Telemetry Ingestion -> ML Detection -> Governor Trace",
            show_lines=True,
        )
        table.add_column("Incident ID", style="bold yellow")
        table.add_column("Target Resource", style="cyan")
        table.add_column("ML Score", style="magenta")
        table.add_column("Key Evidence", style="white")
        table.add_column("Agent Proposal", style="blue")
        table.add_column("Governor Decision", style="bold green")

        for r, inc in zip(reports, incidents[:3]):
            action_desc = (
                f"{r.assessment.recommended_action.action_type.value} on {r.assessment.recommended_action.target_resource_id}"
                if r.assessment.recommended_action
                else "No action proposed"
            )
            gov_desc = (
                f"[{r.governor_decision.decision.value}]\n{r.governor_decision.reason[:60]}..."
                if r.governor_decision
                else "None"
            )
            ev_summary = (
                f"Errors: {inc.detection_evidence.get('error_rate', 0):.2f}, "
                f"Sensitive APIs: {inc.detection_evidence.get('sensitive_api_count', 0)}"
            )
            table.add_row(
                inc.incident_id,
                inc.affected_resource_ids[0],
                f"{inc.detection_evidence.get('ml_anomaly_score', 0):.4f}",
                ev_summary,
                action_desc,
                gov_desc,
            )

        console.print(table)
    finally:
        spark_pipeline.stop()


def demo_detection_benchmark():
    console.print("\n[bold magenta]Running Phase 6 Detection Benchmark (4,000 Telemetry Events)...[/bold magenta]\n")
    runner = DetectionBenchmarkRunner(cloudtrail_events=2000, vpc_flow_events=2000)
    results = runner.run_detection_evaluation()
    console.print(runner.print_detection_report(results))


def demo_controlled_execution_workflow():
    console.print(
        Panel.fit(
            "[bold blue]Phase 7: Cloud Incident Response Workflows and Controlled Execution[/bold blue]\n"
            "[dim]Incident -> Agent & RAG -> Governor Verification -> Human Approval Gate\n"
            "-> Pre-Execution TOCTOU Revalidation -> Simulated Cloud Dispatch -> Post-Execution Invariant Verification[/dim]",
            border_style="blue",
        )
    )

    odg = OperationalDependencyGraph()

    alice = CloudResource(
        id="usr-alice",
        resource_type=ResourceType.IAM_USER,
        name="AliceAdmin",
        criticality=CriticalityTier.TIER_0,
        properties={"is_admin": True, "has_console_access": False},
    )
    alice_key = CloudResource(
        id="ak-alice-01",
        resource_type=ResourceType.ACCESS_KEY,
        name="AliceKey01",
        criticality=CriticalityTier.TIER_0,
        properties={"is_active": True},
    )
    odg.add_resource(alice)
    odg.add_resource(alice_key)
    odg.add_dependency(alice_key.id, alice.id, EdgeType.ATTACHED_TO)

    tg = CloudResource(
        id="tg-prod-web",
        resource_type=ResourceType.TARGET_GROUP,
        name="ProductionWebCluster",
        criticality=CriticalityTier.TIER_0,
        properties={"min_healthy_replicas": 2, "health_check_port_open": True},
    )
    node1 = CloudResource(
        id="i-web-01",
        resource_type=ResourceType.EC2_INSTANCE,
        name="WebNode01",
        criticality=CriticalityTier.TIER_0,
        status="running",
        properties={"health_check_port_open": True},
    )
    node2 = CloudResource(
        id="i-web-02",
        resource_type=ResourceType.EC2_INSTANCE,
        name="WebNode02",
        criticality=CriticalityTier.TIER_0,
        status="running",
        properties={"health_check_port_open": True},
    )
    odg.add_resource(tg)
    odg.add_resource(node1)
    odg.add_resource(node2)
    odg.add_dependency(node1.id, tg.id, EdgeType.MEMBER_OF)
    odg.add_dependency(node2.id, tg.id, EdgeType.MEMBER_OF)

    dev_node = CloudResource(
        id="i-dev-01",
        resource_type=ResourceType.EC2_INSTANCE,
        name="DevSandbox",
        criticality=CriticalityTier.TIER_3,
        status="running",
    )
    odg.add_resource(dev_node)

    env = SimulatedCloudEnvironment(initial_graph=odg)
    workflow = ControlledIncidentResponseWorkflow(environment=env, enforce_tier_0_approval=False)

    # 1. Safe Action Execution
    inc1 = SecurityIncident(
        incident_id="INC-PHASE7-001",
        alert_type="c2_beacon",
        severity="HIGH",
        timestamp="2026-10-12T17:00:00Z",
        affected_resource_ids=["i-dev-01"],
        observed_events=[{"event": "OutboundFlow", "dstport": 4444}],
    )
    res1 = workflow.execute_incident_workflow(inc1)

    # 2. Operational Trap Mitigation (Modify to Scoped Egress Filter)
    inc2 = SecurityIncident(
        incident_id="INC-PHASE7-002",
        alert_type="c2_beacon",
        severity="CRITICAL",
        timestamp="2026-10-12T17:05:00Z",
        affected_resource_ids=["i-web-01"],
        observed_events=[{"event": "C2Egress", "dstport": 1337}],
    )
    res2 = workflow.execute_incident_workflow(inc2)

    # 3. TOCTOU State Drift Detection
    class DriftingInvestigator(IncidentInvestigatorAgent):
        def __init__(self, e):
            super().__init__(llm_provider=MockLLMProvider(mode="normal"))
            self.e = e

        def investigate(self, inc):
            r = super().investigate(inc)
            self.e.mutate_resource_out_of_band("i-web-02", new_status="terminated")
            return r

    workflow_drift = ControlledIncidentResponseWorkflow(
        environment=env,
        agent=DriftingInvestigator(env),
        enforce_tier_0_approval=False,
    )
    inc3 = SecurityIncident(
        incident_id="INC-PHASE7-003",
        alert_type="c2_beacon",
        severity="HIGH",
        timestamp="2026-10-12T17:10:00Z",
        affected_resource_ids=["i-web-01"],
    )
    res3 = workflow_drift.execute_incident_workflow(inc3)

    table = Table(title="Controlled Incident Response Workflow Live Traces", show_lines=True)
    table.add_column("Scenario", style="bold yellow")
    table.add_column("Governor Decision", style="cyan")
    table.add_column("TOCTOU Guard", style="magenta")
    table.add_column("Simulated Execution", style="green")
    table.add_column("Post-Verification", style="white")
    table.add_column("Final Status", style="bold")

    table.add_row(
        "1. Safe Remediation (Dev Node)",
        f"[{res1.governor_decision.decision.value}]",
        "Passed (No Drift)",
        f"{res1.execution_result.action.action_type.value} applied",
        "Passed (Invariants OK)",
        f"[green]{res1.final_status.value}[/green]",
    )
    table.add_row(
        "2. Operational Trap (Web Node)",
        f"[{res2.governor_decision.decision.value}] -> {res2.governor_decision.executed_action.action_type.value}",
        "Passed (No Drift)",
        "Scoped filter applied (health checks open)",
        "Passed (Quorum preserved)",
        f"[green]{res2.final_status.value}[/green]",
    )
    table.add_row(
        "3. Out-of-Band State Drift",
        f"[{res3.governor_decision.decision.value}]",
        "[red]FAILED (Drift Detected)[/red]",
        "Aborted before dispatch",
        "Skipped (Fail-closed)",
        f"[red]{res3.final_status.value}[/red]",
    )

    console.print(table)


def main():
    demo_operational_traps()
    demo_benchmark()
    demo_agent_pipeline()
    demo_agent_benchmark()
    demo_telemetry_pipeline()
    demo_detection_benchmark()
    demo_controlled_execution_workflow()


if __name__ == "__main__":
    main()

