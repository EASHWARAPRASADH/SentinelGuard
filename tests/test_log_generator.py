"""
Unit Tests for SyntheticLogGenerator.
Tests:
- CloudTrail event generation schema conformity.
- VPC Flow Log generation schema conformity.
- Correct injection and labeling of anomaly categories.
- Deterministic reproducibility using random seeds.
"""

from sentinelguard.telemetry.log_generator import SyntheticLogGenerator


def test_cloudtrail_event_generation_schema():
    gen = SyntheticLogGenerator(seed=123)
    events = gen.generate_cloudtrail_events(normal_count=100, anomaly_count=15)

    assert len(events) == 115
    anomaly_events = [e for e in events if e["is_anomaly"]]
    assert len(anomaly_events) == 15

    for e in events:
        assert "eventID" in e
        assert "eventTime" in e
        assert "eventName" in e
        assert "userIdentity" in e
        assert "sourceIPAddress" in e
        assert isinstance(e["is_anomaly"], bool)

    # Check anomaly labels
    labels = {e["label"] for e in anomaly_events}
    assert "credential_abuse" in labels or "privilege_escalation" in labels


def test_vpc_flow_log_generation_schema():
    gen = SyntheticLogGenerator(seed=123)
    flows = gen.generate_vpc_flow_logs(normal_count=100, anomaly_count=20)

    assert len(flows) == 120
    anom_flows = [f for f in flows if f["is_anomaly"]]
    assert len(anom_flows) == 20

    for f in flows:
        assert "instance_id" in f
        assert "srcaddr" in f
        assert "dstaddr" in f
        assert "bytes" in f
        assert "packets" in f
        assert f["action"] == "ACCEPT"


def test_log_generator_seed_reproducibility():
    gen1 = SyntheticLogGenerator(seed=999)
    events1 = gen1.generate_cloudtrail_events(normal_count=50, anomaly_count=5)

    gen2 = SyntheticLogGenerator(seed=999)
    events2 = gen2.generate_cloudtrail_events(normal_count=50, anomaly_count=5)

    assert [e["eventID"] for e in events1] == [e["eventID"] for e in events2]
    assert [e["eventName"] for e in events1] == [e["eventName"] for e in events2]
