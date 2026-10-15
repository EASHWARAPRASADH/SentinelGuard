"""
Unit Tests for PySpark Telemetry Processing Pipeline.
Tests:
- Ingestion of CloudTrail events into Spark DataFrame.
- Extraction of windowed CloudTrail behavioral features.
- Ingestion of VPC Flow logs into Spark DataFrame.
- Extraction of windowed VPC Flow network features.
- Conversion to Pandas DataFrame.
"""

import pytest

from sentinelguard.telemetry.log_generator import SyntheticLogGenerator
from sentinelguard.telemetry.pyspark_pipeline import PySparkTelemetryPipeline


@pytest.fixture(scope="module")
def spark_pipeline():
    pipeline = PySparkTelemetryPipeline(app_name="TestPySparkPipeline")
    yield pipeline
    pipeline.stop()


def test_spark_cloudtrail_ingestion_and_features(spark_pipeline: PySparkTelemetryPipeline):
    gen = SyntheticLogGenerator(seed=42)
    events = gen.generate_cloudtrail_events(normal_count=100, anomaly_count=10)

    df_raw = spark_pipeline.ingest_cloudtrail_events(events)
    assert df_raw.count() == 110
    assert "eventID" in df_raw.columns
    assert "timestamp" in df_raw.columns

    df_features = spark_pipeline.extract_cloudtrail_features(df_raw)
    assert df_features.count() > 0
    assert "event_count" in df_features.columns
    assert "error_rate" in df_features.columns
    assert "sensitive_api_count" in df_features.columns

    pd_features = spark_pipeline.to_pandas(df_features)
    assert len(pd_features) > 0
    assert "accessKeyId" in pd_features.columns


def test_spark_vpc_flow_ingestion_and_features(spark_pipeline: PySparkTelemetryPipeline):
    gen = SyntheticLogGenerator(seed=42)
    flows = gen.generate_vpc_flow_logs(normal_count=100, anomaly_count=10)

    df_raw = spark_pipeline.ingest_vpc_flow_logs(flows)
    assert df_raw.count() == 110
    assert "instance_id" in df_raw.columns
    assert "bytes" in df_raw.columns

    df_features = spark_pipeline.extract_vpc_features(df_raw)
    assert df_features.count() > 0
    assert "bytes_total" in df_features.columns
    assert "c2_port_count" in df_features.columns

    pd_features = spark_pipeline.to_pandas(df_features)
    assert len(pd_features) > 0
    assert "instance_id" in pd_features.columns
