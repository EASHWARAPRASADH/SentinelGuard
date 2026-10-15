"""
PySpark Telemetry Processing Pipeline for SentinelGuard.
Cleans, normalizes, windows, and extracts behavioral feature vectors from
raw CloudTrail and VPC Flow telemetry streams.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import pandas as pd
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    BooleanType,
    IntegerType,
    LongType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

logger = logging.getLogger(__name__)


class PySparkTelemetryPipeline:
    """
    Big data processing pipeline for security event normalization and feature engineering.
    """

    SENSITIVE_APIS = [
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "PutBucketPolicy",
        "DeleteTrail",
        "StopLogging",
        "CreateAccessKey",
        "UpdateAccessKey",
        "AuthorizeSecurityGroupIngress",
    ]

    def __init__(self, app_name: str = "SentinelGuardTelemetry", master: str = "local[2]") -> None:
        self.spark: SparkSession = (
            SparkSession.builder.appName(app_name)
            .master(master)
            .config("spark.ui.enabled", "false")
            .config("spark.driver.bindAddress", "127.0.0.1")
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.sql.shuffle.partitions", "2")
            .getOrCreate()
        )
        self.spark.sparkContext.setLogLevel("ERROR")

    # -----------------------------------------------------------------------
    # CloudTrail Processing & Feature Extraction
    # -----------------------------------------------------------------------

    def ingest_cloudtrail_events(self, events: List[Dict[str, Any]]) -> DataFrame:
        """
        Ingest raw CloudTrail event dictionaries into a normalized Spark DataFrame.
        """
        # Flatten dictionary records for uniform schema
        flattened = []
        for e in events:
            user_id = e.get("userIdentity") or {}
            flattened.append({
                "eventID": str(e.get("eventID", "")),
                "eventTime": str(e.get("eventTime", "")),
                "eventSource": str(e.get("eventSource", "")),
                "eventName": str(e.get("eventName", "")),
                "sourceIPAddress": str(e.get("sourceIPAddress", "")),
                "principalArn": str(user_id.get("arn", "")),
                "userName": str(user_id.get("userName", "")),
                "accessKeyId": str(user_id.get("accessKeyId", "")),
                "errorCode": e.get("errorCode"),
                "is_error": 1 if e.get("errorCode") else 0,
                "is_anomaly": bool(e.get("is_anomaly", False)),
                "label": str(e.get("label", "benign")),
                "incident_type": str(e.get("incident_type", "") or ""),
                "target_resource_id": str(e.get("target_resource_id", "") or ""),
            })

        df = self.spark.createDataFrame(flattened)
        df = df.withColumn("timestamp", F.to_timestamp("eventTime", "yyyy-MM-dd'T'HH:mm:ss'Z'"))
        return df

    def extract_cloudtrail_features(self, df: DataFrame) -> DataFrame:
        """
        Extract numerical behavioral features grouped by principal / accessKeyId:
        - event_count
        - error_count, error_rate
        - distinct_api_count
        - distinct_ip_count
        - sensitive_api_count
        - external_ip_count
        """
        sensitive_expr = F.when(F.col("eventName").isin(self.SENSITIVE_APIS), 1).otherwise(0)
        external_ip_expr = F.when(
            (~F.col("sourceIPAddress").startswith("10.")) & (~F.col("sourceIPAddress").startswith("172.16.")),
            1
        ).otherwise(0)

        df_enriched = (
            df.withColumn("is_sensitive_api", sensitive_expr)
            .withColumn("is_external_ip", external_ip_expr)
            .withColumn("time_window", (F.unix_timestamp("timestamp") / 300).cast("long"))
        )

        features = df_enriched.groupBy("accessKeyId", "principalArn", "time_window").agg(
            F.count("eventID").alias("event_count"),
            F.sum("is_error").alias("error_count"),
            F.countDistinct("eventName").alias("distinct_api_count"),
            F.countDistinct("sourceIPAddress").alias("distinct_ip_count"),
            F.sum("is_sensitive_api").alias("sensitive_api_count"),
            F.sum("is_external_ip").alias("external_ip_count"),
            F.max(F.when(F.col("is_anomaly"), 1).otherwise(0)).alias("is_anomaly"),
            F.max("incident_type").alias("incident_type"),
            F.max("target_resource_id").alias("target_resource_id"),
            F.max("sourceIPAddress").alias("sample_source_ip"),
        )

        features = features.withColumn(
            "error_rate",
            F.round(F.col("error_count") / F.col("event_count"), 4)
        ).withColumn(
            "external_ip_ratio",
            F.round(F.col("external_ip_count") / F.col("event_count"), 4)
        )

        return features

    # -----------------------------------------------------------------------
    # VPC Flow Logs Processing & Feature Extraction
    # -----------------------------------------------------------------------

    def ingest_vpc_flow_logs(self, flows: List[Dict[str, Any]]) -> DataFrame:
        """
        Ingest VPC Flow Log records into a normalized Spark DataFrame.
        """
        flattened = []
        for f in flows:
            flattened.append({
                "instance_id": str(f.get("instance_id", "")),
                "srcaddr": str(f.get("srcaddr", "")),
                "dstaddr": str(f.get("dstaddr", "")),
                "srcport": int(f.get("srcport", 0)),
                "dstport": int(f.get("dstport", 0)),
                "bytes": int(f.get("bytes", 0)),
                "packets": int(f.get("packets", 0)),
                "start": int(f.get("start", 0)),
                "is_anomaly": bool(f.get("is_anomaly", False)),
                "label": str(f.get("label", "benign")),
                "incident_type": str(f.get("incident_type", "") or ""),
                "target_resource_id": str(f.get("target_resource_id", "") or ""),
            })

        df = self.spark.createDataFrame(flattened)
        return df

    def extract_vpc_features(self, df: DataFrame) -> DataFrame:
        """
        Extract numerical behavioral features grouped by compute instance and time window:
        - flow_count
        - bytes_total, bytes_mean, bytes_max
        - c2_port_count (e.g. 4444, 8080, 1337)
        - external_dst_count
        """
        c2_port_expr = F.when(F.col("dstport").isin([4444, 8080, 1337, 6667]), 1).otherwise(0)
        external_dst_expr = F.when(
            (~F.col("dstaddr").startswith("10.")) & (~F.col("dstaddr").startswith("172.16.")),
            1
        ).otherwise(0)

        df_enriched = (
            df.withColumn("is_c2_port", c2_port_expr)
            .withColumn("is_external_dst", external_dst_expr)
            .withColumn("time_window", (F.col("start") / 300).cast("long"))
        )

        features = df_enriched.groupBy("instance_id", "time_window").agg(
            F.count("srcaddr").alias("flow_count"),
            F.sum("bytes").alias("bytes_total"),
            F.round(F.avg("bytes"), 2).alias("bytes_mean"),
            F.max("bytes").alias("bytes_max"),
            F.sum("packets").alias("packets_total"),
            F.sum("is_c2_port").alias("c2_port_count"),
            F.sum("is_external_dst").alias("external_dst_count"),
            F.max(F.when(F.col("is_anomaly"), 1).otherwise(0)).alias("is_anomaly"),
            F.max("incident_type").alias("incident_type"),
            F.max("target_resource_id").alias("target_resource_id"),
            F.max("dstaddr").alias("sample_dst_ip"),
        )


        return features

    def to_pandas(self, df: DataFrame) -> pd.DataFrame:
        """Convert a Spark DataFrame to a Pandas DataFrame for ML consumption."""
        return df.toPandas()

    def stop(self) -> None:
        """Cleanly terminate the SparkSession."""
        if self.spark:
            self.spark.stop()
