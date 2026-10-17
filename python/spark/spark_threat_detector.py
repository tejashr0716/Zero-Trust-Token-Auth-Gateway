"""
SentinelTrust: Federated Security Threat Detection & Anomaly Forensics Job
Analyzes access logs and threat incidents to cluster coordinated attacks and assess zero-trust mesh health.
"""

import os
import sys
import json
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField, StringType, LongType, DoubleType, TimestampType
)

def build_spark_session(app_name: str = "SentinelTrust-Threat-Analytics") -> SparkSession:
    return (
        SparkSession.builder
        .appName(app_name)
        .master("local[*]")
        .config("spark.driver.memory", "2g")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )

def run_federated_threat_analysis(audit_logs_json_path: str, output_report_path: str):
    spark = build_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    schema = StructType([
        StructField("log_id", LongType(), True),
        StructField("token_id", StringType(), True),
        StructField("client_id", StringType(), True),
        StructField("service_id", StringType(), True),
        StructField("requested_endpoint", StringType(), True),
        StructField("decision", StringType(), True),
        StructField("latency_us", DoubleType(), True),
        StructField("source_ip", StringType(), True)
    ])

    df = spark.read.schema(schema).json(audit_logs_json_path)

    total_requests = df.count()

    # 1. Decision Breakdown
    decision_counts = df.groupBy("decision").count().orderBy(F.col("count").desc())
    dec_dict = {row["decision"]: row["count"] for row in decision_counts.collect()}

    # 2. Hostile Source IP Identification (High Denial Ratio)
    denied_df = df.filter(F.col("decision").startswith("DENIED"))
    hostile_ips = (
        denied_df.groupBy("source_ip")
        .agg(
            F.count("*").alias("denied_count"),
            F.collect_set("service_id").alias("targeted_services")
        )
        .orderBy(F.col("denied_count").desc())
        .limit(10)
    )
    top_threat_actors = [
        {
            "ip": row["source_ip"],
            "denied_count": row["denied_count"],
            "targeted_services": list(row["targeted_services"])
        }
        for row in hostile_ips.collect()
    ]

    # 3. Latency Metrics
    latency_stats = df.select(
        F.avg("latency_us").alias("avg_latency_us"),
        F.expr("percentile_approx(latency_us, 0.5)").alias("p50_us"),
        F.expr("percentile_approx(latency_us, 0.99)").alias("p99_us")
    ).collect()[0]

    report = {
        "engine": "SentinelTrust Federated Threat Detector",
        "total_audit_requests_analyzed": total_requests,
        "decision_breakdown": dec_dict,
        "top_hostile_ips": top_threat_actors,
        "latency_profile_us": {
            "avg": round(latency_stats["avg_latency_us"] or 0.0, 2),
            "p50": round(latency_stats["p50_us"] or 0.0, 2),
            "p99": round(latency_stats["p99_us"] or 0.0, 2)
        },
        "zero_trust_mesh_status": "SECURE" if dec_dict.get("ALLOWED", 0) >= (total_requests * 0.5) else "THREAT_DEFENSE_ACTIVE"
    }

    os.makedirs(os.path.dirname(output_report_path), exist_ok=True)
    with open(output_report_path, "w") as f:
        json.dump(report, f, indent=2)

    spark.stop()
    return report

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: spark_threat_detector.py <audit_logs_json> <output_report_path>")
        sys.exit(1)
    run_federated_threat_analysis(sys.argv[1], sys.argv[2])
