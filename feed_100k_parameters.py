"""High-Scale 100,000 Parameter Ingestion & Benchmark Engine
Course: 23CSE528 - NoSQL Databases using MongoDB
Author: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)

Feeds 100,000 cyber threat telemetry parameters and records into MongoDB,
demonstrating bulk batch insertion, compound indexing, memory sizing (Exercise 7),
and multi-stage aggregation framework analytics (Exercise 5) over massive datasets.
"""

import sys
import os
import time
import math
import random
from datetime import datetime, timedelta

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db_connector import get_database, get_mongo_client

# Constants
TOTAL_PARAMETERS = 100000
BATCH_SIZE = 10000

PLATFORMS = ["Linux", "Windows", "macOS", "Android", "iOS"]
STATUSES = ["Anticipated", "Active", "Evolving", "Resolved"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]
MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Command and Control", "Impact"
]

PARAMETER_TYPES = [
    ("buffer_overflow_entropy", 0.0, 100.0, 80.0, "Execution"),
    ("kernel_syscall_frequency", 10.0, 5000.0, 3500.0, "Privilege Escalation"),
    ("dns_tunneling_ratio", 0.0, 1.0, 0.75, "Command and Control"),
    ("process_injection_depth", 1.0, 10.0, 7.0, "Defense Evasion"),
    ("smb_session_burst_rate", 0.0, 200.0, 120.0, "Lateral Movement"),
    ("powershell_obfuscated_tokens", 0.0, 50.0, 25.0, "Execution"),
    ("tls_certificate_entropy", 1.0, 8.0, 6.5, "Defense Evasion"),
    ("failed_auth_burst_velocity", 0.0, 500.0, 300.0, "Credential Access"),
    ("privilege_elevation_delta", 0.0, 100.0, 85.0, "Privilege Escalation"),
    ("unquoted_service_path_flag", 0.0, 1.0, 0.5, "Persistence"),
    ("memory_page_rw_executable", 0.0, 20.0, 12.0, "Defense Evasion"),
    ("lateral_port_scan_count", 0.0, 1000.0, 600.0, "Discovery")
]


def generate_parameter_batch(start_idx: int, count: int) -> list:
    """Generates a batch of structured threat parameters with realistic distributions."""
    batch = []
    base_time = datetime.utcnow()
    rng = random.Random(start_idx + 42)

    for i in range(count):
        idx = start_idx + i
        p_type = PARAMETER_TYPES[idx % len(PARAMETER_TYPES)]
        p_name, min_v, max_v, threshold, tactic = p_type

        # Realistic random distribution with injected anomaly spikes
        is_spike = (rng.random() < 0.22) # 22% anomaly spike rate
        if is_spike:
            val = round(threshold + rng.uniform(0.1, (max_v - threshold) if max_v > threshold else 10.0), 3)
            is_anomaly = True
            severity = rng.choice(["High", "Critical"])
            cvss = round(rng.uniform(7.5, 10.0), 1)
        else:
            val = round(rng.uniform(min_v, threshold), 3)
            is_anomaly = False
            severity = rng.choice(["Low", "Medium"])
            cvss = round(rng.uniform(1.0, 6.9), 1)

        platform = PLATFORMS[idx % len(PLATFORMS)]
        status = STATUSES[idx % len(STATUSES)]
        time_offset = timedelta(seconds=idx * 2)

        record = {
            "param_id": f"PARAM-{idx + 1:06d}",
            "metric_name": p_name,
            "platform": platform,
            "threat_status": status,
            "value": val,
            "threshold": threshold,
            "is_anomaly": is_anomaly,
            "severity": severity,
            "cvss_score": cvss,
            "mitre_tactic": tactic,
            "host_node": f"node-{platform.lower()}-{(idx % 15) + 1:02d}",
            "timestamp": (base_time - time_offset).isoformat() + "Z",
            # Compact 4-d vector for hybrid retrieval
            "vector_embedding": [
                round(val / (max_v if max_v > 0 else 100.0), 4),
                round(cvss / 10.0, 4),
                1.0 if is_anomaly else 0.0,
                round((idx % len(PLATFORMS)) / 5.0, 4)
            ]
        }
        batch.append(record)

    return batch


def feed_100k_parameters_to_mongodb(progress_callback=None):
    """Feeds 100,000 parameters into MongoDB collection using bulk batch insertion."""
    db = get_database()
    col = db["threat_parameters"]
    audit_col = db["audit_log"]

    print("=" * 78)
    print("  🚀 HIGH-SCALE INGESTION: FEEDING 100,000 PARAMETERS TO MONGODB")
    print(f"  Target Collection: threat_parameters | Total Target: {TOTAL_PARAMETERS:,}")
    print(f"  Batch Size: {BATCH_SIZE:,} | Total Batches: {TOTAL_PARAMETERS // BATCH_SIZE}")
    print("=" * 78)

    # 1. Clean collection
    print("[*] Preparing collection and resetting previous telemetry...")
    col.delete_many({})

    # 2. Ingestion Loop
    total_start = time.perf_counter()
    inserted_total = 0

    for b in range(TOTAL_PARAMETERS // BATCH_SIZE):
        batch_start_idx = b * BATCH_SIZE
        batch_data = generate_parameter_batch(batch_start_idx, BATCH_SIZE)
        
        t_batch_start = time.perf_counter()
        col.insert_many(batch_data)
        t_batch_elapsed = time.perf_counter() - t_batch_start

        inserted_total += len(batch_data)
        rate = len(batch_data) / (t_batch_elapsed + 1e-6)

        percent = (inserted_total / TOTAL_PARAMETERS) * 100
        print(f"  [Batch {b + 1:02d}/10] Inserted {inserted_total:,} / {TOTAL_PARAMETERS:,} ({percent:5.1f}%) | Speed: {rate:,.0f} docs/sec | Batch Time: {t_batch_elapsed:.3f}s")

        if progress_callback:
            progress_callback(percent, inserted_total)

    total_time = time.perf_counter() - total_start
    throughput = inserted_total / total_time

    print("-" * 78)
    print(f"[OK] Ingestion Complete! Successfully stored {inserted_total:,} parameters in {total_time:.2f} seconds.")
    print(f"[OK] Average Ingestion Throughput: {throughput:,.0f} parameters/second.")

    # 3. Create Compound Indexes (Exercise 6)
    print("\n[*] Constructing Production Compound Indexes for 100,000 Parameters...")
    idx_start = time.perf_counter()
    col.create_index([("platform", 1), ("threat_status", 1), ("is_anomaly", 1)], name="idx_platform_status_anomaly")
    col.create_index([("severity", 1), ("cvss_score", -1)], name="idx_severity_cvss")
    col.create_index([("param_id", 1)], unique=True, name="idx_param_id_unique")
    idx_time = time.perf_counter() - idx_start
    print(f"[OK] Created 3 compound & unique indexes in {idx_time:.3f}s.")

    # 4. Run Multi-Stage Aggregation Framework (Exercise 5)
    print("\n[*] Running Aggregation Analytics Pipeline over 100,000 records...")
    agg_start = time.perf_counter()
    _, is_mock = get_mongo_client()
    
    if is_mock:
        # Fast in-memory aggregation for mongomock
        pipeline = [
            {"$match": {"is_anomaly": True}},
            {"$group": {"_id": "$platform", "anomaly_count": {"$sum": 1}, "avg_cvss": {"$avg": "$cvss_score"}}},
            {"$sort": {"anomaly_count": -1}}
        ]
    else:
        # Full enterprise pipeline on live MongoDB cluster
        pipeline = [
            {"$match": {"is_anomaly": True}},
            {
                "$group": {
                    "_id": "$platform",
                    "anomaly_count": {"$sum": 1},
                    "avg_cvss": {"$avg": "$cvss_score"},
                    "critical_count": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}
                    }
                }
            },
            {"$sort": {"anomaly_count": -1}}
        ]

    analytics = list(col.aggregate(pipeline))
    agg_elapsed = time.perf_counter() - agg_start

    print(f"[OK] Aggregation completed in {agg_elapsed * 1000:.2f} ms:")
    print(f"  {'Platform':<12} | {'Anomalies':<12} | {'Avg CVSS':<10}")
    print("  " + "-" * 42)
    for row in analytics:
        print(f"  {row['_id']:<12} | {row['anomaly_count']:<12,} | {row.get('avg_cvss', 0):.2f}")

    # 5. Log Audit Record (Exercise 14)
    audit_col.insert_one({
        "event": "HIGH_SCALE_PARAMETERS_INGESTED",
        "actor": "Ayush Yadav (USN: 24BTLCL003)",
        "parameter_count": inserted_total,
        "elapsed_seconds": round(total_time, 2),
        "throughput_docs_per_sec": round(throughput, 1),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })
    print("\n[OK] Transaction logged in MongoDB audit_log.")

    return {
        "status": "success",
        "parameters_fed": inserted_total,
        "elapsed_seconds": round(total_time, 2),
        "throughput": round(throughput, 1),
        "aggregation_results": analytics,
        "aggregation_latency_ms": round(agg_elapsed * 1000, 2)
    }


if __name__ == "__main__":
    feed_100k_parameters_to_mongodb()
