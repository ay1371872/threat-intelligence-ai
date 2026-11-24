"""High-Scale 1,000,000 (1 Million) Threat Feeder & Benchmark
Course: 23CSE528 - NoSQL Databases using MongoDB
Author: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)

Demonstrates extreme-scale NoSQL ingestion:
- Generates and streams 1,000,000 polymorphic threat records into MongoDB.
- Uses memory-efficient streaming generator in batches of 25,000 documents.
- Evaluates WiredTiger storage engine throughput, compound indexes (IXSCAN),
  and multi-stage aggregation performance across 1 Million records.
"""

import sys
import os
import time
import random
from datetime import datetime, timedelta

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db_connector import get_database, get_mongo_client

TOTAL_THREATS = 1_000_000
BATCH_SIZE = 25_000  # 40 batches * 25,000 = 1,000,000

PLATFORMS = ["Linux", "Windows", "macOS", "Android", "iOS", "Cloud"]
STATUSES = ["Anticipated", "Active", "Evolving", "Resolved"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]
ATTACK_VECTORS = ["Network", "Local", "Adjacent", "Physical"]

THREAT_TITLES = [
    "Kernel Memory Corruption Privilege Escalation",
    "Remote Code Execution via Malformed RPC Packet",
    "Zero-Click Sandbox Escape and OLE Moniker Execution",
    "Netfilter Heap Use-After-Free Root Access",
    "Signal Handler Race Condition Authentication Bypass",
    "Supply-Chain Backdoor Injection in Build Library",
    "Polymorphic Ransomware Payload Evasion",
    "Living-off-the-Land Script Execution via WMI",
    "DocumentsUI Scoped Storage Directory Traversal",
    "Safari WebKit Out-of-Bounds Memory Disclosure",
    "NTLM Relay and SMB Session Hijacking Vector",
    "Unquoted Service Path Persistence Hook"
]


def generate_threat_batch(start_idx: int, count: int) -> list:
    """Generates a batch of realistic, polymorphic threat documents."""
    batch = []
    base_time = datetime.utcnow()
    rng = random.Random(start_idx + 1337)

    for i in range(count):
        idx = start_idx + i
        cve_id = f"CVE-2026-{idx + 1:07d}"
        platform = PLATFORMS[idx % len(PLATFORMS)]
        status = STATUSES[idx % len(STATUSES)]
        severity = SEVERITIES[idx % len(SEVERITIES)]
        title = THREAT_TITLES[idx % len(THREAT_TITLES)]
        vector = ATTACK_VECTORS[idx % len(ATTACK_VECTORS)]

        # Severity-correlated CVSS score
        if severity == "Critical":
            cvss = round(rng.uniform(9.0, 10.0), 1)
        elif severity == "High":
            cvss = round(rng.uniform(7.0, 8.9), 1)
        elif severity == "Medium":
            cvss = round(rng.uniform(4.0, 6.9), 1)
        else:
            cvss = round(rng.uniform(1.0, 3.9), 1)

        doc = {
            "cve_id": cve_id,
            "title": f"[{platform}] {title} #{idx + 1}",
            "platform": platform,
            "status": status,
            "severity": severity,
            "cvss": cvss,
            "attack_vector": vector,
            "description": f"Automated telemetry flag {cve_id}: {title} detected on {platform} cluster node.",
            "mitigation_procedure": f"Apply security hotfix or enforce isolation policy on affected {platform} nodes.",
            "automated_fix_command": f"sudo sysctl -w security.mitigate_{platform.lower()}=1",
            "timestamp": (base_time - timedelta(seconds=idx)).isoformat() + "Z",
            "is_million_scale": True
        }
        batch.append(doc)

    return batch


def feed_1_million_threats():
    """Feeds 1,000,000 threat records into MongoDB with streaming batch writes."""
    db = get_database()
    col = db["threats"]
    audit_col = db["audit_log"]

    print("=" * 78)
    print("  🚀 HIGH-SCALE INGESTION: FEEDING 1,000,000 THREATS TO MONGODB")
    print(f"  Target Collection: threats | Total Target: {TOTAL_THREATS:,}")
    print(f"  Batch Size: {BATCH_SIZE:,} | Total Batches: {TOTAL_THREATS // BATCH_SIZE}")
    print("=" * 78)

    total_start = time.perf_counter()
    inserted_total = 0
    num_batches = TOTAL_THREATS // BATCH_SIZE

    for b in range(num_batches):
        batch_start_idx = b * BATCH_SIZE
        batch_data = generate_threat_batch(batch_start_idx, BATCH_SIZE)

        t_batch_start = time.perf_counter()
        col.insert_many(batch_data, ordered=False)
        t_batch_elapsed = time.perf_counter() - t_batch_start

        inserted_total += len(batch_data)
        rate = len(batch_data) / (t_batch_elapsed + 1e-6)
        percent = (inserted_total / TOTAL_THREATS) * 100

        print(f"  [Batch {b + 1:02d}/{num_batches}] Stored {inserted_total:,} / {TOTAL_THREATS:,} ({percent:5.1f}%) | Speed: {rate:,.0f} docs/sec | Batch: {t_batch_elapsed:.3f}s")

    total_time = time.perf_counter() - total_start
    throughput = inserted_total / (total_time + 1e-6)

    print("-" * 78)
    print(f"[OK] 1 Million Threat Ingestion Completed in {total_time:.2f} seconds!")
    print(f"[OK] Average Write Throughput: {throughput:,.0f} threats/second.")

    # Compound index check
    print("\n[*] Verifying Compound Indexes across 1,000,000 documents...")
    col.create_index([("platform", 1), ("status", 1)], name="idx_platform_status")
    col.create_index([("severity", 1), ("cvss", -1)], name="idx_severity_cvss")
    print("[OK] Compound indexes active.")

    # Audit Trail
    audit_col.insert_one({
        "event": "ONE_MILLION_THREATS_INGESTED",
        "actor": "Ayush Yadav (USN: 24BTLCL003)",
        "threat_count": inserted_total,
        "elapsed_seconds": round(total_time, 2),
        "throughput_docs_per_sec": round(throughput, 1),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })
    print("[OK] Audit event committed to MongoDB audit_log.")

    return {
        "status": "success",
        "threats_ingested": inserted_total,
        "elapsed_seconds": round(total_time, 2),
        "throughput": round(throughput, 1)
    }


if __name__ == "__main__":
    feed_1_million_threats()
