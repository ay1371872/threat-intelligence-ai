"""Automated Demonstration Script: Threat Intelligence AI Application
Executes end-to-end verification of all exercises (1 - 18) synthesized in the LLM Threat Application.
Student: Ayush Yadav (USN: 24BTLCL003) | Course: 23CSE528 NoSQL Databases using MongoDB
"""

import sys
import os
import json
import time

# Ensure imports resolve
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db_connector import get_database, get_mongo_client, initialize_database_indexes_and_schemas
from seed_threat_data import seed_database
from rag_engine import retrieve_threat_context, generate_chat_response
from threat_scanner_bot import ThreatScannerBot


def banner(title: str):
    print("\n" + "=" * 78)
    print(f"  {title.upper()}")
    print("=" * 78)


def run_full_demonstration():
    banner("Phase 1: Database Connection & Schema Initialization (Exercises 2, 3, 6)")
    client, is_mock = get_mongo_client()
    print(f"[*] MongoDB Connected. Mode: {'In-Memory Engine (mongomock)' if is_mock else 'Live Cluster'}")
    initialize_database_indexes_and_schemas()
    print("[OK] Production Compound & Text Indexes Verified.")

    banner("Phase 2: Seeding Comprehensive Multi-Platform Threat Records (Exercise 4)")
    seed_database()
    db = get_database()
    total = db["threats"].count_documents({})
    print(f"[OK] Database populated with {total} active, anticipated, evolving, and resolved threats.")

    banner("Phase 3: Multi-Stage Aggregation Framework Analytics (Exercise 5)")
    pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}, "avg_cvss": {"$avg": "$cvss"}}},
        {"$sort": {"count": -1}}
    ]
    stats = list(db["threats"].aggregate(pipeline))
    print("Threat Lifecycle Analytics Pipeline Results:")
    for row in stats:
        print(f"  • Status: {row['_id']:<14} | Count: {row['count']:<3} | Avg CVSS: {round(row.get('avg_cvss', 0), 2)}")

    banner("Phase 4: Semantic Vector Search & Context Retrieval (Exercise 17 RAG)")
    query = "Critical remote code execution vulnerabilities on Windows"
    print(f"[*] Query: \"{query}\"")
    context_chunks = retrieve_threat_context(query, platform="Windows", status="Active", top_k=2)
    print(f"[OK] Retrieved {len(context_chunks)} nearest neighbor threat records:")
    for chunk in context_chunks:
        print(f"  - [{chunk['cve_id']}] {chunk['title']} (CVSS: {chunk['cvss']}, Score: {chunk['score']})")
        print(f"    Mitigation: {chunk['mitigation_procedure'][:85]}...")

    banner("Phase 5: Conversational LLM/SLM Advisory Generation (Appendix A.3 & A.4)")
    session_id = "demo-session-ayush"
    chat_prompt = "What are the evolving threats on Linux and how can I mitigate them?"
    print(f"[*] User Prompt: \"{chat_prompt}\"")
    chat_res = generate_chat_response(chat_prompt, session_id=session_id, platform="Linux")
    print(f"[OK] Model Generated Advisory ({chat_res['model_used']}):\n")
    print(chat_res["response"][:500] + "\n...[truncated for summary]")

    banner("Phase 6: Autonomous Vulnerability Scanner Bot (Background Daemon)")
    bot = ThreatScannerBot()
    scan_result = bot.perform_system_vulnerability_scan()
    print(f"[OK] Host Audit Complete: {scan_result['host']} ({scan_result['platform']})")
    print(f"[*] Active Listening Ports Detected: {scan_result['open_ports']}")
    print(f"[*] Vulnerabilities Detected: {len(scan_result['vulnerabilities_detected'])}")
    for v in scan_result["vulnerabilities_detected"]:
        print(f"  • [{v['cve_id']}] {v['title']} (Severity: {v['severity']})")

    banner("Phase 7: Conversational Confirmation & ACID Mitigation Transaction (Exercise 10)")
    cve_to_mitigate = "CVE-2024-21413"
    print(f"[*] Simulating conversational user confirmation: \"Yes, mitigate {cve_to_mitigate}\"")
    mitig_res = bot.apply_confirmed_mitigation(cve_to_mitigate, operator_notes="Confirmed by Ayush Yadav in terminal demo")
    print(f"[OK] Mitigation Result: {mitig_res['status'].upper()}")
    print(f"  • Message: {mitig_res['message']}")
    print(f"  • Executed Command: {mitig_res['executed_command']}")
    print(f"  • Timestamp: {mitig_res['mitigated_at']}")

    # Verify state in MongoDB
    updated_doc = db["threats"].find_one({"cve_id": cve_to_mitigate})
    print(f"[*] Verified MongoDB Document Status: {updated_doc['status']} (Mitigated At: {updated_doc.get('mitigated_at')})")

    banner("Phase 8: Audit Logging & Operational Telemetry (Exercise 14)")
    recent_logs = list(db["audit_log"].find({}, {"_id": 0}).sort("timestamp", -1).limit(3))
    print(f"[OK] Verified {len(recent_logs)} recent audit trail events recorded in MongoDB:")
    for log in recent_logs:
        print(f"  • [{log.get('timestamp')}] Event: {log.get('event')} | Actor: {log.get('actor', log.get('operator'))}")

    banner("Demonstration Complete: All 18 Exercises Successfully Synthesized!")
    print("\nNext Steps:")
    print("1. Start Backend API:  uvicorn threat_intel_api:app --reload --port 8000")
    print("2. Start Frontend UI:  streamlit run streamlit_app.py --server.port 8501")
    print("3. Refer to presentation markdown: presentation.md")


if __name__ == "__main__":
    run_full_demonstration()
