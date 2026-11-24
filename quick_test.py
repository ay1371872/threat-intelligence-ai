"""Quick Interactive Tester for Threat Intelligence AI Platform
Run this file directly in VS Code / Terminal to test all features interactively!
Student: Ayush Yadav (24BTLCL003) | JAIN University
"""

import sys
import os

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db_connector import get_database
from seed_threat_data import seed_database
from rag_engine import generate_chat_response, retrieve_threat_context
from threat_scanner_bot import ThreatScannerBot


def print_banner():
    print("\n" + "=" * 70)
    print("      🛡️  THREAT INTELLIGENCE AI - QUICK TEST & DEMO")
    print("      Course: 23CSE528 NoSQL Databases using MongoDB")
    print("      Student: Ayush Yadav (USN: 24BTLCL003)")
    print("=" * 70)


def show_menu():
    print("\nChoose an action to test:")
    print("  [1] 💬 Ask AI a Question (RAG Semantic Search & Advisory)")
    print("  [2] 🤖 Scan My Machine for Vulnerabilities (Background Bot)")
    print("  [3] 📋 View All Threats in MongoDB (Grouped by Lifecycle)")
    print("  [4] ⚡ Mitigate an Active Threat (ACID Transaction)")
    print("  [5] 📜 View MongoDB Audit Trail Log")
    print("  [6] 🔄 Re-seed Threat Intelligence Database")
    print("  [7] 🚀 Run Full Automated End-to-End Demo")
    print("  [8] ⚡ Feed & Benchmark 100,000 Parameters in MongoDB")
    print("  [9] 🦙 Ollama SLM Connection & Model Diagnostics")
    print("  [0] ❌ Exit")
    print("-" * 70)


def test_ask_ai():
    print("\n--- 💬 Chat with Threat Intelligence AI (Ollama SLM) ---")
    preset_queries = [
        "What are the active critical threats on Windows?",
        "List evolving Linux kernel privilege escalation exploits.",
        "What are the anticipated zero-days for Android and iOS?",
        "How do I mitigate CVE-2024-21413 (Outlook Moniker)?"
    ]
    print("Suggested queries:")
    for i, q in enumerate(preset_queries, 1):
        print(f"  ({i}) {q}")
    print("  (or type your own custom query)")
    
    choice = input("\nEnter 1-4 or type query [Default: 1]: ").strip()
    if choice in ["1", "2", "3", "4"]:
        query = preset_queries[int(choice) - 1]
    elif choice:
        query = choice
    else:
        query = preset_queries[0]

    print(f"\n[*] Processing Query: \"{query}\"...")
    res = generate_chat_response(query, session_id="cli-quick-test")
    
    print("\n--- Retrieved Grounded Sources (MongoDB Exercise 17) ---")
    for s in res.get("sources", []):
        print(f"  • [{s['cve_id']}] {s['title']} (Platform: {s['platform']}, CVSS: {s['cvss']})")
    
    print(f"\n--- AI Advisory Response (Model Engine: {res.get('model_used', 'Ollama')}) ---")
    print(res["response"])


def test_ollama():
    from rag_engine import check_ollama_status, OLLAMA_BASE_URL, OLLAMA_MODEL
    print("\n--- 🦙 Ollama SLM Connection & Diagnostics ---")
    stat = check_ollama_status()
    print(f"  • Configured Model:  {stat['configured_model']}")
    print(f"  • Ollama Base URL:   {stat['base_url']}")
    if stat["online"]:
        print(f"  • Server Status:     🟢 ONLINE")
        print(f"  • Installed Models:  {', '.join(stat['installed_models']) if stat['installed_models'] else 'None installed yet'}")
        print(f"  • Configured Ready:  {'✅ Yes' if stat['model_ready'] else '⚠️ Not pulled yet'}")
        if not stat['model_ready']:
            print(f"  • Tip: Pull model with:  ollama pull {OLLAMA_MODEL}")
    else:
        print(f"  • Server Status:     🟡 OFFLINE / NOT REACHABLE")
        print(f"  • Diagnostics:       {stat.get('error', 'Connection refused')}")
        print(f"  • Quick Setup:")
        print(f"      Option A (Windows):  ollama run {OLLAMA_MODEL}")
        print(f"      Option B (Docker):   docker compose up threat-ollama -d")


def test_scan_system():
    print("\n--- 🤖 Running Autonomous Vulnerability Scanner Bot ---")
    print("[*] Probing local machine listening ports and operating system configuration...")
    bot = ThreatScannerBot()
    result = bot.perform_system_vulnerability_scan()
    
    print(f"\n[OK] Host Audit Complete!")
    print(f"  • Host Machine:   {result['host']} ({result['platform']})")
    print(f"  • Open Ports:     {result['open_ports']}")
    print(f"  • Detected Risks: {len(result['vulnerabilities_detected'])}")
    
    for v in result["vulnerabilities_detected"]:
        print(f"\n  ⚠️  [{v['cve_id']}] {v['title']}")
        print(f"      Platform: {v['platform']} | Severity: {v['severity']} (CVSS: {v['cvss']})")
        print(f"      Description: {v['description']}")
        print(f"      Remediation: {v['mitigation_procedure']}")
        print(f"      Command:     {v.get('automated_fix_command', 'N/A')}")


def test_view_threats():
    print("\n--- 📋 Threats Currently Stored in MongoDB ---")
    db = get_database()
    threats = list(db["threats"].find({}, {"embedding": 0}))
    
    if not threats:
        print("[!] Database is empty. Seeding now...")
        seed_database()
        threats = list(db["threats"].find({}, {"embedding": 0}))

    for status_group in ["Active", "Anticipated", "Evolving", "Resolved"]:
        group_items = [t for t in threats if t.get("status") == status_group]
        print(f"\n▶ {status_group.upper()} THREATS ({len(group_items)}):")
        for t in group_items:
            print(f"  • [{t.get('cve_id')}] {t.get('title'):<40} | {t.get('platform'):<8} | CVSS: {t.get('cvss')}")


def test_mitigate():
    print("\n--- ⚡ Conversational Threat Mitigation ---")
    db = get_database()
    active_threats = list(db["threats"].find({"status": "Active"}, {"embedding": 0}))
    
    if not active_threats:
        print("[!] No active threats found to mitigate. Re-seeding database first...")
        seed_database()
        active_threats = list(db["threats"].find({"status": "Active"}, {"embedding": 0}))
        
    print("Available Active Threats to mitigate:")
    for idx, t in enumerate(active_threats, 1):
        print(f"  [{idx}] {t.get('cve_id')} - {t.get('title')} ({t.get('platform')})")
        
    sel = input(f"\nSelect threat number to mitigate (1-{len(active_threats)}) [Default: 1]: ").strip()
    idx = int(sel) - 1 if sel.isdigit() and 1 <= int(sel) <= len(active_threats) else 0
    target_cve = active_threats[idx]["cve_id"]

    confirm = input(f"Confirm mitigation for {target_cve}? (yes/no) [Default: yes]: ").strip().lower()
    if confirm in ["", "y", "yes"]:
        bot = ThreatScannerBot()
        res = bot.apply_confirmed_mitigation(target_cve, operator_notes="Manual CLI confirmation by Ayush Yadav")
        print("\n[OK] Transaction Committed in MongoDB:")
        print(f"  • Status:     {res['new_status']}")
        print(f"  • Command:    {res['executed_command']}")
        print(f"  • Timestamp:  {res['mitigated_at']}")
    else:
        print("[*] Mitigation cancelled.")


def test_view_audit():
    print("\n--- 📜 Recent MongoDB Audit Trail Logs ---")
    db = get_database()
    logs = list(db["audit_log"].find({}, {"_id": 0}).sort("timestamp", -1).limit(5))
    if not logs:
        print("[!] No audit logs found yet.")
    else:
        for idx, l in enumerate(logs, 1):
            print(f"  {idx}. [{l.get('timestamp')}] Event: {l.get('event')} | Actor: {l.get('actor', l.get('operator'))}")
            if l.get("cve_id"):
                print(f"     Target CVE: {l.get('cve_id')} -> New Status: {l.get('new_status')}")


def main():
    print_banner()
    db = get_database()
    if db["threats"].count_documents({}) == 0:
        print("[*] Initializing MongoDB database with threat data...")
        seed_database()

    while True:
        show_menu()
        choice = input("Enter option (0-7): ").strip()
        if choice == "1":
            test_ask_ai()
        elif choice == "2":
            test_scan_system()
        elif choice == "3":
            test_view_threats()
        elif choice == "4":
            test_mitigate()
        elif choice == "5":
            test_view_audit()
        elif choice == "6":
            seed_database()
        elif choice == "7":
            import run_demo
            run_demo.run_full_demonstration()
        elif choice == "8":
            import feed_100k_parameters
            feed_100k_parameters.feed_100k_parameters_to_mongodb()
        elif choice == "9":
            test_ollama()
        elif choice == "0":
            print("\nExiting. Good luck with your presentation, Ayush!\n")
            break
        else:
            print("[!] Invalid option. Please enter 0 to 9.")


if __name__ == "__main__":
    main()
