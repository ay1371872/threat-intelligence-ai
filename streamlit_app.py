"""Streamlit Interactive Threat Intelligence & Autonomous Remediation Frontend
Synthesizes Appendix A.5 with real-time Threat Intelligence, RAG Chat, and Bot Controls.
Dual-Mode: Connects to FastAPI Backend if running, or runs full RAG + NoSQL engine directly
(100% cloud-ready for Streamlit Community Cloud and Docker).
Student: Ayush Yadav (USN: 24BTLCL003) | Course: 23CSE528 NoSQL Databases using MongoDB
"""

import os
import sys
import requests
import streamlit as st
import pandas as pd
from datetime import datetime

# Ensure imports resolve whether running from repository root or llm/ folder
CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(CUR_DIR, "llm")):
    sys.path.insert(0, os.path.join(CUR_DIR, "llm"))
else:
    sys.path.insert(0, CUR_DIR)

from db_connector import get_database, get_mongo_client, initialize_database_indexes_and_schemas
from seed_threat_data import seed_database
import importlib
import rag_engine
try:
    importlib.reload(rag_engine)
except Exception:
    pass
from rag_engine import generate_chat_response, retrieve_threat_context
from laptop_connector import get_live_laptop_telemetry, answer_laptop_question
check_ollama_status = getattr(
    rag_engine,
    "check_ollama_status",
    lambda: {
        "online": False,
        "base_url": "http://localhost:11434",
        "configured_model": "llama3.2:1b",
        "installed_models": [],
        "model_ready": False
    }
)
from threat_scanner_bot import ThreatScannerBot

# Configure page layout
st.set_page_config(
    page_title="Threat Intel AI | MongoDB NoSQL",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

# --- Custom Styling ---
st.markdown("""
<style>
    .main-header { font-size: 28px; font-weight: 700; color: #1E3A8A; margin-bottom: 0px; }
    .sub-header { font-size: 15px; color: #4B5563; margin-bottom: 15px; }
    .metric-card { background-color: #F3F4F6; border-radius: 8px; padding: 12px; border-left: 4px solid #1E3A8A; }
    .threat-tag-active { background-color: #FEE2E2; color: #991B1B; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .threat-tag-anticip { background-color: #FEF3C7; color: #92400E; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .threat-tag-evolve { background-color: #F3E8FF; color: #6B21A8; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .threat-tag-resolved { background-color: #D1FAE5; color: #065F46; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
</style>
""", unsafe_allow_html=True)


# --- Initialize Local Database if empty ---
db = get_database()
if db["threats"].count_documents({}) == 0:
    seed_database()

scanner_bot = ThreatScannerBot()

# --- Initialize Session State ---
if "messages" not in st.session_state:
    st.session_state.messages = [
        {
            "role": "assistant",
            "content": (
                "👋 Hello! I am your **Threat Intelligence AI Assistant**, powered by **MongoDB Atlas Vector Search** "
                "and synthetic RAG. I track **Anticipated**, **Active**, **Evolving**, and **Resolved** threats "
                "across **Linux, Windows, macOS, Android, and iOS**.\n\n"
                "Ask me about any security advisory, request mitigation scripts, or ask the background bot to scan your machine!"
            )
        }
    ]

if "session_id" not in st.session_state:
    st.session_state.session_id = f"session-ayush-{int(datetime.utcnow().timestamp())}"


# --- Header ---
col_head1, col_head2 = st.columns([3, 1])
with col_head1:
    st.markdown('<div class="main-header">🛡️ Threat Intelligence AI Platform</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">JAIN University • 23CSE528 NoSQL Databases using MongoDB • Ayush Yadav (24BTLCL003)</div>', unsafe_allow_html=True)
with col_head2:
    st.caption(f"**Session:** `{st.session_state.session_id[:18]}...`")


# --- Fetch Backend Status or Activate Local Engine ---
backend_online = False
health_data = {}
try:
    resp = requests.get(f"{BACKEND_URL}/health", timeout=1.5)
    if resp.status_code == 200:
        backend_online = True
        health_data = resp.json()
except Exception:
    backend_online = False


# --- Sidebar ---
with st.sidebar:
    st.header("⚙️ Platform Controls")
    
    # Status indicator
    if backend_online:
        st.success(f"🟢 Backend Online ({health_data.get('llm_backend', 'Ollama SLM')})")
        st.caption(f"Engine: FastAPI Microservice")
    else:
        st.success("🟢 Standalone Python Engine (Direct RAG + NoSQL)")
        st.caption("Engine: Ollama SLM / Embedded Cyber-SLM")

    st.markdown("---")
    st.subheader("🦙 Ollama Model Engine")
    ollama_stat = check_ollama_status()
    default_models = ["llama3.2:1b", "llama3.2:3b", "llama3.1:8b", "llama3:latest", "mistral", "phi3:mini"]
    
    if ollama_stat.get("online"):
        st.success(f"🟢 **Ollama Connected** (`{ollama_stat.get('base_url')}`)")
        installed_models = ollama_stat.get("installed_models", [])
        if installed_models:
            all_options = list(dict.fromkeys(installed_models + default_models))
        else:
            all_options = default_models
    else:
        st.warning(f"🟡 **Ollama Server Offline** (`{ollama_stat.get('base_url')}`)")
        st.caption("Active fallback: Embedded Cyber-SLM engine. To connect Ollama: run `ollama run llama3.2:1b` or use Docker Compose.")
        all_options = default_models

    selected_ollama_model = st.selectbox("Active Model", all_options, index=0)

    st.markdown("---")
    st.subheader("🔍 Threat Filters")
    platform_choice = st.selectbox("Target Platform", ["All", "Windows", "Linux", "macOS", "Android", "iOS"])
    status_choice = st.selectbox("Threat Status", ["All", "Active", "Anticipated", "Evolving", "Resolved"])

    st.markdown("---")
    st.subheader("🤖 Autonomous Scanner Bot")
    st.info("The background daemon audits listening ports and operating system exposures.")
    
    if st.button("🚀 Run System Vulnerability Scan", use_container_width=True):
        with st.spinner("Bot auditing system telemetry and network ports..."):
            try:
                if backend_online:
                    s_resp = requests.post(f"{BACKEND_URL}/scan", json={}, timeout=15)
                    s_data = s_resp.json()
                else:
                    s_data = scanner_bot.perform_system_vulnerability_scan()

                st.success(f"Audit Complete! Host: {s_data.get('host')}")
                st.write(f"• Open Ports: `{s_data.get('open_ports')}`")
                st.write(f"• Vulnerabilities: `{len(s_data.get('vulnerabilities_detected', []))}`")
                st.rerun()
            except Exception as ex:
                st.error(f"Scan failed: {ex}")

    if st.button("⚡ Feed 100,000 Parameters to DB", use_container_width=True):
        with st.spinner("Ingesting 100,000 threat parameters into MongoDB (Bulk Operations)..."):
            try:
                if backend_online:
                    f_res = requests.post(f"{BACKEND_URL}/feed-100k", timeout=180)
                    d = f_res.json()
                else:
                    from feed_100k_parameters import feed_100k_parameters_to_mongodb
                    d = feed_100k_parameters_to_mongodb()
                st.success(f"✅ Ingested {d.get('parameters_fed', 100000):,} parameters in {d.get('elapsed_seconds')}s! Throughput: {d.get('throughput'):,.0f} docs/sec")
                st.rerun()
            except Exception as ex:
                st.error(f"Ingestion error: {ex}")

    if st.button("🔄 Reset / Re-seed Intelligence DB", use_container_width=True):
        seed_database()
        st.success("MongoDB Threat collection re-seeded!")
        st.rerun()

    if st.button("🗑️ Clear Chat History", use_container_width=True):
        st.session_state.messages = []
        st.rerun()


# --- Real-Time Analytics Banner (Exercise 5 Aggregation) ---
stats_data = {"categories": {"Anticipated": 0, "Active": 0, "Evolving": 0, "Resolved": 0}, "total_threats": 0}
try:
    if backend_online:
        s_res = requests.get(f"{BACKEND_URL}/stats", timeout=3)
        if s_res.status_code == 200:
            stats_data = s_res.json()
    else:
        # Direct Aggregation Framework execution (Exercise 5)
        pipeline = [{"$group": {"_id": "$status", "count": {"$sum": 1}}}]
        status_counts = list(db["threats"].aggregate(pipeline))
        c_dict = {item["_id"]: item["count"] for item in status_counts if item["_id"]}
        stats_data = {
            "total_threats": db["threats"].count_documents({}),
            "categories": {
                "Anticipated": c_dict.get("Anticipated", 0),
                "Active": c_dict.get("Active", 0),
                "Evolving": c_dict.get("Evolving", 0),
                "Resolved": c_dict.get("Resolved", 0)
            }
        }
except Exception:
    pass

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Total Threats", stats_data.get("total_threats", 0))
m2.metric("🔴 Active", stats_data["categories"].get("Active", 0))
m3.metric("🟡 Anticipated", stats_data["categories"].get("Anticipated", 0))
m4.metric("🟣 Evolving", stats_data["categories"].get("Evolving", 0))
m5.metric("🟢 Resolved", stats_data["categories"].get("Resolved", 0))
param_count = db["threat_parameters"].count_documents({})
m6.metric("⚡ 100K Telemetry", f"{param_count:,}" if param_count else "0")

st.markdown("---")


# --- Main Tabs ---
tab_chat, tab_matrix, tab_bot, tab_100k, tab_laptop = st.tabs([
    "💬 Conversational Threat AI",
    "📊 Threat Intelligence Matrix",
    "🤖 Scanner Bot & Audit Trail",
    "⚡ 100K Scale Telemetry",
    "💻 Live Laptop Diagnostics"
])


# === TAB 1: Conversational Chat ===
with tab_chat:
    # Example Prompt Quick Buttons
    st.caption("Quick Queries & Laptop Diagnostics:")
    c_btn1, c_btn2, c_btn3, c_btn4 = st.columns(4)
    quick_prompt = None
    if c_btn1.button("🔴 Active Windows Threats", use_container_width=True):
        quick_prompt = "What are the Active threats currently affecting Windows?"
    if c_btn2.button("🟣 Evolving Linux Exploits", use_container_width=True):
        quick_prompt = "List evolving Linux kernel privilege escalation threats."
    if c_btn3.button("🟡 Anticipated Zero-Days", use_container_width=True):
        quick_prompt = "What are the anticipated zero-days across Android and iOS?"
    if c_btn4.button("⚡ Mitigate CVE-2024-21413", use_container_width=True):
        quick_prompt = "Mitigate CVE-2024-21413 on my system immediately."

    c_btn5, c_btn6, c_btn7, c_btn8 = st.columns(4)
    if c_btn5.button("💻 Full Laptop Specs", use_container_width=True):
        quick_prompt = "What are my full laptop hardware specifications?"
    if c_btn6.button("🔋 Live Battery Status", use_container_width=True):
        quick_prompt = "How much battery is left and is my charger plugged in?"
    if c_btn7.button("⚙️ Live CPU & RAM Load", use_container_width=True):
        quick_prompt = "What is my live CPU usage and RAM usage right now?"
    if c_btn8.button("📶 Wi-Fi & IP Address", use_container_width=True):
        quick_prompt = "What Wi-Fi network and IP address is this laptop connected to?"

    c_btn9, c_btn10, c_btn11, c_btn12 = st.columns(4)
    if c_btn9.button("💽 Disk Free Space", use_container_width=True):
        quick_prompt = "How much free disk space is available on my C and D drives?"
    if c_btn10.button("🎮 Dedicated GPU Info", use_container_width=True):
        quick_prompt = "What dedicated graphics card does this laptop have?"
    if c_btn11.button("⏱️ System Uptime", use_container_width=True):
        quick_prompt = "How long has my laptop been running and when was it booted?"
    if c_btn12.button("🎓 Project & Author", use_container_width=True):
        quick_prompt = "Who created this project and what is the university attribution?"

    c_btn13, c_btn14, c_btn15, c_btn16 = st.columns(4)
    if c_btn13.button("🔍 Is Claude Installed?", use_container_width=True):
        quick_prompt = "Is Claude installed on my laptop?"
    if c_btn14.button("🔍 Is Ollama Installed?", use_container_width=True):
        quick_prompt = "Is Ollama installed on my laptop?"
    if c_btn15.button("🔍 Is VS Code Available?", use_container_width=True):
        quick_prompt = "Is VS Code available on my laptop?"
    if c_btn16.button("🛠️ Check Python & Git", use_container_width=True):
        quick_prompt = "Do I have Python and Git installed on my laptop?"

    # Render Chat History
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if "sources" in msg and msg["sources"]:
                with st.expander(f"📚 Retrieved MongoDB Threat Records ({len(msg['sources'])})"):
                    for s in msg["sources"]:
                        st.markdown(f"**[{s.get('cve_id')}] {s.get('title')}** | Platform: `{s.get('platform')}` | CVSS: `{s.get('cvss')}` (RAG Score: `{s.get('score', 0):.4f}`)")
                        st.caption(f"Procedure: {s.get('mitigation_procedure')[:130]}...")

    # Chat Input
    user_query = st.chat_input("Ask about CVEs, platform vulnerabilities, or type 'mitigate CVE-XXXX'...")
    final_input = quick_prompt if quick_prompt else user_query

    if final_input:
        st.session_state.messages.append({"role": "user", "content": final_input})
        with st.chat_message("user"):
            st.markdown(final_input)

        with st.chat_message("assistant"):
            with st.spinner("Retrieving MongoDB Threat Context & Synthesizing Advisory..."):
                try:
                    if backend_online:
                        chat_payload = {
                            "session_id": st.session_state.session_id,
                            "message": final_input,
                            "platform": None if platform_choice == "All" else platform_choice,
                            "status": None if status_choice == "All" else status_choice,
                            "backend": "ollama",
                            "model": selected_ollama_model
                        }
                        c_res = requests.post(f"{BACKEND_URL}/chat", json=chat_payload, timeout=60)
                        data = c_res.json()
                        response_text = data["response"]
                        sources = data.get("sources", [])
                        model_used = data.get("model_used", f"Ollama ({selected_ollama_model})")
                    else:
                        # Direct RAG Engine Execution
                        p_filt = None if platform_choice == "All" else platform_choice
                        s_filt = None if status_choice == "All" else status_choice
                        data = generate_chat_response(
                            final_input,
                            session_id=st.session_state.session_id,
                            platform=p_filt,
                            status=s_filt,
                            backend="ollama",
                            model_name=selected_ollama_model
                        )
                        response_text = data["response"]
                        sources = data.get("sources", [])
                        model_used = data.get("model_used", f"Ollama ({selected_ollama_model})")

                    st.markdown(response_text)
                    st.caption(f"🧠 **Model Engine:** `{model_used}`")
                    if sources:
                        with st.expander(f"📚 Grounded MongoDB Threat Context ({len(sources)} items)"):
                            for s in sources:
                                st.write(f"- **{s.get('cve_id')}**: {s.get('title')} (Platform: {s.get('platform')}, CVSS: {s.get('cvss')})")
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": response_text,
                        "sources": sources,
                        "model_used": model_used
                    })
                except Exception as err:
                    st.error(f"Inference error: {err}")


# === TAB 2: Threat Matrix & 1-Click Interactive Mitigation ===
with tab_matrix:
    st.subheader("📋 Operational Threat Matrix")
    
    t_query = {}
    if platform_choice != "All":
        t_query["platform"] = {"$regex": f"^{platform_choice}$", "$options": "i"}
    if status_choice != "All":
        t_query["status"] = {"$regex": f"^{status_choice}$", "$options": "i"}

    try:
        if backend_online:
            t_params = {}
            if platform_choice != "All":
                t_params["platform"] = platform_choice
            if status_choice != "All":
                t_params["status"] = status_choice
            t_res = requests.get(f"{BACKEND_URL}/threats", params=t_params, timeout=5)
            threats_list = t_res.json().get("threats", [])
        else:
            threats_list = list(db["threats"].find(t_query, {"embedding": 0}).sort("cvss", -1))

        if threats_list:
            for t in threats_list:
                with st.container():
                    col_cve, col_info, col_act = st.columns([2, 5, 2])
                    with col_cve:
                        st.markdown(f"### `{t['cve_id']}`")
                        st.caption(f"Platform: **{t['platform']}** | CVSS: **{t['cvss']}**")
                        status = t["status"]
                        badge_cls = {
                            "Active": "threat-tag-active",
                            "Anticipated": "threat-tag-anticip",
                            "Evolving": "threat-tag-evolve",
                            "Resolved": "threat-tag-resolved"
                        }.get(status, "threat-tag-active")
                        st.markdown(f'<span class="{badge_cls}">{status.upper()}</span>', unsafe_allow_html=True)

                    with col_info:
                        st.markdown(f"**{t['title']}**")
                        st.write(t["description"])
                        with st.expander("🛠️ Mitigation Procedure & Command"):
                            st.markdown(f"**Procedure:** {t['mitigation_procedure']}")
                            if t.get("automated_fix_command"):
                                st.code(t["automated_fix_command"], language="bash")
                            if t.get("mitigated_at"):
                                st.success(f"Mitigated At: {t['mitigated_at']}")

                    with col_act:
                        if t["status"] in ["Active", "Evolving"]:
                            if st.button(f"⚡ Mitigate", key=f"mit_{t['cve_id']}", use_container_width=True):
                                with st.spinner("Applying mitigation transaction in MongoDB..."):
                                    if backend_online:
                                        m_req = requests.post(
                                            f"{BACKEND_URL}/mitigate",
                                            json={"cve_id": t["cve_id"], "confirm": True, "operator": "Ayush Yadav"},
                                            timeout=10
                                        )
                                        m_data = m_req.json()
                                    else:
                                        m_data = scanner_bot.apply_confirmed_mitigation(t["cve_id"], "Approved via Web UI")
                                    st.toast(f"✅ {t['cve_id']} successfully mitigated!", icon="🛡️")
                                    st.rerun()
                        else:
                            st.button("✅ Resolved", key=f"res_{t['cve_id']}", disabled=True, use_container_width=True)

                    st.divider()
        else:
            st.info("No threats found matching current filter.")
    except Exception as ex:
        st.error(f"Error loading threats: {ex}")


# === TAB 3: Scanner Bot & Audit Trail ===
with tab_bot:
    st.subheader("🤖 Background Vulnerability Scanner & Diagnostics")
    
    col_host1, col_host2 = st.columns(2)
    with col_host1:
        st.markdown("#### 💻 Host Machine Status")
        import socket, platform as py_plat
        st.write(f"- **Operating System:** `{py_plat.system()} {py_plat.release()}`")
        st.write(f"- **Host Architecture:** `{py_plat.machine()}`")
        st.write(f"- **Host Machine Name:** `{socket.gethostname()}`")
    with col_host2:
        st.markdown("#### 🔒 Security Enforcement Policy")
        st.write("- **Database Storage:** `MongoDB Atlas / In-Memory NoSQL`")
        st.write("- **Consistency Level:** `w:majority (ACID Transactional Auditing)`")
        st.write("- **Vector Indexing:** `384-dimensional HNSW Cosine Vectors`")

    st.markdown("---")
    st.subheader("📜 System Audit Trail (MongoDB `audit_log`)")
    try:
        logs = list(db["audit_log"].find({}, {"_id": 0}).sort("timestamp", -1).limit(15))
        if logs:
            df_logs = pd.DataFrame(logs)
            st.dataframe(df_logs, use_container_width=True)
        else:
            st.info("No audit logs recorded yet.")
    except Exception as ex:
        st.error(f"Failed to fetch audit trail: {ex}")


# === TAB 4: 100,000 Parameter High-Scale Telemetry ===
with tab_100k:
    st.subheader("⚡ 100,000 Security Parameter Ingestion & Analytics")
    st.markdown(
        "Demonstrates high-throughput bulk insertion, compound indexing (`IXSCAN`), "
        "and multi-stage aggregation pipelines over **100,000 structured cyber parameters** in MongoDB (Exercises 5, 6 & 7)."
    )

    col_p = db["threat_parameters"]
    p_total = col_p.count_documents({})
    
    if p_total > 0:
        anomalies = col_p.count_documents({"is_anomaly": True})
        p_c1, p_c2, p_c3 = st.columns(3)
        p_c1.metric("Total Parameters Stored", f"{p_total:,}")
        p_c2.metric("🚨 Anomalies Detected", f"{anomalies:,}")
        p_c3.metric("🛡️ Normal Parameters", f"{(p_total - anomalies):,}")

        st.markdown("#### 📊 Platform Distribution of 100,000 Parameters")
        pipeline = [{"$group": {"_id": "$platform", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]
        dist_rows = list(col_p.aggregate(pipeline))
        if dist_rows:
            df_dist = pd.DataFrame([(r["_id"], r["count"]) for r in dist_rows if r["_id"]], columns=["Platform", "Parameter Count"])
            st.bar_chart(df_dist.set_index("Platform"))

        st.markdown("#### ⚡ Active Compound Indexes")
        st.code(
            "- db.threat_parameters.createIndex({ platform: 1, threat_status: 1, is_anomaly: 1 })\n"
            "- db.threat_parameters.createIndex({ severity: 1, cvss_score: -1 })\n"
            "- db.threat_parameters.createIndex({ param_id: 1 }, { unique: true })",
            language="javascript"
        )
    else:
        st.info("No parameters loaded yet. Click the button below to feed 100,000 parameters into MongoDB.")
        if st.button("🚀 Ingest 100,000 Parameters Now"):
            with st.spinner("Ingesting 100,000 records into MongoDB..."):
                from feed_100k_parameters import feed_100k_parameters_to_mongodb
                feed_100k_parameters_to_mongodb()
                st.success("Successfully ingested 100,000 parameters!")
                st.rerun()


# === TAB 5: Live Laptop Diagnostics & Hardware Telemetry ===
with tab_laptop:
    st.subheader("💻 Live Laptop Diagnostics & Hardware Telemetry")
    st.markdown(
        "Your AI Chatbot is directly connected to this laptop's hardware sensors, "
        "monitoring real-time power, processor clock speeds, memory utilization, and active network interfaces."
    )

    t = get_live_laptop_telemetry()
    batt = t.get("battery", {})
    cpu = t.get("cpu", {})
    ram = t.get("ram", {})
    net = t.get("network", {})
    disks = t.get("disks", [])
    uptime = t.get("uptime", {})

    # Top KPI Gauges
    c_k1, c_k2, c_k3, c_k4 = st.columns(4)
    batt_pct = f"{batt.get('percent', 30)}%" if batt.get("present") else "AC Power"
    batt_sub = "⚡ Plugged In" if batt.get("power_plugged") else f"🔋 {batt.get('estimated_runtime', 'On Battery')}"
    c_k1.metric("Battery Level", batt_pct, batt_sub)

    c_k2.metric("Live CPU Load", f"{cpu.get('live_usage_percent', 0)}%", f"{cpu.get('physical_cores', 10)} Cores ({cpu.get('current_frequency_mhz', 2400)} MHz)")
    c_k3.metric("RAM Utilization", f"{ram.get('usage_percent', 0)}%", f"{ram.get('available_gb', 0)} GB Available")
    c_k4.metric("Active Wi-Fi", net.get("wifi_ssid", "Connected"), f"IP: {net.get('local_ip', '')}")

    st.markdown("---")
    
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        st.markdown("#### 💽 Disk Partitions & Storage Space")
        for d in disks:
            st.write(f"**Drive {d['drive']}** ({d['file_system']})")
            st.progress(1.0 - (d["free_gb"] / d["total_gb"]))
            st.caption(f"Used: {d['used_gb']} GB / Total: {d['total_gb']} GB • **Free: {d['free_gb']} GB ({d['free_percent']}%)**")

    with col_t2:
        st.markdown("#### ⚡ System & Graphics Hardware")
        st.write(f"• **Laptop Model:** `{t.get('device_model')}`")
        st.write(f"• **Dedicated GPU:** `{t.get('gpu', {}).get('dedicated')}`")
        st.write(f"• **Integrated GPU:** `{t.get('gpu', {}).get('integrated')}`")
        st.write(f"• **Display Resolution:** `{t.get('display', {}).get('resolution')}`")
        st.write(f"• **System Uptime:** `{uptime.get('uptime_formatted')}`")
        st.write(f"• **Boot Time:** `{uptime.get('boot_time')}`")
        st.write(f"• **Operating System:** `{t.get('os_name')} {t.get('os_release')} (Build {t.get('os_version')})`")

    st.markdown("---")
    st.markdown("#### 📊 Top Running Processes by Memory Consumption")
    top_p = t.get("top_processes", [])
    if top_p:
        df_p = pd.DataFrame(top_p)
        st.dataframe(df_p, use_container_width=True)

    if st.button("🔄 Refresh Hardware Telemetry Now"):
        st.rerun()
