# 🚀 Step-by-Step Guide: How to Run the Threat Intelligence AI Platform

**Course:** 23CSE528 — NoSQL Databases using MongoDB  
**Author:** Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)  
**Faculty Guide:** Prof. Sujeet S Jagtap  

---

## ⚡ Fast Track: Choose How You Want to Run

| If You Want To... | Do This (Quick Command) | What It Gives You |
|---|---|---|
| **Test in 5 Seconds** | `python quick_test.py` | Interactive terminal menu to query AI, scan machine, and mitigate threats |
| **Verify All 18 Exercises** | `python run_demo.py` | Automated 8-phase benchmark with complete pass verification |
| **Launch Full Web GUI** | Run Backend & Streamlit (Commands below) | Rich web dashboard at `http://localhost:8501` with chat, metrics & 1-click fixes |
| **Run in Docker** | `docker compose up --build` | Full multi-tier containerized stack with MongoDB 7.0 |

---

## 📋 Prerequisites
Open PowerShell or your terminal and ensure you are in the `llm` directory:
```powershell
cd "d:\mangoDB and no sql\llm"
```
*(Dependencies are already installed: `fastapi`, `uvicorn`, `streamlit`, `pymongo`, `mongomock`, `pydantic`, `requests`, `psutil`).*

---

## 🟢 Method 1: The Interactive Console Tester (Fastest & Simplest)

Since you already have `quick_test.py` open in your editor, you can test everything right in your terminal:

```powershell
python quick_test.py
```

### What You Will See:
```text
======================================================================
      🛡️  THREAT INTELLIGENCE AI - QUICK TEST & DEMO
      Course: 23CSE528 NoSQL Databases using MongoDB
      Student: Ayush Yadav (USN: 24BTLCL003)
======================================================================

Choose an action to test:
  [1] 💬 Ask AI a Question (RAG Semantic Search & Advisory)
  [2] 🤖 Scan My Machine for Vulnerabilities (Background Bot)
  [3] 📋 View All Threats in MongoDB (Grouped by Lifecycle)
  [4] ⚡ Mitigate an Active Threat (ACID Transaction)
  [5] 📜 View MongoDB Audit Trail Log
  [6] 🔄 Re-seed Threat Intelligence Database
  [7] 🚀 Run Full Automated End-to-End Demo
  [0] ❌ Exit
----------------------------------------------------------------------
Enter option (0-7):
```

### Try These Options:
1. **Press `1`**: Ask the AI: *"What are the active critical threats on Windows?"*  
   *Watch it retrieve grounded records from MongoDB and generate an advisory.*
2. **Press `2`**: Watch the bot audit your Windows machine's listening ports (Port 445, 135, etc.) and flag risks!
3. **Press `4`**: Select an active threat and type `yes` to authorize mitigation via an **ACID Transaction (Exercise 10)**.

---

## 🌐 Method 2: The Full Visual Web Application (Recommended for Presentation)

This launches the full graphical web application with the **Chat UI, Real-Time Threat Metrics, and 1-Click Interactive Remediation**.

### Step 1: Start the Backend API Server
Open a PowerShell terminal and run:
```powershell
cd "d:\mangoDB and no sql\llm"
uvicorn threat_intel_api:app --reload --port 8000
```
- ✅ You should see: `Uvicorn running on http://0.0.0.0:8000`
- 📖 Interactive Swagger API Docs: Open [http://localhost:8000/docs](http://localhost:8000/docs)
- 🩺 Health Check: Open [http://localhost:8000/health](http://localhost:8000/health)

---

### Step 2: Start the Streamlit Frontend Web App
Open a **second** PowerShell window and run:
```powershell
cd "d:\mangoDB and no sql\llm"
streamlit run streamlit_app.py --server.port 8501
```
- 🌐 Open your web browser at: **`http://localhost:8501`**

---

### Step 3: Interacting with the Web Application
Once the browser opens:

1. **Check Live Threat Metrics (Top Banner)**:
   - Observe real-time counts for **Total Threats**, 🔴 **Active**, 🟡 **Anticipated**, 🟣 **Evolving**, and 🟢 **Resolved**.
2. **Conversational AI Chat (Tab 1)**:
   - Click one of the quick prompt buttons:
     - *"Active Windows Threats"*
     - *"Evolving Linux Exploits"*
     - *"Mitigate CVE-2024-21413"*
   - Expand the **"Retrieved MongoDB Threat Records"** box to see the exact context chunks and CVSS scores retrieved from MongoDB.
3. **Run Autonomous Vulnerability Scan (Left Sidebar)**:
   - Click **"🚀 Run System Vulnerability Scan"**.
   - The bot audits your laptop's open ports and security configurations, reporting detected vulnerabilities directly into MongoDB!
4. **1-Click Mitigation (Tab 2 - Threat Intelligence Matrix)**:
   - Look at any Active threat (e.g. `CVE-2024-21413`).
   - Click the orange **"⚡ Mitigate"** button.
   - The button instantly turns to **"✅ Resolved"**, the dashboard counter updates, and an audit entry is recorded!
5. **View Tamper-Evident Audit Trail (Tab 3)**:
   - Check the **"System Audit Trail"** table to see your operator name (`Ayush Yadav`), exact timestamps, and executed remediation commands.

---

## 🤖 Method 3: 1-Click Automated Benchmark Demonstration

If you want to run a complete, non-interactive script that validates all 18 exercises from start to finish and prints a structured benchmark report:

```powershell
cd "d:\mangoDB and no sql\llm"
python run_demo.py
```

### What It Executes Automatically:
- **Phase 1**: Connects to MongoDB and builds compound indexes (`idx_platform_status`, `idx_severity_cvss`).
- **Phase 2**: Seeds 14 multi-platform threat intelligence documents with 384-d vector embeddings.
- **Phase 3**: Runs MongoDB Aggregation Framework analytics (`$group`, `$sort`, `$avg`).
- **Phase 4**: Performs semantic vector search and Reciprocal Rank Fusion (RRF) context retrieval.
- **Phase 5**: Generates structured AI advisory.
- **Phase 6**: Runs autonomous scanner bot on host machine detecting listening ports.
- **Phase 7**: Executes conversational mitigation via multi-document ACID transaction.
- **Phase 8**: Verifies immutable audit logs in MongoDB.

---

## 🐳 Method 4: Run with Docker Compose

If you have Docker Desktop installed and want to run the full stack containerized:

```powershell
cd "d:\mangoDB and no sql\llm"
docker compose up --build
```

- **Frontend**: `http://localhost:8501`
- **Backend API**: `http://localhost:8000`
- **MongoDB**: `localhost:27017`

To stop:
```powershell
docker compose down
```

---

## ❓ Troubleshooting & FAQs

### Q1: What if local MongoDB service is not running on my machine?
**Answer:** Zero configuration needed! The application includes a smart `db_connector.py` that automatically falls back to an in-memory `mongomock` engine. Everything—indexing, CRUD, aggregation, and vector search—works out of the box without errors.

### Q2: Port 8000 or 8501 is already in use?
Run on custom ports:
```powershell
uvicorn threat_intel_api:app --port 8080
streamlit run streamlit_app.py --server.port 8502
```

### Q3: How do I present this to Prof. Sujeet S Jagtap?
Open [presentation.md](file:///d:/mangoDB%20and%20no%20sql/llm/presentation.md). It gives you a complete slide-by-slide script, exercise-by-exercise defense arguments, and answers to typical viva questions!
