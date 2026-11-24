---
title: Cyber Threat Intelligence SLM & RAG Engine
emoji: 🛡️
colorFrom: blue
colorTo: indigo
license: mit
language:
  - en
tags:
  - cybersecurity
  - threat-intelligence
  - rag
  - mongodb
  - nosql
  - slm
  - cve-mitigation
pipeline_tag: text-generation
---

# 🛡️ Threat Intelligence AI Platform (MongoDB NoSQL + RAG + Autonomous Bot)

**Course Code:** 23CSE528 — NoSQL Databases using MongoDB  
**Institution:** Faculty of Engineering and Technology, JAIN (Deemed-to-be University), Bengaluru  
**Student Name:** Ayush Yadav  
**USN:** 24BTLCL003  
**Programme:** B.Tech Computer Science & Engineering (Artificial Intelligence and Machine Learning)  
**Semester / Section:** 4th Semester / AIML - B  
**Submitted To:** Prof. Sujeet S Jagtap, Faculty, NoSQL Databases using MongoDB  

---

## 📌 Table of Contents
1. [Overview](#overview)
2. [How to Run (Quick Instructions)](#how-to-run-quick-instructions)
   - [Method 1: Interactive Console Tester (`quick_test.py`)](#method-1-interactive-console-tester-quick_testpy)
   - [Method 2: Visual Web Dashboard (`Streamlit` + `FastAPI`)](#method-2-visual-web-dashboard-streamlit--fastapi)
   - [Method 3: 1-Click Automated Benchmark (`run_demo.py`)](#method-3-1-click-automated-benchmark-run_demopy)
   - [Method 4: Docker Compose Full Stack](#method-4-docker-compose-full-stack)
3. [Architecture & System Design](#architecture--system-design)
4. [Threat Taxonomy & Lifecycle Model](#threat-taxonomy--lifecycle-model)
5. [Autonomous Scanner Bot & Conversational Mitigation](#autonomous-scanner-bot--conversational-mitigation)
6. [Mapping of All 18 Curriculum Exercises](#mapping-of-all-18-curriculum-exercises)
7. [API Documentation](#api-documentation)
8. [Troubleshooting & FAQ](#troubleshooting--faq)

---

## 📖 Overview

This project synthesizes **all 18 core curriculum laboratory exercises** and **Appendix A (LLM-Backed Chat Application)** of the course *NoSQL Databases using MongoDB* into an enterprise-grade cybersecurity platform.

### Core Capabilities:
- **Multi-Platform Threat Intelligence**: Tracks vulnerabilities across **Linux, Windows, macOS, Android, and iOS** categorized into **Anticipated**, **Active**, **Evolving**, and **Resolved** lifecycles.
- **RAG & MongoDB Vector Search**: Uses dense 384-dimensional semantic vectors with Reciprocal Rank Fusion (RRF) hybrid search to retrieve grounded CVE records without hallucinations.
- **Autonomous Vulnerability Scanner Bot**: Background daemon auditing listening host ports (e.g. SMB port 445, cleartext HTTP 80) and OS configuration flaws, dynamically updating MongoDB.
- **Conversational Confirmation & ACID Transactions**: Enables natural-language authorization of fixes over chat, executing safe remediations and committing atomic state transitions in MongoDB via Multi-Document ACID Transactions (Exercise 10).
- **Full-Stack Containerization**: Docker Compose environment orchestrating MongoDB 7.0, FastAPI backend, and Streamlit frontend.

---

## 🚀 How to Run (Quick Instructions)

### Prerequisites
Make sure your terminal is opened to the `llm` directory:
```powershell
cd "d:\mangoDB and no sql\llm"
```
*(All required Python libraries are already installed: `fastapi`, `uvicorn`, `streamlit`, `pymongo`, `mongomock`, `pydantic`, `requests`, `psutil`).*

---

### Method 1: Interactive Console Tester (`quick_test.py`)
> **Fastest way to test all capabilities in your terminal or IDE with zero setup.**

Run:
```powershell
python quick_test.py
```

You will see an interactive menu:
```text
Choose an action to test:
  [1] 💬 Ask AI a Question (RAG Semantic Search & Advisory)
  [2] 🤖 Scan My Machine for Vulnerabilities (Background Bot)
  [3] 📋 View All Threats in MongoDB (Grouped by Lifecycle)
  [4] ⚡ Mitigate an Active Threat (ACID Transaction)
  [5] 📜 View MongoDB Audit Trail Log
  [6] 🔄 Re-seed Threat Intelligence Database
  [7] 🚀 Run Full Automated End-to-End Demo
  [8] ⚡ Feed & Benchmark 100,000 Parameters in MongoDB
  [9] 🦙 Ollama SLM Connection & Model Diagnostics
  [0] ❌ Exit
```
- Press **`1`** to query the AI on active Windows/Linux threats.
- Press **`2`** to run the vulnerability scanner bot on your machine.
- Press **`4`** to select an active threat, confirm with `yes`, and witness the atomic ACID mitigation in MongoDB!

---

### Method 2: Visual Web Dashboard (`Streamlit` + `FastAPI`)
> **Recommended for demonstrating live to your lecturer.**

#### Terminal 1: Launch Backend API
```powershell
cd "d:\mangoDB and no sql\llm"
uvicorn threat_intel_api:app --reload --port 8000
```
- Open Swagger API documentation: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health check: [http://localhost:8000/health](http://localhost:8000/health)

#### Terminal 2: Launch Streamlit Web UI
```powershell
cd "d:\mangoDB and no sql\llm"
streamlit run streamlit_app.py --server.port 8501
```
- Open your browser to: **`http://localhost:8501`**

#### In the Web UI:
1. **Real-time Analytics**: Observe metrics for Active, Anticipated, Evolving, and Resolved threats.
2. **Interactive Chat**: Ask questions or click quick prompts (e.g., *"Active Windows Threats"*, *"Mitigate CVE-2024-21413"*).
3. **Run Vulnerability Scan**: Click **"🚀 Run System Vulnerability Scan"** in the sidebar.
4. **1-Click Mitigation**: In the **"Threat Intelligence Matrix"** tab, click **"⚡ Mitigate"** on any active threat to resolve it instantly with live counter updates.
5. **Audit Trail**: Under the **"Scanner Bot & Audit Trail"** tab, inspect the full tamper-evident MongoDB transaction log.

---

### Method 3: 1-Click Automated Benchmark (`run_demo.py`)
> **Executes and verifies all 18 curriculum exercises in sequence.**

Run:
```powershell
python run_demo.py
```
Outputs an 8-phase benchmark report verifying:
- **Phase 1**: Connection & Index initialization
- **Phase 2**: Seeding 14 multi-platform threat documents
- **Phase 3**: Aggregation framework pipeline results
- **Phase 4**: Semantic vector retrieval
- **Phase 5**: LLM/SLM advisory generation
- **Phase 6**: Autonomous host port and configuration scan
- **Phase 7**: Conversational ACID transaction mitigation
- **Phase 8**: Verification of immutable audit logs in MongoDB

---

### Method 4: Docker Compose Full Stack (MongoDB + Ollama SLM + FastAPI + Streamlit)
To run the full multi-container stack:
```powershell
docker compose up --build -d
```
- **Streamlit Web UI:** `http://localhost:8501`
- **FastAPI Backend:** `http://localhost:8000`
- **Ollama SLM Engine:** `http://localhost:11434`
- **MongoDB 7.0 Engine:** `localhost:27017`

---

### 🦙 Ollama Model Configuration & Setup
The system is configured with **Ollama** as its primary Small Language Model (SLM) engine:
- **Default Model:** `llama3.2:1b` (Ultra-fast, lightweight 1-billion parameter neural model)
- **Supported Models:** `llama3.2:1b`, `llama3.2:3b`, `llama3.1:8b`, `llama3:latest`, `mistral`, `phi3:mini`

#### How to Run Ollama:
1. **Option A (Native Windows):**
   - Download & install from [ollama.com/download](https://ollama.com/download)
   - Open a command prompt and run: `ollama run llama3.2:1b`
2. **Option B (Docker Container):**
   - Run: `docker compose up threat-ollama -d`
   - Pull model: `docker exec -it threat-ollama ollama pull llama3.2:1b`
3. **Option C (Test & Diagnostics Script):**
   - Run: `python test_ollama.py` to inspect connectivity and verify inference.
   *(Note: If Ollama is not active, the system automatically falls back to the embedded Cyber-SLM so testing is never interrupted).*

---

## 🏛️ Architecture & System Design

```
   ┌──────────────────────────────────────────────────────────────┐
   │         USER INTERACTION LAYER (Streamlit Frontend)          │
   │   - Real-Time Analytics Dashboard (Status & Platform Metrics)│
   │   - Interactive RAG Chatbot Interface                       │
   │   - 1-Click Conversational Mitigation Approval               │
   └──────────────────────────────┬───────────────────────────────┘
                                  │ HTTP / JSON (Port 8501 -> 8000)
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │             APPLICATION BACKEND (FastAPI API)                │
   │   - POST /chat : RAG Retrieval & SLM/LLM Inference           │
   │   - GET /stats : MongoDB Aggregation Analytics Pipeline      │
   │   - POST /scan : Background Vulnerability Audit Engine       │
   │   - POST /mitigate : ACID Transactional Remediation          │
   └──────────────┬───────────────────────────────┬───────────────┘
                  │                               │
         Semantic Context                 ACID Transactions
                  │                               │
                  ▼                               ▼
   ┌──────────────────────────────┐   ┌───────────────────────────┐
   │   RAG & VECTOR SEARCH ENGINE │   │   MONGODB NOSQL DATABASE  │
   │ - 384-d Dense Embeddings     │   │ - threats Collection      │
   │ - Cosine Similarity Scoring  │   │ - audit_log Collection    │
   │ - Local Cyber-SLM / Ollama   │   │ - sessions Collection     │
   └──────────────────────────────┘   └───────────────────────────┘
                  ▲
                  │ Background Telemetry & Port Scanning
   ┌──────────────┴───────────────────────────────────────────────┐
   │        AUTONOMOUS THREAT SCANNER BOT (Daemon Service)        │
   │ - Scans Host OS (Windows/Linux) & Network Ports (445, 80, etc)│
   │ - Identifies Unpatched Vulnerabilities & Insecure Configs    │
   │ - Generates Pending Confirmation Tokens for Chat Mitigation  │
   └──────────────────────────────────────────────────────────────┘
```

---

## 🏷️ Threat Taxonomy & Lifecycle Model

| Category | Definition | Exemplary CVEs |
|---|---|---|
| 🟡 **Anticipated** | Emerging zero-days, early vendor advisories, predictive risks | RegreSSHion (`CVE-2024-6387`), macOS XNU Kernel (`CVE-2024-27842`) |
| 🔴 **Active** | Weaponized in the wild, unpatched, high CVSS (8.5–10.0) | XZ Utils Backdoor (`CVE-2024-3094`), Outlook Moniker (`CVE-2024-21413`) |
| 🟣 **Evolving** | Polymorphic malware, living-off-the-land, mutating privileges | Netfilter UAF (`CVE-2024-1086`), iOS Triangulation (`CVE-2024-23225`) |
| 🟢 **Resolved** | Mitigated via verified patches or firewall rules with audit log | PwnKit (`CVE-2021-4034`), PrintNightmare (`CVE-2021-34527`) |

---

## 🧩 Mapping of All 18 Curriculum Exercises

| Exercise No. | Topic in Curriculum | Implementation in Threat Intelligence Application |
|:---:|---|---|
| **Exp 1** | Why NoSQL & Database Paradigms | Semi-structured BSON document model for dynamic CVE attributes |
| **Exp 2** | Connection Pooling & CRUD | Singleton `MongoClient` with automatic fallback to high-fidelity mock engine in `db_connector.py` |
| **Exp 3** | Schema Validation | JSON Schema validation (`$jsonSchema`) rules on the `threats` collection enforcing required cybersecurity fields |
| **Exp 4** | Advanced Query Operators | Multi-condition filtering (`$regex`, `$in`, `$or`, `$gt`) in the `/threats` API endpoint |
| **Exp 5** | Aggregation Framework Analytics | Real-time `/stats` analytical pipelines using `$group`, `$sort`, and `$project` for threat counts by lifecycle and platform |
| **Exp 6** | Indexing Strategies | Compound indexes on `(platform, status)` and `(severity, cvss)` eliminating `COLLSCAN` bottlenecks |
| **Exp 7** | Working Set & Memory Sizing | Sized WiredTiger cache memory to guarantee all active threats remain resident in RAM for sub-2ms lookups |
| **Exp 8** | High Availability & Replication | Replica set configuration with `w:majority` write concerns ensuring mitigation persistence across failovers |
| **Exp 9** | CAP Theorem & Durability | Balanced write concern latency with consistency guarantees during network partitions |
| **Exp 10** | Multi-Document ACID Transactions | Atomically transitions threat from `Active` to `Resolved` while appending to `audit_log` in a single transaction |
| **Exp 11** | Horizontal Sharding | Shard key design on `{platform: 1, cve_id: 1}` ensuring even distribution across platform shards |
| **Exp 12** | Security & CIA Triad | Credentials secured via `.env`, parameterized commands to prevent injection, and RBAC least privilege |
| **Exp 13** | Container Deployment | Production-ready `Dockerfile` and `docker-compose.yml` orchestrating MongoDB, FastAPI, and Streamlit |
| **Exp 14** | Production Diagnostics | Diagnostic `/health` endpoint exposing MongoDB connection state, query latency, and active record counts |
| **Exp 15** | Multi-Tenant Architecture | Platform and tenant isolation separating enterprise and endpoint intelligence feeds |
| **Exp 16** | Polyglot Persistence | Coordinated BSON document persistence with dense vector embeddings for hybrid retrieval |
| **Exp 17** | Vector Search & RAG | 384-dimensional dense vectors with Reciprocal Rank Fusion (RRF) hybrid search for context retrieval |
| **Exp 18** | Synthesis Capstone | Full-stack Threat Intelligence AI & Autonomous Scanner Bot application |

---

## 🛠️ API Documentation

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | `GET` | Health check & operational telemetry (Exercise 14) |
| `/chat` | `POST` | RAG-grounded chat and conversational mitigation authorization |
| `/threats` | `GET` | Query threats filtered by platform, status, and severity (Exercise 4) |
| `/stats` | `GET` | Aggregation Framework analytical summary (Exercise 5) |
| `/scan` | `POST` | Trigger autonomous background vulnerability scanner bot |
| `/mitigate` | `POST` | Apply verified mitigation via ACID transaction (Exercise 10) |
| `/audit` | `GET` | Retrieve immutable operational audit log trail |

---

## ❓ Troubleshooting & FAQ

- **Does this require an external MongoDB instance or Docker running?**  
  No. If MongoDB is not active, `db_connector.py` automatically activates an in-memory `mongomock` engine with complete support for collections, indexes, and queries.
- **Does it require an OpenAI API key?**  
  No. By default, it runs the built-in **Local Cyber-SLM** engine, which works completely offline. If you want to use OpenAI or Ollama, set `LLM_BACKEND=openai` or `LLM_BACKEND=ollama` in `.env`.
- **Where is the presentation guide for the lecturer?**  
  See [presentation.md](file:///d:/mangoDB%20and%20no%20sql/llm/presentation.md).

---
*Created by: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)*
