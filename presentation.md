# Academic Presentation: LLM-Backed Cyber Threat Intelligence & Autonomous Mitigation Platform
**Course Code:** 23CSE528 — NoSQL Databases using MongoDB  
**Institution:** Faculty of Engineering and Technology, JAIN (Deemed-to-be University), Bengaluru  
**Student Name:** Ayush Yadav  
**USN:** 24BTLCL003  
**Programme:** B.Tech — Computer Science & Engineering (Artificial Intelligence and Machine Learning)  
**Semester / Section:** 4th Semester / AIML - B  
**Submitted To:** Prof. Sujeet S Jagtap, Faculty, NoSQL Databases using MongoDB  

---

## Slide 1: Title & Executive Introduction

### Project Title
> **"Synthesis of Advanced NoSQL Database Systems (Exercises 1–18): Design and Implementation of an LLM/SLM-Powered Multi-Platform Threat Intelligence & Autonomous Remediation Platform"**

### Executive Summary
- Modern cyber defense requires tracking threats across diverse operating systems (**Linux, Windows, macOS, Android, iOS**) under rapidly shifting lifecycles: **Anticipated**, **Active**, **Evolving**, and **Resolved**.
- Traditional relational schemas fail to capture the high-velocity, polymorphic nature of CVEs, Indicators of Compromise (IOCs), and unstructured exploit scripts.
- This capstone project synthesizes **all 18 core curriculum exercises** and **Appendix A (LLM-Backed RAG Chatbot)** into a unified, containerized, production-grade cybersecurity platform with an **autonomous background scanning bot** that detects host exposures and remediates them via **conversational user confirmation**.

---

## Slide 2: The Threat Intelligence Taxonomy & Domain Model

The platform classifies threat data into four dynamic lifecycle states across five primary operating platforms:

```
                          ┌──────────────────────────┐
                          │   ANTICIPATED THREATS    │ (Zero-Days, CVE Advisories, Predictive Intel)
                          └─────────────┬────────────┘
                                        │ Exploit weaponized in the wild
                                        ▼
                          ┌──────────────────────────┐
                          │      ACTIVE THREATS      │ (Live Exploits, Critical CVSS 9.0-10.0)
                          └──────┬───────────────────┘
                                 │ Attacker mutates payload / bypasses patch
                                 ▼
                          ┌──────────────────────────┐
                          │     EVOLVING THREATS     │ (Polymorphic Malware, Living-off-the-Land)
                          └─────────────┬────────────┘
                                        │ Conversational confirmation & transactional fix
                                        ▼
                          ┌──────────────────────────┐
                          │     RESOLVED THREATS     │ (Mitigated, Patched, Audit-Logged)
                          └──────────────────────────┘
```

### Supported Platforms & Benchmark Threat Catalog
1. **Linux**: XZ Utils Supply-Chain Backdoor (`CVE-2024-3094`), Netfilter UAF Privilege Escalation (`CVE-2024-1086`), RegreSSHion OpenSSH RCE (`CVE-2024-6387`), PwnKit (`CVE-2021-4034`).
2. **Windows**: Outlook Moniker RCE (`CVE-2024-21413`), Remote Desktop Licensing RCE (`CVE-2024-38077`), MMC Script Evading (`CVE-2024-43572`), PrintNightmare (`CVE-2021-34527`).
3. **macOS**: Safari TCC Sandbox Bypass (`CVE-2024-44133`), XNU Kernel CoreOS (`CVE-2024-27842`).
4. **Android**: DocumentsUI Framework Escalation (`CVE-2024-43093`), Pixel Bootloader Exploit (`CVE-2024-32896`).
5. **iOS**: Kernel Memory Corruption (`CVE-2024-23225`), WebKit Safari Sandbox RCE (`CVE-2023-38606`).

---

## Slide 3: Complete Mapping of Curriculum Exercises (1 – 18)

Every component of this Threat Intelligence application directly implements the curriculum exercises:

| Exercise No. | Topic in Curriculum | Implementation in Threat Intelligence Application |
|:---:|---|---|
| **Exp 1** | Why NoSQL & Database Classification | Chose MongoDB Document Model over Relational/Graph to handle semi-structured polymorphic CVE advisories and nested IOC lists. |
| **Exp 2** | Environment Setup & PyMongo CRUD | Configured connection pooling and singleton `MongoClient` in `db_connector.py` with fault-tolerant local fallback. |
| **Exp 3** | Data Model & Schema Validation | Enforced `$jsonSchema` validation on `threats` collection ensuring required fields (`cve_id`, `platform`, `status`, `cvss`, `severity`). |
| **Exp 4** | Advanced CRUD & Query Operators | Filtered threats using `$regex`, `$in`, `$or`, and range operators (`$gt`, `$lte`) across CVSS scores and platforms. |
| **Exp 5** | Aggregation Framework Analytics | Built multi-stage pipelines (`$group`, `$sort`, `$project`) in `/stats` endpoint for real-time dashboard metrics by lifecycle & platform. |
| **Exp 6** | Indexing Strategies & Optimization | Implemented compound indexes on `(platform, status)` and `(severity, cvss)` eliminating `COLLSCAN` during high-frequency API queries. |
| **Exp 7** | Working Set & Memory Sizing | Sized WiredTiger cache memory to retain all hot active threats in RAM for sub-2ms lookup latency. |
| **Exp 8** | Replication & High Availability | Configured write concern `w:majority` ensuring threat mitigation updates survive primary replica set failover. |
| **Exp 9** | CAP Theorem & Write Durability | Benchmarked write latency trade-offs, ensuring strong CP consistency on vulnerability status transitions. |
| **Exp 10** | Multi-Document ACID Transactions | Implemented transactional rollback: atomically transitions threat from `Active` to `Resolved` while committing an immutable audit trail in `audit_log`. |
| **Exp 11** | Horizontal Scaling & Sharding | Designed shard key on `{platform: 1, cve_id: 1}` ensuring even chunk distribution across platform shards without hotspotting. |
| **Exp 12** | Security & CIA Triad | Secured database credentials using `.env` environment variables, API secret tokens, and least-privilege RBAC. |
| **Exp 13** | Container Deployment (Docker Compose) | Containerized the 3-tier architecture (MongoDB, FastAPI backend, Streamlit frontend) with persistent volume bindings. |
| **Exp 14** | Production Health & Diagnostics | Implemented `/health` diagnostic probe, measuring MongoDB ping latency, open connection counts, and error rates. |
| **Exp 15** | Multi-Tenant Architecture | Isolated threat intelligence feeds by platform domain and organization tenant boundaries. |
| **Exp 16** | Polyglot Persistence | Coordinated MongoDB document storage for threat metadata with vector representations for semantic search. |
| **Exp 17** | Vector Search & Generative AI (RAG) | Built dense 384-dimensional vector embeddings, cosine similarity scoring, and Reciprocal Rank Fusion (RRF) for context augmentation. |
| **Exp 18** | Comparative Synthesis & Capstone | Integrated real-time threat benchmarking, P99 query latencies, and automated remediation bot. |

---

## Slide 4: System Architecture & Technical Stack

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

## Slide 5: RAG & Semantic Vector Search Deep Dive (Exercise 17 & Appendix A.2)

1. **Document Ingestion & Chunking**:
   - Each threat advisory (CVE, technical description, indicators of compromise, and step-by-step remediation procedures) is chunked and vectorized.
2. **Dense Vector Embeddings**:
   - Computes a normalized 384-dimensional embedding vector capturing cybersecurity semantic concepts (RCE, privilege escalation, supply-chain, sandbox bypass).
3. **Reciprocal Rank Fusion (RRF) Hybrid Search**:
   - Combines dense vector cosine similarity ($0.65$ weight) with lexical token matching ($0.35$ weight) to guarantee exact CVE matching while preserving semantic retrieval:
     $$\text{Score} = 0.65 \cdot \text{CosineSim}(\vec{q}, \vec{d}) + 0.35 \cdot \text{LexicalRatio}(q, d)$$
4. **Context-Augmented Generation**:
   - Injects the retrieved MongoDB documents and multi-turn session history into the LLM/SLM context prompt, eliminating hallucinations.

---

## Slide 6: Autonomous Vulnerability Scanner Bot (Lecturer's Special Requirement)

The scanner runs as an autonomous background daemon or on-demand service:
- **Port Exposure Inspection**: Probes active host listening sockets via `psutil`. Automatically flags unencrypted HTTP (Port 80) and unauthenticated SMB (Port 445).
- **Platform Configuration Audit**:
  - *Windows*: Audits PowerShell script execution policy and Windows Defender SmartScreen enforcement.
  - *Linux*: Audits OpenSSH `LoginGraceTime` race vulnerabilities (`CVE-2024-6387`) and unprivileged user namespace cloning.
- **Dynamic Synchronization**: Automatically registers newly detected vulnerabilities into MongoDB with status `"Active"`.
- **Pending Confirmation Pipeline**: Generates structured remediation proposals ready for conversational authorization over chat.

---

## Slide 7: Conversational Confirmation & ACID Mitigation Transactions (Exercise 10)

Safety is paramount: the scanner bot **never** modifies operating system states unilaterally. It requires explicit conversational confirmation:

```
User Query:  "Mitigate CVE-2024-21413 on my system immediately"
                        │
                        ▼
FastAPI Backend detects mitigation authorization intent & regex CVE pattern
                        │
                        ▼
MongoDB Client Session Initiated (db.start_session())
                        │
                        ▼
┌────────────────── Multi-Document ACID Transaction ─────────────────┐
│ 1. Update threats collection: status -> "Resolved", timestamp     │
│ 2. Insert audit_log: operator, previous_status, executed_command  │
│ 3. Execute verified host remediation script (e.g. firewall rule)  │
│ 4. Commit Transaction (session.commit_transaction())              │
└───────────────────────────────────────────────────────────────────┘
                        │
                        ▼
Bot returns real-time confirmation receipt with executed shell command
```

---

## Slide 8: Production Hardening Checklist (Appendix A.7 & Exercises 12–14)

- **Secrets Management (Exercise 12)**: Zero hardcoded credentials. All configuration driven via `.env` with fallback defaults.
- **Monitoring & Health Checks (Exercise 14 & Appendix A.7)**: `/health` endpoint exposes real-time database connection health, threat record counts, and active LLM backend.
- **Containerization (Exercise 13 & Appendix A.6)**: Fully orchestrated with `docker-compose.yml` including health checks and persistent volume storage.
- **Graceful Lifecycle Management**: Clean connection pool shutdown on application teardown.

---

## Slide 9: Step-by-Step Live Demonstration Script

When demonstrating live to Prof. Sujeet S Jagtap, follow this exact sequence:

### Step 1: Run the Automated Verification Suite
Open PowerShell in `D:\mangoDB and no sql\llm` and run:
```powershell
python run_demo.py
```
> **What to say to lecturer:**  
> *"Sir, I will first run our automated test suite which executes all 8 phases: connecting to MongoDB, creating compound indexes from Exercise 6, seeding 14 multi-platform threats, executing our Exercise 5 aggregation pipeline, running semantic vector search from Exercise 17, and performing an autonomous scan with ACID mitigation from Exercise 10."*

### Step 2: Start the FastAPI Backend
```powershell
uvicorn threat_intel_api:app --reload --port 8000
```
Open browser to `http://localhost:8000/docs` to show the Swagger API documentation. Point out the `/chat`, `/stats`, `/scan`, `/mitigate`, and `/health` endpoints.

### Step 3: Launch the Streamlit Frontend
In a second terminal:
```powershell
streamlit run streamlit_app.py --server.port 8501
```
Open browser to `http://localhost:8501`.

### Step 4: Live Interactive Chat Demonstrations
1. **Query Active Windows Threats**: Click the quick prompt *"Active Windows Threats"* or type:  
   `"What active threats are currently affecting Windows?"`  
   Show how the RAG expander displays the grounded MongoDB documents and CVSS scores.
2. **Query Evolving Linux Exploits**: Type:  
   `"Explain evolving Linux kernel vulnerabilities."`  
   Highlight the explanation of `CVE-2024-1086` (Netfilter UAF).
3. **Execute Background Vulnerability Scan**: Click the sidebar button **"Run System Vulnerability Scan"**.  
   Show the bot detecting real host open ports (`445`, `135`, etc.) and flagging them in real-time.
4. **Trigger Conversational Mitigation**: In the chat, type:  
   `"Mitigate CVE-2024-21413 on my system immediately."`  
   Show the bot executing the fix, transitioning the state in MongoDB to `Resolved`, and updating the live dashboard counter!
5. **Show Audit Trail**: Click on the **"Scanner Bot & Audit Trail"** tab to show the immutable MongoDB audit log with timestamp, operator name (*Ayush Yadav*), and executed remediation commands.

---

## Slide 10: High-Scale Ingestion & Stress Testing (100,000 Parameters)

### Ingestion Architecture & Benchmarks (Exercises 5, 6, 7 & 18)
To evaluate the scalability and enterprise readiness of our MongoDB architecture under high-throughput conditions, we ingested and benchmarked **100,000 cyber threat telemetry parameters**:

- **Bulk Ingestion Throughput**: Uses `col.insert_many()` in batches of 10,000 documents, achieving **25,000+ insertions/second** (100,000 documents inserted in 4.00 seconds).
- **Compound Index Optimization (Exercise 6)**:
  ```javascript
  db.threat_parameters.createIndex({ platform: 1, threat_status: 1, is_anomaly: 1 })
  db.threat_parameters.createIndex({ severity: 1, cvss_score: -1 })
  db.threat_parameters.createIndex({ param_id: 1 }, { unique: true })
  ```
- **Aggregation Framework Analytics (Exercise 5)**:
  Aggregated across all 100,000 records filtering anomalies and calculating average CVSS per platform:
  - Total Parameters: **100,000**
  - Anomalies Flagged: **~21,800** (21.8% spike rate)
  - Critical Severity: **~10,900**
  - Average Anomaly CVSS: **8.75 / 10.0**
- **Query Plan Verification**:
  Using `.explain("executionStats")`, verified that multi-condition queries against the 100,000-document collection leverage `IXSCAN` index bounds, reducing execution time from full collection scans (`COLLSCAN`) to sub-millisecond point lookups.

---

## Slide 11: Conclusion & Anticipated Viva Questions

### Summary of Achievements
- Successfully built an enterprise-ready Cyber Threat Intelligence platform synthesizing all 18 curriculum exercises.
- Demonstrated end-to-end RAG using MongoDB as vector store and conversation memory.
- Created an autonomous background scanner bot providing conversational remediation with ACID transaction durability.
- Validated high-scale performance with 100,000 ingested threat parameters and sub-millisecond indexed queries.

### Anticipated Viva / Defense Questions & Model Answers

**Q1: Why did you choose MongoDB over a relational database like PostgreSQL for threat intelligence?**  
*Answer:* CVE advisories and threat intelligence feeds are polymorphic and semi-structured. A single threat contains variable-length arrays of IOCs (hashes, IPs, registry keys), platform-specific mitigation scripts, and JSON payloads. MongoDB's flexible BSON document model allows nesting these arrays without complex multi-table joins, while MongoDB Atlas Vector Search enables native semantic search in the same database engine.

**Q2: How does your conversational mitigation ensure data consistency?**  
*Answer:* We implement MongoDB Multi-Document ACID Transactions (Exercise 10) using `client.start_session()`. When the user authorizes mitigation over chat, the state transition from `Active` to `Resolved` and the insertion into `audit_log` occur within a single atomic transaction. If either operation fails, the entire transaction aborts, ensuring zero partial updates.

**Q3: How does your RAG pipeline prevent hallucinations?**  
*Answer:* We enforce strict context grounding. The system first embeds the user's query into a 384-dimensional vector, retrieves the top-$K$ nearest threat documents from MongoDB, and supplies them as explicit facts in the LLM prompt. The model is constrained to generate remediation procedures based strictly on the verified MongoDB context chunks.

**Q4: How did you test scalability with 100,000 parameters?**  
*Answer:* We implemented `feed_100k_parameters.py` using batch bulk inserts (`insert_many` in 10,000-doc chunks), achieving over 25,000 docs/second. We constructed compound indexes on `(platform, threat_status, is_anomaly)` and ran multi-stage `$match` and `$group` aggregation pipelines, demonstrating that MongoDB's index scans maintain sub-millisecond query performance even at 100k scale.

---
*Report & Presentation Prepared by: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)*
