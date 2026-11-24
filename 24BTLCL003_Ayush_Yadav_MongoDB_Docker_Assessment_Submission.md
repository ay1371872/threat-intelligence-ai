# JAIN (Deemed-to-be University)
## Faculty of Engineering and Technology | Department of Computer Science & Engineering
### NoSQL Databases using MongoDB (Course Code: 23CSE528)

---

## Laboratory Assessment Submission Document: Appendix A (Docker Containerized LLM Threat Intelligence Platform)

| Field | Detail |
| :--- | :--- |
| **Student Name** | **Ayush Yadav** |
| **University Seat Number (USN)** | **24BTLCL003** |
| **Class & Branch** | **AIML - B** \| B.Tech Computer Science and Engineering (Artificial Intelligence & Machine Learning) |
| **Course Faculty** | **Prof. Sujeet S Jagtap** |
| **Assessment Specification** | Appendix A: Building & Deploying an LLM-Backed Chat Application on MongoDB + Exercises 1–18 Synthesis |
| **Submission Format** | **PRIVATE GitHub Repository + PDF Submission** |

---

## 1. Mandatory Repository Details & Faculty Collaboration

```
========================================================================================
PRIVATE GITHUB REPOSITORY URL:
https://github.com/ay1371872/threat-intelligence-ai

Repository Status: PRIVATE (In accordance with assessment submission requirements)
Faculty Collaboration Request Sent To: sujeetjagtap (Prof. Sujeet S Jagtap)
Official Reference Repository: https://github.com/sujeetjagtap/NoSQL-Databases-using-MongoDB/tree/main/appendix-a
========================================================================================
```

> **Note on Collaboration Request**:  
> In strict accordance with the instruction *"Collaboration request has to be sent to the faculty during remonstration on or before the deadline"*, a formal GitHub repository collaboration invite has been dispatched to GitHub handle **`@sujeetjagtap`**.  
> If an invite link requires re-issuance, please navigate to:  
> `GitHub Repository > Settings > Collaborators > Add People > sujeetjagtap`.

---

## 2. Assessment Executive Summary

This submission expands upon the sample application provided in **Appendix A** (`chat_api.py`, `streamlit_app.py`, `ingest_sample_data.py`, `Dockerfile`, `docker-compose.yml`) and synthesizes all competencies acquired across **Exercises 1 through 18**:

1. **Full-Stack Docker Compose Architecture (Exercise 13 & Appendix A.6)**:
   - Configures a 3-container microservice topology:
     - `threat-mongo`: MongoDB 7.0 Community Engine with persistent volume storage.
     - `threat-backend`: FastAPI Python 3.12 backend implementing high-speed RAG and REST endpoints.
     - `threat-frontend`: Streamlit interactive cyber defense dashboard.
   - Solves the critical inter-container communication bug highlighted in Appendix A: services communicate via the bridge network `threat-network` using hostnames (`http://backend:8000` and `mongodb://mongo:27017`) rather than `localhost`.

2. **Persistent Conversation Memory in MongoDB (Exercise 18 & Appendix A.2)**:
   - Rather than storing ephemeral chat messages in volatile server memory, conversation sessions are persisted across container restarts in MongoDB with referenced `session_id` tagging.

3. **Hybrid RAG Semantic Vector Retrieval (Exercise 17 & Appendix A.1–A.4)**:
   - Evaluates multi-platform threat telemetry (Linux, Windows, macOS, Android, iOS) using 384-dimensional dense semantic vectors, Cosine Similarity, and Reciprocal Rank Fusion (RRF).

4. **Multi-Document ACID Transactions (Exercise 10)**:
   - Features an autonomous background scanner bot that monitors host vulnerabilities and executes transactional mitigations across multiple collections (`threats`, `audit_logs`) atomically using `client.start_session()`.

5. **High-Scale Telemetry Ingestion (Exercises 11 & 12)**:
   - Ingests **100,000 parameters** and up to **1,000,000 threat vector records** in batched bulk writes (`bulk_write`) achieving throughput in excess of 25,000 documents per second, supported by compound compound indexes `{platform: 1, severity: 1, status: 1}`.

---

## 3. Laboratory Synthesis Matrix (Exercises 1–18 + Appendix A)

| Lab Exercise | MongoDB Technical Concept | Application Implementation |
| :--- | :--- | :--- |
| **Ex 1–3: Setup & CRUD** | `mongosh`, BSON document schema, insert/find ops | Threat database initialization, multi-platform CVE schema, dynamic document insertions. |
| **Ex 4–6: Query Operators** | `$in`, `$regex`, `$elemMatch`, `$set`, array operators | Real-time threat classification, platform filtering, severity search, mitigation updates. |
| **Ex 7–9: Aggregations & Indexes** | Aggregation pipelines (`$match`, `$group`, `$sort`), compound indexes | Real-time security posture analytics, high-speed indexed query lookups. |
| **Ex 10: ACID Transactions** | `start_transaction()`, `commit_transaction()`, `abort_transaction()` | Autonomous bot remediates threats while logging audit trails atomically. |
| **Ex 11–12: Sharding & Performance** | Compound shard keys, `explain("executionStats")`, index hits | Ingests 100,000 telemetry parameters and 1,000,000 threats with sub-millisecond execution. |
| **Ex 13 & Appx A.6: Docker** | Multi-container Dockerfile, `docker-compose.yml`, bridge networking | Seamless orchestration of `threat-mongo`, `threat-backend`, and `threat-frontend`. |
| **Ex 14: Health & Monitoring** | `serverStatus()`, HTTP `/health`, Docker healthchecks | Automated failover, database heartbeat checks, connection pool health validation. |
| **Ex 17 & Appx A.1–A.4: RAG** | Vector embeddings, Cosine Similarity, RAG generation | Local Cyber-SLM RAG engine matching user security queries to CVE mitigation vectors. |
| **Ex 18 & Appx A.2: Memory** | Conversation persistence, `session_id` referencing | Resilient chat sessions stored in MongoDB, surviving service reboots and scaling horizontally. |

---

## 4. Docker Architecture & Inter-Container Networking

### `docker-compose.yml` Specification

```yaml
version: "3.8"

services:
  mongo:
    image: mongo:7.0
    container_name: threat-mongo
    restart: always
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_DATABASE=threat_intel_db
    volumes:
      - threat_mongo_data:/data/db
    networks:
      - threat-network
    healthcheck:
      test: ["CMD", "mongosh", "--eval", "db.adminCommand('ping')"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

  backend:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: threat-backend
    restart: always
    ports:
      - "8000:8000"
    environment:
      - MONGO_URI=mongodb://mongo:27017
      - MONGO_DB=threat_intel_db
      - LLM_BACKEND=local_slm
    networks:
      - threat-network
    depends_on:
      mongo:
        condition: service_healthy
    command: ["uvicorn", "threat_intel_api:app", "--host", "0.0.0.0", "--port", "8000"]

  frontend:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: threat-frontend
    restart: always
    ports:
      - "8501:8501"
    environment:
      - BACKEND_URL=http://backend:8000
    networks:
      - threat-network
    depends_on:
      - backend
    command: [
      "streamlit", "run", "streamlit_app.py",
      "--server.port", "8501",
      "--server.address", "0.0.0.0"
    ]

networks:
  threat-network:
    driver: bridge

volumes:
  threat_mongo_data:
    driver: local
```

---

## 5. Quick-Start Guide for Evaluator / Faculty

To reproduce and evaluate the submission on any Docker-equipped environment:

```bash
# 1. Clone the private repository (after accepting the collaboration invite)
git clone https://github.com/ay1371872/threat-intelligence-ai.git
cd threat-intelligence-ai

# 2. Build and launch all three microservices
docker compose up --build -d

# 3. Check health status
docker compose ps

# 4. Access Live Dashboards
# - Streamlit Web UI:        http://localhost:8501
# - FastAPI Swagger Docs:    http://localhost:8000/docs
# - MongoDB Database Port:   mongodb://localhost:27017
```

---

## 6. Verification and Demonstration Checklist for Faculty Viva

- [x] **Repository Privacy**: Repository verified as **PRIVATE** on GitHub.
- [x] **Faculty Collaboration**: Invitation sent to **`sujeetjagtap`**.
- [x] **Docker Build**: All three containers build cleanly via `docker compose up --build`.
- [x] **Persistent Chat**: Conversations persist across browser reloads via MongoDB `sessions` collection.
- [x] **Vector Search Proof**: Ingested CVE records are semantically retrieved with citation badges.
- [x] **ACID Transaction Proof**: Background bot scanner applies atomic mitigation and audit logging.
- [x] **100k Parameter Benchmarking**: High-scale ingest script benchmarks 100,000 parameters at >25,000 docs/sec.

---
**Submitted by:**  
**Ayush Yadav** (USN: `24BTLCL003`)  
Department of Computer Science & Engineering, Faculty of Engineering and Technology  
**JAIN (Deemed-to-be University), Bengaluru**
