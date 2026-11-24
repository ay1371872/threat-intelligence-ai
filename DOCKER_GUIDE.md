# 🐳 Dockerization Guide: Threat Intelligence AI Platform
**Course Code:** 23CSE528 — NoSQL Databases using MongoDB (Exercise 13 & Appendix A.6)  
**Author:** Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)  
**Faculty Guide:** Prof. Sujeet S Jagtap  

---

## 🏛️ Multi-Container Docker Architecture

The Threat Intelligence AI application is structured into a production-grade 3-tier microservice architecture fully orchestrated via Docker Compose:

```
                            ┌──────────────────────────────────────────────┐
                            │               USER BROWSER                   │
                            │  http://localhost:8501  (Streamlit Web UI)   │
                            │  http://localhost:8000  (FastAPI Swagger)    │
                            └──────────────────────┬───────────────────────┘
                                                   │
                ┌──────────────────────────────────┴──────────────────────────────────┐
                │             DOCKER BRIDGE NETWORK: threat-network                   │
                │                                                                     │
                │   ┌──────────────────────────┐    ┌─────────────────────────────┐   │
                │   │  CONTAINER: frontend     │    │   CONTAINER: backend        │   │
                │   │  Image: threat-frontend  ├───►│   Image: threat-backend     │   │
                │   │  Port: 8501:8501         │    │   Port: 8000:8000           │   │
                │   │  Service: Streamlit UI   │    │   Service: FastAPI + RAG    │   │
                │   └──────────────────────────┘    └──────────────┬──────────────┘   │
                │                                                  │                  │
                │                                                  ▼                  │
                │                                   ┌─────────────────────────────┐   │
                │                                   │   CONTAINER: mongo          │   │
                │                                   │   Image: mongo:7.0          │   │
                │                                   │   Port: 27017:27017         │   │
                │                                   │   Service: NoSQL Engine     │   │
                │                                   └──────────────┬──────────────┘   │
                └──────────────────────────────────────────────────┼──────────────────┘
                                                                   │
                                                                   ▼
                                                    ┌─────────────────────────────┐
                                                    │   PERSISTENT DOCKER VOLUME  │
                                                    │   threat_mongo_data         │
                                                    │   (/data/db)                │
                                                    └─────────────────────────────┘
```

---

## 📦 Container Services Overview

| Container Name | Service Role | Base Image | Exposed Port | Purpose |
|---|---|---|---|---|
| **`threat-mongo`** | Database Layer | `mongo:7.0` | `27017:27017` | Hosts MongoDB collections (`threats`, `threat_parameters`, `audit_log`, `sessions`) with persistent volume storage. |
| **`threat-backend`** | Application API & RAG | `python:3.12-slim` | `8000:8000` | FastAPI server managing RAG semantic search, autonomous vulnerability scanning, and conversational ACID mitigations. |
| **`threat-frontend`** | User Interface | `python:3.12-slim` | `8501:8501` | Streamlit interactive web dashboard with real-time metrics, live threat chat, and 1-click mitigation controls. |
| **`threat-ollama`** | Local SLM Model Engine | `ollama/ollama:latest` | `11434:11434` | Self-hosted SLM engine running local neural models (e.g. `llama3.2:1b`, `llama3.1:8b`) with persistent model volume. |

---

## ⚡ How to Build and Run with Docker

### 1. Build and Start Full Stack (1 Single Command)
Open your terminal in the `llm` folder:
```bash
cd "d:\mangoDB and no sql\llm"
docker compose up --build -d
```

### 2. Verify Running Containers
```bash
docker compose ps
```
*Expected Output:*
```text
NAME                IMAGE               COMMAND                  SERVICE             STATUS              PORTS
threat-mongo        mongo:7.0           "docker-entrypoint.s…"   mongo               running (healthy)   0.0.0.0:27017->27017/tcp
threat-backend      llm-backend         "uvicorn threat_inte…"   backend             running             0.0.0.0:8000->8000/tcp
threat-frontend     llm-frontend        "streamlit run strea…"   frontend            running             0.0.0.0:8501->8501/tcp
```

### 3. Access Services in Your Browser
- **Streamlit Web UI**: [http://localhost:8501](http://localhost:8501)
- **FastAPI Documentation (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Backend Diagnostic Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

## 📊 Running 100k Parameters & 1 Million Threats in Docker

You can execute high-scale ingestion benchmarks directly inside the running Docker container:

### Ingest 100,000 Parameters inside Container:
```bash
docker exec -it threat-backend python feed_100k_parameters.py
```

### Ingest 1,000,000 Threats inside Container:
```bash
docker exec -it threat-backend python feed_1m_threats.py
```

---

## 🔧 Useful Docker Commands

### View Live Logs:
```bash
docker compose logs -f
```
Or for a specific service:
```bash
docker compose logs -f backend
docker compose logs -f frontend
```

### Stop All Containers:
```bash
docker compose down
```

### Stop Containers and Erase Volumes (Clean Slate):
```bash
docker compose down -v
```

---

## ❓ Windows Docker Desktop Note (WSL2)
If running on Windows and Docker reports `failed to connect to docker API`:
1. Ensure Docker Desktop is installed.
2. In PowerShell (Run as Administrator), run:
   ```powershell
   wsl --install
   ```
   and restart your PC to enable the Linux kernel subsystem for Docker Desktop.
3. If you want to run the platform **natively without Docker**, you can execute:
   ```powershell
   python quick_test.py
   # or
   streamlit run streamlit_app.py --server.port 8501
   ```
   *(The application includes a smart in-memory connector that works 100% natively without Docker).*

---
*Created by: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)*
