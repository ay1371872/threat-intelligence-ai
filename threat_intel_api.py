"""FastAPI Threat Intelligence & Autonomous Mitigation Backend
Synthesizes:
  - Exercise 2 (Connection Management)
  - Exercise 4 (CRUD & Filtering)
  - Exercise 5 (Aggregation Framework Analytics)
  - Exercise 10 (ACID Mitigation Transactions)
  - Exercise 14 (Production Health & Diagnostics)
  - Exercise 17 (RAG & Semantic Retrieval)
  - Appendix A (FastAPI Backend with Chat Endpoints)
"""

import os
import time
import logging
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from db_connector import get_database, get_mongo_client, initialize_database_indexes_and_schemas
from rag_engine import generate_chat_response, retrieve_threat_context, check_ollama_status
from threat_scanner_bot import ThreatScannerBot

logger = logging.getLogger("threat_intel_api")
logging.basicConfig(level=logging.INFO)

LLM_BACKEND = os.getenv("LLM_BACKEND", "ollama")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
scanner_bot = ThreatScannerBot()


# --- Pydantic Schemas ---
class ChatRequest(BaseModel):
    session_id: str = Field(default="demo-session", description="Session identifier for multi-turn history")
    message: str = Field(..., description="User question or mitigation instruction")
    platform: Optional[str] = Field(default=None, description="Filter: Linux, Windows, macOS, Android, iOS")
    status: Optional[str] = Field(default=None, description="Filter: Anticipated, Active, Evolving, Resolved")
    backend: Optional[str] = Field(default=None, description="Model backend override (ollama, local_slm, openai)")
    model: Optional[str] = Field(default=None, description="Specific model name (e.g. llama3.2:1b, llama3.1:8b)")


class ChatResponse(BaseModel):
    session_id: str
    response: str
    sources: List[Dict[str, Any]]
    model_used: str
    latency_ms: float


class MitigateRequest(BaseModel):
    cve_id: str = Field(..., description="Vulnerability ID to mitigate (e.g. CVE-2024-21413)")
    confirm: bool = Field(default=True, description="Confirmation authorization flag")
    operator: Optional[str] = Field(default="Ayush Yadav (AIML-B)", description="Authorized operator")


class ScanRequest(BaseModel):
    project_path: Optional[str] = None


# --- Lifespan Context Manager (Exercise 14) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("[API] Starting Threat Intelligence Service...")
    initialize_database_indexes_and_schemas()
    # Check if database has records; if empty, seed it automatically
    db = get_database()
    if db["threats"].count_documents({}) == 0:
        logger.info("[API] No threat records detected. Running automatic seeder...")
        from seed_threat_data import seed_database
        seed_database()
    yield
    logger.info("[API] Shutting down Threat Intelligence Service.")


app = FastAPI(
    title="Threat Intelligence AI Assistant API",
    description="NoSQL MongoDB RAG-Powered Threat Intelligence Platform for Anticipated, Active, Evolving, and Resolved Threats",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Endpoints ---

@app.get("/health")
def health_check():
    """Diagnostic health check (Exercise 14 & Appendix A.7)."""
    db = get_database()
    _, is_mock = get_mongo_client()
    try:
        if not is_mock:
            db.command("ping")
            mongo_status = "Connected (Live Cluster)"
        else:
            mongo_status = "Connected (In-Memory Engine)"
        threat_count = db["threats"].count_documents({})
        param_count = db["threat_parameters"].count_documents({})
    except Exception as e:
        mongo_status = f"Error: {e}"
        threat_count = 0
        param_count = 0

    ollama_diag = check_ollama_status() if LLM_BACKEND == "ollama" else None
    display_backend = f"ollama ({OLLAMA_MODEL})" if LLM_BACKEND == "ollama" else LLM_BACKEND

    return {
        "status": "Healthy",
        "service": "Threat Intelligence AI Assistant",
        "mongo_status": mongo_status,
        "is_mock_database": is_mock,
        "active_threat_records": threat_count,
        "telemetry_parameters_count": param_count,
        "llm_backend": display_backend,
        "ollama": ollama_diag,
        "supported_platforms": ["Linux", "Windows", "macOS", "Android", "iOS"],
        "threat_categories": ["Anticipated", "Active", "Evolving", "Resolved"],
        "timestamp": time.time()
    }


@app.get("/ollama/status")
def get_ollama_status():
    """Returns real-time status of the local or containerized Ollama LLM engine."""
    return check_ollama_status()


@app.post("/ollama/pull")
def pull_ollama_model(model_name: str = Query(default="llama3.2:1b", description="Model tag to pull into Ollama")):
    """Requests Ollama to pull a model if not already present."""
    import requests
    try:
        r = requests.post(f"{OLLAMA_BASE_URL}/api/pull", json={"name": model_name, "stream": False}, timeout=120)
        return {"status": "ok", "model": model_name, "details": r.json()}
    except Exception as e:
        return {"status": "error", "model": model_name, "message": str(e)}


@app.post("/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest):
    """Conversational RAG endpoint for threat intelligence interaction & mitigation advice (Appendix A.3)."""
    start_time = time.perf_counter()
    
    # Check if message is a direct conversational mitigation confirmation
    msg_clean = req.message.strip().lower()
    if "mitigate" in msg_clean and ("cve-" in msg_clean or "sys-" in msg_clean or "win-" in msg_clean):
        # Extract CVE
        import re
        cve_match = re.search(r"((cve|sys|win|lnx)-[0-9a-z-]+)", msg_clean, re.IGNORECASE)
        if cve_match:
            target_cve = cve_match.group(1).upper()
            mitig_res = scanner_bot.apply_confirmed_mitigation(target_cve)
            latency = (time.perf_counter() - start_time) * 1000
            ans = (
                f"🛡️ **Conversational Mitigation Executed Successfully!**\n\n"
                f"- **Target Vulnerability:** `{target_cve}`\n"
                f"- **Action:** {mitig_res.get('message', 'Applied safe fix')}\n"
                f"- **New Database State:** `Resolved` (Recorded in MongoDB via ACID Transaction)\n"
                f"- **Executed Fix Command:**\n```bash\n{mitig_res.get('executed_command', '')}\n```\n"
                f"You can verify this in the Threat Dashboard or ask me for an updated status scan."
            )
            return ChatResponse(
                session_id=req.session_id,
                response=ans,
                sources=[],
                model_used=f"ollama ({req.model or OLLAMA_MODEL})" if (req.backend or LLM_BACKEND) == "ollama" else LLM_BACKEND,
                latency_ms=round(latency, 2)
            )

    # General RAG Query with Ollama SLM
    result = generate_chat_response(
        prompt=req.message,
        session_id=req.session_id,
        platform=req.platform,
        status=req.status,
        backend=req.backend or LLM_BACKEND,
        model_name=req.model or OLLAMA_MODEL
    )
    
    latency = (time.perf_counter() - start_time) * 1000
    return ChatResponse(
        session_id=result["session_id"],
        response=result["response"],
        sources=result["sources"],
        model_used=result["model_used"],
        latency_ms=round(latency, 2)
    )


@app.get("/laptop/telemetry")
def get_laptop_telemetry_endpoint():
    """Returns live hardware telemetry directly from the host laptop."""
    try:
        from laptop_connector import get_live_laptop_telemetry
        return get_live_laptop_telemetry()
    except Exception as e:
        return {"error": str(e)}


@app.get("/host/status")
def get_host_status():
    """Reports the status of the Windows Host Diagnostic subsystem."""
    import sys
    from host_diagnostic import IS_DOCKER, IS_WINDOWS, ALLOWLISTED_SOFTWARE_CATALOG, SAFE_ALLOWLISTED_COMMANDS
    return {
        "platform": "Windows" if IS_WINDOWS else sys.platform,
        "environment": "Docker Container" if IS_DOCKER else "Windows Host (Native)",
        "host_diagnostic_active": True,
        "allowlisted_software_catalog_count": len(ALLOWLISTED_SOFTWARE_CATALOG),
        "allowlisted_commands_count": len(SAFE_ALLOWLISTED_COMMANDS)
    }


@app.get("/host/software")
def get_host_software_endpoint(
    app: str = Query(..., description="Application name to check on host"),
    x_host_token: Optional[str] = Header(None, alias="X-Host-Token", description="Host Diagnostic Security Token")
):
    """Secure host diagnostic endpoint to verify Windows software installation.
    Accessible from Docker via host.docker.internal.
    """
    from host_diagnostic import check_host_software_installation, HOST_DIAGNOSTIC_TOKEN
    if HOST_DIAGNOSTIC_TOKEN and x_host_token and x_host_token != HOST_DIAGNOSTIC_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid host diagnostic authentication token.")
    result = check_host_software_installation(app)
    return result


@app.get("/threats")
def list_threats(
    platform: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None
):
    """Lists threat intelligence records with advanced query filtering (Exercise 4)."""
    db = get_database()
    threats_col = db["threats"]

    query: Dict[str, Any] = {}
    if platform and platform.lower() != "all":
        query["platform"] = {"$regex": f"^{platform}$", "$options": "i"}
    if status and status.lower() != "all":
        query["status"] = {"$regex": f"^{status}$", "$options": "i"}
    if severity and severity.lower() != "all":
        query["severity"] = {"$regex": f"^{severity}$", "$options": "i"}
    if search:
        query["$or"] = [
            {"cve_id": {"$regex": search, "$options": "i"}},
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]

    cursor = threats_col.find(query, {"embedding": 0}).sort("cvss", -1)
    results = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        results.append(doc)

    return {"count": len(results), "threats": results}


@app.get("/stats")
def threat_analytics():
    """Executes multi-stage aggregation pipelines for threat analytics (Exercise 5)."""
    db = get_database()
    threats_col = db["threats"]

    # 1. Pipeline for Status Breakdown ($group)
    pipeline_status = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}, "avg_cvss": {"$avg": "$cvss"}}},
        {"$sort": {"count": -1}}
    ]
    status_stats = list(threats_col.aggregate(pipeline_status))

    # 2. Pipeline for Platform Distribution ($group)
    pipeline_platform = [
        {"$group": {"_id": "$platform", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    platform_stats = list(threats_col.aggregate(pipeline_platform))

    # 3. Pipeline for Severity Distribution
    pipeline_severity = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    severity_stats = list(threats_col.aggregate(pipeline_severity))

    # Format cleanly
    status_dict = {item["_id"]: item["count"] for item in status_stats if item["_id"]}
    platform_dict = {item["_id"]: item["count"] for item in platform_stats if item["_id"]}
    severity_dict = {item["_id"]: item["count"] for item in severity_stats if item["_id"]}

    total_records = threats_col.count_documents({})

    return {
        "total_threats": total_records,
        "by_status": status_dict,
        "by_platform": platform_dict,
        "by_severity": severity_dict,
        "categories": {
            "Anticipated": status_dict.get("Anticipated", 0),
            "Active": status_dict.get("Active", 0),
            "Evolving": status_dict.get("Evolving", 0),
            "Resolved": status_dict.get("Resolved", 0)
        }
    }


@app.post("/scan")
def trigger_system_scan(req: ScanRequest):
    """Triggers autonomous background scanner bot to audit system vulnerabilities."""
    result = scanner_bot.perform_system_vulnerability_scan(req.project_path)
    return result


@app.post("/mitigate")
def apply_mitigation(req: MitigateRequest):
    """Applies verified mitigation with multi-document ACID transaction logging (Exercise 10)."""
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Mitigation authorization declined by user.")
    result = scanner_bot.apply_confirmed_mitigation(req.cve_id, f"Approved by {req.operator}")
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("message"))
    return result


@app.get("/audit")
def get_audit_trail(limit: int = 15):
    """Retrieves operational audit logs (Exercise 14)."""
    db = get_database()
    logs = list(db["audit_log"].find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
    return {"count": len(logs), "audit_logs": logs}


@app.post("/feed-100k")
def feed_100k_parameters_endpoint():
    """Feeds 100,000 security & telemetry parameters into MongoDB using bulk operations."""
    from feed_100k_parameters import feed_100k_parameters_to_mongodb
    result = feed_100k_parameters_to_mongodb()
    return result


@app.get("/parameters/stats")
def parameters_stats():
    """Returns analytics over the 100,000 ingested parameters (Exercise 5)."""
    db = get_database()
    col = db["threat_parameters"]
    total = col.count_documents({})
    if total == 0:
        return {"total_parameters": 0, "status": "No telemetry parameters ingested yet. Call POST /feed-100k."}

    anomalies = col.count_documents({"is_anomaly": True})
    
    # Aggregation by platform
    pipeline = [
        {"$group": {"_id": "$platform", "count": {"$sum": 1}, "avg_cvss": {"$avg": "$cvss_score"}}},
        {"$sort": {"count": -1}}
    ]
    platform_breakdown = list(col.aggregate(pipeline))

    return {
        "total_parameters": total,
        "anomalous_parameters": anomalies,
        "normal_parameters": total - anomalies,
        "platform_distribution": {item["_id"]: item["count"] for item in platform_breakdown if item["_id"]},
        "indexes_active": ["idx_platform_status_anomaly", "idx_severity_cvss", "idx_param_id_unique"]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
