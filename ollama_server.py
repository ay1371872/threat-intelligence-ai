"""Local Ollama-Compatible SLM Server
Emulates Ollama REST API endpoints on port 11434 so the frontend and backend can connect seamlessly.
Author: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)
Course: 23CSE528 - NoSQL Databases using MongoDB
"""

import sys
import os
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel

# Add current folder to sys.path
CUR_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_DIR)

from rag_engine import local_slm_generate, retrieve_threat_context

app = FastAPI(title="Ollama SLM Server", version="0.4.1")

AVAILABLE_MODELS = [
    {
        "name": "llama3.2:1b",
        "model": "llama3.2:1b",
        "modified_at": "2026-11-24T14:00:00Z",
        "size": 1300000000,
        "digest": "78e26417b3c69d46896f1f6c4c95f50244ba2629b19e992797e88402ccba6214",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "llama",
            "families": ["llama"],
            "parameter_size": "1.2B",
            "quantization_level": "Q4_K_M"
        }
    },
    {
        "name": "llama3.2:3b",
        "model": "llama3.2:3b",
        "modified_at": "2026-11-24T14:00:00Z",
        "size": 2000000000,
        "digest": "62e26417b3c69d46896f1f6c4c95f50244ba2629b19e992797e88402ccba6214",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "llama",
            "families": ["llama"],
            "parameter_size": "3.2B",
            "quantization_level": "Q4_K_M"
        }
    },
    {
        "name": "llama3.1:8b",
        "model": "llama3.1:8b",
        "modified_at": "2026-11-24T14:00:00Z",
        "size": 4700000000,
        "digest": "8ab4849b038cf03f330e6988820f3d99b1e92a844d26cdc49137a504271b5b91",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "llama",
            "families": ["llama"],
            "parameter_size": "8.0B",
            "quantization_level": "Q4_K_M"
        }
    },
    {
        "name": "mistral",
        "model": "mistral",
        "modified_at": "2026-11-24T14:00:00Z",
        "size": 4100000000,
        "digest": "f0e26417b3c69d46896f1f6c4c95f50244ba2629b19e992797e88402ccba6214",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "mistral",
            "families": ["mistral"],
            "parameter_size": "7B",
            "quantization_level": "Q4_K_M"
        }
    }
]


@app.get("/", response_class=PlainTextResponse)
def root():
    return "Ollama is running"


@app.get("/api/tags")
def get_tags():
    return {"models": AVAILABLE_MODELS}


@app.get("/api/version")
def get_version():
    return {"version": "0.4.1"}


@app.post("/api/pull")
def pull_model(req: Dict[str, Any]):
    model_name = req.get("name", "llama3.2:1b")
    # Add if not present
    if not any(m["name"] == model_name for m in AVAILABLE_MODELS):
        AVAILABLE_MODELS.append({
            "name": model_name,
            "model": model_name,
            "modified_at": datetime.utcnow().isoformat() + "Z",
            "size": 1500000000,
            "digest": "dynamic_pulled_model_digest",
            "details": {"format": "gguf", "family": "llama", "parameter_size": "1B"}
        })
    return {"status": "success"}


@app.post("/api/chat")
async def chat(request: Request):
    body = await request.json()
    model = body.get("model", "llama3.2:1b")
    messages = body.get("messages", [])
    
    # Extract prompt
    user_prompt = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            user_prompt = m.get("content", "")
            break
            
    # Check if context was passed in prompt
    clean_query = user_prompt
    if "User Query:" in user_prompt:
        clean_query = user_prompt.split("User Query:")[-1].strip()
    elif "User Question:" in user_prompt:
        clean_query = user_prompt.split("User Question:")[-1].strip()

    # Retrieve context
    context = retrieve_threat_context(clean_query, top_k=4)
    history_tuples = [{"role": m.get("role"), "content": m.get("content")} for m in messages[:-1]]
    
    # Generate high-fidelity SLM response
    response_text = local_slm_generate(clean_query, context, history_tuples)

    # Prepend Ollama model header tag
    ollama_header = f"🦙 *[Ollama Engine — `{model}`]*\n\n"
    final_content = ollama_header + response_text

    return {
        "model": model,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "message": {
            "role": "assistant",
            "content": final_content
        },
        "done": True,
        "total_duration": 125000000,
        "load_duration": 4000000,
        "prompt_eval_count": 48,
        "eval_count": 165
    }


@app.post("/api/generate")
async def generate(request: Request):
    body = await request.json()
    model = body.get("model", "llama3.2:1b")
    prompt = body.get("prompt", "")
    
    context = retrieve_threat_context(prompt, top_k=4)
    response_text = local_slm_generate(prompt, context, [])
    
    return {
        "model": model,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "response": f"🦙 *[Ollama Engine — `{model}`]*\n\n" + response_text,
        "done": True
    }


if __name__ == "__main__":
    port = int(os.getenv("OLLAMA_PORT", "11434"))
    print(f"[*] Starting Local Ollama SLM Server on http://127.0.0.1:{port}...")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
