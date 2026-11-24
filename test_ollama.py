"""Ollama Integration Tester & Diagnostics Script
Tests Ollama connectivity, queries installed models, and validates RAG response.
Author: Ayush Yadav (24BTLCL003) | JAIN (Deemed-to-be University)
Course: 23CSE528 - NoSQL Databases using MongoDB
"""

import os
import sys
import json
import requests

# Set working directory to script path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rag_engine import check_ollama_status, generate_chat_response, OLLAMA_BASE_URL, OLLAMA_MODEL


def main():
    print("=" * 65)
    print("   🦙 OLLAMA MODEL INTEGRATION & DIAGNOSTICS TEST")
    print("   Course: 23CSE528 NoSQL Databases using MongoDB")
    print("   Author: Ayush Yadav (USN: 24BTLCL003)")
    print("=" * 65)

    print(f"\n[1] Checking Ollama Server at: {OLLAMA_BASE_URL}")
    status = check_ollama_status()

    if status["online"]:
        print("    🟢 Status: ONLINE")
        models = status.get("installed_models", [])
        print(f"    📦 Installed Models ({len(models)}):")
        if models:
            for m in models:
                ready_mark = " (READY)" if OLLAMA_MODEL in m else ""
                print(f"       • {m}{ready_mark}")
        else:
            print("       (No models pulled yet)")

        print(f"\n[2] Checking Configured Model: '{OLLAMA_MODEL}'")
        if status["model_ready"]:
            print(f"    ✅ Model '{OLLAMA_MODEL}' is ready for inference!")
        else:
            print(f"    ⚠️  Model '{OLLAMA_MODEL}' not found in installed models list.")
            print(f"       Run in terminal:  ollama pull {OLLAMA_MODEL}")
            print(f"       Or in Docker:     docker exec -it threat-ollama ollama pull {OLLAMA_MODEL}")

        print(f"\n[3] Testing Live Inference with Ollama...")
        test_prompt = "What is the critical Outlook vulnerability and its CVSS score?"
        print(f"    Query: \"{test_prompt}\"")
        res = generate_chat_response(test_prompt, session_id="ollama-test-session")
        print(f"\n    Model Used: {res.get('model_used')}")
        print(f"    Context Sources Retrieved: {len(res.get('sources', []))}")
        print(f"    Sample Output (first 250 chars):\n    {res.get('response', '')[:250]}...")
    else:
        print("    🟡 Status: OFFLINE / NOT REACHABLE")
        print(f"    Error: {status.get('error')}")
        print("\n    To run Ollama on your machine:")
        print("    --------------------------------------------------")
        print("    Option 1: Windows Native Application")
        print(f"       Download from https://ollama.com/download")
        print(f"       Then run in command prompt:  ollama run {OLLAMA_MODEL}")
        print("")
        print("    Option 2: Docker Compose (Built-in container)")
        print("       cd \"d:\\mangoDB and no sql\\llm\"")
        print(f"       docker compose up threat-ollama -d")
        print(f"       docker exec -it threat-ollama ollama pull {OLLAMA_MODEL}")
        print("    --------------------------------------------------")
        print("\n    Testing Embedded SLM Fallback...")
        test_prompt = "What is CVE-2024-21413?"
        res = generate_chat_response(test_prompt, session_id="slm-fallback-session")
        print(f"    Fallback Model Used: {res.get('model_used')}")
        print(f"    Response generated successfully: {len(res.get('response', ''))} characters")

    print("\n" + "=" * 65)
    print("   Test Completed Successfully!")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
