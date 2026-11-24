@echo off
title Standalone LLM Docker Service - Ayush Yadav (24BTLCL003)
color 0A
cls
echo ==============================================================================
echo    LAUNCHING STANDALONE LLM DOCKER CONTAINER (OLLAMA ENGINE)
echo    Student: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)
echo ==============================================================================
echo.

echo [*] Checking Docker daemon status...
docker info >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Docker is not running. Please start Docker Desktop and retry.
    pause
    exit /b 1
)

echo [*] Starting dedicated LLM container...
docker compose -f "%~dp0docker-compose.llm.yml" up -d

echo.
echo [OK] Standalone LLM Container is running!
echo      - Container Name: ollama-llm
echo      - API Endpoint:   http://localhost:11434
echo      - Health Status:  http://localhost:11434/api/tags
echo.
pause
