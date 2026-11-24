# Standalone LLM Docker Service Launcher
# Student: Ayush Yadav (USN: 24BTLCL003)

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "   LAUNCHING STANDALONE LLM DOCKER CONTAINER (OLLAMA ENGINE)" -ForegroundColor Green
Write-Host "   Student: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

$composePath = Join-Path $PSScriptRoot "docker-compose.llm.yml"

Write-Host "[*] Launching container via Docker Compose..." -ForegroundColor Yellow
docker compose -f $composePath up -d

Write-Host ""
Write-Host "[OK] Standalone LLM Container is running!" -ForegroundColor Green
Write-Host "     - Container Name: ollama-llm" -ForegroundColor White
Write-Host "     - API Endpoint:   http://localhost:11434" -ForegroundColor White
Write-Host "     - Tags / Models:  http://localhost:11434/api/tags" -ForegroundColor White
Write-Host ""
