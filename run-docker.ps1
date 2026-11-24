# PowerShell Script to Launch Dockerized Threat Intelligence Platform
# Course: 23CSE528 - NoSQL Databases using MongoDB
# Author: Ayush Yadav (USN: 24BTLCL003)

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Launching Docker Containers for Threat Intelligence AI" -ForegroundColor Green
Write-Host "  Author: Ayush Yadav (24BTLCL003) | JAIN University" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Cyan

Set-Location $PSScriptRoot

# Check Docker status
try {
    $null = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker not running"
    }
} catch {
    Write-Host "[!] Docker daemon is not active on this host." -ForegroundColor Red
    Write-Host "    If Docker Desktop requires WSL2, install it via: wsl --install" -ForegroundColor Yellow
    Write-Host "    To run natively without Docker right now, execute: python quick_test.py" -ForegroundColor Cyan
    exit 1
}

Write-Host "[*] Building and spinning up multi-container full-stack..." -ForegroundColor Yellow
docker compose up --build -d

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[OK] Containers Running Successfully!" -ForegroundColor Green
    Write-Host "  • Streamlit Web UI:   http://localhost:8501" -ForegroundColor Cyan
    Write-Host "  • FastAPI RAG API:    http://localhost:8000" -ForegroundColor Cyan
    Write-Host "  • Swagger API Docs:   http://localhost:8000/docs" -ForegroundColor Cyan
    Write-Host "  • MongoDB Port:       localhost:27017" -ForegroundColor Cyan
    Write-Host "`nUse 'docker compose logs -f' to inspect container logs." -ForegroundColor Gray
    Write-Host "Use 'docker compose down' to stop containers." -ForegroundColor Gray
}
