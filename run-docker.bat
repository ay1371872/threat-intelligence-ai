@echo off
echo ========================================================
echo   Starting Docker Containers for Threat Intelligence AI
echo   Course: 23CSE528 - NoSQL Databases using MongoDB
echo   Author: Ayush Yadav (USN: 24BTLCL003)
echo ========================================================

cd /d "%~dp0"

echo Checking Docker daemon status...
docker info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker daemon is not running!
    echo Please ensure Docker Desktop is open and running (or install WSL2 via: wsl --install).
    echo.
    echo If you want to run without Docker right now, run:
    echo   python quick_test.py
    echo or
    echo   streamlit run streamlit_app.py --server.port 8501
    pause
    exit /b 1
)

echo Building and starting containers (MongoDB + Ollama SLM + FastAPI Backend + Streamlit Frontend)...
docker compose up --build -d

echo.
echo ========================================================
echo Containers launched successfully!
echo   - Streamlit Web UI: http://localhost:8501
echo   - FastAPI Backend:  http://localhost:8000
echo   - Ollama Engine:    http://localhost:11434
echo   - MongoDB Port:     localhost:27017
echo ========================================================
echo To view container logs: docker compose logs -f
echo To stop containers:    docker compose down
pause
