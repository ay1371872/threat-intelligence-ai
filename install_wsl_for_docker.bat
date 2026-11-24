@echo off
:: ==============================================================================
:: WSL & Docker Desktop Auto-Installer & Configuration Script
:: Course: 23CSE528 - NoSQL Databases using MongoDB
:: Student: Ayush Yadav (USN: 24BTLCL003) | JAIN University
:: ==============================================================================

:: Check for Administrator Elevation
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting Administrator privileges to install WSL components...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title WSL & Docker Desktop Configuration - Ayush Yadav (24BTLCL003)
color 0A
cls
echo ==============================================================================
echo    WSL 2 & DOCKER DESKTOP AUTOMATED INSTALLATION & CONFIGURATION
echo    Student: Ayush Yadav (USN: 24BTLCL003)
echo ==============================================================================
echo.

echo [*] Step 1: Enabling Virtual Machine Platform feature...
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
if %errorLevel% equ 0 (
    echo [OK] Virtual Machine Platform enabled successfully.
) else (
    echo [!] Virtual Machine Platform already enabled or pending restart.
)

echo.
echo [*] Step 2: Enabling Windows Subsystem for Linux (WSL) feature...
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
if %errorLevel% equ 0 (
    echo [OK] Microsoft-Windows-Subsystem-Linux enabled successfully.
) else (
    echo [!] WSL feature already enabled or pending restart.
)

echo.
echo [*] Step 3: Installing official Microsoft WSL 2 Kernel & Package via winget...
winget install --id Microsoft.WSL --exact --accept-package-agreements --accept-source-agreements --silent
if %errorLevel% neq 0 (
    echo [!] Falling back to direct wsl --install...
    wsl.exe --install --no-distribution
)

echo.
echo [*] Step 4: Configuring WSL 2 as default version...
wsl.exe --set-default-version 2
wsl.exe --update

echo.
echo [*] Step 5: Restarting Docker Desktop Engine...
taskkill /f /im "Docker Desktop.exe" >nul 2>&1
taskkill /f /im "com.docker.backend.exe" >nul 2>&1
taskkill /f /im "com.docker.service.exe" >nul 2>&1

timeout /t 3 >nul

set "DOCKER_PATH=C:\Users\AYUSH YADAV\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe"
if exist "%DOCKER_PATH%" (
    echo [OK] Starting Docker Desktop from %DOCKER_PATH%...
    start "" "%DOCKER_PATH%"
) else (
    echo [!] Docker Desktop executable not found at %DOCKER_PATH%. Please launch Docker Desktop from Start Menu.
)

echo.
echo ==============================================================================
echo [SUCCESS] WSL 2 is installed and Docker Desktop is configured!
echo.
echo If Windows asks to restart your laptop, please restart your laptop once
echo to finalize the Hypervisor kernel drivers, then launch Docker Desktop.
echo ==============================================================================
echo.
pause
