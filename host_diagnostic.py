"""Host Machine Diagnostic Module
Intelligent Laptop-Aware AI Assistant & Windows Host Diagnostic Engine
Course: 23CSE528 - NoSQL Databases using MongoDB
Author: Ayush Yadav (USN: 24BTLCL003) | JAIN (Deemed-to-be University)

Architecture Highlights:
  1. Intent Detection Mechanism:
     Classifies user intent (Hardware Specs vs. Software Installation vs.
     Running Processes vs. OS vs. Dev Environment vs. Security Vulnerabilities).
  2. Windows Host Diagnostic Probe:
     Inspects the Windows Registry (HKLM, HKCU, WOW6432Node), PATH environment,
     standard Program Files, and User AppData directories.
  3. Container-to-Host Secure Communication:
     When running inside Docker (Linux), safely probes the Windows host diagnostic
     endpoint via HTTP with token authentication (X-Host-Token).
     Never substitutes Docker container state for Windows host state.
  4. Allowlisted Diagnostic Commands:
     Strictly permits only pre-approved, safe diagnostic commands.
     Arbitrary execution is prohibited.
  5. Exact User-Specified Response Format:
     Application: <Name>
     Platform: Windows
     Installation Status: Installed / Not Installed / Unable to Verify
     Version: <Version / Not Available>
     Installation Path: <Path / Not Available>
     Additional Information: <Details & Official Installation URLs>
"""

import os
import sys
import re
import json
import shutil
import socket
import logging
import subprocess
import difflib
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger("host_diagnostic")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

# --- Configuration & Environment Constants ---
HOST_DIAGNOSTIC_TOKEN = os.getenv("HOST_DIAGNOSTIC_TOKEN", "ayush-aimlb-host-sec-token-2026")
HOST_DIAGNOSTIC_URL = os.getenv("HOST_DIAGNOSTIC_URL", "http://host.docker.internal:8000").rstrip("/")
IS_DOCKER = os.path.exists("/.dockerenv") or os.getenv("IS_DOCKER", "").lower() in ["true", "1"]
IS_WINDOWS = sys.platform == "win32"

# --- Intent Classification Constants ---
INTENT_SOFTWARE_INSTALL = "SOFTWARE_INSTALL"
INTENT_SOFTWARE_VERSION = "SOFTWARE_VERSION"
INTENT_SOFTWARE_LIST    = "SOFTWARE_LIST"
INTENT_RUNNING_PROCESS  = "RUNNING_PROCESS"
INTENT_DEV_ENVIRONMENT  = "DEV_ENVIRONMENT"
INTENT_OPERATING_SYSTEM = "OPERATING_SYSTEM"
INTENT_HARDWARE_METRIC  = "HARDWARE_METRIC"
INTENT_HARDWARE_SPECS   = "HARDWARE_SPECS"
INTENT_SECURITY_THREAT  = "SECURITY_THREAT"
INTENT_PROJECT_INFO     = "PROJECT_INFO"
INTENT_MONGODB_ROLE     = "MONGODB_ROLE"
INTENT_GREETING         = "GREETING"
INTENT_GENERAL          = "GENERAL"

# --- Allowlisted Software Probes Catalog ---
ALLOWLISTED_SOFTWARE_CATALOG: Dict[str, Dict[str, Any]] = {
    "claude": {
        "display_name": "Claude Desktop",
        "aliases": ["claude", "claude desktop", "anthropic claude", "cluade", "claud"],
        "executables": ["claude-desktop.exe", "claude.exe", "claude"],
        "cli_cmd_allowlisted": None,  # GUI application, no CLI version
        "registry_names": ["Claude", "Anthropic Claude"],
        "standard_paths": [
            r"AppData\Local\Microsoft\WindowsApps\claude-desktop.exe",
            r"AppData\Local\Packages\Claude_pzs8sxrjxfjjc",
            r"AppData\Local\Programs\Claude\Claude.exe",
            r"AppData\Local\Claude\Claude.exe",
            r"AppData\Roaming\Claude\Claude.exe",
            r"C:\Program Files\Claude\Claude.exe",
            r"C:\Program Files (x86)\Claude\Claude.exe",
        ],
        "install_url": "https://claude.ai/download",
        "description": "Anthropic Claude Desktop application for Windows."
    },
    "chatgpt": {
        "display_name": "ChatGPT Desktop",
        "aliases": ["chatgpt", "chat gpt", "openai chatgpt", "chatgpt desktop"],
        "executables": ["chatgpt-classic.exe", "chatgpt.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["ChatGPT", "OpenAI.ChatGPT-Desktop"],
        "standard_paths": [
            r"AppData\Local\Microsoft\WindowsApps\chatgpt-classic.exe",
            r"AppData\Local\Microsoft\WindowsApps\chatgpt.exe"
        ],
        "install_url": "https://openai.com/chatgpt/download/",
        "description": "OpenAI ChatGPT Desktop application for Windows."
    },
    "whatsapp": {
        "display_name": "WhatsApp Desktop",
        "aliases": ["whatsapp", "whatsapp desktop", "what's app"],
        "executables": ["WhatsApp.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["WhatsApp", "5319275A.WhatsAppDesktop"],
        "standard_paths": [
            r"AppData\Local\WhatsApp\WhatsApp.exe"
        ],
        "install_url": "https://www.whatsapp.com/download",
        "description": "Meta WhatsApp Desktop messaging client."
    },
    "ollama": {
        "display_name": "Ollama",
        "aliases": ["ollama", "ollama slm", "ollama model"],
        "executables": ["ollama.exe", "ollama"],
        "cli_cmd_allowlisted": "ollama --version",
        "registry_names": ["Ollama"],
        "standard_paths": [
            r"AppData\Local\Programs\Ollama\ollama.exe",
            r"AppData\Local\Programs\Ollama\ollama app.exe",
            r"C:\Program Files\Ollama\ollama.exe",
        ],
        "install_url": "https://ollama.com/download/windows",
        "description": "Ollama local Large and Small Language Model runner."
    },
    "python": {
        "display_name": "Python",
        "aliases": ["python", "python3", "py", "python interpreter", "cpython"],
        "executables": ["python.exe", "python3.exe", "py.exe", "python"],
        "cli_cmd_allowlisted": "python --version",
        "registry_names": ["Python", "Python 3", "Python Launcher", "Anaconda"],
        "standard_paths": [
            r"AppData\Local\Programs\Python",
            r"C:\Program Files\Python",
            r"C:\Program Files (x86)\Python",
        ],
        "install_url": "https://www.python.org/downloads/",
        "description": "Python programming language runtime and standard library."
    },
    "vscode": {
        "display_name": "Visual Studio Code (VS Code)",
        "aliases": ["vscode", "vs code", "visual studio code", "code editor", "code"],
        "executables": ["code.cmd", "code.exe", "code"],
        "cli_cmd_allowlisted": "cmd /c code --version",
        "registry_names": ["Microsoft Visual Studio Code", "VS Code"],
        "standard_paths": [
            r"AppData\Local\Programs\Microsoft VS Code\Code.exe",
            r"AppData\Local\Programs\Microsoft VS Code\bin\code.cmd",
            r"C:\Program Files\Microsoft VS Code\Code.exe",
        ],
        "install_url": "https://code.visualstudio.com/download",
        "description": "Microsoft Visual Studio Code source-code editor."
    },
    "git": {
        "display_name": "Git",
        "aliases": ["git", "git scm", "git version control"],
        "executables": ["git.exe", "git"],
        "cli_cmd_allowlisted": "git --version",
        "registry_names": ["Git"],
        "standard_paths": [
            r"C:\Program Files\Git\cmd\git.exe",
            r"C:\Program Files (x86)\Git\cmd\git.exe",
            r"AppData\Local\Programs\Git\cmd\git.exe",
        ],
        "install_url": "https://git-scm.com/download/win",
        "description": "Distributed version control system for software development."
    },
    "docker": {
        "display_name": "Docker Desktop",
        "aliases": ["docker", "docker desktop", "docker engine"],
        "executables": ["docker.exe", "docker"],
        "cli_cmd_allowlisted": "docker --version",
        "registry_names": ["Docker Desktop"],
        "standard_paths": [
            r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
            r"AppData\Local\Programs\DockerDesktop\Docker Desktop.exe",
            r"AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe",
        ],
        "install_url": "https://www.docker.com/products/docker-desktop/",
        "description": "Enterprise containerization platform and desktop engine."
    },
    "mongodb": {
        "display_name": "MongoDB / Mongosh",
        "aliases": ["mongodb", "mongosh", "mongo", "mongodb server", "mongodb compass"],
        "executables": ["mongod.exe", "mongosh.exe", "mongo.exe", "mongosh"],
        "cli_cmd_allowlisted": "mongosh --version",
        "registry_names": ["MongoDB", "MongoDB Compass"],
        "standard_paths": [
            r"C:\Program Files\MongoDB\Server",
            r"AppData\Local\Programs\mongosh",
            r"AppData\Local\MongoDBCompass",
        ],
        "install_url": "https://www.mongodb.com/try/download/community",
        "description": "NoSQL document database and MongoDB interactive shell."
    },
    "chrome": {
        "display_name": "Google Chrome",
        "aliases": ["chrome", "google chrome"],
        "executables": ["chrome.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Google Chrome"],
        "standard_paths": [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ],
        "install_url": "https://www.google.com/chrome/",
        "description": "Google Chrome web browser."
    },
    "node": {
        "display_name": "Node.js",
        "aliases": ["node", "nodejs", "node.js", "npm"],
        "executables": ["node.exe", "node"],
        "cli_cmd_allowlisted": "node --version",
        "registry_names": ["Node.js"],
        "standard_paths": [
            r"C:\Program Files\nodejs\node.exe",
            r"AppData\Roaming\nvm",
        ],
        "install_url": "https://nodejs.org/",
        "description": "JavaScript runtime built on Chrome's V8 engine."
    },
    "antigravity": {
        "display_name": "Antigravity IDE",
        "aliases": ["antigravity", "antigravity ide", "google antigravity", "agy"],
        "executables": ["antigravity.exe", "agy.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Antigravity", "Antigravity IDE", "Antigravity IDE (User)"],
        "standard_paths": [
            r"AppData\Local\Programs\Antigravity IDE\Antigravity IDE.exe",
            r"AppData\Local\Programs\Antigravity\Antigravity.exe",
            r"AppData\Local\antigravity",
            r".gemini\antigravity",
        ],
        "install_url": "https://antigravity.google",
        "description": "Google Antigravity Next-Generation AI Development Environment & IDE."
    },
    "postman": {
        "display_name": "Postman",
        "aliases": ["postman", "postman api"],
        "executables": ["postman.exe", "postman"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Postman"],
        "standard_paths": [
            r"AppData\Local\Postman\Postman.exe",
            r"AppData\Local\Programs\Postman\Postman.exe"
        ],
        "install_url": "https://www.postman.com/downloads/",
        "description": "API platform for building and using APIs."
    },
    "slack": {
        "display_name": "Slack",
        "aliases": ["slack", "slack app"],
        "executables": ["slack.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Slack"],
        "standard_paths": [
            r"AppData\Local\slack\slack.exe"
        ],
        "install_url": "https://slack.com/downloads/windows",
        "description": "Slack productivity and team messaging platform."
    },
    "brave": {
        "display_name": "Brave Browser",
        "aliases": ["brave", "brave browser", "brave-browser"],
        "executables": ["brave.exe", "brave"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Brave"],
        "standard_paths": [
            r"AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
        ],
        "install_url": "https://brave.com/download/",
        "description": "Brave privacy-focused web browser."
    },
    "edge": {
        "display_name": "Microsoft Edge",
        "aliases": ["edge", "ms edge", "microsoft edge", "msedge"],
        "executables": ["msedge.exe", "edge.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Microsoft Edge"],
        "standard_paths": [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        ],
        "install_url": "https://www.microsoft.com/edge",
        "description": "Microsoft Edge Chromium-based web browser."
    },
    "anaconda": {
        "display_name": "Anaconda Data Science Platform",
        "aliases": ["anaconda", "anaconda3", "conda", "anaconda navigator"],
        "executables": ["conda.exe", "anaconda.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Anaconda3", "Anaconda"],
        "standard_paths": [
            r"Anaconda3\python.exe",
            r"AppData\Local\anaconda3\python.exe",
            r"C:\ProgramData\anaconda3\python.exe"
        ],
        "install_url": "https://www.anaconda.com/download",
        "description": "Enterprise Python distribution and data science platform."
    },
    "mysql": {
        "display_name": "MySQL Server & Tools",
        "aliases": ["mysql", "mysql server", "mysql workbench", "mysqld"],
        "executables": ["mysql.exe", "mysqld.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["MySQL Server", "MySQL Workbench", "MySQL"],
        "standard_paths": [
            r"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe",
            r"C:\Program Files\MySQL\MySQL Workbench 8.0 CE\MySQLWorkbench.exe"
        ],
        "install_url": "https://dev.mysql.com/downloads/",
        "description": "Open-source relational database management system."
    },
    "github": {
        "display_name": "GitHub Desktop",
        "aliases": ["github desktop", "github app", "github"],
        "executables": ["GitHubDesktop.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["GitHub Desktop"],
        "standard_paths": [
            r"AppData\Local\GitHubDesktop\GitHubDesktop.exe"
        ],
        "install_url": "https://desktop.github.com/",
        "description": "GUI client for GitHub version control workflows."
    },
    "excel": {
        "display_name": "Microsoft Excel",
        "aliases": ["excel", "ms excel", "microsoft excel"],
        "executables": ["excel.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Microsoft Excel", "Office", "Microsoft 365"],
        "standard_paths": [
            r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
            r"C:\Program Files (x86)\Microsoft Office\root\Office16\EXCEL.EXE"
        ],
        "install_url": "https://www.microsoft.com/microsoft-365/excel",
        "description": "Microsoft Excel spreadsheet application."
    },
    "word": {
        "display_name": "Microsoft Word",
        "aliases": ["word", "ms word", "microsoft word"],
        "executables": ["winword.exe", "word.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Microsoft Word", "Office", "Microsoft 365"],
        "standard_paths": [
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            r"C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE"
        ],
        "install_url": "https://www.microsoft.com/microsoft-365/word",
        "description": "Microsoft Word word processing application."
    },
    "spotify": {
        "display_name": "Spotify",
        "aliases": ["spotify", "spotify music"],
        "executables": ["spotify.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Spotify"],
        "standard_paths": [
            r"AppData\Roaming\Spotify\Spotify.exe",
            r"AppData\Local\Microsoft\WindowsApps\spotify.EXE"
        ],
        "install_url": "https://www.spotify.com/download/",
        "description": "Digital music and podcast streaming service."
    },
    "discord": {
        "display_name": "Discord",
        "aliases": ["discord", "discord app"],
        "executables": ["Discord.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Discord"],
        "standard_paths": [
            r"AppData\Local\Discord\Update.exe"
        ],
        "install_url": "https://discord.com/download",
        "description": "Voice, video, and text communication platform."
    },
    "vlc": {
        "display_name": "VLC Media Player",
        "aliases": ["vlc", "vlc media player", "vlc player"],
        "executables": ["vlc.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["VLC media player", "VLC"],
        "standard_paths": [
            r"C:\Program Files\VideoLAN\VLC\vlc.exe",
            r"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe"
        ],
        "install_url": "https://www.videolan.org/vlc/",
        "description": "Open-source cross-platform multimedia player."
    },
    "steam": {
        "display_name": "Steam",
        "aliases": ["steam", "steam client"],
        "executables": ["steam.exe"],
        "cli_cmd_allowlisted": None,
        "registry_names": ["Steam"],
        "standard_paths": [
            r"C:\Program Files (x86)\Steam\steam.exe"
        ],
        "install_url": "https://store.steampowered.com/about/",
        "description": "Valve Steam digital game distribution platform."
    }
}

# --- Safe Allowlisted Commands Table ---
SAFE_ALLOWLISTED_COMMANDS = {
    "python --version": ["python", "--version"],
    "git --version": ["git", "--version"],
    "cmd /c code --version": ["cmd", "/c", "code --version"],
    "code --version": ["cmd", "/c", "code --version"],
    "docker --version": ["docker", "--version"],
    "ollama --version": ["ollama", "--version"],
    "node --version": ["node", "--version"],
    "mongosh --version": ["mongosh", "--version"],
    "curl --version": ["curl", "--version"],
    "pip --version": ["python", "-m", "pip", "--version"]
}


# ==============================================================================
# 1. INTENT DETECTION MECHANISM
# ==============================================================================

def detect_user_intent(query: str) -> Dict[str, Any]:
    """Analyzes user query and extracts the exact intent and target entity.
    Returns:
      {
        "intent": <INTENT_CONSTANT>,
        "entity": <TARGET_ENTITY_OR_APP>,
        "confidence": 0.0 - 1.0,
        "raw_query": query
      }
    """
    q = query.strip()
    q_lower = q.lower()
    
    # 1. Greetings
    if re.match(r"^(hi|hello|hey|greetings|good morning|good afternoon)\b", q_lower):
        return {"intent": INTENT_GREETING, "entity": None, "confidence": 0.95, "raw_query": q}

    # 2. Project Attribution & Student Identity
    if any(k in q_lower for k in [
        "who made", "who built", "who developed", "who created", "who is the author",
        "who is the creator", "who are you", "author", "student", "creator", "usn",
        "jain university", "sujeet", "sujeet jagtap", "ayush", "ayush yadav", "what is this project"
    ]):
        return {"intent": INTENT_PROJECT_INFO, "entity": "author", "confidence": 0.95, "raw_query": q}

    # 3. MongoDB Curriculum & Role
    if any(k in q_lower for k in ["how is mongodb used", "role of mongodb", "why mongodb", "what does mongodb do"]):
        return {"intent": INTENT_MONGODB_ROLE, "entity": "mongodb", "confidence": 0.95, "raw_query": q}

    # 4. Cybersecurity, Threat Intelligence & Mitigation Queries
    cyber_terms = [
        "threat", "threats", "cve", "vulnerability", "vulnerabilities", "exploit", "exploits",
        "ransomware", "attack", "attacks", "zero-day", "zero-days", "malware", "trojan",
        "mitigate", "mitigation", "patch", "payload", "backdoor", "scanner",
        "scan", "audit", "nosql injection", "active threats", "evolving",
        "anticipated", "resolved", "cvss"
    ]
    if any(re.search(r"\b" + re.escape(t) + r"\b", q_lower) for t in cyber_terms):
        return {"intent": INTENT_SECURITY_THREAT, "entity": None, "confidence": 0.90, "raw_query": q}

    # 5. List Installed Applications Queries
    clean_q = re.sub(r"[\?\.\!]+$", "", q_lower).strip()
    list_patterns = [
        r"\b(list|show|what|tell\s+me)\b.*?\b(installed\s+(apps|applications|software|programs)|applications\s+installed|software\s+installed)\b",
        r"\bwhat\s+(apps|applications|software|programs)\s+(are\s+installed|do\s+i\s+have)\b",
        r"\b(all\s+installed\s+(apps|software|applications|programs))\b",
        r"\binstalled\s+(apps|applications|software|programs)\b"
    ]
    for lp in list_patterns:
        if re.search(lp, clean_q):
            return {"intent": INTENT_SOFTWARE_LIST, "entity": "all", "confidence": 0.95, "raw_query": q}

    # 6. Software Installation Queries (Any Phrasing & Natural Language)
    install_patterns = [
        r"^(?:is|check\s+if)\s+([a-zA-Z0-9_\-\.\s\+]+?)\s+(?:installed|available|present|downloaded|there)(?:\s+(?:in|on)\s+my\s+(?:laptop|pc|computer|system|windows|machine))?$",
        r"^(?:is|check\s+if)\s+([a-zA-Z0-9_\-\.\s\+]+?)\s+(?:in|on)\s+my\s+(?:laptop|pc|computer|system|windows|machine)$",
        r"^do\s+i\s+have\s+([a-zA-Z0-9_\-\.\s\+]+?)(?:\s+installed|\s+available|\s+downloaded)?(?:\s+(?:in|on)\s+my\s+(?:laptop|pc|computer|system|windows|machine))?$",
        r"^does\s+my\s+(?:laptop|pc|computer|system|windows|machine)\s+have\s+([a-zA-Z0-9_\-\.\s\+]+?)(?:\s+installed|\s+available)?$",
        r"^(?:tell\s+me\s+if|can\s+you\s+check\s+if|check\s+if)\s+([a-zA-Z0-9_\-\.\s\+]+?)\s+(?:is\s+)?(?:installed|available|present|on\s+my\s+laptop|in\s+my\s+laptop)$",
        r"^(?:check|verify)\s+([a-zA-Z0-9_\-\.\s\+]+?)(?:\s+installation)?$",
        r"^have\s+i\s+installed\s+([a-zA-Z0-9_\-\.\s\+]+?)(?:\s+(?:in|on)\s+my\s+(?:laptop|pc|computer|system|windows|machine))?$",
        r"^([a-zA-Z0-9_\-\.\s\+]+?)\s+installed$",
        r"\bis\s+([a-zA-Z0-9_\-\.\s\+]+?)\s+(?:installed|available|present|there|downloaded)\b",
        r"\bcheck\s+if\s+([a-zA-Z0-9_\-\.\s\+]+?)\s+is\s+(?:installed|available|present)\b",
        r"\bdo\s+i\s+have\s+([a-zA-Z0-9_\-\.\s\+]+?)\s+(?:installed|available|present|downloaded)\b",
        r"\bcan\s+you\s+find\s+([a-zA-Z0-9_\-\.\s\+]+?)\s+on\s+my\s+(?:laptop|pc|system|computer)\b"
    ]
    for pat in install_patterns:
        m = re.search(pat, clean_q)
        if m:
            raw_entity = m.group(1).strip()
            raw_entity = re.sub(r"^(is|are|a|an|the|my)\s+", "", raw_entity).strip()
            raw_entity = re.sub(r"\s+(?:in|on)\s+my\s+(?:laptop|pc|computer|system|windows|machine).*$", "", raw_entity).strip()
            raw_entity = re.sub(r"\s+(is|are)$", "", raw_entity).strip()
            if raw_entity and not any(w in raw_entity for w in ["laptop", "pc", "computer", "system", "specs", "specifications", "cpu", "ram", "battery", "gpu", "storage", "wifi", "uptime"]):
                return {
                    "intent": INTENT_SOFTWARE_INSTALL,
                    "entity": normalize_app_name(raw_entity),
                    "raw_entity": raw_entity,
                    "confidence": 0.95,
                    "raw_query": q
                }

    # 6. Software Version Queries (e.g. "What version of Python is installed?", "Git version")
    version_patterns = [
        r"\bwhat\s+version\s+of\s+([a-zA-Z0-9_\-\.\s]+?)\s+(is|do\s+i\s+have|installed)\b",
        r"\bwhat\s+is\s+my\s+([a-zA-Z0-9_\-\.\s]+?)\s+version\b",
        r"\b([a-zA-Z0-9_\-\.\s]+?)\s+version\b",
        r"\bversion\s+of\s+([a-zA-Z0-9_\-\.\s]+)\b"
    ]
    for pat in version_patterns:
        m = re.search(pat, q_lower)
        if m:
            raw_entity = m.group(1).strip()
            raw_entity = re.sub(r"\s+(is|do|installed|on).*$", "", raw_entity).strip()
            # Avoid matching "windows version" or "os version" as software version (routes to OS instead)
            if any(w in raw_entity for w in ["windows", "os", "operating system"]):
                return {"intent": INTENT_OPERATING_SYSTEM, "entity": "windows", "confidence": 0.95, "raw_query": q}
            return {
                "intent": INTENT_SOFTWARE_VERSION,
                "entity": normalize_app_name(raw_entity),
                "raw_entity": raw_entity,
                "confidence": 0.92,
                "raw_query": q
            }

    # 7. Running Processes & Services
    process_patterns = [
        r"\bis\s+([a-zA-Z0-9_\-\.\s]+?)\s+running\b",
        r"\bwhat\s+processes\s+are\s+running\b",
        r"\btask\s+manager\b",
        r"\btop\s+processes\b",
        r"\bconsuming\s+(cpu|ram|memory)\b"
    ]
    for pat in process_patterns:
        m = re.search(pat, q_lower)
        if m:
            matched_app = m.group(1).strip() if m.lastindex and m.lastindex >= 1 else None
            return {
                "intent": INTENT_RUNNING_PROCESS,
                "entity": normalize_app_name(matched_app) if matched_app else "all",
                "confidence": 0.90,
                "raw_query": q
            }

    # 8. Development Environment & Path
    if any(k in q_lower for k in ["what is my path", "environment variables", "dev tools", "development tools", "developer environment"]):
        return {"intent": INTENT_DEV_ENVIRONMENT, "entity": "env", "confidence": 0.90, "raw_query": q}

    # 9. Operating System & Build
    if any(k in q_lower for k in ["operating system", "what os", "which os", "windows version", "os build", "windows build", "my os", "what is my os", "os", "windows 11"]):
        return {"intent": INTENT_OPERATING_SYSTEM, "entity": "windows", "confidence": 0.95, "raw_query": q}

    # 10. Specific Hardware Metrics (Battery, CPU, RAM, Storage, Wi-Fi, GPU, Uptime)
    hardware_metric_map = [
        (["battery", "charger", "charging", "plugged in", "power left", "power remaining", "ac power", "battery percentage", "battery health"], "battery"),
        (["wifi", "wi-fi", "ssid", "ip address", "my ip", "network connection", "ip", "ethernet"], "wifi"),
        (["cpu", "processor", "i5", "i5-13450hx", "cpu usage", "cpu load", "processor usage", "processor load", "clock speed", "cpu cores", "cores", "threads"], "cpu"),
        (["ram", "memory", "how much ram", "ram usage", "memory usage", "free ram", "ram free", "free memory", "installed ram", "ddr", "ddr5"], "ram"),
        (["storage", "storage space", "free storage", "disk space", "hard drive", "c drive", "d drive", "free space", "space left", "space available", "disk", "ssd", "hdd"], "storage"),
        (["gpu", "graphics", "video card", "rtx", "rtx 3050", "vram", "display card", "nvidia"], "gpu"),
        (["uptime", "boot time", "how long running", "when was my laptop booted", "running time"], "uptime"),
        (["display", "screen", "resolution", "refresh rate", "monitor", "display resolution"], "display")
    ]
    for terms, metric in hardware_metric_map:
        if any(re.search(r"\b" + re.escape(t) + r"\b", q_lower) for t in terms):
            return {"intent": INTENT_HARDWARE_METRIC, "entity": metric, "confidence": 0.95, "raw_query": q}

    # 11. Full Hardware Specs (ONLY when user explicitly asks for all/complete specs)
    full_specs_terms = [
        "laptop specs", "full specs", "all specs", "specifications", "tell me about my laptop",
        "laptop specifications", "hardware profile", "machine specs", "system specs"
    ]
    if any(t in q_lower for t in full_specs_terms):
        return {"intent": INTENT_HARDWARE_SPECS, "entity": "laptop", "confidence": 0.95, "raw_query": q}

    # Fallback to General
    return {"intent": INTENT_GENERAL, "entity": None, "confidence": 0.50, "raw_query": q}


def normalize_app_name(raw_name: str) -> str:
    """Normalizes colloquial and alias application names to canonical catalog keys,
    with built-in fuzzy typo matching (e.g. 'cluade' -> 'claude').
    """
    if not raw_name:
        return "unknown"
    n = raw_name.lower().strip()
    n = re.sub(r"^(is|are|a|an|the|my)\s+", "", n).strip()
    n = re.sub(r"\s+(is|are|app|application|software|client|browser)$", "", n).strip()

    # Pass 1: Exact key or exact alias match (check longer phrases first)
    all_items = sorted(
        ALLOWLISTED_SOFTWARE_CATALOG.items(),
        key=lambda x: max([len(x[0])] + [len(a) for a in x[1].get("aliases", [])]),
        reverse=True
    )
    for key, info in all_items:
        if n == key or n in info["aliases"]:
            return key

    # Pass 2: Whole-word boundary match
    for key, info in all_items:
        for alias in sorted(info["aliases"], key=len, reverse=True):
            if re.search(r"\b" + re.escape(alias) + r"\b", n):
                return key

    # Pass 3: Fuzzy Typo Matching against Catalog keys and aliases
    candidates = {}
    for key, info in ALLOWLISTED_SOFTWARE_CATALOG.items():
        candidates[key] = key
        for alias in info.get("aliases", []):
            candidates[alias] = key

    matches = difflib.get_close_matches(n, candidates.keys(), n=1, cutoff=0.72)
    if matches:
        matched_target = matches[0]
        canonical_key = candidates[matched_target]
        logger.info(f"[SPELLCHECK] Fuzzy matched typo '{n}' -> '{matched_target}' ({canonical_key})")
        return canonical_key

    return n


# ==============================================================================
# 2. SECURE ALLOWLISTED COMMAND EXECUTOR
# ==============================================================================

def execute_allowlisted_command(cmd_str: str) -> Tuple[bool, str]:
    """Safely executes an allowlisted diagnostic command on the Windows host.
    Strictly prohibits arbitrary or untrusted command strings.
    """
    clean_cmd = cmd_str.strip()
    cmd_args = SAFE_ALLOWLISTED_COMMANDS.get(clean_cmd)
    
    if not cmd_args:
        logger.warning("[SECURITY] Blocked non-allowlisted command attempt: %s", clean_cmd)
        return False, "Security Violation: Diagnostic command is not in the allowlisted set."

    if not IS_WINDOWS:
        return False, "Host Execution Unavailable: Not running directly on Windows host."

    try:
        res = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            timeout=3.0,
            shell=(cmd_args[0] == "cmd")
        )
        out = (res.stdout or res.stderr or "").strip()
        first_line = out.split("\n")[0].strip() if out else "Executed successfully."
        return True, first_line
    except subprocess.TimeoutExpired:
        return False, "Command timed out after 3.0 seconds."
    except Exception as e:
        return False, f"Execution error: {str(e)}"


# ==============================================================================
# 3. WINDOWS SOFTWARE DETECTION ENGINE (Local Host Execution)
# ==============================================================================

def query_windows_registry_applications() -> Dict[str, Dict[str, str]]:
    """Scans standard 64-bit and 32-bit Windows Uninstall registry keys to discover
    all officially installed and registered desktop applications.
    """
    installed_apps: Dict[str, Dict[str, str]] = {}
    if not IS_WINDOWS:
        return installed_apps

    try:
        import winreg
    except ImportError:
        return installed_apps

    reg_hives = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
    ]

    for root_hive, hive_path in reg_hives:
        try:
            with winreg.OpenKey(root_hive, hive_path) as key:
                num_subkeys = winreg.QueryInfoKey(key)[0]
                for i in range(num_subkeys):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            vals = {}
                            num_vals = winreg.QueryInfoKey(subkey)[1]
                            for j in range(num_vals):
                                vname, vval, _ = winreg.EnumValue(subkey, j)
                                vals[vname] = vval
                            display_name = vals.get("DisplayName")
                            if display_name and isinstance(display_name, str):
                                dname_clean = display_name.strip()
                                installed_apps[dname_clean] = {
                                    "display_name": dname_clean,
                                    "version": str(vals.get("DisplayVersion") or "Not Available"),
                                    "install_location": str(vals.get("InstallLocation") or vals.get("InstallSource") or "Not Available"),
                                    "publisher": str(vals.get("Publisher") or "Unknown")
                                }
                    except Exception:
                        pass
        except Exception:
            pass

    return installed_apps


def query_start_menu_applications() -> Dict[str, str]:
    """Scans Windows Start Menu shortcut directories for registered user & system applications."""
    apps: Dict[str, str] = {}
    if not IS_WINDOWS:
        return apps
    user_start = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs")
    common_start = os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs")
    for base in [user_start, common_start]:
        if os.path.exists(base):
            for root, _, files in os.walk(base):
                for f in files:
                    if f.lower().endswith(".lnk"):
                        name = f[:-4].strip()
                        full_path = os.path.join(root, f)
                        apps[name] = full_path
    return apps


def query_windows_appx_packages() -> Dict[str, Dict[str, str]]:
    """Scans the Windows AppModel/MSIX package repository in the user registry
    to discover modern packaged Windows apps (e.g. Claude Desktop, WhatsApp, ChatGPT, Spotify).
    """
    apps: Dict[str, Dict[str, str]] = {}
    if not IS_WINDOWS:
        return apps

    try:
        import winreg
        key_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as root_key:
            num_subkeys = winreg.QueryInfoKey(root_key)[0]
            for i in range(num_subkeys):
                try:
                    pkg_id = winreg.EnumKey(root_key, i)
                    with winreg.OpenKey(root_key, pkg_id) as pkg_key:
                        dname = None
                        root_folder = None
                        try:
                            dname, _ = winreg.QueryValueEx(pkg_key, "DisplayName")
                        except Exception:
                            pass
                        try:
                            root_folder, _ = winreg.QueryValueEx(pkg_key, "PackageRootFolder")
                        except Exception:
                            pass
                        
                        clean_name = dname or pkg_id.split("_")[0]
                        version = "Not Available"
                        parts = pkg_id.split("_")
                        if len(parts) >= 2 and re.match(r"^\d+\.", parts[1]):
                            version = parts[1]
                        
                        if clean_name and not str(clean_name).startswith("ms-resource:") and not str(clean_name).startswith("@{") and not str(clean_name).startswith("{"):
                            apps[clean_name] = {
                                "display_name": clean_name,
                                "package_id": pkg_id,
                                "version": version,
                                "install_location": root_folder or "C:\\Program Files\\WindowsApps",
                                "source": "MSIX Package"
                            }
                except Exception:
                    continue
    except Exception:
        pass

    return apps


def query_windows_apps_folder_executables() -> Dict[str, str]:
    """Scans %LOCALAPPDATA%\\Microsoft\\WindowsApps for execution aliases (e.g. claude-desktop.exe)."""
    aliases: Dict[str, str] = {}
    if not IS_WINDOWS:
        return aliases
    user_profile = os.environ.get("USERPROFILE", "C:\\Users\\AYUSH YADAV")
    winapps_dir = os.path.join(user_profile, "AppData", "Local", "Microsoft", "WindowsApps")
    if os.path.isdir(winapps_dir):
        try:
            for item in os.listdir(winapps_dir):
                if item.lower().endswith(".exe"):
                    aliases[item.lower()] = os.path.join(winapps_dir, item)
        except Exception:
            pass
    return aliases


def score_software_match(query: str, target: str) -> int:
    """Computes a relevance score (0-100) between user query and detected software name."""
    q = query.lower().strip()
    t = target.lower().strip()
    if q == t:
        return 100
    q_norm = re.sub(r"[^a-z0-9]", "", q)
    t_norm = re.sub(r"[^a-z0-9]", "", t)
    if q_norm and q_norm == t_norm:
        return 95
    noise = {"browser", "desktop", "client", "app", "application", "software", "edition", "ide", "editor", "community", "tool", "tools", "player", "ce"}
    q_words = [w for w in re.split(r"[^a-z0-9]+", q) if len(w) > 1 and w not in noise]
    t_words = [w for w in re.split(r"[^a-z0-9]+", t) if len(w) > 1 and w not in noise]
    if not q_words or not t_words:
        q_words = [w for w in re.split(r"[^a-z0-9]+", q) if len(w) > 1]
        t_words = [w for w in re.split(r"[^a-z0-9]+", t) if len(w) > 1]
    if not q_words or not t_words:
        return 0
    if all(w in t_words for w in q_words):
        return 85 - abs(len(q_words) - len(t_words))
    if q in t_words:
        return 75
    if all(any(tw.startswith(w) for tw in t_words) for w in q_words):
        return 65
    return 0


def check_local_windows_software(app_key: str) -> Dict[str, Any]:
    """Performs deep, multi-vector verification on the Windows host machine
    to determine whether the requested application is truly installed.
    """
    if not IS_WINDOWS:
        return {
            "application": app_key.title(),
            "platform": "Windows",
            "status": "Unable to Verify",
            "version": "Not Available",
            "install_path": "Not Available",
            "additional_info": "Diagnostic engine is currently not running on a Windows host."
        }

    catalog_entry = ALLOWLISTED_SOFTWARE_CATALOG.get(app_key)
    display_title = catalog_entry["display_name"] if catalog_entry else app_key.title()
    install_url = (catalog_entry.get("install_url") if catalog_entry else None) or f"https://google.com/search?q={app_key}+download"

    user_profile = os.environ.get("USERPROFILE", "C:\\Users\\AYUSH YADAV")
    reg_apps = query_windows_registry_applications()
    appx_apps = query_windows_appx_packages()
    winapps_aliases = query_windows_apps_folder_executables()
    start_apps = query_start_menu_applications()

    # --- Probe 1: Windows Registry Check (Catalog Target OR Smart Score Matching) ---
    registry_match = None
    if catalog_entry and catalog_entry.get("registry_names"):
        reg_targets = catalog_entry.get("registry_names", [])
        for reg_name, reg_data in reg_apps.items():
            if any(t.lower() in reg_name.lower() for t in reg_targets):
                registry_match = reg_data
                break

    if not registry_match:
        # Score-based search across all registered Windows applications
        best_reg, best_reg_score = None, 0
        search_terms = [app_key]
        if catalog_entry:
            search_terms.extend(catalog_entry.get("aliases", []))
        for sterm in search_terms:
            for reg_name, reg_data in reg_apps.items():
                s = score_software_match(sterm, reg_name)
                if s > best_reg_score:
                    best_reg, best_reg_score = reg_data, s
        if best_reg_score >= 65:
            registry_match = best_reg
            if not catalog_entry:
                display_title = registry_match.get("display_name", display_title)

    # --- Probe 2: Windows Modern AppX / MSIX Package Repository Check ---
    appx_match = None
    search_terms = [app_key]
    if catalog_entry:
        search_terms.extend(catalog_entry.get("aliases", []))
    for sterm in search_terms:
        for pname, pdata in appx_apps.items():
            s = score_software_match(sterm, pname)
            if s >= 65 or sterm.lower() in pname.lower():
                appx_match = pdata
                break
        if appx_match:
            break
    if appx_match and not catalog_entry and not registry_match:
        display_title = appx_match.get("display_name", display_title)

    # --- Probe 3: WindowsApps Execution Aliases Check ---
    winapps_match = None
    target_exes = [f"{app_key.lower()}.exe", f"{app_key.lower()}-desktop.exe"]
    if catalog_entry:
        target_exes.extend([e.lower() for e in catalog_entry.get("executables", [])])
    for tex in target_exes:
        if tex in winapps_aliases:
            winapps_match = winapps_aliases[tex]
            break

    # --- Probe 4: Start Menu Applications Check ---
    start_menu_match = None
    best_start, best_start_score = None, 0
    for sterm in search_terms:
        for sname, spath in start_apps.items():
            s = score_software_match(sterm, sname)
            if s > best_start_score:
                best_start, best_start_score = (sname, spath), s
    if best_start_score >= 65:
        start_menu_match = best_start
        if not catalog_entry and not registry_match and not appx_match:
            display_title = start_menu_match[0]

    # --- Probe 5: Executable & PATH Detection ---
    active_binary_path = None
    if catalog_entry:
        for exe in catalog_entry.get("executables", []):
            found_which = shutil.which(exe)
            if found_which:
                active_binary_path = found_which
                break
    if not active_binary_path:
        active_binary_path = (
            shutil.which(app_key)
            or shutil.which(f"{app_key}.exe")
            or shutil.which(f"{app_key}.cmd")
            or shutil.which(f"{app_key}.bat")
        )

    # --- Probe 6: Standard Directory Inspection ---
    standard_path_match = None
    if catalog_entry:
        for rel_path in catalog_entry.get("standard_paths", []):
            full_path = rel_path if os.path.isabs(rel_path) else os.path.join(user_profile, rel_path)
            if os.path.exists(full_path):
                standard_path_match = full_path
                break
    if not standard_path_match:
        dynamic_candidates = [
            os.path.join(user_profile, "AppData", "Local", "Programs", app_key.title()),
            os.path.join(user_profile, "AppData", "Local", "Programs", f"{app_key.title()} IDE"),
            os.path.join(user_profile, "AppData", "Local", app_key.lower()),
            os.path.join(user_profile, "AppData", "Local", "Microsoft", "WindowsApps", f"{app_key.lower()}.exe"),
            os.path.join(user_profile, ".gemini", app_key.lower()),
            os.path.join(r"C:\Program Files", app_key.title()),
            os.path.join(r"C:\Program Files (x86)", app_key.title()),
        ]
        for cpath in dynamic_candidates:
            if os.path.exists(cpath):
                standard_path_match = cpath
                break

    # --- Probe 7: Version Execution (Allowlisted Only) ---
    cli_version_str = None
    if catalog_entry and catalog_entry.get("cli_cmd_allowlisted"):
        success, ver_out = execute_allowlisted_command(catalog_entry["cli_cmd_allowlisted"])
        if success and ver_out:
            cli_version_str = ver_out

    # --- Synthesize Verification Findings ---
    is_installed = bool(registry_match or appx_match or winapps_match or start_menu_match or active_binary_path or standard_path_match)

    if is_installed:
        # Resolve Version
        version = "Not Available"
        if cli_version_str:
            version = cli_version_str
        elif appx_match and appx_match.get("version") and appx_match.get("version") != "Not Available":
            version = appx_match["version"]
        elif registry_match and registry_match.get("version") and registry_match.get("version") != "Not Available":
            version = registry_match["version"]
        elif start_menu_match or winapps_match:
            version = "Available (Desktop Application)"

        # Resolve Path
        resolved_path = (
            active_binary_path
            or winapps_match
            or (appx_match.get("install_location") if appx_match else None)
            or standard_path_match
            or (start_menu_match[1] if start_menu_match else None)
            or (registry_match.get("install_location") if registry_match else None)
        )
        if not resolved_path or resolved_path == "Not Available":
            resolved_path = standard_path_match or "Registered in Windows Application Hive"

        details = []
        if appx_match:
            details.append(f"Modern Windows Package: '{appx_match['display_name']}' ({appx_match.get('package_id', '')})")
        if winapps_match:
            details.append(f"Execution alias active in WindowsApps ({winapps_match})")
        if registry_match:
            details.append(f"Registered Windows Application: '{registry_match['display_name']}'")
        if start_menu_match:
            details.append(f"Verified Windows Start Menu Shortcut ('{start_menu_match[0]}')")
        if active_binary_path:
            details.append(f"Executable active in PATH ({active_binary_path})")
        if standard_path_match and standard_path_match != active_binary_path:
            details.append(f"Binary verified in directory ({standard_path_match})")

        return {
            "application": display_title,
            "platform": "Windows",
            "status": "Installed",
            "version": version,
            "install_path": resolved_path,
            "additional_info": ". ".join(details) + "."
        }
    else:
        # Verified Not Installed
        reasons = [
            f"No registered Windows application matching '{display_title}' was found in registry uninstall keys",
            f"No matching modern Windows Store (MSIX) package was found",
            f"No matching application shortcut was found in Windows Start Menu programs",
            f"Executable was not found in the Windows PATH environment or WindowsApps",
            f"Not found in standard installation directories (%LOCALAPPDATA%\\Programs, Program Files)"
        ]
        install_advice = f"You can download and install {display_title} from the official source: {install_url}"

        # Special contextual note for Ollama if running as daemon
        if app_key == "ollama":
            install_advice += " (Note: The project's Ollama SLM API daemon is running locally on port 11434 serving llama3.2:3b, but native Windows desktop client is not installed)."

        return {
            "application": display_title,
            "platform": "Windows",
            "status": "Not Installed",
            "version": "Not Available",
            "install_path": "Not Available",
            "additional_info": f"{'. '.join(reasons)}. {install_advice}"
        }


def handle_list_installed_software() -> str:
    """Returns a clean, sorted, categorized overview of installed applications on the Windows laptop."""
    reg_apps = query_windows_registry_applications()
    appx_apps = query_windows_appx_packages()
    
    # Filter out system component noise
    filtered = {}
    noise_prefixes = ["microsoft visual c++", "windows driver", "intel(r)", "update for", "security update", "@{", "ms-resource:"]
    for name, data in reg_apps.items():
        if any(name.lower().startswith(p) for p in noise_prefixes):
            continue
        filtered[name] = data.get("version", "Installed")

    for name, data in appx_apps.items():
        if any(name.lower().startswith(p) for p in noise_prefixes):
            continue
        if name.startswith("{") or "cw5n1h2txyewy" in name or "neutral" in name.lower() or "experiencehost" in name.lower() or "brokerplugin" in name.lower():
            continue
        if name not in filtered:
            filtered[name] = data.get("version", "Installed")
    
    # Sort by name
    sorted_apps = sorted(filtered.items(), key=lambda x: x[0].lower())
    lines = [f"• **{name}** (Version: `{ver}`)" for name, ver in sorted_apps[:40]]
    
    return (
        f"📦 **Applications Installed on Host Machine ({socket.gethostname()}):**\n\n"
        f"Detected **{len(filtered)}** verified desktop and modern applications registered on Windows:\n\n"
        + "\n".join(lines) + "\n\n"
        "💡 *You can ask specifically about any software (e.g. \"Is Claude installed?\", \"Is Chrome installed?\", \"Is Docker available?\") for complete installation path and version details.*"
    )


# ==============================================================================
# 4. CONTAINER-TO-HOST SECURE DIAGNOSTIC CLIENT
# ==============================================================================

def check_host_software_installation(app_name: str) -> Dict[str, Any]:
    """Unified entry point for checking software installation.
    - If running on Windows host: executes diagnostic routines directly.
    - If running inside Docker: queries the Windows host diagnostic service
      via authenticated HTTP request (X-Host-Token).
    - If host service unreachable: returns 'Unable to Verify' with clear reporting.
    """
    clean_key = normalize_app_name(app_name)

    # 1. Direct Native Windows Execution
    if IS_WINDOWS:
        return check_local_windows_software(clean_key)

    # 2. Containerized Execution (Query Windows Host Diagnostic Service)
    if IS_DOCKER:
        import urllib.request
        import urllib.parse
        target_url = f"{HOST_DIAGNOSTIC_URL}/host/software?app={urllib.parse.quote(clean_key)}"
        req = urllib.request.Request(
            target_url,
            headers={
                "X-Host-Token": HOST_DIAGNOSTIC_TOKEN,
                "Accept": "application/json"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    return data
        except Exception as e:
            catalog_entry = ALLOWLISTED_SOFTWARE_CATALOG.get(clean_key)
            display_title = catalog_entry["display_name"] if catalog_entry else clean_key.title()
            logger.warning("[HOST_DIAGNOSTIC] Docker cannot contact host at %s: %s", target_url, e)
            return {
                "application": display_title,
                "platform": "Windows",
                "status": "Unable to Verify",
                "version": "Not Available",
                "install_path": "Not Available",
                "additional_info": (
                    f"Host-level verification is unavailable. The chatbot is currently running inside a Docker "
                    f"container (Linux) and could not establish a secure connection to the Windows Host Diagnostic "
                    f"Service at {HOST_DIAGNOSTIC_URL}. "
                    f"To verify software on your Windows host from Docker, ensure the host diagnostic service is running "
                    f"and extra_hosts is configured in docker-compose.yml."
                )
            }

    # 3. Fallback for non-Windows, non-Docker environments
    return {
        "application": clean_key.title(),
        "platform": sys.platform,
        "status": "Unable to Verify",
        "version": "Not Available",
        "install_path": "Not Available",
        "additional_info": f"Host machine platform is {sys.platform}. Windows diagnostics are not applicable."
    }


# ==============================================================================
# 5. RESPONSE FORMATTER & HANDLERS
# ==============================================================================

def format_software_response(diag: Dict[str, Any]) -> str:
    """Formats the software installation diagnostic result strictly according
    to the user's required response specification.
    """
    app_name = diag.get("application", "Software Application")
    platform = diag.get("platform", "Windows")
    status = diag.get("status", "Unable to Verify")
    version = diag.get("version", "Not Available")
    install_path = diag.get("install_path", "Not Available")
    additional_info = diag.get("additional_info", "")

    status_icon = "✅" if status == "Installed" else ("❌" if status == "Not Installed" else "⚠️")

    return (
        f"**Application:** {app_name}\n\n"
        f"**Platform:** {platform}\n\n"
        f"**Installation Status:** {status_icon} **`{status}`**\n\n"
        f"**Version:** `{version}`\n\n"
        f"**Installation Path:** `{install_path}`\n\n"
        f"**Additional Information:** {additional_info}"
    )


def handle_running_process_query(entity: str) -> str:
    """Safely checks if a specific process is running on the host machine,
    or returns top resource-consuming processes without dumping hardware specs.
    """
    try:
        import psutil
    except ImportError:
        return "⚠️ Process telemetry unavailable: `psutil` library is not loaded."

    if entity and entity != "all":
        # Check specific process
        matching_procs = []
        for p in psutil.process_iter(["name", "pid", "memory_percent", "cpu_percent"]):
            try:
                name = p.info.get("name", "")
                if entity.lower() in name.lower():
                    matching_procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if matching_procs:
            lines = [f"• **`{p['name']}`** (PID: `{p['pid']}`, RAM: `{p.get('memory_percent', 0):.1f}%`)" for p in matching_procs[:5]]
            return (
                f"🟢 **Process Status: Running**\n\n"
                f"The process **`{entity}`** is currently active on your host machine:\n"
                + "\n".join(lines)
            )
        else:
            return (
                f"🔴 **Process Status: Not Running**\n\n"
                f"No active processes matching **`{entity}`** were found in the host machine process table."
            )
    else:
        # Top processes
        top = []
        for p in psutil.process_iter(["name", "pid", "memory_percent"]):
            try:
                mem = p.info.get("memory_percent")
                if mem and mem > 1.0:
                    top.append((p.info["name"], p.info["pid"], round(mem, 1)))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        top = sorted(top, key=lambda x: x[2], reverse=True)[:5]
        lines = [f"• **`{name}`** (PID `{pid}`): `{mem}%` RAM" for name, pid, mem in top]
        return "📊 **Top Resource-Consuming Running Processes:**\n\n" + "\n".join(lines)


def handle_dev_environment_query() -> str:
    """Returns verified development tools and runtime versions without dumping hardware specs."""
    tools = ["python", "git", "code", "docker", "mongosh", "node"]
    results = []
    for t in tools:
        diag = check_host_software_installation(t)
        st_icon = "✅" if diag["status"] == "Installed" else "❌"
        results.append(f"• **{diag['application']}**: {st_icon} `{diag['status']}` (Version: `{diag['version']}`)")

    return (
        "🛠️ **Host Development Environment & Tools Status:**\n\n"
        + "\n".join(results) + "\n\n"
        f"- **Operating System:** Windows 11 AMD64 (Hostname: `{socket.gethostname()}`)\n"
        f"- **Primary Python Path:** `{shutil.which('python') or 'Not in PATH'}`"
    )
