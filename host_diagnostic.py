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
        "aliases": ["claude", "claude desktop", "anthropic claude"],
        "executables": ["claude.exe", "claude"],
        "cli_cmd_allowlisted": None,  # GUI application, no CLI version
        "registry_names": ["Claude", "Anthropic Claude"],
        "standard_paths": [
            r"AppData\Local\Programs\Claude\Claude.exe",
            r"AppData\Local\Claude\Claude.exe",
            r"AppData\Roaming\Claude\Claude.exe",
            r"C:\Program Files\Claude\Claude.exe",
            r"C:\Program Files (x86)\Claude\Claude.exe",
        ],
        "install_url": "https://claude.ai/download",
        "description": "Anthropic Claude Desktop application for Windows."
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
        "registry_names": ["Git", "GitHub Desktop"],
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
        "who made you", "who created you", "who are you", "author", "student",
        "creator", "usn", "jain university", "sujeet", "ayush"
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

    # 5. Software Installation Queries (e.g. "Is Claude installed?", "Do I have Git?")
    install_patterns = [
        r"\bis\s+([a-zA-Z0-9_\-\.\s]+?)\s+(installed|available|present|there|downloaded)\b",
        r"\bdo\s+i\s+have\s+([a-zA-Z0-9_\-\.\s]+?)\s+(installed|available|present|downloaded|on\s+my\s+laptop)\b",
        r"\bcheck\s+if\s+([a-zA-Z0-9_\-\.\s]+?)\s+is\s+(installed|available|present)\b",
        r"\bhave\s+i\s+installed\s+([a-zA-Z0-9_\-\.\s]+)\b",
        r"\bcan\s+you\s+find\s+([a-zA-Z0-9_\-\.\s]+?)\s+on\s+my\s+(laptop|pc|system|computer)\b",
        r"\bis\s+there\s+([a-zA-Z0-9_\-\.\s]+?)\s+on\s+my\s+(laptop|pc|system|computer)\b"
    ]
    for pat in install_patterns:
        m = re.search(pat, q_lower)
        if m:
            raw_entity = m.group(1).strip()
            # Clean up trailing words like 'on my laptop', 'on my pc'
            raw_entity = re.sub(r"\s+on\s+(my\s+)?(laptop|pc|computer|system|windows).*$", "", raw_entity).strip()
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
    if any(k in q_lower for k in ["operating system", "what os", "which os", "windows version", "os build", "windows build"]):
        return {"intent": INTENT_OPERATING_SYSTEM, "entity": "windows", "confidence": 0.95, "raw_query": q}

    # 10. Specific Hardware Metrics (Battery, CPU, RAM, Storage, Wi-Fi, GPU, Uptime)
    hardware_metric_map = [
        (["battery", "charger", "charging", "plugged in", "power left", "power remaining", "ac power"], "battery"),
        (["wifi", "wi-fi", "ssid", "ip address", "my ip", "network connection"], "wifi"),
        (["cpu usage", "cpu load", "processor usage", "processor load", "clock speed", "cpu cores"], "cpu"),
        (["how much ram", "ram usage", "memory usage", "free ram", "ram free", "free memory"], "ram"),
        (["storage space", "free storage", "disk space", "hard drive", "c drive", "d drive", "free space", "space left", "space available"], "storage"),
        (["gpu", "graphics", "video card", "rtx", "rtx 3050", "vram"], "gpu"),
        (["uptime", "boot time", "how long running", "when was my laptop booted", "running time"], "uptime")
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
    """Normalizes colloquial and alias application names to canonical catalog keys."""
    if not raw_name:
        return "unknown"
    n = raw_name.lower().strip()
    # Check catalog aliases
    for key, info in ALLOWLISTED_SOFTWARE_CATALOG.items():
        if n == key or n in info["aliases"]:
            return key
        if any(alias in n for alias in info["aliases"]):
            return key
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
    install_url = (catalog_entry.get("install_url") if catalog_entry else None) or f"https://google.com/search?q={app_key}"

    user_profile = os.environ.get("USERPROFILE", "C:\\Users\\AYUSH YADAV")
    reg_apps = query_windows_registry_applications()

    # --- Probe 1: Windows Registry Check ---
    registry_match = None
    if catalog_entry:
        reg_targets = catalog_entry.get("registry_names", [])
        for reg_name, reg_data in reg_apps.items():
            if any(t.lower() in reg_name.lower() for t in reg_targets):
                registry_match = reg_data
                break
    else:
        # Dynamic search for arbitrary application
        for reg_name, reg_data in reg_apps.items():
            if app_key.lower() in reg_name.lower():
                registry_match = reg_data
                display_title = reg_data.get("display_name", display_title)
                break

    # --- Probe 2: Executable & PATH Detection ---
    active_binary_path = None
    if catalog_entry:
        for exe in catalog_entry.get("executables", []):
            found_which = shutil.which(exe)
            if found_which:
                active_binary_path = found_which
                break
    else:
        active_binary_path = shutil.which(app_key) or shutil.which(f"{app_key}.exe")

    # --- Probe 3: Standard Directory Inspection ---
    standard_path_match = None
    if catalog_entry:
        for rel_path in catalog_entry.get("standard_paths", []):
            full_path = rel_path if os.path.isabs(rel_path) else os.path.join(user_profile, rel_path)
            if os.path.exists(full_path):
                standard_path_match = full_path
                break
    else:
        # Dynamic inspection of common Windows installation paths
        dynamic_candidates = [
            os.path.join(user_profile, "AppData", "Local", "Programs", app_key.title()),
            os.path.join(user_profile, "AppData", "Local", "Programs", f"{app_key.title()} IDE"),
            os.path.join(user_profile, "AppData", "Local", app_key.lower()),
            os.path.join(user_profile, ".gemini", app_key.lower()),
            os.path.join(r"C:\Program Files", app_key.title()),
            os.path.join(r"C:\Program Files (x86)", app_key.title()),
        ]
        for cpath in dynamic_candidates:
            if os.path.exists(cpath):
                standard_path_match = cpath
                break

    # --- Probe 4: Version Execution (Allowlisted Only) ---
    cli_version_str = None
    if catalog_entry and catalog_entry.get("cli_cmd_allowlisted"):
        success, ver_out = execute_allowlisted_command(catalog_entry["cli_cmd_allowlisted"])
        if success and ver_out:
            cli_version_str = ver_out

    # --- Synthesize Verification Findings ---
    is_installed = bool(registry_match or active_binary_path or standard_path_match)

    if is_installed:
        # Resolve Version
        version = "Not Available"
        if cli_version_str:
            version = cli_version_str
        elif registry_match and registry_match.get("version") and registry_match.get("version") != "Not Available":
            version = registry_match["version"]

        # Resolve Path
        resolved_path = active_binary_path or standard_path_match or (registry_match.get("install_location") if registry_match else None)
        if not resolved_path or resolved_path == "Not Available":
            resolved_path = standard_path_match or "Registered in Windows Application Hive"

        details = []
        if registry_match:
            details.append(f"Registered Windows Application: '{registry_match['display_name']}'")
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
            f"Executable was not found in the Windows PATH environment",
            f"Not found in standard installation directories (%LOCALAPPDATA%\\Programs, Program Files)"
        ]
        install_advice = f"You can download and install {display_title} from the official source: {install_url}"

        # Special contextual note for Ollama if running as daemon
        if app_key == "ollama":
            install_advice += " (Note: The project's Ollama SLM API daemon is running locally on port 11434 serving llama3.2:1b, but native Windows desktop client is not installed)."

        return {
            "application": display_title,
            "platform": "Windows",
            "status": "Not Installed",
            "version": "Not Available",
            "install_path": "Not Available",
            "additional_info": f"{'. '.join(reasons)}. {install_advice}"
        }


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
