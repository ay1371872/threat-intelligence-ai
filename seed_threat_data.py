"""Threat Intelligence Seed Data Generator
Populates MongoDB with comprehensive, multi-platform threat intelligence records:
- Anticipated, Active, Evolving, and Resolved threats across Windows, Linux, macOS, Android, and iOS.
- Embeds dense vector embeddings (Exercise 17) and creates initial audit records (Exercise 10).
"""

import sys
import os
from datetime import datetime

from db_connector import get_database, initialize_database_indexes_and_schemas
from rag_engine import compute_embedding

SAMPLE_THREATS = [
    # --- LINUX THREATS ---
    {
        "cve_id": "CVE-2024-3094",
        "title": "XZ Utils Malicious Backdoor (liblzma)",
        "platform": "Linux",
        "status": "Active",
        "severity": "Critical",
        "cvss": 10.0,
        "attack_vector": "Network",
        "affected_components": ["liblzma 5.6.0", "liblzma 5.6.1", "sshd"],
        "indicators_of_compromise": [
            "SHA256: 4f1873523450e181e1147814b7e8d66922a46e1074a16127b68d6e32630d7b38",
            "Modified crc64_fast function hijacking RSA decryption in sshd"
        ],
        "description": "Sophisticated upstream supply-chain backdoor injected into XZ Utils tarballs. Intercepts sshd daemon authentication routines to allow unauthorized remote code execution.",
        "mitigation_procedure": "Immediately downgrade xz-utils to version 5.4.x or upgrade to clean upstream packages. Terminate and audit all active OpenSSH sessions.",
        "automated_fix_command": "sudo apt-get update && sudo apt-get install --only-upgrade xz-utils=5.4.5-0.3 -y && sudo systemctl restart sshd",
        "mitigated_at": None
    },
    {
        "cve_id": "CVE-2024-1086",
        "title": "Linux Kernel Netfilter Use-After-Free Privilege Escalation",
        "platform": "Linux",
        "status": "Evolving",
        "severity": "High",
        "cvss": 7.8,
        "attack_vector": "Local",
        "affected_components": ["nf_tables", "Linux Kernel 5.14 to 6.6"],
        "indicators_of_compromise": [
            "Unprivileged user namespaces allocating high volume of nftable sets",
            "Kernel panic logs referencing nft_verdict_init drop verdict"
        ],
        "description": "A use-after-free flaw in netfilter nf_tables permits local unprivileged users to obtain root access or trigger kernel execution via crafted netlink messages.",
        "mitigation_procedure": "Disable unprivileged user namespaces if not required, or patch kernel to 6.7+.",
        "automated_fix_command": "echo 'kernel.unprivileged_userns_clone=0' | sudo tee /etc/sysctl.d/99-disable-userns.conf && sudo sysctl --system",
        "mitigated_at": None
    },
    {
        "cve_id": "CVE-2024-6387",
        "title": "RegreSSHion OpenSSH Remote Code Execution",
        "platform": "Linux",
        "status": "Anticipated",
        "severity": "Critical",
        "cvss": 9.8,
        "attack_vector": "Network",
        "affected_components": ["OpenSSH 8.5p1 through 9.7p1"],
        "indicators_of_compromise": [
            "Excessive parallel SSH connections from anomalous IP blocks",
            "SIGALRM signal handler race condition in sshd"
        ],
        "description": "Signal handler race condition in OpenSSH server allowing unauthenticated remote code execution as root on glibc-based Linux systems.",
        "mitigation_procedure": "Set LoginGraceTime to 0 in sshd_config as immediate temporary mitigation, then patch OpenSSH to version 9.8p1+.",
        "automated_fix_command": "sudo sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 0/' /etc/ssh/sshd_config && sudo systemctl reload ssh",
        "mitigated_at": None
    },
    {
        "cve_id": "CVE-2021-4034",
        "title": "PwnKit: Polkit Local Privilege Escalation",
        "platform": "Linux",
        "status": "Resolved",
        "severity": "High",
        "cvss": 7.8,
        "attack_vector": "Local",
        "affected_components": ["polkit pkexec"],
        "indicators_of_compromise": [
            "pkexec executed without command line arguments",
            "Out-of-bounds array write in main() loop"
        ],
        "description": "Memory corruption vulnerability in Polkit pkexec tool present since its inception, allowing any unprivileged user to acquire full root privileges.",
        "mitigation_procedure": "Remove SUID bit from pkexec or install upstream vendor distribution security patches.",
        "automated_fix_command": "sudo chmod 0755 /usr/bin/pkexec",
        "mitigated_at": "2026-01-10T14:30:00Z"
    },

    # --- WINDOWS THREATS ---
    {
        "cve_id": "CVE-2024-21413",
        "title": "Microsoft Outlook Moniker Remote Code Execution (Checkm8-style)",
        "platform": "Windows",
        "status": "Active",
        "severity": "Critical",
        "cvss": 9.8,
        "attack_vector": "Network",
        "affected_components": ["Microsoft Outlook 2016/2019/365", "OLE Linking"],
        "indicators_of_compromise": [
            "Inbound emails with 'file:///' URLs ending in '!' anchor",
            "Outbound SMB connections on TCP port 445 triggered by preview pane"
        ],
        "description": "Allows an unauthenticated threat actor to bypass Protected View and trigger NTLM credential relaying or remote code execution via malicious OLE moniker links.",
        "mitigation_procedure": "Block outbound SMB traffic (TCP 445) at boundary firewalls and apply Microsoft February 2024 Security Update KB5034127.",
        "automated_fix_command": "netsh advfirewall firewall add rule name=\"Block Outbound SMB 445\" dir=out action=block protocol=TCP localport=any remoteport=445",
        "mitigated_at": None
    },
    {
        "cve_id": "CVE-2024-38077",
        "title": "Windows Remote Desktop Licensing Service RCE (MadLicence)",
        "platform": "Windows",
        "status": "Active",
        "severity": "Critical",
        "cvss": 9.8,
        "attack_vector": "Network",
        "affected_components": ["Remote Desktop Licensing Service", "RDLS.exe"],
        "indicators_of_compromise": [
            "Anomalous RPC calls directed at Windows Server TCP port 135/49152+",
            "Heap overflow in TermServLicensing service"
        ],
        "description": "Unauthenticated remote code execution vulnerability in Windows Remote Desktop Licensing service due to improper heap buffer memory management.",
        "mitigation_procedure": "Disable the Remote Desktop Licensing service if not actively in use, or apply Microsoft July 2024 Patch Tuesday update.",
        "automated_fix_command": "powershell -Command \"Stop-Service -Name TermServLicensing -Force; Set-Service -Name TermServLicensing -StartupType Disabled\"",
        "mitigated_at": None
    },
    {
        "cve_id": "CVE-2024-43572",
        "title": "Microsoft Management Console (MMC) Untrusted File Execution",
        "platform": "Windows",
        "status": "Evolving",
        "severity": "High",
        "cvss": 7.8,
        "attack_vector": "Local",
        "affected_components": ["mmc.exe", ".msc console files"],
        "indicators_of_compromise": [
            "Opening untrusted .msc files downloaded from internet zones",
            "Spawned child processes under mmc.exe like cmd.exe or powershell.exe"
        ],
        "description": "Malicious MSC files exploit the Microsoft Management Console to execute arbitrary script code and evade AppLocker and Defender application controls.",
        "mitigation_procedure": "Deploy Group Policy preventing unprivileged users from opening downloaded .msc files; enable Microsoft Defender SmartScreen.",
        "automated_fix_command": "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name 'EnableSmartScreen' -Value 1\"",
        "mitigated_at": None
    },
    {
        "cve_id": "CVE-2021-34527",
        "title": "PrintNightmare: Windows Print Spooler RCE",
        "platform": "Windows",
        "status": "Resolved",
        "severity": "Critical",
        "cvss": 8.8,
        "attack_vector": "Network",
        "affected_components": ["spoolsv.exe", "RpcAddPrinterDriverEx"],
        "indicators_of_compromise": [
            "spoolsv.exe loading untrusted dynamic link libraries (.dll)",
            "RPC calls to add printer drivers by non-admin accounts"
        ],
        "description": "Critical vulnerability in the Windows Print Spooler service allowing authenticated attackers to execute arbitrary code with SYSTEM privileges.",
        "mitigation_procedure": "Disable Print Spooler service on domain controllers and endpoints that do not print.",
        "automated_fix_command": "powershell -Command \"Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled\"",
        "mitigated_at": "2025-11-20T09:15:00Z"
    },

    # --- MACOS THREATS ---
    {
        "cve_id": "CVE-2024-44133",
        "title": "macOS Transparency, Consent, and Control (TCC) Bypass (Safari Sandbox)",
        "platform": "macOS",
        "status": "Active",
        "severity": "High",
        "cvss": 8.2,
        "attack_vector": "Local",
        "affected_components": ["Safari Sandbox", "com.apple.TCC"],
        "indicators_of_compromise": [
            "Modifications to ~/Library/Safari directories by non-Safari binaries",
            "Unauthorized access to Camera/Microphone/Screen recording permissions"
        ],
        "description": "Allows an unprivileged local application or malware payload to bypass Apple's TCC permissions framework and steal sensitive data without user consent.",
        "mitigation_procedure": "Update macOS Sonoma to 14.6+ or macOS Sequoia to 15.0+; enforce strict Mobile Device Management (MDM) privacy profiles.",
        "automated_fix_command": "sudo softwareupdate -i -a --restart",
        "mitigated_at": None
    },
    {
        "cve_id": "CVE-2024-27842",
        "title": "macOS Kernel Memory Corruption (CoreOS)",
        "platform": "macOS",
        "status": "Anticipated",
        "severity": "High",
        "cvss": 7.5,
        "attack_vector": "Local",
        "affected_components": ["XNU Kernel", "I/O Kit"],
        "indicators_of_compromise": [
            "Panic reports referencing memory corruption in IOHIDEventService",
            "Attempts to read kernel memory pointers from userland"
        ],
        "description": "An app with system privileges may be able to execute arbitrary code with kernel privileges due to an out-of-bounds write flaw.",
        "mitigation_procedure": "Apply Apple Security Advisory HT214106; restrict unverified third-party kernel extensions via System Integrity Protection (SIP).",
        "automated_fix_command": "csrutil status",
        "mitigated_at": None
    },

    # --- ANDROID THREATS ---
    {
        "cve_id": "CVE-2024-43093",
        "title": "Android DocumentsUI Framework Privilege Escalation (Zero-Day Exploited)",
        "platform": "Android",
        "status": "Active",
        "severity": "High",
        "cvss": 8.4,
        "attack_vector": "Local",
        "affected_components": ["Android Framework", "DocumentsUI component"],
        "indicators_of_compromise": [
            "Sideloaded apps accessing Scoped Storage Android/data directories",
            "Intents launched with URI permissions bypassing storage access framework"
        ],
        "description": "Allows malicious applications to bypass Android Scoped Storage restrictions and access unauthorized user directories containing private credentials.",
        "mitigation_procedure": "Apply Android Security Bulletin November 2024; prevent sideloading from unknown sources in Android Settings.",
        "automated_fix_command": "adb shell settings put global install_non_market_apps 0",
        "mitigated_at": None
    },
    {
        "cve_id": "CVE-2024-32896",
        "title": "Android Pixel Firmware Local Privilege Escalation",
        "platform": "Android",
        "status": "Resolved",
        "severity": "High",
        "cvss": 7.8,
        "attack_vector": "Physical/Local",
        "affected_components": ["Pixel Bootloader", "Qualcomm TrustZone"],
        "indicators_of_compromise": [
            "Forensic extraction tools triggering bootloader exploit during locked state"
        ],
        "description": "Targeted zero-day exploit utilized by commercial surveillance software vendors to bypass Android lock screen protections and elevate privileges.",
        "mitigation_procedure": "Upgrade to June 2024 or later security patch level.",
        "automated_fix_command": "adb shell getprop ro.build.version.security_patch",
        "mitigated_at": "2025-12-05T11:00:00Z"
    },

    # --- IOS THREATS ---
    {
        "cve_id": "CVE-2024-23225",
        "title": "iOS Kernel Memory Corruption (Operation Triangulation Variant)",
        "platform": "iOS",
        "status": "Evolving",
        "severity": "Critical",
        "cvss": 9.1,
        "attack_vector": "Network",
        "affected_components": ["iOS Kernel", "WebKit sandbox"],
        "indicators_of_compromise": [
            "iMessage attachments containing malformed font/PDF exploits",
            "Hidden shadow processes executing with root privileges"
        ],
        "description": "Sophisticated zero-click memory corruption flaw allowing state-sponsored actors to install surveillance rootkits on unpatched iPhones.",
        "mitigation_procedure": "Enable iOS Lockdown Mode; immediately upgrade to iOS 17.4+ or 18.1+.",
        "automated_fix_command": "defaults write com.apple.security.lockdownmode enabled -bool true",
        "mitigated_at": None
    },
    {
        "cve_id": "CVE-2023-38606",
        "title": "iOS WebKit Arbitrary Code Execution via Safari",
        "platform": "iOS",
        "status": "Resolved",
        "severity": "High",
        "cvss": 8.8,
        "attack_vector": "Network",
        "affected_components": ["WebKit", "Safari Mobile"],
        "indicators_of_compromise": [
            "Visiting malicious web domains triggering WebProcess crash"
        ],
        "description": "Processing maliciously crafted web content could bypass WebKit sandbox boundaries and lead to arbitrary code execution.",
        "mitigation_procedure": "Update iOS device via Settings -> General -> Software Update to iOS 16.6+.",
        "automated_fix_command": "softwareupdate -d",
        "mitigated_at": "2025-08-14T16:00:00Z"
    },
    # --- HOST SYSTEM TELEMETRY & LAPTOP SPECIFICATIONS ---
    {
        "cve_id": "SYS-HOST-SPECS",
        "title": "Host Laptop Hardware Specifications & Telemetry Profile (Dell G15 5530)",
        "platform": "Windows",
        "status": "Resolved",
        "severity": "Info",
        "cvss": 0.0,
        "attack_vector": "Host Hardware Telemetry",
        "affected_components": [
            "Dell G15 5530 Gaming Laptop",
            "13th Gen Intel Core i5-13450HX (10 Cores, 16 Threads)",
            "NVIDIA GeForce RTX 3050 6GB Laptop GPU",
            "Intel UHD Graphics",
            "16GB DDR5 Physical RAM",
            "Windows 11 64-bit AMD64",
            "NVMe SSD 250GB (C:), Secondary 202GB (D:)"
        ],
        "indicators_of_compromise": [
            "Hostname: DESKTOP-4PRQ401",
            "Operator: Ayush Yadav (USN: 24BTLCL003)"
        ],
        "description": "Host machine hardware specification profile. Model: Dell G15 5530 powered by a 13th Gen Intel Core i5-13450HX processor (10 cores, 16 threads), dedicated NVIDIA GeForce RTX 3050 6GB GPU, 16 GB DDR5 RAM, and Windows 11 OS.",
        "mitigation_procedure": "Hardware telemetry is actively monitored by the Threat Scanner Bot. All firmware, drivers, and listening ports are audited and logged in MongoDB.",
        "automated_fix_command": "echo 'Hardware telemetry verified on Dell G15 5530'",
        "mitigated_at": "2026-11-24T14:00:00Z"
    },
    # --- ACADEMIC PROJECT ATTRIBUTION & FAQ ---
    {
        "cve_id": "FAQ-PROJECT-INFO",
        "title": "Academic Project Identity, Student Details & MongoDB Curriculum Overview",
        "platform": "All",
        "status": "Resolved",
        "severity": "Info",
        "cvss": 0.0,
        "attack_vector": "Academic Metadata",
        "affected_components": [
            "JAIN (Deemed-to-be University), Bengaluru",
            "Student: Ayush Yadav (USN: 24BTLCL003)",
            "Programme: B.Tech CSE (AIML - B) Semester 5th",
            "Course: 23CSE528 - NoSQL Databases using MongoDB",
            "Faculty: Prof. Sujeet S Jagtap"
        ],
        "indicators_of_compromise": [
            "Repository: https://github.com/ay1371872/threat-intelligence-ai"
        ],
        "description": "Mini Project: Building and Deploying an LLM/SLM-Backed Threat Intelligence Chat Application on MongoDB. Authored by Ayush Yadav (24BTLCL003) at JAIN University, guided by Prof. Sujeet S Jagtap.",
        "mitigation_procedure": "Full project source code, Docker configs, and reports are maintained in the student repository.",
        "automated_fix_command": "echo '23CSE528 Project successfully operational'",
        "mitigated_at": "2026-11-24T14:00:00Z"
    }
]


def seed_database():
    """Populates MongoDB collection with threat records and computed embeddings."""
    db = get_database()
    initialize_database_indexes_and_schemas()

    threats_col = db["threats"]
    audit_col = db["audit_log"]

    print(f"[*] Seeding {len(SAMPLE_THREATS)} multi-platform Threat Intelligence records...")
    
    # Clean old sample records to ensure freshness
    threats_col.delete_many({})
    
    for threat in SAMPLE_THREATS:
        # Precompute dense 384-d vector embeddings (Exercise 17)
        full_text = f"{threat['title']} {threat['platform']} {threat['status']} {threat['description']} {threat['mitigation_procedure']}"
        threat["embedding"] = compute_embedding(full_text)
        threat["created_at"] = datetime.utcnow().isoformat() + "Z"
        threat["last_updated"] = threat["created_at"]
        threats_col.insert_one(threat)

    print(f"[OK] Successfully seeded {threats_col.count_documents({})} threat records into MongoDB!")

    # Initial Audit Trail (Exercise 10 & 14)
    audit_col.insert_one({
        "event": "DATABASE_SEEDED",
        "actor": "SystemInitializer",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "details": f"Seeded {len(SAMPLE_THREATS)} threats spanning Windows, Linux, macOS, Android, and iOS."
    })
    print("[OK] Audit log entry recorded.")


if __name__ == "__main__":
    seed_database()
