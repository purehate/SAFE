"""IOC (Indicator of Compromise) simulation and MITRE ATT&CK mapping."""

from __future__ import annotations

import hashlib
import logging
import platform
from datetime import datetime
from pathlib import Path

from safe.constants import THREAT_PROFILES
from safe.utils import fake_ciphertext

logger = logging.getLogger(__name__)

# MITRE ATT&CK technique and tool mappings per threat actor
_MITRE_DATA: dict[str, dict] = {
    "fin7": {
        "techniques": {
            "T1204.002": {
                "name": "User Execution: Malicious File",
                "artifacts": ["weaponized Office documents", "malicious .lnk files"],
            },
            "T1055": {
                "name": "Process Injection",
                "artifacts": ["injected DLLs", "memory-resident malware"],
            },
            "T1543.003": {
                "name": "Create or Modify System Process: Windows Service",
                "artifacts": ["suspicious services", "service registry entries"],
            },
            "T1027": {
                "name": "Obfuscated Files or Information",
                "artifacts": ["encoded PowerShell", "obfuscated JavaScript"],
            },
            "T1056.001": {
                "name": "Input Capture: Keylogging",
                "artifacts": ["keystroke logs", "memory-scraped POS data"],
            },
        },
        "tools": {
            "S0118": "Carbanak",
            "S0457": "Griffon",
            "S0242": "Astra",
            "S0568": "SQLRat",
            "S0500": "BOOSTWRITE",
        },
    },
    "apt29": {
        "techniques": {
            "T1195": {
                "name": "Supply Chain Compromise",
                "artifacts": ["modified system DLLs", "compromised updates"],
            },
            "T1573": {
                "name": "Encrypted Channel",
                "artifacts": ["encrypted C2 traffic", "custom SSL certificates"],
            },
            "T1505.002": {
                "name": "Server Software Component: Transport Agent",
                "artifacts": [
                    "Exchange transport agents",
                    "mail server modifications",
                ],
            },
            "T1053.005": {
                "name": "Scheduled Task/Job: Scheduled Task",
                "artifacts": ["WMI persistence", "scheduled tasks"],
            },
            "T1134": {
                "name": "Access Token Manipulation",
                "artifacts": ["token impersonation", "elevated processes"],
            },
            "T1070.001": {
                "name": "Indicator Removal: Clear Windows Event Logs",
                "artifacts": ["cleared logs", "modified audit policies"],
            },
        },
        "tools": {
            "S0354": "HAMMERTOSS",
            "S0416": "WellMess",
            "S0446": "WellMail",
            "S0363": "Empire",
            "S0552": "AdFind",
        },
    },
    "lockbit": {
        "techniques": {
            "T1486": {
                "name": "Data Encrypted for Impact",
                "artifacts": ["encrypted files", "ransom notes"],
            },
            "T1490": {
                "name": "Inhibit System Recovery",
                "artifacts": [
                    "vssadmin delete shadows",
                    "wmic shadowcopy delete",
                ],
            },
            "T1489": {
                "name": "Service Stop",
                "artifacts": [
                    "stopped backup services",
                    "disabled security services",
                ],
            },
            "T1112": {
                "name": "Modify Registry",
                "artifacts": ["persistence keys", "disabled security features"],
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "artifacts": ["enumerated shares", "file listings"],
            },
            "T1566": {
                "name": "Phishing",
                "artifacts": ["malicious documents", "phishing emails"],
            },
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "artifacts": ["web shell uploads", "RCE attempts"],
            },
        },
        "tools": {
            "S0363": "Empire",
            "S0154": "Cobalt Strike",
            "S0029": "PsExec",
            "S0002": "Mimikatz",
        },
    },
    "scattered_spider": {
        "techniques": {
            "T1078": {
                "name": "Valid Accounts",
                "artifacts": ["unauthorized admin accounts", "hijacked sessions"],
            },
            "T1187": {
                "name": "Forced Authentication",
                "artifacts": ["NTLM hashes", "credential harvesting"],
            },
            "T1557": {
                "name": "MFA Interception",
                "artifacts": ["intercepted tokens", "bypassed 2FA"],
            },
            "T1552": {
                "name": "Unsecured Credentials",
                "artifacts": ["found API keys", "exposed credentials"],
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "artifacts": ["LSASS dumps", "NTDS.dit extracts"],
            },
            "T1098": {
                "name": "Account Manipulation",
                "artifacts": ["modified permissions", "added privileges"],
            },
            "T1133": {
                "name": "External Remote Services",
                "artifacts": ["VPN access", "RDP connections"],
            },
        },
        "tools": {
            "S0519": "Veeam",
            "S0002": "Mimikatz",
            "S0521": "ProcDump",
            "S0125": "SharpHound",
            "S0552": "ADRecon",
            "S0113": "Social Engineering Toolkit",
        },
    },
}


class IOCSimulator:
    """Create threat-actor-specific IOC files and MITRE ATT&CK reports."""

    def __init__(self, base_dir: str | Path, system_info: dict) -> None:
        self.base_dir = Path(base_dir)
        self.system_info = system_info
        self.selected_profile: str | None = None

    def select_profile(self) -> bool:
        """Prompt the user to choose a threat actor profile.

        Returns True if a valid profile was selected.
        """
        logger.info("\nAvailable Threat Profiles:")
        for i, (key, profile) in enumerate(THREAT_PROFILES.items(), start=1):
            logger.info("%2d) %s", i, profile["name"])
            logger.info("    %s", profile["description"])

        sel = input("\nSelect a profile number: ").strip()
        try:
            n = int(sel)
            if 1 <= n <= len(THREAT_PROFILES):
                self.selected_profile = list(THREAT_PROFILES.keys())[n - 1]
                logger.info(
                    "Selected profile: %s",
                    THREAT_PROFILES[self.selected_profile]["name"],
                )
                return True
        except ValueError:
            pass
        logger.info("Invalid selection.")
        return False

    def create_file_iocs(self) -> list[str]:
        """Write benign files matching the selected profile's IOC patterns.

        Returns a list of created filenames.
        """
        if not self.selected_profile:
            return []

        profile = THREAT_PROFILES[self.selected_profile]
        created: list[str] = []

        for pattern in profile["file_patterns"]:
            path = self.base_dir / pattern
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("--- Simulated IOC File ---\n")
                fh.write(f"Profile: {profile['name']}\n")
                fh.write(f"Pattern: {pattern}\n")
                fh.write(f"Created: {datetime.now().isoformat()}\n")
                fh.write(fake_ciphertext(100, 200))
            created.append(pattern)

        return created

    def get_mitre_info(self, profile_name: str) -> dict:
        """Return MITRE ATT&CK techniques and tools for a threat actor."""
        return _MITRE_DATA.get(profile_name, {"techniques": {}, "tools": {}})

    def generate_ioc_report(self) -> str:
        """Build a comprehensive IOC report for the selected profile.

        Includes MITRE techniques, tool IDs, file hashes, network IOCs,
        registry keys, mutexes, system info, and OS-specific persistence paths.
        """
        if not self.selected_profile:
            return ""

        profile = THREAT_PROFILES[self.selected_profile]
        mitre = self.get_mitre_info(self.selected_profile)

        lines = [
            "=== Simulated IOC Report ===",
            f"Profile: {profile['name']}",
            f"Description: {profile['description']}",
            f"Timestamp: {datetime.now().isoformat()}",
            f"Target Directory: {self.base_dir}",
            "",
            "=== MITRE ATT&CK Techniques ===",
        ]

        for tid, tech in mitre["techniques"].items():
            lines.append(f"  {tid}: {tech['name']}")
            lines.append("    Expected Artifacts:")
            lines.extend(f"    - {a}" for a in tech["artifacts"])
            lines.append("")

        lines.append("=== Known Tools (with MITRE Software IDs) ===")
        lines.extend(f"  {sid}: {tool}" for sid, tool in mitre["tools"].items())
        lines.extend(["", "=== File Artifacts ==="])

        for pattern in profile["file_patterns"]:
            path = self.base_dir / pattern
            if path.exists():
                md5 = hashlib.md5()
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(4096), b""):
                        md5.update(chunk)
                lines.append(f"  - {pattern}")
                lines.append(f"    MD5: {md5.hexdigest()}")

        lines.extend(
            [
                "",
                "Network IOCs:",
                *(f"  - {ioc}" for ioc in profile["network_iocs"]),
                "",
                "Registry Keys (Windows):",
                *(f"  - {key}" for key in profile["registry_keys"]),
                "",
                "Mutexes:",
                *(f"  - {m}" for m in profile["mutexes"]),
                "",
                "System Information:",
                f"  OS: {platform.system()} {platform.release()}",
                f"  Version: {platform.version()}",
                f"  Architecture: {platform.machine()}",
                f"  Node: {platform.node()}",
                "",
                "OS-Specific Persistence Locations:",
                *(f"  - {k}: {v}" for k, v in self.system_info["common_paths"].items()),
                "",
                "Available Simulation Features:",
                *(f"  - {feat}" for feat in self.system_info["features"]),
            ]
        )

        return "\n".join(lines)
