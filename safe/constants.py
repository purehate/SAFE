"""Static data: ransomware extensions and threat actor profiles."""

from __future__ import annotations

# Curated ransomware extension options (benign simulation only)
EXTENSIONS: list[str] = [
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypto",
    ".cerber",
    ".zepto",
    ".odin",
    ".thor",
    ".arena",
    ".vvv",
    ".ecc",
    ".zzz",
    ".xyz",
    ".vault",
    ".LOCKY",
    ".chaos",
    ".v1cesO0ciety",
]

# Threat actor profiles keyed by slug
THREAT_PROFILES: dict[str, dict] = {
    "fin7": {
        "name": "FIN7",
        "description": (
            "Sophisticated financial threat actor known for targeting "
            "POS systems and financial data"
        ),
        "file_patterns": [
            "msupdate_ssl.exe",
            "error_report.pdf.lnk",
            "menu_prices.xls.js",
            "capt001.cmd",
            "wmstat32.dll",
            "libgcc_downloader.ps1",
        ],
        "network_iocs": [
            "microsoft-update-ssl.com",
            "cdn-download.cloud",
            "error-report.net",
            "45.77.xxx.yyy",
            "185.159.xxx.yyy",
        ],
        "registry_keys": [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
            r"HKCU\Software\Microsoft\Office\16.0\Common\Identity",
        ],
        "mutexes": [
            "Global\\FIN7_Command",
            "Global\\POS_Scraper",
            "Global\\CardReader",
        ],
    },
    "apt29": {
        "name": "APT29 (Cozy Bear)",
        "description": (
            "Sophisticated state-sponsored actor known for stealth and custom malware"
        ),
        "file_patterns": [
            "cozyduke.dll",
            "CosmicDuke.exe",
            "PasswordFilter.dll",
            "dns_updater.ps1",
            "miniDuke.exe",
            "secd.bin",
        ],
        "network_iocs": [
            "google-up.com",
            "twitter-cdn.com",
            "microsoft-update.org",
            "162.12.xxx.yyy",
            "185.86.xxx.yyy",
        ],
        "registry_keys": [
            r"HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\GPExtensions",
        ],
        "mutexes": [
            "Global\\WellKnown_Sid",
            "Global\\SeDebugPrivilege",
            "Global\\DnsCache",
        ],
    },
    "lockbit": {
        "name": "LockBit Ransomware",
        "description": "LockBit ransomware group TTPs and IOCs",
        "file_patterns": [
            "LOCKBIT-DECRYPTION-README.txt",
            "HLJkNskOq.lockbit",
            "lockbit_recovery.exe",
            "lock64.dll",
            ".lockbit_recovery.txt",
        ],
        "network_iocs": [
            "lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion",
            "lockbitfile2tcudkcqqt2ve6btssyvqwlizbpv5vz337lslmhff2uad.onion",
            "api.lockbit.su",
            "cdn.lockbit.su",
        ],
        "registry_keys": [
            r"HKCU\Software\LockBit\Config",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*",
            r"HKLM\SYSTEM\CurrentControlSet\Services\LockBitService",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LockBitStart",
        ],
        "mutexes": [
            "Global\\LockBitCrypt",
            "Global\\LockBitCommand",
            "Global\\LockBitRecover",
        ],
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
            "veeam_backup.exe",
        ],
        "network_iocs": [
            "scattered-c2.dynamic-dns.net",
            "okta-service.com",
            "duo-push.net",
            "azure-mgmt-service.com",
            "cloudflare-cdn.net",
        ],
        "registry_keys": [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
            r"HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters",
            r"HKCU\Software\Microsoft\Terminal Server Client\Servers",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers",
        ],
        "mutexes": [
            "Global\\ScatteredSpider_Session",
            "Global\\LSASS_Dump_Progress",
            "Global\\VeeamBackupSession",
        ],
    },
    "generic_ransomware": {
        "name": "Generic Ransomware",
        "description": "Common ransomware behavior patterns",
        "file_patterns": [
            "README.txt",
            "DECRYPT.txt",
            "HOW_TO_RECOVER.html",
            "restore.txt",
            "YOUR_FILES.html",
        ],
        "network_iocs": [
            "ransom-payment.bit",
            "decrypt-service.onion",
            "195.123.xxx.yyy",
            "btc-wallet.payment.net",
        ],
        "registry_keys": [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Ransom",
            r"HKLM\SOFTWARE\Microsoft\Cryptography\Ransom",
        ],
        "mutexes": [
            "Global\\RansomEncryption",
            "Global\\PaymentPending",
        ],
    },
    "apt_simulation": {
        "name": "APT Simulation",
        "description": "Advanced Persistent Threat patterns",
        "file_patterns": [
            "system32.dll.exe",
            "svchost_backdoor.exe",
            "update_service.exe",
        ],
        "network_iocs": [
            "command-control.dynamic-dns.org",
            "data-exfil.cloud",
            "45.67.xxx.yyy",
            "91.234.xxx.yyy",
        ],
        "registry_keys": [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateService",
            r"HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess",
        ],
        "mutexes": [
            "Global\\APT_Command_Channel",
            "Global\\DataExfiltration",
        ],
    },
}
