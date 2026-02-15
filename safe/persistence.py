"""OS-specific persistence mechanism simulation."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# --- Artifact content templates ---------------------------------------------------

_WINDOWS_REG = """\
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"UpdateService"="C:\\\\Windows\\\\System32\\\\WindowsUpdate.exe"
"OfficeHelper"="C:\\\\Program Files\\\\Microsoft Office\\\\Office16\\\\OfficeHelper.exe"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]
"SecurityService"="C:\\\\Program Files\\\\Security Suite\\\\SecService.exe"
"""

_WINDOWS_TASK_XML = """\
<?xml version="1.0" encoding="UTF-16"?>
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

_WINDOWS_VBS = """\
Set WScript = CreateObject("WScript.Shell")
Set link = WScript.CreateShortcut("startup_helper.lnk")
link.TargetPath = "C:\\Windows\\System32\\WindowsUpdate.exe"
link.WorkingDirectory = "C:\\Windows\\System32"
link.Description = "Windows Update Helper"
link.Save"""

_MACOS_LAUNCH_AGENT = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
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

_MACOS_DYLIB = """\
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
static void initializer(void) {
    // Simulated malicious code would run here
    printf("Library loaded\\n");
}"""

_LINUX_SYSTEMD = """\
[Unit]
Description=Update Helper Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/update_helper
Restart=always

[Install]
WantedBy=multi-user.target"""

_LINUX_CRON = """\
# Update helper runs every 30 minutes
*/30 * * * * root /usr/local/bin/update_helper >/dev/null 2>&1

# Daily system maintenance
@daily root /usr/local/bin/system_maintenance.sh"""

_LINUX_BASHRC = """\
# Added by system update
export PATH="/usr/local/bin:$PATH"
alias ls='ls --color=auto'
# Persistence mechanism
nohup /usr/local/bin/update_helper >/dev/null 2>&1 &"""


class PersistenceSimulator:
    """Create OS-specific persistence artifacts for detection testing."""

    def __init__(self, base_dir: str | Path, system_info: dict) -> None:
        self.base_dir = Path(base_dir)
        self.system_info = system_info
        self.created_artifacts: list[tuple[str, str]] = []

    # -- per-OS artifact generators ------------------------------------------------

    def _simulate_windows(self) -> list[tuple[str, str]]:
        """Create Windows persistence artifacts (registry, task, startup)."""
        artifacts: list[tuple[str, str]] = []

        reg_file = self.base_dir / "persistence_keys.reg"
        reg_file.write_text(_WINDOWS_REG, encoding="utf-8")
        artifacts.append(("registry", str(reg_file)))

        task_file = self.base_dir / "update_helper.xml"
        task_file.write_text(_WINDOWS_TASK_XML, encoding="utf-8")
        artifacts.append(("scheduled_task", str(task_file)))

        vbs_file = self.base_dir / "create_shortcut.vbs"
        vbs_file.write_text(_WINDOWS_VBS, encoding="utf-8")
        artifacts.append(("startup_script", str(vbs_file)))

        return artifacts

    def _simulate_macos(self) -> list[tuple[str, str]]:
        """Create macOS persistence artifacts (launch agent, dylib)."""
        artifacts: list[tuple[str, str]] = []

        agent_file = self.base_dir / "com.apple.update.helper.plist"
        agent_file.write_text(_MACOS_LAUNCH_AGENT, encoding="utf-8")
        artifacts.append(("launch_agent", str(agent_file)))

        dylib_file = self.base_dir / "libsystem_override.c"
        dylib_file.write_text(_MACOS_DYLIB, encoding="utf-8")
        artifacts.append(("dylib_hijack", str(dylib_file)))

        return artifacts

    def _simulate_linux(self) -> list[tuple[str, str]]:
        """Create Linux persistence artifacts (systemd, cron, bashrc)."""
        artifacts: list[tuple[str, str]] = []

        service_file = self.base_dir / "update-helper.service"
        service_file.write_text(_LINUX_SYSTEMD, encoding="utf-8")
        artifacts.append(("systemd_service", str(service_file)))

        cron_file = self.base_dir / "update-helper.cron"
        cron_file.write_text(_LINUX_CRON, encoding="utf-8")
        artifacts.append(("cron_job", str(cron_file)))

        bashrc_file = self.base_dir / ".bashrc_mod"
        bashrc_file.write_text(_LINUX_BASHRC, encoding="utf-8")
        artifacts.append(("bash_profile", str(bashrc_file)))

        return artifacts

    # -- public API ----------------------------------------------------------------

    def simulate_persistence(self) -> list[tuple[str, str]]:
        """Create persistence simulation artifacts for the current OS."""
        dispatch = {
            "windows": self._simulate_windows,
            "darwin": self._simulate_macos,
            "linux": self._simulate_linux,
        }
        handler = dispatch.get(self.system_info["type"])
        if handler:
            self.created_artifacts = handler()
        return self.created_artifacts

    def generate_persistence_report(self) -> str:
        """Build a human-readable persistence simulation report."""
        if not self.created_artifacts:
            return "No persistence artifacts have been created yet."

        os_label = (
            "macOS"
            if self.system_info["type"] == "darwin"
            else self.system_info["type"].title()
        )

        lines = [
            "=== Persistence Simulation Report ===",
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

        lines.extend(
            [
                "Note: These are benign simulation files that demonstrate "
                "common persistence techniques.",
                "They can be used to test detection and monitoring systems.",
                "",
                "Recommended Detection Methods:",
                "- Monitor file creation in system directories",
                "- Track autorun locations and startup items",
                "- Watch for suspicious service creation",
                "- Monitor scheduled task creation",
                "- Implement baseline deviation alerts",
            ]
        )

        return "\n".join(lines)
