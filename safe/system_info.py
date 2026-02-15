"""OS detection, path resolution, and platform-specific feature discovery."""

from __future__ import annotations

import logging
import os
import platform
from pathlib import Path

logger = logging.getLogger(__name__)


def get_system_info() -> dict:
    """Detect the current OS and return platform-specific paths and features.

    Returns a dict with keys: type, release, version, machine, hostname,
    common_paths (dict of label->path), and features (list of capability strings).
    """
    os_type = platform.system().lower()
    os_info: dict = {
        "type": os_type,
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
        "common_paths": {},
        "features": [],
    }

    if os_type == "windows":
        os_info["common_paths"].update(
            {
                "system32": r"C:\Windows\System32",
                "program_files": r"C:\Program Files",
                "appdata": os.getenv("APPDATA", r"C:\Users\Default\AppData\Roaming"),
                "temp": os.getenv("TEMP", r"C:\Windows\Temp"),
                "startup": os.path.join(
                    os.getenv("APPDATA", ""),
                    r"Microsoft\Windows\Start Menu\Programs\Startup",
                ),
            }
        )
        os_info["features"].extend(
            [
                "registry_simulation",
                "service_simulation",
                "startup_persistence",
                "scheduled_tasks",
            ]
        )
    elif os_type == "darwin":
        os_info["common_paths"].update(
            {
                "applications": "/Applications",
                "library": "/Library",
                "launch_agents": "~/Library/LaunchAgents",
                "system_launch_daemons": "/Library/LaunchDaemons",
                "temp": "/tmp",
            }
        )
        os_info["features"].extend(
            [
                "launch_agent_simulation",
                "kernel_extension_simulation",
                "dylib_hijacking",
            ]
        )
    elif os_type == "linux":
        os_info["common_paths"].update(
            {
                "etc": "/etc",
                "opt": "/opt",
                "tmp": "/tmp",
                "systemd": "/etc/systemd/system",
                "cron": "/etc/cron.d",
            }
        )
        os_info["features"].extend(
            [
                "systemd_service_simulation",
                "cron_persistence",
                "bash_rc_simulation",
            ]
        )

    return os_info


def get_desktop() -> Path:
    """Return the user's Desktop path with cross-platform fallbacks.

    Resolution order:
    1. ~/Desktop (if it exists)
    2. Windows: %USERPROFILE%\\Desktop
    3. Linux: XDG_DESKTOP_DIR from ~/.config/user-dirs.dirs
    4. Fallback: home directory
    """
    os_type = platform.system().lower()
    home = Path.home()

    desktop = home / "Desktop"
    if desktop.exists() and desktop.is_dir():
        return desktop

    if os_type == "windows":
        desktop = Path(os.path.expandvars("%USERPROFILE%\\Desktop"))
        if desktop.exists() and desktop.is_dir():
            return desktop
    elif os_type == "linux":
        xdg_config = home / ".config" / "user-dirs.dirs"
        try:
            with open(xdg_config, encoding="utf-8") as fh:
                for line in fh:
                    if "XDG_DESKTOP_DIR" in line:
                        desktop_path = line.split("=")[1].strip().strip('"')
                        desktop_path = os.path.expandvars(desktop_path)
                        desktop = Path(desktop_path)
                        if desktop.exists() and desktop.is_dir():
                            return desktop
        except FileNotFoundError:
            logger.debug("XDG user-dirs.dirs not found, falling back to home")

    return home
