"""Small, stateless helper functions used across SAFE modules."""

from __future__ import annotations

import base64
import os
import random
import string
from pathlib import Path


def random_filename(length: int = 10) -> str:
    """Generate a random alphanumeric filename stem."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def fake_ciphertext(min_bytes: int = 800, max_bytes: int = 2000) -> str:
    """Return base64-encoded random bytes that look like encrypted content."""
    raw = os.urandom(random.randint(min_bytes, max_bytes))
    return base64.b64encode(raw).decode("ascii")


def make_note_text(sim_folder: str | Path, ext_choice: str, file_count: int) -> str:
    """Build the content of a simulated ransom note."""
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
        "Stay safe.",
    ]
    return "\n".join(lines)
