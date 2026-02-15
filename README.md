# SAFE

---

## Description
SAFE (**Simulated Adversary File Events**) is a non-destructive security testing framework. Instead of encrypting real files, it creates a folder on your Desktop and fills it with fake "encrypted" files, threat actor IOCs, persistence artifacts, and suspicious process patterns — all mapped to MITRE ATT&CK.

It's designed for **purple team exercises, detection engineering, and EDR/SIEM validation** — with zero risk to production systems.

Think of it as *Hackers* meets *Sneakers*:

- Like Zero Cool said — *"There is no right and wrong, there's only fun and boring."* SAFE keeps it fun **and safe**.
- As Cosmo reminded us in *Sneakers* — *"It's all about who controls the information."* SAFE gives you control of the simulation to see how your defenses respond.

And yes, it's got a TrustedSec vibe — because no tool is complete without some hacker-style ASCII art and a dash of Gibson green.

---

## Features

### File Simulation
- 17 ransomware extensions (`.locked`, `.encrypted`, `.crypt`, `.chaos`, etc.) or **Kitchen Sink** mode for one of each
- Configurable file count (1–5,000)
- Realistic base64-encoded "ciphertext" content (not dangerous)
- Optional ransom note for detection testing

### Threat Actor Profiles
- **FIN7** — POS/financial targeting
- **APT29 (Cozy Bear)** — state-sponsored stealth
- **LockBit** — ransomware group TTPs
- **Scattered Spider** — credential theft & lateral movement
- **Generic Ransomware** and **APT Simulation**
- Each profile generates file IOCs, network IOCs, registry keys, and mutexes
- Full MITRE ATT&CK technique mappings with expected artifacts

### Persistence Simulation
- **Windows**: Registry run keys, scheduled tasks, startup folder shortcuts
- **macOS**: Launch agents, dylib hijacking source
- **Linux**: Systemd services, cron jobs, bashrc modifications

### Process Simulation
- OS-specific suspicious process patterns for EDR/XDR testing
- MITRE-mapped command-line patterns with detection guidance
- Simulation scripts (`.bat` / `.sh`) and documentation

### Reports
- IOC report with MD5 hashes, network IOCs, MITRE techniques, and tool IDs
- Persistence and process simulation reports
- All reports saved to the simulation directory

---

## Usage

```bash
python3 SAFE.py
```

or:

```bash
python3 -m safe
```

All output is stored in a timestamped folder on your Desktop:

```
~/Desktop/RansomSim-20250903-153200/
```

### Workflow
1. Choose a ransomware extension (or Kitchen Sink)
2. Set file count and ransom note preference
3. Optionally select a threat actor profile
4. Run the simulation
5. Create persistence and/or process artifacts
6. Review generated reports
7. Clean up when done

---

## Project Structure

```
SAFE/
├── SAFE.py                 # Entry point
├── safe/
│   ├── __init__.py
│   ├── __main__.py         # python -m safe support
│   ├── constants.py        # Extensions & threat profiles
│   ├── ioc_simulator.py    # IOC generation & MITRE mapping
│   ├── persistence.py      # OS-specific persistence artifacts
│   ├── process.py          # Suspicious process patterns
│   ├── simulator.py        # Main menu & orchestration
│   ├── system_info.py      # OS detection & path resolution
│   └── utils.py            # Filename generation, fake ciphertext
├── README.md
└── LICENSE
```

---

## Requirements

- Python 3.7+
- No external dependencies — standard library only

---

## Disclaimer

SAFE does not encrypt or modify any existing files. It only creates new dummy files inside a controlled folder. It is provided "as-is" for educational, research, and detection engineering purposes.

"Hack the planet. But do it safely." — TrustedSec
