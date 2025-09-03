#!/usr/bin/env python3
"""
Simulated Adversary File Events (SAFE)
- Creates a folder on the user's Desktop (or home if Desktop not found)
- Generates fake "encrypted" files with chosen extensions
- Optional ransom note
NO destructive actions. Does not touch existing files.
"""

import os
import sys
import time
import base64
import random
import string
from pathlib import Path
from datetime import datetime

# Curated extension options (benign)
EXTENSIONS = [
    ".locked", ".encrypted", ".crypt", ".crypto",
    ".cerber", ".zepto", ".odin", ".thor", ".arena",
    ".vvv", ".ecc", ".zzz", ".xyz", ".vault",
    ".LOCKY", ".chaos", ".v1cesO0ciety"
]

def get_desktop():
    # Cross-platform best effort for Desktop
    home = Path.home()
    desktop = home / "Desktop"
    if desktop.exists() and desktop.is_dir():
        return desktop
    # Fallback to home if no Desktop
    return home

def random_filename(length=10):
    stem = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    return stem

def fake_ciphertext(min_bytes=800, max_bytes=2000):
    # Produce random bytes and base64 them so it *looks* encoded
    raw = os.urandom(random.randint(min_bytes, max_bytes))
    return base64.b64encode(raw).decode("ascii")

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
    def menu(self):
        # Gibson Green ANSI (approx 46 in 256-color table)
        G = "\033[38;5;46m"
        R = "\033[0m"  # reset

        banner = r"""
          _________   _____  ______________________
         /   _____/  /  _  \ \_   _____/\_   _____/
         \_____  \  /  /_\  \ |    __)   |    __)_  
         /        \/    |    \|     \    |        \
        /_______  /\____|__  /\___  /   /_______  /
                \/         \/     \/            \/ 
        S I M U L A T E D   A T T A C K
             F I L E   E N C R Y P T I O N   
         """
        while True:
            print("\033c", end="")  # clear screen for a fresh menu look
            print(G + banner + R)
            print("1) Choose extension")
            print("2) Set file count (current: {})".format(self.file_count))
            print("3) Toggle ransom note (current: {})".format("ON" if self.write_note else "OFF"))
            print("4) RUN simulation")
            if self.last_output_dir:
                print("5) Clean up last simulation folder")
                print("6) Exit")
            else:
                print("5) Exit")
            choice = input("Select an option: ").strip()

            if choice == "1":
                self.choose_extension()
            elif choice == "2":
                self.set_file_count()
            elif choice == "3":
                self.write_note = not self.write_note
                print(f"Ransom note now {'ON' if self.write_note else 'OFF'}")
            elif choice == "4":
                self.run_sim()
            elif choice == "5" and self.last_output_dir:
                self.cleanup_last()
            elif (choice == "5" and not self.last_output_dir) or (choice == "6" and self.last_output_dir):
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

        self.last_output_dir = outdir
        print(f"\nSimulation complete.\nFolder: {outdir}\nFiles created: {created}\nNote: {'YES' if self.write_note else 'NO'}")

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

