"""Main interactive simulator with menu-driven workflow."""

from __future__ import annotations

import logging
import random
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from safe.constants import EXTENSIONS, THREAT_PROFILES
from safe.ioc_simulator import IOCSimulator
from safe.persistence import PersistenceSimulator
from safe.process import ProcessSimulator
from safe.system_info import get_desktop, get_system_info
from safe.utils import fake_ciphertext, make_note_text, random_filename

logger = logging.getLogger(__name__)

# Gibson Green ANSI (256-color 46)
_G = "\033[38;5;46m"
_R = "\033[0m"

_BANNER = r"""

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

_OS_ICONS: dict[str, str] = {
    "windows": "\U0001fa9f",
    "darwin": "\U0001f34e",
    "linux": "\U0001f427",
}


def _os_label(system_info: dict) -> tuple[str, str]:
    """Return (icon, display_name) for the current OS."""
    os_type = system_info["type"]
    icon = _OS_ICONS.get(os_type, "\U0001f4bb")
    name = "macOS" if os_type == "darwin" else os_type.upper()
    return icon, name


def _pause() -> None:
    """Wait for the user to press Enter before continuing."""
    input("\nPress Enter to continue...")


class Simulator:
    """Top-level interactive menu that orchestrates all simulation modules."""

    def __init__(self) -> None:
        self.ext_choice: str | None = None
        self.file_count: int = 50
        self.write_note: bool = True
        self.last_output_dir: Path | None = None
        self.system_info: dict = get_system_info()
        self.ioc_simulator: IOCSimulator | None = None
        self.persistence_simulator: PersistenceSimulator | None = None
        self.process_simulator: ProcessSimulator | None = None

    # -- menu rendering ------------------------------------------------------------

    def menu(self) -> None:
        """Run the main interactive menu loop."""
        while True:
            sys.stdout.write("\033c")  # clear screen
            logger.info("%s%s%s", _G, _BANNER, _R)
            self._print_status()
            self._print_menu_options()

            choice = input("Select an option: ").strip()
            self._handle_choice(choice)

    def _print_status(self) -> None:
        """Display current configuration status."""
        profile_label = (
            self.ioc_simulator.selected_profile.upper()
            if self.ioc_simulator and self.ioc_simulator.selected_profile
            else "Not selected"
        )
        logger.info("\nCurrent Status:")
        logger.info("  Extension: %s", self.ext_choice or "Not selected")
        logger.info("  File Count: %s", self.file_count)
        logger.info("  Ransom Note: %s", "Enabled" if self.write_note else "Disabled")
        logger.info("  Threat Profile: %s", profile_label)
        logger.info("  Output Directory: %s", self.last_output_dir or "Not created")

        if not self.ext_choice:
            logger.info("\n[!] Required: Choose an extension first (option 1)")
        elif not self.last_output_dir:
            logger.info("\n[>] Ready to run simulation (option 8)")

    def _print_menu_options(self) -> None:
        """Print the numbered menu options."""
        icon, os_name = _os_label(self.system_info)

        logger.info("\nStep 1 - File Encryption Setup:")
        logger.info("1) Choose extension (required)")
        logger.info("2) Set file count (current: %s)", self.file_count)
        logger.info(
            "3) Toggle ransom note (current: %s)",
            "ON" if self.write_note else "OFF",
        )

        logger.info("\nStep 2 - Threat Actor Simulation:")
        logger.info("4) Select threat actor profile (optional)")
        logger.info("5) Generate IOC report (preview available IOCs)")

        logger.info("\nStep 3 - Persistence Simulation:")
        logger.info(
            "6) Create persistence artifacts for %s %s (after running simulation)",
            icon,
            os_name,
        )
        logger.info("7) View persistence report")

        logger.info("\nStep 4 - Process Simulation:")
        logger.info("9) Create process artifacts for %s %s", icon, os_name)
        logger.info("10) View process simulation report")

        logger.info("\nExecution:")
        logger.info("8) RUN simulation (creates selected artifacts)")
        logger.info("   - Creates simulation directory")
        logger.info("   - Generates encrypted files")
        logger.info("   - Plants selected IOCs")
        logger.info("   - Generates detailed report")

        logger.info("\nCleanup:")
        if self.last_output_dir:
            logger.info("11) Clean up last simulation folder")
            logger.info("12) Exit")
        else:
            logger.info("11) Exit")

    # -- choice dispatch -----------------------------------------------------------

    def _handle_choice(self, choice: str) -> None:
        """Route a menu selection to the appropriate handler."""
        handlers: dict[str, callable] = {
            "1": self._choose_extension,
            "2": self._set_file_count,
            "3": self._toggle_ransom_note,
            "4": self._select_threat_profile,
            "5": self._preview_iocs,
            "6": self._create_persistence_artifacts,
            "7": self._view_persistence_report,
            "8": self._run_sim,
            "9": self._create_process_artifacts,
            "10": self._view_process_report,
        }

        handler = handlers.get(choice)
        if handler:
            handler()
            return

        # Dynamic exit / cleanup options
        if choice == "11" and self.last_output_dir:
            self._cleanup_last()
        elif choice == "11" and not self.last_output_dir:
            self._exit()
        elif choice == "12" and self.last_output_dir:
            self._exit()
        else:
            logger.info("Invalid choice.")

    @staticmethod
    def _exit() -> None:
        """Exit the application."""
        logger.info("Bye.")
        sys.exit(0)

    # -- option handlers -----------------------------------------------------------

    def _choose_extension(self) -> None:
        """Prompt user to pick a ransomware extension."""
        logger.info("\nAvailable extensions:")
        for i, ext in enumerate(EXTENSIONS, start=1):
            logger.info("%2d) %s", i, ext)
        logger.info("%2d) Kitchen Sink (one file of each)", len(EXTENSIONS) + 1)

        sel = input("Pick a number: ").strip()
        try:
            n = int(sel)
            if 1 <= n <= len(EXTENSIONS):
                self.ext_choice = EXTENSIONS[n - 1]
                logger.info("Selected extension: %s", self.ext_choice)
            elif n == len(EXTENSIONS) + 1:
                self.ext_choice = "KITCHEN_SINK"
                logger.info("Selected: Kitchen Sink")
            else:
                logger.info("Out of range.")
        except ValueError:
            logger.info("Please enter a number.")

    def _set_file_count(self) -> None:
        """Set the number of simulated files to create."""
        val = input("How many files to create? (1-5000, default 50): ").strip()
        if not val:
            logger.info("File count unchanged.")
            return
        try:
            n = int(val)
            if 1 <= n <= 5000:
                self.file_count = n
                logger.info("File count set to %d", self.file_count)
            else:
                logger.info("Please choose between 1 and 5000.")
        except ValueError:
            logger.info("Please enter a valid integer.")

    def _toggle_ransom_note(self) -> None:
        """Toggle ransom note generation on/off."""
        self.write_note = not self.write_note
        logger.info("Ransom note now %s", "ON" if self.write_note else "OFF")

    def _select_threat_profile(self) -> None:
        """Initialize IOC simulator and prompt for a profile."""
        if not self.ioc_simulator:
            self.ioc_simulator = IOCSimulator(get_desktop(), self.system_info)
        self.ioc_simulator.select_profile()

    def _preview_iocs(self) -> None:
        """Show IOCs for the selected threat profile."""
        if not self.ioc_simulator or not self.ioc_simulator.selected_profile:
            logger.info("Select a threat actor profile first (option 4).")
            return

        profile = THREAT_PROFILES[self.ioc_simulator.selected_profile]
        logger.info("\nPreviewing IOCs for %s:", profile["name"])
        logger.info("Description: %s", profile["description"])
        logger.info("\nFile Patterns:")
        for p in profile["file_patterns"]:
            logger.info("  - %s", p)
        logger.info("\nNetwork IOCs:")
        for ioc in profile["network_iocs"]:
            logger.info("  - %s", ioc)
        logger.info("\nRegistry Keys:")
        for key in profile["registry_keys"]:
            logger.info("  - %s", key)
        logger.info("\nMutexes:")
        for mutex in profile["mutexes"]:
            logger.info("  - %s", mutex)
        logger.info("\nNote: Run simulation (option 8) to create these artifacts.")
        _pause()

    def _create_persistence_artifacts(self) -> None:
        """Generate OS-specific persistence artifacts."""
        if not self.last_output_dir:
            logger.info("Run a simulation first to create a target directory.")
            return
        if not self.persistence_simulator:
            self.persistence_simulator = PersistenceSimulator(
                self.last_output_dir, self.system_info
            )
        artifacts = self.persistence_simulator.simulate_persistence()
        if artifacts:
            logger.info("\nCreated persistence artifacts:")
            for artifact_type, path in artifacts:
                logger.info("  - %s: %s", artifact_type, path)
        else:
            logger.info(
                "\nNo persistence artifacts created for %s OS.",
                self.system_info["type"],
            )
        _pause()

    def _view_persistence_report(self) -> None:
        """Display the persistence simulation report."""
        if (
            not self.persistence_simulator
            or not self.persistence_simulator.created_artifacts
        ):
            logger.info("Create persistence artifacts first (option 6).")
            return
        logger.info("\n%s", self.persistence_simulator.generate_persistence_report())
        _pause()

    def _create_process_artifacts(self) -> None:
        """Generate OS-specific process simulation artifacts."""
        if not self.last_output_dir:
            logger.info("Run a simulation first to create a target directory.")
            return
        if not self.process_simulator:
            self.process_simulator = ProcessSimulator(
                self.last_output_dir, self.system_info
            )
        artifacts = self.process_simulator.create_process_artifacts()
        if artifacts:
            logger.info("\nCreated process simulation artifacts:")
            for artifact_type, path in artifacts:
                logger.info("  - %s: %s", artifact_type, path)
            logger.info(
                "\nNOTE: These are benign script files that SIMULATE "
                "malicious process patterns."
            )
            logger.info("      They can be used to test detection capabilities.")
            logger.info("      Review process_simulation.txt for full details.")
        else:
            logger.info(
                "\nNo process artifacts created for %s OS.",
                self.system_info["type"],
            )
        _pause()

    def _view_process_report(self) -> None:
        """Display the process simulation report."""
        if not self.process_simulator or not self.process_simulator.created_artifacts:
            logger.info("Create process artifacts first (option 9).")
            return
        logger.info("\n%s", self.process_simulator.generate_process_report())
        _pause()

    # -- simulation execution ------------------------------------------------------

    def _run_sim(self) -> None:
        """Execute the simulation: create files, IOCs, and reports."""
        if not self.ext_choice:
            logger.info("Pick an extension first (option 1).")
            return

        base = get_desktop()
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        outdir = base / f"RansomSim-{ts}"
        outdir.mkdir(parents=True, exist_ok=True)

        created = self._write_simulated_files(outdir, ts)

        if self.write_note:
            note_path = outdir / "READ_ME_NOW.txt"
            note_path.write_text(
                make_note_text(str(outdir), self.ext_choice, created),
                encoding="utf-8",
            )

        ioc_count = self._write_ioc_artifacts(outdir)

        self.last_output_dir = outdir
        logger.info("\nSimulation complete.")
        logger.info("Folder: %s", outdir)
        logger.info("Encrypted files: %d", created)
        logger.info("IOC files: %d", ioc_count)
        logger.info("Ransom note: %s", "YES" if self.write_note else "NO")
        if ioc_count:
            logger.info("IOC report generated: IOC_REPORT.txt")

    def _write_simulated_files(self, outdir: Path, ts: str) -> int:
        """Create fake-encrypted files in *outdir*. Returns the count."""
        created = 0
        if self.ext_choice == "KITCHEN_SINK":
            for ext in EXTENSIONS:
                path = outdir / f"{random_filename()}{ext}"
                path.write_text(
                    f"--- Simulation file (fake encrypted) ---\n"
                    f"Extension: {ext}\nTimestamp: {ts}\n\n"
                    f"{fake_ciphertext()}",
                    encoding="utf-8",
                )
                created += 1
        else:
            for _ in range(self.file_count):
                path = outdir / f"{random_filename()}{self.ext_choice}"
                path.write_text(
                    f"--- Simulation file (fake encrypted) ---\n"
                    f"Extension: {self.ext_choice}\nTimestamp: {ts}\n\n"
                    f"{fake_ciphertext()}",
                    encoding="utf-8",
                )
                created += 1
        return created

    def _write_ioc_artifacts(self, outdir: Path) -> int:
        """Create IOC files and report if a profile is selected. Returns count."""
        if not self.ioc_simulator or not self.ioc_simulator.selected_profile:
            return 0

        self.ioc_simulator.base_dir = outdir
        ioc_files = self.ioc_simulator.create_file_iocs()

        report_path = outdir / "IOC_REPORT.txt"
        report_path.write_text(
            self.ioc_simulator.generate_ioc_report(), encoding="utf-8"
        )
        return len(ioc_files)

    # -- cleanup -------------------------------------------------------------------

    def _cleanup_last(self) -> None:
        """Safely remove the last simulation directory after confirmation."""
        if not self.last_output_dir or not self.last_output_dir.exists():
            logger.info("No existing simulation folder found.")
            self.last_output_dir = None
            return

        confirm = (
            input(f"Delete folder {self.last_output_dir}? (y/N): ").strip().lower()
        )
        if confirm == "y":
            try:
                shutil.rmtree(self.last_output_dir)
                logger.info("Deleted.")
            except OSError as exc:
                logger.error("Error removing folder: %s", exc)
            self.last_output_dir = None
        else:
            logger.info("Cleanup canceled.")


def main() -> None:
    """Entry point: configure logging, seed RNG, and launch the menu."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    random.seed(time.time_ns())

    sim = Simulator()
    try:
        sim.menu()
    except KeyboardInterrupt:
        logger.info("\nInterrupted. Bye.")
        sys.exit(0)
