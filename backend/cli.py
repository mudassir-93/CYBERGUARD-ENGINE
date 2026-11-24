"""Guided command-line workspace for CyberGuard's local operations.

Run with: python backend/cli.py
The CLI talks directly to the local SQLite repositories and simulator bridge;
it does not start a network listener or expose the API.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any, Callable, Sequence

from ai_analyst import OllamaAnalyst
from incidents import STATUSES, IncidentStore, default_store
from simulation_bridge import SimulationBridge


class CyberGuardCLI:
    """Coordinates safe, local CyberGuard workflows from a terminal."""

    def __init__(
        self,
        store: IncidentStore | None = None,
        simulation_bridge: SimulationBridge | None = None,
        input_fn: Callable[[str], str] = input,
        output_fn: Callable[[str], None] = print,
        analyst: Any | None = None,
    ) -> None:
        self.store = store or default_store()
        self.simulation_bridge = simulation_bridge or SimulationBridge()
        self.analyst = analyst or OllamaAnalyst()
        self.input = input_fn
        self.output = output_fn

    def _parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="cyberguard",
            description="Guided local operations for CyberGuard Engine.",
            epilog=(
                "Run without a command to open the interactive menu. "
                "All commands use the local SQLite data directory."
            ),
        )
        commands = parser.add_subparsers(dest="command")

        commands.add_parser("doctor", help="Check local setup and optional capabilities")
        commands.add_parser("summary", help="Show incident summary")

        incidents = commands.add_parser("incidents", help="List incidents")
        incidents.add_argument("--status", choices=sorted(STATUSES))
        incidents.add_argument("--severity", choices=("low", "medium", "high", "critical"))
        incidents.add_argument("--limit", type=int, default=20)

        detail = commands.add_parser("show", help="Show one incident and its evidence")
        detail.add_argument("incident_id")

        status = commands.add_parser("status", help="Update an incident status")
        status.add_argument("incident_id")
        status.add_argument("new_status", choices=sorted(STATUSES))
        status.add_argument("--note", default=None, help="Optional resolution note")

        explain = commands.add_parser("explain", help="Ask the local Ollama analyst to explain an incident")
        explain.add_argument("incident_id")

        simulate = commands.add_parser("simulate", help="Run local C++ scenarios and ingest detections")
        simulate.add_argument("--executable", help="Path to the compiled CyberGuard executable")
        return parser

    def _show_summary(self) -> None:
        summary = self.store.summary()
        self.output("CyberGuard incident summary")
        self.output(f"  Total incidents : {summary['total']}")
        self.output(f"  Open incidents  : {summary['open']}")
        self.output(f"  Critical open   : {summary['critical']}")
        self.output(f"  High open       : {summary['high']}")
        self.output("  By status       : " + ", ".join(
            f"{name}={count}" for name, count in summary["by_status"].items()
        ))

    def _list_incidents(self, status: str | None = None,
                        severity: str | None = None, limit: int = 20) -> None:
        if isinstance(limit, bool) or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        incidents = self.store.list_incidents(status=status, severity=severity, limit=limit)
        if not incidents:
            self.output("No incidents match those filters.")
            return
        self.output("ID              SEVERITY  STATUS          SCORE  SUMMARY")
        self.output("-" * 86)
        for item in incidents:
            summary = item["summary"].replace("\\n", " ").replace("\n", " ")
            self.output(
                f"{item['id']:<15} {item['severity']:<8}  {item['status']:<14} "
                f"{item['risk_score']:>5}  {summary[:48]}"
            )

    def _show_incident(self, incident_id: str) -> None:
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident not found: {incident_id}")
        self.output(json.dumps(incident, indent=2, ensure_ascii=False))

    def _explain_incident(self, incident_id: str) -> None:
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident not found: {incident_id}")
        result = self.analyst.explain(incident)
        self.output(f"Local analyst ({result['model']})")
        self.output(result["explanation"])
        self.output("Advisory only: verify findings against source telemetry; no response action was taken.")

    def _update_status(self, incident_id: str, new_status: str,
                       note: str | None = None) -> None:
        incident = self.store.update_status(incident_id, new_status, note)
        if incident is None:
            raise ValueError(f"Incident not found: {incident_id}")
        self.output(f"{incident['id']} status updated to {incident['status']}.")

    def _doctor(self) -> int:
        checks: list[tuple[str, bool, str]] = []
        database_path = self.store.database_path
        checks.append(("SQLite database", database_path.is_file(), str(database_path)))
        try:
            executable = self.simulation_bridge.find_executable()
            checks.append(("Native simulator", True, str(executable)))
        except (FileNotFoundError, OSError) as error:
            checks.append(("Native simulator", False, str(error)))
        for label, module in (("Passive capture (Scapy)", "scapy"),
                              ("ML tools (scikit-learn)", "sklearn")):
            available = importlib.util.find_spec(module) is not None
            checks.append((label, available, "available" if available else "optional dependency not installed"))
        self.output("CyberGuard local setup")
        for label, ok, detail in checks:
            self.output(f"[{'OK' if ok else 'OPTIONAL / NOT READY'}] {label}: {detail}")
        self.output("The dashboard API is loopback-only and is not checked as a remote service.")
        return 0

    def _run_simulation(self, executable: str | None = None) -> int:
        report = self.simulation_bridge.run(executable=executable, store=self.store)
        self.output(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    def _interactive(self) -> int:
        actions = {
            "1": ("Incident summary", self._show_summary),
            "2": ("List incidents", self._list_incidents),
            "3": ("Run local C++ simulation", self._run_simulation),
            "4": ("Check local setup", self._doctor),
        }
        while True:
            self.output("\nCyberGuard — Local Security Workspace")
            self.output("  1. Incident summary")
            self.output("  2. List incidents")
            self.output("  3. Run local C++ simulation")
            self.output("  4. Check local setup")
            self.output("  5. Show incident details")
            self.output("  6. Update incident status")
            self.output("  7. Explain incident with local AI")
            self.output("  0. Exit")
            choice = self.input("Select an option: ").strip()
            if choice == "0":
                self.output("CyberGuard session closed.")
                return 0
            if choice in actions:
                try:
                    result = actions[choice][1]()
                    if isinstance(result, int) and result:
                        self.output(f"Command finished with exit code {result}.")
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                    self.output(f"Unable to complete action: {error}")
                continue
            if choice == "5":
                incident_id = self.input("Incident ID: ").strip()
                try:
                    self._show_incident(incident_id)
                except ValueError as error:
                    self.output(str(error))
                continue
            if choice == "6":
                incident_id = self.input("Incident ID: ").strip()
                self.output("Available statuses: " + ", ".join(sorted(STATUSES)))
                new_status = self.input("New status: ").strip()
                note = self.input("Optional note (press Enter to skip): ").strip() or None
                try:
                    self._update_status(incident_id, new_status, note)
                except ValueError as error:
                    self.output(str(error))
                continue
            if choice == "7":
                incident_id = self.input("Incident ID: ").strip()
                try:
                    self._explain_incident(incident_id)
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                    self.output(f"Unable to complete action: {error}")
                continue
            self.output("Choose one of the listed options.")

    def run(self, argv: Sequence[str] | None = None) -> int:
        parser = self._parser()
        args = parser.parse_args(argv)
        if args.command is None:
            return self._interactive()
        try:
            if args.command == "doctor":
                return self._doctor()
            if args.command == "summary":
                self._show_summary()
            elif args.command == "incidents":
                self._list_incidents(args.status, args.severity, args.limit)
            elif args.command == "show":
                self._show_incident(args.incident_id)
            elif args.command == "status":
                self._update_status(args.incident_id, args.new_status, args.note)
            elif args.command == "explain":
                self._explain_incident(args.incident_id)
            elif args.command == "simulate":
                return self._run_simulation(args.executable)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            self.output(f"Error: {error}")
            return 1
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    return CyberGuardCLI().run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
