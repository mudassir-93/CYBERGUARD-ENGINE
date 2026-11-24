"""Object-oriented bridge from the native simulator to the incident repository."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Callable

from incidents import IncidentStore, default_store

ROOT = Path(__file__).resolve().parent.parent


class SimulationBridge:
    """Owns executable discovery, process execution, and JSONL ingestion."""

    def __init__(
        self,
        repository_root: str | Path = ROOT,
        process_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ) -> None:
        self.repository_root = Path(repository_root)
        self._process_runner = process_runner

    def find_executable(self, explicit: str | None = None) -> Path:
        configured = explicit or os.environ.get("CYBERGUARD_EXECUTABLE")
        if configured:
            path = Path(configured).expanduser().resolve()
            if not path.is_file():
                raise FileNotFoundError(f"CyberGuard executable not found: {path}")
            return path

        candidates = (
            self.repository_root / "build" / "CyberGuard",
            self.repository_root / "build" / "CyberGuard.exe",
            self.repository_root / "build" / "Release" / "CyberGuard.exe",
            self.repository_root / "build" / "Debug" / "CyberGuard.exe",
            self.repository_root / "build" / "bin" / "CyberGuard",
            self.repository_root / "build" / "bin" / "CyberGuard.exe",
        )
        for path in candidates:
            if path.is_file():
                return path
        raise FileNotFoundError(
            "CyberGuard executable not found. Build the project first or set CYBERGUARD_EXECUTABLE."
        )

    @staticmethod
    def ingest_jsonl(output: str, store: IncidentStore) -> dict[str, Any]:
        counts: dict[str, int] = {}
        created = correlated = 0
        for line_number, line in enumerate(output.splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Simulator emitted invalid JSON on line {line_number}"
                ) from error
            if not isinstance(event, dict):
                raise ValueError(
                    f"Simulator output line {line_number} is not a JSON object"
                )
            incident, was_correlated = store.ingest(event)
            kind = incident["type"]
            counts[kind] = counts.get(kind, 0) + 1
            if was_correlated:
                correlated += 1
            else:
                created += 1
        return {
            "detections_received": sum(counts.values()),
            "incidents_created": created,
            "detections_correlated": correlated,
            "by_type": counts,
            "summary": store.summary(),
        }

    def run(
        self,
        executable: str | None = None,
        store: IncidentStore | None = None,
    ) -> dict[str, Any]:
        binary = self.find_executable(executable)
        result = self._process_runner(
            [str(binary), "--jsonl"],
            cwd=self.repository_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(
                (result.stderr.strip() or f"Simulator exited with code {result.returncode}")[:2000]
            )
        report = self.ingest_jsonl(result.stdout, store or default_store())
        expected = {"port_scan", "brute_force", "dos", "lateral_movement"}
        missing = expected - set(report["by_type"])
        if missing:
            raise RuntimeError(
                "Native simulator did not emit expected detection types: "
                + ", ".join(sorted(missing))
            )
        report["executable"] = str(binary)
        return report


# Compatibility functions keep the CLI and existing callers stable while
# delegating all stateful behavior to the SimulationBridge object.
_default_bridge = SimulationBridge()


def find_executable(explicit: str | None = None) -> Path:
    return _default_bridge.find_executable(explicit)


def ingest_jsonl(output: str, store: IncidentStore) -> dict[str, Any]:
    return _default_bridge.ingest_jsonl(output, store)


def run_simulation(
    executable: str | None = None,
    store: IncidentStore | None = None,
) -> dict[str, Any]:
    return _default_bridge.run(executable, store)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run CyberGuard C++ simulation and ingest detections into SQLite."
    )
    parser.add_argument("--executable", help="Path to compiled CyberGuard executable")
    args = parser.parse_args()
    try:
        report = run_simulation(args.executable)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Simulation integration failed: {error}\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
