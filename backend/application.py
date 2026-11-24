"""Application composition root for CyberGuard's local services.

The application object owns runtime dependencies and exposes use-case methods.
HTTP handlers receive this object from their server instead of reading module globals.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Callable

from incidents import IncidentStore, default_store
from live_monitor import LiveTrafficMonitor, list_capture_interfaces
from simulation_bridge import SimulationBridge
from threat_intel import ThreatIntelStore


class CyberGuardApplication:
    """Owns and coordinates the services used by one CyberGuard server instance."""

    def __init__(
        self,
        incident_store: IncidentStore | None = None,
        threat_intel: ThreatIntelStore | None = None,
        live_monitor: LiveTrafficMonitor | None = None,
        simulation_runner: Callable[..., dict[str, Any]] | None = None,
        interface_provider: Callable[[], list[dict[str, str]]] | None = None,
        anomaly_model_path: str | None = None,
    ) -> None:
        self.incidents = incident_store or default_store()
        self.threat_intelligence = threat_intel or ThreatIntelStore(self.incidents.database_path)
        self.live_monitor = live_monitor or LiveTrafficMonitor(self.incidents)
        self._simulation_bridge = SimulationBridge()
        self._simulation_runner = simulation_runner
        self._interface_provider = interface_provider or list_capture_interfaces
        self._anomaly_model_path = anomaly_model_path
        self._anomaly_analyzer = None
        self._anomaly_model_loaded = False
        self._anomaly_lock = threading.Lock()

    def list_interfaces(self) -> list[dict[str, str]]:
        return self._interface_provider()

    def run_simulation(self) -> dict[str, Any]:
        if self._simulation_runner is not None:
            return self._simulation_runner(store=self.incidents)
        return self._simulation_bridge.run(store=self.incidents)

    def score_anomaly(self, features: Any) -> dict[str, Any]:
        model_path = self._anomaly_model_path or os.environ.get("CYBERGUARD_ANOMALY_MODEL")
        if not model_path:
            raise RuntimeError(
                "Set CYBERGUARD_ANOMALY_MODEL to a trusted local Isolation Forest artifact"
            )
        try:
            from ml_isolation_forest import IsolationForestAnalyzer
        except ImportError as error:
            raise ImportError(
                "Install optional ML dependencies from requirements-ml.txt"
            ) from error

        try:
            with self._anomaly_lock:
                if not self._anomaly_model_loaded or self._loaded_model_path != model_path:
                    self._anomaly_analyzer = IsolationForestAnalyzer.from_file(model_path)
                    self._loaded_model_path = model_path
                    self._anomaly_model_loaded = True
                analyzer = self._anomaly_analyzer
            return analyzer.score(features)
        except (ValueError, TypeError):
            raise
        except Exception as error:
            with self._anomaly_lock:
                self._anomaly_analyzer = None
                self._anomaly_model_loaded = False
                self._loaded_model_path = None
            raise RuntimeError(
                "Unable to load or score with the configured anomaly model; verify the trusted local artifact and restart the server"
            ) from error

    def close(self) -> None:
        """Stop long-running local resources owned by this application."""
        self.live_monitor.stop()


def create_application(data_directory: str | Path | None = None) -> CyberGuardApplication:
    """Build a fully wired application, optionally using an isolated data directory."""
    if data_directory is None:
        store = default_store()
    else:
        store = IncidentStore(Path(data_directory) / "incidents.sqlite3")
    intel = ThreatIntelStore(store.database_path)
    return CyberGuardApplication(incident_store=store, threat_intel=intel)
