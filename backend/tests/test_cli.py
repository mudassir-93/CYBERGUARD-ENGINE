"""Tests for the guided CyberGuard CLI."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cli import CyberGuardCLI
from incidents import IncidentStore


class FakeSimulationBridge:
    def __init__(self, report=None):
        self.report = report or {"detections_received": 0, "incidents_created": 0}

    def run(self, executable=None, store=None):
        return self.report


class CyberGuardCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = IncidentStore(Path(self.temp.name) / "incidents.sqlite3")
        self.output = []
        self.analyst = Mock()
        self.analyst.explain.return_value = {
            "model": "test-model", "explanation": "A suspicious scan-like pattern was observed."
        }
        self.cli = CyberGuardCLI(
            store=self.store,
            simulation_bridge=FakeSimulationBridge(),
            input_fn=lambda _prompt: "0",
            output_fn=self.output.append,
            analyst=self.analyst,
        )

    def tearDown(self):
        self.temp.cleanup()

    def create_incident(self):
        incident, _ = self.store.ingest({
            "type": "port_scan",
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "destination_port": 443,
            "protocol": "TCP",
            "summary": "Test scan",
        })
        return incident

    def test_summary_command(self):
        self.create_incident()
        self.assertEqual(self.cli.run(["summary"]), 0)
        self.assertTrue(any("Total incidents : 1" in line for line in self.output))

    def test_list_incidents_command(self):
        self.create_incident()
        self.assertEqual(self.cli.run(["incidents", "--severity", "medium"]), 0)
        self.assertTrue(any("Test scan" in line for line in self.output))

    def test_show_incident_command(self):
        incident = self.create_incident()
        self.assertEqual(self.cli.run(["show", incident["id"]]), 0)
        self.assertTrue(any(incident["id"] in line for line in self.output))

    def test_status_command_uses_repository_transition_rules(self):
        incident = self.create_incident()
        self.assertEqual(self.cli.run(["status", incident["id"], "acknowledged"]), 0)
        self.assertEqual(self.store.get_incident(incident["id"])["status"], "acknowledged")

    def test_invalid_status_transition_is_reported(self):
        incident = self.create_incident()
        self.store.update_status(incident["id"], "resolved")
        self.assertEqual(self.cli.run(["status", incident["id"], "investigating"]), 1)
        self.assertTrue(any("Cannot move incident" in line for line in self.output))

    def test_simulation_delegates_to_bridge(self):
        self.assertEqual(self.cli.run(["simulate"]), 0)
        self.assertTrue(any("detections_received" in line for line in self.output))

    def test_explain_command_uses_read_only_analyst(self):
        incident = self.create_incident()
        self.assertEqual(self.cli.run(["explain", incident["id"]]), 0)
        self.analyst.explain.assert_called_once()
        self.assertTrue(any("test-model" in line for line in self.output))
        self.assertTrue(any("Advisory only" in line for line in self.output))

    def test_explain_command_rejects_unknown_incident(self):
        self.assertEqual(self.cli.run(["explain", "CG-MISSING"]), 1)
        self.assertTrue(any("Incident not found" in line for line in self.output))
        self.analyst.explain.assert_not_called()

    def test_doctor_reports_local_ai_model_readiness(self):
        self.analyst.diagnose.return_value = (True, "model llama3.2:3b is installed and ready")
        self.assertEqual(self.cli.run(["doctor"]), 0)
        self.assertTrue(any(
            "Local AI analyst (Ollama)" in line and "installed and ready" in line
            for line in self.output
        ))

    def test_doctor_keeps_missing_ollama_optional(self):
        self.analyst.diagnose.return_value = (
            False, "Ollama is not responding on the configured loopback address"
        )
        self.assertEqual(self.cli.run(["doctor"]), 0)
        self.assertTrue(any(
            "Local AI analyst (Ollama)" in line and "not responding" in line
            for line in self.output
        ))

    def test_interactive_menu_can_exit(self):
        self.assertEqual(self.cli.run([]), 0)
        self.assertTrue(any("session closed" in line for line in self.output))

    def test_invalid_limit_is_rejected(self):
        self.assertEqual(self.cli.run(["incidents", "--limit", "0"]), 1)
        self.assertTrue(any("limit must be between" in line for line in self.output))


if __name__ == "__main__":
    unittest.main()
