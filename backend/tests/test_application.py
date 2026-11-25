import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from application import CyberGuardApplication, create_application
from incidents import IncidentStore
from threat_intel import ThreatIntelStore


class ApplicationCompositionTests(unittest.TestCase):
    def test_injected_services_are_owned_by_application(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.sqlite3")
            intel = ThreatIntelStore(store.database_path)
            live_monitor = Mock()
            runner = Mock(return_value={"detections_received": 0})
            provider = Mock(return_value=[{"name": "loopback", "description": "test"}])
            application = CyberGuardApplication(
                incident_store=store,
                threat_intel=intel,
                live_monitor=live_monitor,
                simulation_runner=runner,
                interface_provider=provider,
            )
            self.assertIs(application.incidents, store)
            self.assertIs(application.threat_intelligence, intel)
            self.assertIs(application.live_monitor, live_monitor)
            self.assertEqual(application.list_interfaces()[0]["name"], "loopback")
            self.assertEqual(application.run_simulation()["detections_received"], 0)
            runner.assert_called_once_with(store=store)
            application.close()
            live_monitor.stop.assert_called_once_with()

    def test_threatfox_sync_persists_normalized_indicators(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            application = create_application(directory)
            feed_result = {
                "indicators": [{"type": "domain", "value": "feed.example", "source": "ThreatFox",
                                "confidence": 90, "severity": "high", "description": "",
                                "tags": [], "first_seen": "2026-11-20T12:00:00+00:00",
                                "last_seen": None, "expires_at": None}],
                "received": 1, "accepted": 1, "skipped": 0,
            }
            with patch("threatfox_feed.ThreatFoxFeed") as feed:
                feed.return_value.fetch.return_value = feed_result
                result = application.sync_threatfox(days=2)
            self.assertEqual((result["inserted"], result["total_processed"]), (1, 1))
            self.assertEqual(application.threat_intelligence.list_indicators()[0]["value"], "feed.example")
            feed.return_value.fetch.assert_called_once_with(days=2)
            application.close()

    def test_factory_creates_isolated_application_database(self):
        with tempfile.TemporaryDirectory() as directory:
            application = create_application(directory)
            self.assertTrue(application.incidents.database_path.exists())
            self.assertEqual(application.incidents.database_path.parent, Path(directory))
            application.close()


if __name__ == "__main__":
    unittest.main()
