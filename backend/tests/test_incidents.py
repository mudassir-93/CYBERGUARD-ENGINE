import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from incidents import IncidentStore, normalize_detection


def sample(**overrides):
    payload = {
        "type": "port_scan", "source_ip": "10.0.0.20", "destination_ip": "10.0.0.10",
        "destination_port": 443, "protocol": "TCP",
        "summary": "Repeated connections to multiple service ports",
        "evidence": {"distinct_ports": 12, "window_seconds": 60},
    }
    payload.update(overrides)
    return payload


class IncidentStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = IncidentStore(Path(self.temp.name) / "incidents.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_create_incident(self):
        incident, correlated = self.store.ingest(sample())
        self.assertFalse(correlated)
        self.assertEqual((incident["status"], incident["severity"], incident["occurrence_count"]), ("new", "medium", 1))
        self.assertEqual(len(incident["evidence"]["observations"]), 1)

    def test_correlates_repeated_detection_and_preserves_evidence(self):
        first, _ = self.store.ingest(sample())
        second, correlated = self.store.ingest(sample(evidence={"distinct_ports": 15}))
        self.assertTrue(correlated)
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["occurrence_count"], 2)
        self.assertEqual(len(second["evidence"]["observations"]), 2)

    def test_closed_incident_does_not_absorb_new_detection(self):
        first, _ = self.store.ingest(sample())
        self.store.update_status(first["id"], "resolved", "Reviewed")
        second, correlated = self.store.ingest(sample())
        self.assertFalse(correlated)
        self.assertNotEqual(first["id"], second["id"])

    def test_lifecycle_and_audit_timeline(self):
        incident, _ = self.store.ingest(sample())
        self.store.update_status(incident["id"], "acknowledged")
        self.store.update_status(incident["id"], "investigating")
        self.store.update_status(incident["id"], "resolved", "No further activity")
        detail = self.store.get_incident(incident["id"])
        self.assertEqual(detail["status"], "resolved")
        self.assertEqual(detail["resolution_note"], "No further activity")
        self.assertEqual(len(detail["timeline"]), 4)

    def test_rejects_invalid_transitions(self):
        incident, _ = self.store.ingest(sample())
        with self.assertRaises(ValueError):
            self.store.update_status(incident["id"], "false_positive")
        self.store.update_status(incident["id"], "acknowledged")
        with self.assertRaises(ValueError):
            self.store.update_status(incident["id"], "new")

    def test_validates_type_ip_port_evidence(self):
        for payload in (sample(type="unknown"), sample(source_ip="not-an-ip"),
                        sample(destination_port=70000), sample(evidence=[])):
            with self.assertRaises(ValueError):
                normalize_detection(payload)

    def test_filters_and_summary(self):
        self.store.ingest(sample())
        self.store.ingest(sample(type="dos", source_ip="10.0.0.21"))
        self.assertEqual(len(self.store.list_incidents(severity="critical")), 1)
        summary = self.store.summary()
        self.assertEqual((summary["total"], summary["open"], summary["critical"]), (2, 2, 1))

    def test_explicit_reopen(self):
        incident, _ = self.store.ingest(sample())
        self.store.update_status(incident["id"], "resolved")
        self.assertEqual(self.store.update_status(incident["id"], "new")["status"], "new")


if __name__ == "__main__":
    unittest.main()
