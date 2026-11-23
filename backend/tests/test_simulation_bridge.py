import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from incidents import IncidentStore
from simulation_bridge import ingest_jsonl


class SimulationBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = IncidentStore(Path(self.temp.name) / "bridge.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_ingests_native_jsonl_detection_records(self):
        records = [
            {"type":"port_scan","source_ip":"10.0.0.20","destination_ip":"10.0.0.10","protocol":"TCP","summary":"Port scan","evidence":{"distinct_ports":12}},
            {"type":"brute_force","source_ip":"10.0.0.20","destination_ip":"10.0.0.10","destination_port":22,"protocol":"TCP","summary":"Failed attempts","evidence":{"failed_attempts":6}},
            {"type":"dos","source_ip":"10.0.0.21","destination_ip":"10.0.0.10","protocol":"TCP","summary":"High volume","evidence":{"packet_count":120}},
            {"type":"lateral_movement","source_ip":"10.0.0.20","destination_ip":"10.0.0.11","protocol":"TCP","summary":"Host fan-out","evidence":{"destinations":["10.0.0.10","10.0.0.11","10.0.0.12"]}},
        ]
        output = "\n".join(__import__("json").dumps(item) for item in records) + "\n"
        result = ingest_jsonl(output, self.store)
        self.assertEqual(result["detections_received"], 4)
        self.assertEqual(result["incidents_created"], 4)
        self.assertEqual(set(result["by_type"]), {"port_scan","brute_force","dos","lateral_movement"})
        self.assertEqual(result["summary"]["open"], 4)

    def test_correlates_repeated_native_detection(self):
        import json
        event = {"type":"port_scan","source_ip":"10.0.0.20","destination_ip":"10.0.0.10","protocol":"TCP","evidence":{"distinct_ports":12}}
        result = ingest_jsonl(json.dumps(event)+"\n"+json.dumps(event), self.store)
        self.assertEqual(result["incidents_created"], 1)
        self.assertEqual(result["detections_correlated"], 1)
        self.assertEqual(result["summary"]["total"], 1)

    def test_rejects_malformed_native_output(self):
        with self.assertRaises(ValueError):
            ingest_jsonl('{"type":\n', self.store)


if __name__ == "__main__":
    unittest.main()
