import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server as api_server


class IncidentApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.application = api_server.create_application(self.temp.name)
        self.httpd = api_server.create_server("127.0.0.1", 0, self.application)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.httpd.server_port)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.application.close()
        self.temp.cleanup()

    def request_json(self, path, method="GET", payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(self.base + path, data=data, method=method,
                          headers={"Content-Type": "application/json"} if data is not None else {})
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def test_health_endpoint(self):
        status, body = self.request_json("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_detection_ingest_list_and_status_update(self):
        detection = {
            "type": "brute_force", "source_ip": "10.0.0.21",
            "destination_ip": "10.0.0.10", "destination_port": 22,
            "protocol": "TCP", "evidence": {"failed_attempts": 8}
        }
        status, created = self.request_json("/api/detections", "POST", detection)
        self.assertEqual(status, 201)
        status, correlated = self.request_json("/api/detections", "POST", detection)
        self.assertEqual(status, 200)
        self.assertTrue(correlated["correlated"])
        incident_id = created["incident"]["id"]
        status, listing = self.request_json("/api/incidents")
        self.assertEqual(status, 200)
        self.assertEqual(listing["summary"]["total"], 1)
        status, updated = self.request_json(
            "/api/incidents/" + incident_id + "/status", "PATCH", {"status": "acknowledged"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(updated["incident"]["status"], "acknowledged")

    def test_native_simulation_endpoint_returns_ingestion_summary(self):
        from unittest.mock import patch
        report = {"detections_received": 4, "incidents_created": 4, "detections_correlated": 0,
                  "by_type": {"port_scan": 1, "brute_force": 1, "dos": 1, "lateral_movement": 1}}
        with patch.object(self.application, "run_simulation", return_value=report):
            status, body = self.request_json("/api/simulate", "POST", {})
        self.assertEqual(status, 200)
        self.assertEqual(body["detections_received"], 4)

    def test_live_monitor_status_endpoint(self):
        from unittest.mock import patch
        with patch.object(self.application.live_monitor, "status", return_value={"available": False, "running": False}):
            status, body = self.request_json("/api/live/status")
        self.assertEqual(status, 200)
        self.assertFalse(body["available"])

    def test_live_interface_endpoint_reports_optional_dependency(self):
        from unittest.mock import patch
        with patch.object(self.application, "list_interfaces", side_effect=RuntimeError("Scapy is missing")):
            with self.assertRaises(HTTPError) as caught:
                self.request_json("/api/live/interfaces")
        self.assertEqual(caught.exception.code, 503)

    def test_live_start_and_stop_endpoints(self):
        from unittest.mock import patch
        with patch.object(self.application.live_monitor, "start", return_value={"running": True}) as start:
            status, body = self.request_json("/api/live/start", "POST", {"interface": "test0"})
        self.assertEqual(status, 200)
        self.assertTrue(body["running"])
        start.assert_called_once_with("test0")
        with patch.object(self.application.live_monitor, "stop", return_value={"running": False}):
            status, body = self.request_json("/api/live/stop", "POST")
        self.assertEqual(status, 200)
        self.assertFalse(body["running"])


    def test_live_capture_controls_reject_non_loopback_clients(self):
        from unittest.mock import patch
        with patch.object(api_server.CyberGuardHandler, "_is_loopback_client", return_value=False):
            with self.assertRaises(HTTPError) as caught:
                self.request_json("/api/live/start", "POST", {"interface": "test0"})
        self.assertEqual(caught.exception.code, 403)


    def test_threat_intel_import_and_incident_enrichment_and_notes(self):
        from unittest.mock import patch
        detection = {"type": "port_scan", "source_ip": "203.0.113.88",
                     "destination_ip": "10.0.0.10", "evidence": {"hostname": "ioc.example"}}
        _, created = self.request_json("/api/detections", "POST", detection)
        incident_id = created["incident"]["id"]
        with patch.object(api_server.CyberGuardHandler, "_is_loopback_client", return_value=True):
            status, imported = self.request_json("/api/threat-intel/import", "POST", {
                "indicators": [{"type": "ip", "value": "203.0.113.88", "source": "test-feed", "confidence": 90},
                               {"type": "domain", "value": "ioc.example", "source": "test-feed"}]
            })
            self.assertEqual(status, 200)
            self.assertEqual(imported["inserted"], 2)
            status, note = self.request_json("/api/incidents/" + incident_id + "/notes", "POST",
                                             {"note": "Matched a local test feed", "author": "tester"})
        self.assertEqual(status, 201)
        self.assertEqual(note["note"]["author"], "tester")
        status, detail = self.request_json("/api/incidents/" + incident_id)
        self.assertEqual(status, 200)
        self.assertEqual(len(detail["incident"]["threat_intel_matches"]), 2)
        self.assertEqual(len(detail["incident"]["analyst_notes"]), 1)

    def test_threat_intel_writes_reject_non_loopback_clients(self):
        from unittest.mock import patch
        with patch.object(api_server.CyberGuardHandler, "_is_loopback_client", return_value=False):
            with self.assertRaises(HTTPError) as caught:
                self.request_json("/api/threat-intel/import", "POST", {
                    "indicators": [{"type": "ip", "value": "203.0.113.1"}]
                })
        self.assertEqual(caught.exception.code, 403)


    def test_all_api_routes_reject_non_loopback_clients(self):
        from unittest.mock import patch
        with patch.object(api_server.CyberGuardHandler, "_is_loopback_client", return_value=False):
            for path, method, payload in (
                ("/api/health", "GET", None),
                ("/api/detections", "POST", {"type": "port_scan", "source_ip": "10.0.0.1"}),
                ("/api/incidents/CG-NOTREAL/status", "PATCH", {"status": "resolved"}),
            ):
                with self.subTest(path=path):
                    with self.assertRaises(HTTPError) as caught:
                        self.request_json(path, method, payload)
                    self.assertEqual(caught.exception.code, 403)


    def test_anomaly_scoring_api_uses_configured_local_model(self):
        import os
        from unittest.mock import patch
        from ml_isolation_forest import FEATURES, save_model, train_model
        rows = [{name: 10 + (index % 5) * 0.2 for name in FEATURES} for index in range(60)]
        model_path = Path(self.temp.name) / "api-model.joblib"
        save_model(train_model(rows), model_path)
        with patch.dict(os.environ, {"CYBERGUARD_ANOMALY_MODEL": str(model_path)}):
            status, body = self.request_json("/api/anomaly/score", "POST",
                                             {"features": {name: 10.2 for name in FEATURES}})
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["algorithm"], "IsolationForest")

    def test_anomaly_scoring_api_requires_configured_model(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(HTTPError) as caught:
                self.request_json("/api/anomaly/score", "POST", {"features": {}})
        self.assertEqual(caught.exception.code, 503)

    def test_invalid_detection_returns_client_error(self):
        with self.assertRaises(HTTPError) as caught:
            self.request_json("/api/detections", "POST", {"type": "not-a-rule"})
        self.assertEqual(caught.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
