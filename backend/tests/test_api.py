import json
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server as api_server
from incidents import IncidentStore


class IncidentApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_store = api_server.STORE
        api_server.STORE = IncidentStore(Path(self.temp.name) / "api.sqlite3")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), api_server.CyberGuardHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.httpd.server_port)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        api_server.STORE = self.previous_store
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

    def test_invalid_detection_returns_client_error(self):
        with self.assertRaises(HTTPError) as caught:
            self.request_json("/api/detections", "POST", {"type": "not-a-rule"})
        self.assertEqual(caught.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
