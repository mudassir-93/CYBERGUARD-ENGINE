import json
import ipaddress
import os
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from incidents import default_store
from simulation_bridge import run_simulation
from live_monitor import LiveTrafficMonitor, list_capture_interfaces
from threat_intel import ThreatIntelStore

ROOT = Path(__file__).resolve().parent.parent
MAX_BODY_BYTES = 1_000_000
STORE = default_store()
LIVE_MONITOR = LiveTrafficMonitor(STORE)
THREAT_INTEL = ThreatIntelStore(STORE.database_path)


class CyberGuardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, format, *args):
        return

    def _json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _is_loopback_client(self):
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except (ValueError, IndexError):
            return False

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("Invalid Content-Length") from error
        if length < 1 or length > MAX_BODY_BYTES:
            raise ValueError("Request body must be between 1 byte and 1 MB")
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ValueError("Content-Type must be application/json")
        try:
            payload = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Request body must contain valid JSON") from error
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object")
        return payload

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/api/health":
            return self._json(200, {"status": "ok", "service": "cyberguard-local-api"})
        if parsed.path == "/api/live/status":
            return self._json(200, LIVE_MONITOR.status())
        if parsed.path == "/api/live/interfaces":
            try:
                return self._json(200, {"available": True, "interfaces": list_capture_interfaces()})
            except RuntimeError as error:
                return self._json(503, {"available": False, "interfaces": [], "error": str(error)})
        if parsed.path == "/api/threat-intel":
            query = parse_qs(parsed.query)
            try:
                return self._json(200, {"indicators": THREAT_INTEL.list_indicators(query.get("type", [None])[0], int(query.get("limit", ["100"])[0]))})
            except (ValueError, TypeError) as error:
                return self._json(400, {"error": str(error)})
        if parsed.path == "/api/incidents":
            query = parse_qs(parsed.query)
            try:
                incidents = STORE.list_incidents(
                    query.get("status", [None])[0],
                    query.get("severity", [None])[0],
                    int(query.get("limit", ["100"])[0]),
                )
                return self._json(200, {"incidents": incidents, "summary": STORE.summary()})
            except (ValueError, TypeError) as error:
                return self._json(400, {"error": str(error)})
        if parsed.path.startswith("/api/incidents/"):
            incident_id = parsed.path.rsplit("/", 1)[-1]
            incident = STORE.get_incident(incident_id)
            if incident is None:
                return self._json(404, {"error": "Incident not found"})
            incident["threat_intel_matches"] = THREAT_INTEL.match_incident(incident)
            incident["analyst_notes"] = THREAT_INTEL.list_notes(incident_id)
            return self._json(200, {"incident": incident})
        return super().do_GET()

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/threat-intel/import":
            if not self._is_loopback_client():
                return self._json(403, {"error": "Threat-intelligence imports are restricted to local clients"})
            try:
                payload = self._body()
                return self._json(200, THREAT_INTEL.import_indicators(payload.get("indicators")))
            except ValueError as error:
                return self._json(400, {"error": str(error)})
        if path.startswith("/api/incidents/") and path.endswith("/notes"):
            if not self._is_loopback_client():
                return self._json(403, {"error": "Analyst note writes are restricted to local clients"})
            incident_id = path[len("/api/incidents/"):-len("/notes")].strip("/")
            if not incident_id or "/" in incident_id:
                return self._json(404, {"error": "Incident not found"})
            try:
                payload = self._body()
                note = THREAT_INTEL.add_note(incident_id, payload.get("note"), payload.get("author", "local-analyst"))
                if note is None:
                    return self._json(404, {"error": "Incident not found"})
                return self._json(201, {"note": note})
            except ValueError as error:
                return self._json(400, {"error": str(error)})
        if path == "/api/simulate":
            try:
                return self._json(200, run_simulation(store=STORE))
            except FileNotFoundError as error:
                return self._json(503, {"error": str(error)})
            except (RuntimeError, ValueError) as error:
                return self._json(500, {"error": str(error)})
        if path in {"/api/live/start", "/api/live/stop"} and not self._is_loopback_client():
            return self._json(403, {"error": "Live capture controls are restricted to local clients"})
        if path == "/api/live/start":
            try:
                payload = self._body()
                return self._json(200, LIVE_MONITOR.start(payload.get("interface")))
            except ValueError as error:
                return self._json(400, {"error": str(error)})
            except RuntimeError as error:
                return self._json(503, {"error": str(error)})
        if path == "/api/live/stop":
            return self._json(200, LIVE_MONITOR.stop())
        if path != "/api/detections":
            return self._json(404, {"error": "Endpoint not found"})
        try:
            incident, correlated = STORE.ingest(self._body())
            return self._json(200 if correlated else 201, {"incident": incident, "correlated": correlated})
        except ValueError as error:
            return self._json(400, {"error": str(error)})
        except Exception:
            return self._json(500, {"error": "Unable to persist detection"})

    def do_PATCH(self):
        path = urlsplit(self.path).path
        prefix, suffix = "/api/incidents/", "/status"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return self._json(404, {"error": "Endpoint not found"})
        incident_id = path[len(prefix):-len(suffix)].strip("/")
        if not incident_id or "/" in incident_id:
            return self._json(404, {"error": "Incident not found"})
        try:
            payload = self._body()
            incident = STORE.update_status(incident_id, payload.get("status"), payload.get("resolution_note"))
            if incident is None:
                return self._json(404, {"error": "Incident not found"})
            return self._json(200, {"incident": incident})
        except ValueError as error:
            return self._json(400, {"error": str(error)})
        except Exception:
            return self._json(500, {"error": "Unable to update incident"})


if __name__ == "__main__":
    host = os.environ.get("CYBERGUARD_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("CYBERGUARD_PORT", "8000"))
    except ValueError as error:
        raise SystemExit("CYBERGUARD_PORT must be an integer between 1 and 65535") from error
    if not 1 <= port <= 65535:
        raise SystemExit("CYBERGUARD_PORT must be an integer between 1 and 65535")
    server = ThreadingHTTPServer((host, port), CyberGuardHandler)
    print(f"Serving CyberGuard on {host}:{port} (open http://localhost:{port}/ in your browser)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()
