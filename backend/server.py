import json
import ipaddress
import os
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from application import CyberGuardApplication, create_application

ROOT = Path(__file__).resolve().parent.parent
MAX_BODY_BYTES = 1_000_000


class CyberGuardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def setup(self):
        # BaseRequestHandler assigns self.server before setup(), and setup()
        # runs before handle(); bind dependencies here so the first request
        # can never observe an uninitialized application.
        super().setup()
        self.application: CyberGuardApplication = self.server.application

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
        if parsed.path.startswith("/api/") and not self._is_loopback_client():
            return self._json(403, {"error": "CyberGuard API is restricted to local clients"})
        if parsed.path == "/api/health":
            return self._json(200, {"status": "ok", "service": "cyberguard-local-api"})
        if parsed.path == "/api/live/status":
            return self._json(200, self.application.live_monitor.status())
        if parsed.path == "/api/live/interfaces":
            try:
                return self._json(200, {"available": True, "interfaces": self.application.list_interfaces()})
            except RuntimeError as error:
                return self._json(503, {"available": False, "interfaces": [], "error": str(error)})
        if parsed.path == "/api/threat-intel":
            query = parse_qs(parsed.query)
            try:
                return self._json(200, {"indicators": self.application.threat_intelligence.list_indicators(query.get("type", [None])[0], int(query.get("limit", ["100"])[0]))})
            except (ValueError, TypeError) as error:
                return self._json(400, {"error": str(error)})
        if parsed.path == "/api/incidents":
            query = parse_qs(parsed.query)
            try:
                incidents = self.application.incidents.list_incidents(
                    query.get("status", [None])[0],
                    query.get("severity", [None])[0],
                    int(query.get("limit", ["100"])[0]),
                )
                return self._json(200, {"incidents": incidents, "summary": self.application.incidents.summary()})
            except (ValueError, TypeError) as error:
                return self._json(400, {"error": str(error)})
        if parsed.path.startswith("/api/incidents/"):
            incident_id = parsed.path.rsplit("/", 1)[-1]
            incident = self.application.incidents.get_incident(incident_id)
            if incident is None:
                return self._json(404, {"error": "Incident not found"})
            incident["threat_intel_matches"] = self.application.threat_intelligence.match_incident(incident)
            incident["analyst_notes"] = self.application.threat_intelligence.list_notes(incident_id)
            return self._json(200, {"incident": incident})
        return super().do_GET()

    def do_POST(self):
        path = urlsplit(self.path).path
        if path.startswith("/api/") and not self._is_loopback_client():
            return self._json(403, {"error": "CyberGuard API is restricted to local clients"})
        if path == "/api/analyst/explain":
            try:
                incident_id = self._body().get("incident_id")
                if not isinstance(incident_id, str) or not incident_id.strip():
                    raise ValueError("incident_id is required")
                return self._json(200, self.application.explain_incident(incident_id.strip()))
            except KeyError as error:
                return self._json(404, {"error": str(error).strip("'")})
            except ValueError as error:
                return self._json(400, {"error": str(error)})
            except RuntimeError as error:
                return self._json(503, {"error": str(error)})
        if path == "/api/anomaly/score":
            try:
                features = self._body().get("features")
                return self._json(200, {"result": self.application.score_anomaly(features)})
            except ImportError as error:
                return self._json(503, {"error": str(error)})
            except RuntimeError as error:
                return self._json(503, {"error": str(error)})
            except (ValueError, TypeError) as error:
                return self._json(400, {"error": str(error)})
        if path == "/api/threat-intel/import":
            try:
                payload = self._body()
                return self._json(200, self.application.threat_intelligence.import_indicators(payload.get("indicators")))
            except ValueError as error:
                return self._json(400, {"error": str(error)})
        if path.startswith("/api/incidents/") and path.endswith("/notes"):
            incident_id = path[len("/api/incidents/"):-len("/notes")].strip("/")
            if not incident_id or "/" in incident_id:
                return self._json(404, {"error": "Incident not found"})
            try:
                payload = self._body()
                note = self.application.threat_intelligence.add_note(incident_id, payload.get("note"), payload.get("author", "local-analyst"))
                if note is None:
                    return self._json(404, {"error": "Incident not found"})
                return self._json(201, {"note": note})
            except ValueError as error:
                return self._json(400, {"error": str(error)})
        if path == "/api/simulate":
            try:
                return self._json(200, self.application.run_simulation())
            except FileNotFoundError as error:
                return self._json(503, {"error": str(error)})
            except (RuntimeError, ValueError) as error:
                return self._json(500, {"error": str(error)})
        if path == "/api/live/start":
            try:
                payload = self._body()
                return self._json(200, self.application.live_monitor.start(payload.get("interface")))
            except ValueError as error:
                return self._json(400, {"error": str(error)})
            except RuntimeError as error:
                return self._json(503, {"error": str(error)})
        if path == "/api/live/stop":
            return self._json(200, self.application.live_monitor.stop())
        if path != "/api/detections":
            return self._json(404, {"error": "Endpoint not found"})
        try:
            incident, correlated = self.application.incidents.ingest(self._body())
            return self._json(200 if correlated else 201, {"incident": incident, "correlated": correlated})
        except ValueError as error:
            return self._json(400, {"error": str(error)})
        except Exception:
            return self._json(500, {"error": "Unable to persist detection"})

    def do_PATCH(self):
        path = urlsplit(self.path).path
        if path.startswith("/api/") and not self._is_loopback_client():
            return self._json(403, {"error": "CyberGuard API is restricted to local clients"})
        prefix, suffix = "/api/incidents/", "/status"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return self._json(404, {"error": "Endpoint not found"})
        incident_id = path[len(prefix):-len(suffix)].strip("/")
        if not incident_id or "/" in incident_id:
            return self._json(404, {"error": "Incident not found"})
        try:
            payload = self._body()
            incident = self.application.incidents.update_status(incident_id, payload.get("status"), payload.get("resolution_note"))
            if incident is None:
                return self._json(404, {"error": "Incident not found"})
            return self._json(200, {"incident": incident})
        except ValueError as error:
            return self._json(400, {"error": str(error)})
        except Exception:
            return self._json(500, {"error": "Unable to update incident"})


def create_server(host: str = "127.0.0.1", port: int = 8000,
                  application: CyberGuardApplication | None = None) -> ThreadingHTTPServer:
    """Create a server with an explicitly injected application instance."""
    server = ThreadingHTTPServer((host, port), CyberGuardHandler)
    server.application = application or create_application()
    return server


if __name__ == "__main__":
    host = os.environ.get("CYBERGUARD_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("CYBERGUARD_PORT", "8000"))
    except ValueError as error:
        raise SystemExit("CYBERGUARD_PORT must be an integer between 1 and 65535") from error
    if not 1 <= port <= 65535:
        raise SystemExit("CYBERGUARD_PORT must be an integer between 1 and 65535")
    application = create_application()
    server = create_server(host, port, application)
    print(f"Serving CyberGuard on {host}:{port} (open http://localhost:{port}/ in your browser)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CyberGuard...")
    finally:
        server.server_close()
        application.close()
