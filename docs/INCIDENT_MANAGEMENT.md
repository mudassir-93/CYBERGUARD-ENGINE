# Incident Management v1

## Start
Run `python backend/server.py` and open http://127.0.0.1:8000. The service binds to loopback by default. SQLite is created at `data/incidents.sqlite3`; set `CYBERGUARD_DATA_DIR` to select another local directory.

## API
- `GET /api/health` — local API health.
- `GET /api/incidents` — incident list and summary; optional `status`, `severity`, and `limit` (1–200).
- `GET /api/incidents/{id}` — evidence and audit timeline.
- `POST /api/detections` — validate and ingest a detection event.
- `PATCH /api/incidents/{id}/status` — analyst status update.

Detection example:
```json
{"type":"brute_force","source_ip":"10.0.0.21","destination_ip":"10.0.0.10","destination_port":22,"protocol":"TCP","summary":"Repeated failed connection attempts","evidence":{"failed_attempts":8,"window_seconds":60}}
```
Supported types: `port_scan`, `brute_force`, `dos`, `lateral_movement`. Severity and initial risk scores are deterministic starter defaults, not calibrated probabilities.

## Correlation and lifecycle
Active incidents are correlated by type, source, destination, destination port, and protocol. A match increments occurrence count, updates last-seen, retains the latest 100 evidence observations, and adds an audit event. A closed incident does not absorb new detections.

- New → Acknowledged / Investigating / Resolved / False positive
- Acknowledged → Investigating / Resolved / False positive
- Investigating → Acknowledged / Resolved / False positive
- Resolved or False positive → New (explicit reopen)

No automated blocking or response action is performed.

## Safety and limitations
Request bodies are capped at 1 MB and evidence at 16 KB. IP, type, protocol, port, timestamp, and evidence shape are validated. Evidence is rendered as text in the dashboard. Do not expose this unauthenticated local API publicly without authentication, authorization, TLS, and deployment hardening. The dashboard demo sends normalized local sample detections. Native C++ detector output is not yet automatically bridged to the Python API. User/tenant isolation, RBAC, analyst identities, notifications, retention policies, and multi-user deployment are not included.
