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

## Native simulator integration

The native executable supports `--jsonl`, emitting one structured JSON detection per line. `backend/simulation_bridge.py` runs that executable and ingests the resulting events through the same validated SQLite incident store. The dashboard's **Run C++ simulation** action invokes this bridge through `POST /api/simulate`.

The executable is discovered in common CMake build locations; set `CYBERGUARD_EXECUTABLE` or pass `--executable` to override it. The bridge uses a 60-second process timeout. The current native demo emits port-scan, brute-force-pattern, DoS-like, and lateral-movement events from deterministic in-memory scenarios. Simulator timestamps are relative ticks, so incident observation times are assigned at ingestion. This is a local process integration, not a live network sensor.

## Safety and limitations
Request bodies are capped at 1 MB and evidence at 16 KB. IP, type, protocol, port, timestamp, and evidence shape are validated. Evidence is rendered as text in the dashboard. Do not expose this unauthenticated local API publicly without authentication, authorization, TLS, and deployment hardening. The dashboard retains a separate normalized sample-detection demo for UI exploration. User/tenant isolation, RBAC, analyst identities, notifications, retention policies, and multi-user deployment are not included.
