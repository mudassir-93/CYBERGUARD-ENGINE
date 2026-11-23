# Threat Intelligence and Incident Investigation

CyberGuard includes a local SQLite indicator catalog. Import IP, domain, MD5, SHA-1, and SHA-256 indicators explicitly as JSON. Each item supports source attribution, confidence (0-100), severity, description, tags, first/last-seen timestamps, and optional expiry. Imports are idempotent per type/value/source. Expired indicators are excluded. The application does not fetch feeds, resolve domains, or call paid reputation services.

API:
- `POST /api/threat-intel/import` — JSON body `{ "indicators": [...] }`, up to 5,000 records.
- `GET /api/threat-intel?type=ip&limit=100` — list active indicators.
- `GET /api/incidents/{id}` — incident evidence, timeline, exact-match `threat_intel_matches`, and `analyst_notes`.
- `POST /api/incidents/{id}/notes` — append `{ "note": "...", "author": "..." }`.

Matches compare source/destination IPs and explicit domain/hash fields in evidence. A match is enrichment, not proof of compromise. No match triggers blocking. Writes are loopback-client restricted; the unauthenticated API must remain bound to 127.0.0.1.

## Explainable anomaly baseline

`backend/ml_anomaly.py` trains a dependency-free median/MAD baseline from trusted CSV telemetry. Columns: `packet_rate`, `distinct_ports`, `failed_attempts`, `bytes_per_second`, `destination_fanout`. At least 20 trusted baseline rows are required.

```powershell
python backend/ml_anomaly.py path\to\trusted-baseline.csv --output data\anomaly-baseline.json
```

Use `score_features(features, model)` to get an anomaly flag, heuristic score, and per-feature explanations. This is a statistical baseline, not a calibrated probability, supervised classifier, or production verdict. It is not connected to automatic severity changes or response. Train and validate with representative local data before operational use.

Automated feed polling/TAXII, domain resolution, production ML calibration, tenant isolation, analyst authentication, and automated response remain out of scope.
