# Threat Intelligence and Incident Investigation

CyberGuard includes a local SQLite indicator catalog. Import IP, domain, MD5, SHA-1, and SHA-256 indicators explicitly as JSON. Each item supports source attribution, confidence (0-100), severity, description, tags, first/last-seen timestamps, and optional expiry. Imports are idempotent per type/value/source. Expired indicators are excluded. The application does not resolve domains or call paid reputation services. An explicit, read-only ThreatFox community-feed sync is available; no feed polling or background network activity occurs unless an operator invokes it.

API:
- `POST /api/threat-intel/import` — JSON body `{ "indicators": [...] }`, up to 5,000 records.
- `GET /api/threat-intel?type=ip&limit=100` — list active indicators.\n- `POST /api/threat-intel/sync` — explicitly fetch recent ThreatFox IOCs and import supported public IP/domain records. JSON body: `{ "days": 3 }` (1–7).
- `GET /api/incidents/{id}` — incident evidence, timeline, exact-match `threat_intel_matches`, and `analyst_notes`.
- `POST /api/incidents/{id}/notes` — append `{ "note": "...", "author": "..." }`.

Set `CYBERGUARD_THREATFOX_API_KEY` to an Auth-Key obtained from the [ThreatFox authentication portal](https://auth.abuse.ch/) before calling the sync endpoint. The adapter uses the documented `get_iocs` API, enforces a 20-second timeout and 5 MB response cap, accepts at most 5,000 rows, keeps only normalized public IP/domain indicators, and skips unsupported or malformed records. Sync is manual, local-loopback-only, and idempotent through the existing `(type, value, source)` database key. No indicator triggers blocking. ThreatFox community access follows its fair-use policy; commercial use may require the enhanced API. See the [ThreatFox API documentation](https://threatfox.abuse.ch/api/).\n\nMatches compare source/destination IPs and explicit domain/hash fields in evidence. A match is enrichment, not proof of compromise. No match triggers blocking. All API routes (reads and writes) reject non-loopback clients, even if the server is accidentally bound to a public interface. This is a local-use boundary, not user authentication.

## Explainable anomaly baseline

`backend/ml_anomaly.py` trains a dependency-free median/MAD baseline from trusted CSV telemetry. Columns: `packet_rate`, `distinct_ports`, `failed_attempts`, `bytes_per_second`, `destination_fanout`. At least 20 trusted baseline rows are required.

```powershell
python backend/ml_anomaly.py path\to\trusted-baseline.csv --output data\anomaly-baseline.json
```

Use `score_features(features, model)` to get an anomaly flag, heuristic score, and per-feature explanations. This is a statistical baseline, not a calibrated probability, supervised classifier, or production verdict. It is not connected to automatic severity changes or response. Train and validate with representative local data before operational use.

Automated feed polling/TAXII, domain resolution, production ML calibration, tenant isolation, analyst authentication, and automated response remain out of scope.


## Optional Isolation Forest model

The optional scikit-learn pipeline provides an actual unsupervised model in addition to the dependency-free robust baseline. Install it only when you want to train or score models:

```powershell
python -m pip install -r requirements-ml.txt
python backend/ml_isolation_forest.py path\to\trusted-baseline.csv --output data\isolation-forest.joblib
```

The CSV uses the same five numeric telemetry columns. Training requires at least 50 trusted baseline observations. Python code can use `load_model(path)` and `score_observation(features, model)`. The result includes the Isolation Forest decision value and robust per-feature context. The numeric score is not a calibrated probability. Treat model artifacts as trusted local files because joblib uses Python object serialization. CI installs the optional ML dependency and tests the training/scoring pipeline on Ubuntu and Windows.

## Dashboard Isolation Forest scoring API

After installing `requirements-ml.txt` and training a trusted local model, configure the server before startup:

```powershell
$env:CYBERGUARD_ANOMALY_MODEL = (Resolve-Path .\data\isolation-forest.joblib).Path
python backend/server.py
```

The dashboard's Telemetry Anomaly Scoring panel sends a JSON object containing a `features` object to `POST /api/anomaly/score`. The server loads and caches the configured local model. Restart the server after replacing the model artifact. The endpoint is loopback-only like every other API route. Model files must be trusted; do not load artifacts from untrusted sources. A missing model returns HTTP 503 rather than silently falling back to a different detector.
