# CyberGuard Engine — Upgrade Plan

**Status:** The initial platform foundations are merged through PR #1 (merge commit `022b310a110794005a1b6cf5e71a6a452c5d9328`). CLI/Ollama readiness is merged through PR #2 (merge commit `34b7fa200526759fa6e1c49d381b433cc5b1e50a`); its post-merge Ubuntu/Windows CI passed in run [45307030414](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45307030414). Leakage-aware ML evaluation is merged through PR #3 (merge commit `6ff5369a1f174e6f45ac58c8d5caf388a089385e`); post-merge CI run [45307730613](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45307730613) is currently running. The next owner-PC readiness milestone is being developed on `feature/windows-verification-and-docs`.  
**Product direction:** AI-powered network security platform.  
**Initial environment:** Local network simulator and safe, reproducible attack scenarios.  
**Baseline branch:** `master`  
**Current implementation branch:** `feature/windows-verification-and-docs`

## 1. Product vision

Evolve the existing educational C++ network simulator into **CyberGuard Lab**, an AI-assisted network threat detection and investigation platform. The first release will operate entirely against a local simulated network. It will detect suspicious behavior, preserve evidence, create incidents, enrich indicators with optional public threat intelligence, and provide an AI analyst that explains findings.

The long-term path is **CyberGuard Monitor**, which may later ingest telemetry from authorized real networks through adapters such as Zeek or Suricata. Real-network monitoring is explicitly out of scope for the first implementation stage.

### Product positioning

> An AI-assisted network threat detection and investigation platform. Understand your network, detect suspicious behavior, and investigate threats intelligently.

## 2. Scope boundaries

### In scope for the first product stage

- Preserve and extend the existing C++20 network simulator.
- Build a reproducible local traffic and threat-scenario engine.
- Aggregate packets into network-flow records suitable for detection.
- Add deterministic detection rules and explainable risk scoring.
- Add a Python security-analysis service for ML experiments and optional enrichment.
- Add incident lifecycle and evidence records.
- Add an optional local Ollama-powered AI analyst for explanation and investigation.
- Connect the dashboard to one authoritative simulation/security state.
- Provide tests, setup instructions, evaluation reports, and a clear CLI experience.

### Explicitly out of scope initially

- Capturing or generating attacks against real networks or third-party systems.
- Autonomous firewall changes, device blocking, or other disruptive response.
- Full antivirus, EDR, full SIEM, IPS, or enterprise SOC replacement.
- Cloud-hosted paid LLM inference as a required dependency.
- Kubernetes, Kafka, Redis, multiple microservices, or unnecessary infrastructure.
- Mandatory biometric, endpoint, transport, or unrelated ERP functionality.

All attack-like behavior in the initial release must remain inside the local simulator and be safe, bounded, and reproducible.

## 3. Current branch baseline — verified implementation state

The repository is a small C++20/CMake project with a separate browser simulation.

### Existing components

- `include/core/`: `NetworkDevice.hpp`, `Network.hpp`, `Packet.hpp`.
- `include/devices/`: `Router.hpp`, `Firewall.hpp`, `Server.hpp`, `Workstation.hpp`.
- `src/core/`: network and packet implementations.
- `src/devices/`: router, firewall, server, and workstation implementations.
- `src/main.cpp`: native console demonstration.
- `tests/`: smoke test and GoogleTest suites for current network behavior.
- `backend/server.py`: Python static-file server.
- Root `index.html`, `app.js`, and `dashboard.css`: primary browser dashboard.
- `web/`: legacy/duplicate browser assets.
- `docs/`: architecture, development process, and OOP documentation.

### Confirmed architectural limitations and current capabilities

1. The native C++ simulation and browser dashboard remain separate simulations with independent state.
2. The C++ engine is an in-memory simulator; it does not send network traffic. Optional live monitoring is a separate passive IPv4 metadata sensor.
3. The native engine has bidirectional flow aggregation and bounded deterministic scenarios/detections. The live sensor has narrower metadata-only heuristics and does not inspect payloads, process identity, or authentication outcomes.
4. The Python backend is an application/API layer with SQLite incident management, IOC enrichment, analyst notes, anomaly scoring, and a native simulator bridge; it is no longer a static-file server only.
5. The browser dashboard is organized into five feature controllers. The guided local CLI and optional Ollama analyst are covered by the latest green cross-platform CI run.
6. Cross-platform CI run [45303756562](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45303756562) passed on Ubuntu and Windows, including C++ build/tests, Python syntax/tests, JavaScript syntax, and C++-to-SQLite integration.
7. The API enforces loopback-only access and has no user authentication or authorization. It is not suitable for remote or multi-user deployment.
8. The Isolation Forest and robust baseline are experimental. Their scores are not calibrated probabilities and have not been validated against representative labeled network traffic.
9. External threat-feed polling, TAXII, autonomous AI actions, production deployment, and automated response/blocking are not implemented. A read-only local Ollama incident explanation adapter is now implemented; see docs/LOCAL_AI_ANALYST.md.
10. Physical live capture still depends on host-specific Scapy/Npcap or libpcap installation, supported interfaces, and capture permissions; this requires testing on the user's Windows machine.

### Preserve before changing

- Keep the current C++ core and its public behavior wherever practical.
- Keep the existing dashboard available during the transition.
- Add new behavior incrementally behind clear interfaces.
- Do not delete legacy assets, tracked files, or existing features without reviewing usage and getting owner approval.
- Record the original baseline commit and compare every implementation branch against it.

## 4. Target architecture

Start with a simple modular, local-first architecture — not a fleet of microservices.

```text
CyberGuard Lab
|
+-- C++20 Simulation Core
|   +-- Network devices and packet lifecycle
|   +-- Traffic generator
|   +-- Flow aggregation / observation windows
|   +-- Safe attack-scenario simulator
|   +-- Structured event and flow export
|
+-- Python Security Service
|   +-- Event ingestion and validation
|   +-- Rule-based detection
|   +-- ML inference and evaluation
|   +-- Risk scoring and evidence correlation
|   +-- Incident management
|   +-- Threat-intelligence cache/adapters
|   +-- Local AI analyst (Ollama, optional)
|
+-- SQLite persistence
|
+-- Dashboard + user-friendly CLI
    +-- Overview / topology
    +-- Traffic and detections
    +-- Incidents and investigation
    +-- Threat intelligence
    +-- ML Lab / model evaluation
    +-- Scenario runner and settings
```

### Technology direction

| Layer | Initial choice | Reason |
|---|---|---|
| Simulation and deterministic core | Existing C++20 | Preserve project foundation and performance |
| Service/API | Python + FastAPI | Simple integration boundary and ML ecosystem |
| ML baseline | scikit-learn | Lightweight, explainable experiments |
| Additional model benchmark | XGBoost, only if useful | Compare against a strong tree-based baseline |
| Persistence | SQLite | Zero-admin local storage |
| Local AI | Ollama | Avoid mandatory per-call cloud inference costs |
| Dashboard | Evolve existing HTML/CSS/JS | Avoid an unnecessary frontend rewrite |
| CLI | Python CLI or C++ CLI enhancement, selected after UX review | Clear guided user workflow |
| Tests | GoogleTest + pytest + API/integration tests | Match each layer |
| Future telemetry adapters | Zeek / Suricata | Optional real-network data ingestion later |

Do not add Redis, Kafka, Docker, Kubernetes, LangGraph, or other infrastructure unless a demonstrated requirement justifies it.

## 5. Detection and data strategy

### Detection layers

1. **Deterministic rules first:** transparent rules for port scans, repeated connection failures, unusual traffic volume, and suspicious internal patterns.
2. **ML classification experiments:** compare Logistic Regression baseline, Random Forest, and optionally XGBoost for benign/malicious and attack-category classification.
3. **Anomaly detection:** evaluate Isolation Forest as a separate signal. An anomaly is not automatically proof of an attack.
4. **Evidence correlation:** combine observations into a risk score and incident with explainable reasons.
5. **AI analyst:** summarize and investigate recorded evidence; it must not be the authoritative detection engine.

### Candidate datasets

- **UNSW-NB15** — primary initial benchmark candidate: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **CIC-IDS2017** — secondary independent benchmark: https://www.unb.ca/cic/datasets/ids-2017.html
- **CSE-CIC-IDS2018** — possible later validation dataset after confirming access, format, and licensing terms.

Before downloading or training, verify current dataset access, terms, data size, label quality, feature definitions, and redistribution constraints. Do not commit large datasets or trained model binaries to the Git repository.

### Feature and evaluation rules

- Define a versioned flow schema before training or inference.
- Aggregate packet observations into time-windowed flows.
- Align simulator features with dataset features explicitly; never assume packet fields can be fed directly into a benchmark model.
- Prevent train/test leakage; split by capture/time/source where feasible.
- Handle class imbalance and duplicates.
- Evaluate precision, recall, F1, confusion matrix, false-positive rate, false-negative rate, and inference latency — not accuracy alone.
- Report cross-dataset performance and simulator-generated scenario performance separately.
- Treat benchmark performance as experimental evidence, not proof of production-grade detection.

### Initial local scenarios

- Port-scan behavior.
- Repeated authentication/connection failures (simulated brute-force pattern).
- High-volume DoS/DDoS-like traffic within bounded simulation limits.
- Unusual internal host-to-host communication.
- Normal baseline traffic to measure false positives.

Each scenario must have deterministic configuration, ground-truth labels, reproducible seeds where practical, and automated tests. No real attack traffic is required.

## 6. Threat intelligence and AI safety

### Optional public/community intelligence sources

Potential adapters to evaluate — not mandatory dependencies:

- ThreatFox: https://threatfox.abuse.ch/api/
- URLhaus: https://urlhaus.abuse.ch/api/
- MalwareBazaar: https://bazaar.abuse.ch/
- AlienVault OTX: https://otx.alienvault.com/api
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Check current API access, rate limits, authentication, attribution, commercial-use terms, and redistribution rights before integration. Prefer scheduled feed ingestion and local caching over repeated live lookups. A free API is not automatically unrestricted for commercial use.

### AI analyst guardrails

- Prefer Ollama/local inference; core product functionality must remain useful when no LLM is installed.
- AI receives structured incident evidence and uses a small allowlisted set of read-only/proposal tools.
- Treat packet payloads, logs, hostnames, and other ingested text as untrusted data, never as agent instructions.
- AI may explain, summarize, investigate, and propose defensive actions.
- AI must not run arbitrary shell commands or autonomously block hosts/change firewall rules.
- Any future active response must be deterministic, permission-checked, auditable, and require explicit human approval.

## 7. Delivery roadmap and gates

### Phase 0 — Planning and baseline (completed)
- Repository inventory, architecture review, baseline CI, product requirements, data contracts, and security boundaries were recorded.
- The owner approved implementation and authorized safe PR-based integration with recovery snapshots.

**Exit gate:** completed; implementation is underway in focused feature branches.

### Phase 1 — Simulation foundation
- Add traffic generation and flow aggregation.
- Define versioned event/flow JSON schema.
- Add reproducible normal and threat scenarios.
- Keep old packet-routing behavior working.

**Exit gate:** C++ tests pass; scenario output is deterministic and schema-validated.

### Phase 2 — Detection foundation
- Add Python service and validated event ingestion.
- Implement rule-based detections and evidence records.
- Add incident lifecycle and SQLite persistence.
- Add API and integration tests.

**Exit gate:** end-to-end simulated scenarios create correct, explainable incidents with normal traffic false-positive checks.

### Phase 3 — ML Lab
- Build reproducible dataset preparation and training pipeline.
- Establish baseline metrics and model comparison.
- Version feature schema, preprocessing, model artifacts, and evaluation reports.
- Integrate ML inference as an optional detection signal.

**Exit gate:** independent evaluation report with leakage checks, precision/recall/F1, false-positive analysis, and latency.

### Phase 4 — Threat intelligence
- Implement provider adapters behind a common interface.
- Add local cache, source attribution, timestamps, expiry, and rate-limit handling.
- Keep the system functional when providers are unavailable.

**Exit gate:** tests use mocked providers; no API key is required for core simulator operation.

### Phase 5 — AI analyst
- Add Ollama integration and structured outputs/tool calling where supported.
- Implement read-only investigation tools and report generation.
- Add prompt-injection and untrusted-evidence tests.
- Provide graceful fallback when Ollama/model is unavailable.

**Exit gate:** AI cannot change network state; every explanation links back to evidence.

### Phase 6 — Product UX
- Connect dashboard to the authoritative backend state.
- Add guided CLI setup, scenario execution, incident inspection, and health checks.
- Improve installation, configuration, logs, and troubleshooting.
- Remove duplicated behavior only after parity and approval.

**Exit gate:** a new user can install, launch, run a scenario, and inspect an incident using documented steps.

### Phase 7 — Release hardening
- CI for C++ and Python tests, linting, and build checks.
- Dependency/license/security review.
- Windows-first local install validation, then other platforms if required.
- Release documentation, known limitations, and versioned artifacts.

**Exit gate:** clean CI, repeatable install, documented limitations, and owner approval.

### Future Phase 8 — Authorized real-network integrations
- Evaluate Zeek and Suricata ingestion formats.
- Build a separate telemetry adapter boundary.
- Require explicit operator configuration and authorization.
- Keep detection and incident pipeline reusable.
- Do not enable packet capture or active response by default.

## 8. Quality and release principles

- No merge to `master` without review and green required checks.
- Keep feature branches focused and use pull requests for meaningful milestones.
- Preserve existing tests and add regression tests for changed behavior.
- Never claim a test passed unless it actually ran and its result was inspected.
- No secrets, API keys, datasets, local logs, or generated binaries committed.
- Pin or constrain dependencies and document installation.
- Use secure defaults; local services should bind to loopback unless the operator explicitly configures otherwise.
- Document telemetry collection, data retention, privacy, and limitations before any real-network support.
- Keep the CLI understandable: clear commands, useful errors, progress feedback, and safe defaults.

## 9. Owner decisions and approval points

The owner has already selected:
- Product direction: AI-powered Network Security Platform.
- Initial environment: local network simulator first, real network integrations later.
- Cost preference: prioritize free/open-source tools and local inference.

Owner approval is still required before:
- Any destructive cleanup or removal of existing functionality.
- Choosing a software license.
- Adding real-network capture or integrations.
- Enabling active response or automated blocking.
- Adding paid services or recurring infrastructure costs.
- Merging implementation work into `master`.

## 10. Current execution status

- [x] Repository metadata and default branch inspected.
- [x] Existing source tree, CMake configuration, tests, and primary documentation inspected.
- [x] Existing C++/dashboard separation confirmed from source and documentation.
- [x] Planning branch created from current `master`.
- [x] Static baseline audit recorded in [docs/BASELINE_AUDIT.md](BASELINE_AUDIT.md).
- [x] Cross-platform baseline CI workflow added at `.github/workflows/ci.yml`.
- [x] Hosted Linux and Windows CI run completed and reviewed for the baseline-hardening batch.
- [x] Baseline hardening batch passed hosted Linux and Windows CI (15 C++ tests plus Python/JavaScript syntax checks).
- [x] First hardening milestone committed on the isolated implementation branch.
- [x] Traffic & Flow Engine v1 implementation and cross-platform CI validation (Linux and Windows, 25/25 C++ tests each).

The owner explicitly approved implementation and authorized safe PR merges with rollback preparation. The initial 214-commit upgrade branch was integrated through PR #1 into `master`; the post-merge CI run [45304372340](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45304372340) passed both Ubuntu and Windows jobs. Recovery snapshots are preserved as `safety/pre-integration-master-2026-11-24` and `safety/pre-integration-research-2026-11-24`. Follow-up work has dated recovery snapshots: `safety/pre-cli-doctor-2026-11-24`, `safety/pre-ml-evaluation-2026-11-24`, and `safety/pre-windows-verify-v2-2026-11-24`. Physical Windows Npcap capture and real Ollama inference still require owner-PC verification.


## 11. Traffic & Flow Engine v1 (completed)

The next milestone adds a standalone C++ flow aggregation layer without changing packet routing semantics.

- Bidirectional five-tuple identity: protocol plus two canonical IPv4/port endpoints.
- Aggregate packet/byte totals and canonical A-to-B / B-to-A counters.
- Track first/last observed timestamps and calculate duration and rates.
- Count delivered, blocked, and dropped packet outcomes.
- Keep the flow manager independent of Network; callers observe packets after routing.
- Document the version-1 feature contract in docs/FLOW_SCHEMA.md.
- Defer flow expiry, TCP lifecycle tracking, payload parsing, and real packet capture.

Acceptance: regression tests cover reverse-direction aggregation, port/protocol separation, outcome counts, out-of-order timestamps, zero-duration rates, and clear/reset behavior. Linux and Windows CI must pass before the milestone is marked complete.


## 12. Traffic monitoring and first detection milestone

Implemented on the development branch:
- Network records every routed packet in its FlowManager after the final outcome is known.
- Added deterministic normal-traffic and sequential port-scan scenario generation.
- Added configurable port-scan detection (default: 10 distinct destination ports within 60 timestamp-seconds).
- Native CLI demo now runs both scenarios and prints flow totals and alerts.
- Added integration, detector, scenario, and invalid-input regression tests.
- Added docs/TRAFFIC_DETECTION.md and updated README usage/status.

Acceptance passed hosted Linux and Windows CI: 25/25 C++ tests on each platform, plus Python and JavaScript syntax checks. No real network capture or live traffic generation is enabled.


## 13. Multi-pattern threat detection milestone (implemented; cross-platform CI passed)

Added deterministic, explainable detection over the existing in-memory flow records:

- Repeated failed-connection / brute-force pattern: default 5 failed or dropped attempts to one service within 60 timestamp-seconds.
- DoS-like high-volume traffic: default 100 packets from one source to one destination within 10 timestamp-seconds.
- Suspicious internal host fan-out: default 3 distinct RFC1918 private IPv4 destinations from one source within 60 timestamp-seconds.
- Added bounded deterministic scenario generators for each pattern. Generators are limited to 10,000 packets/attempts and 100 lateral destinations.
- Expanded native CLI demo, regression tests, and traffic-detection documentation.

These are initial heuristics, not authentication-aware or payload-aware detection. They do not establish that an account or host is compromised. All scenarios remain in-memory simulator packets and open no sockets.

**Latest implementation CI:** hosted Linux and Windows checks passed in run [45303756562](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45303756562). The milestone is integrated into `master` through PR #1.


## 15. Incident management v1 implementation status
- [x] SQLite incident repository and schema.
- [x] Validated detection ingestion and exact-key correlation.
- [x] Bounded evidence observations and audit history.
- [x] Incident lifecycle and summary/filter APIs.
- [x] Local dashboard incident queue, evidence/timeline inspection, demo detections, and status controls.
- [x] Python unit and API integration tests added to CI.
- [x] Consolidated Linux/Windows CI verification for this milestone (see latest Actions result before release).


## 16. Threat intelligence and investigation milestone

Implemented on the isolated development branch:
- SQLite-backed indicator catalog for IP, domain, MD5, SHA-1, and SHA-256 indicators.
- Source attribution, confidence, severity, tags, first/last-seen metadata, expiry, and idempotent imports.
- Explicit JSON import API and dashboard panel; no automatic network feed polling or paid reputation calls.
- Exact-match incident enrichment for source/destination IPs and explicit domain/hash evidence fields.
- Append-only analyst notes associated with an incident and included in incident detail.
- Dashboard note entry and expanded evidence inspection showing timeline, IOC matches, and notes.
- Loopback-client checks for indicator imports and note writes.
- Unit and API integration tests for validation, expiry, matching, note persistence, and remote-write rejection.

IOC matches are contextual enrichment, not proof of compromise, and never trigger automated blocking.

## 17. Explainable anomaly-baseline milestone

Implemented a dependency-free median/MAD baseline plus an optional scikit-learn Isolation Forest trainer/scorer for packet rate, distinct ports, failed attempts, bytes per second, and destination fan-out. Isolation Forest training requires at least 50 trusted baseline observations and produces a local joblib model artifact with per-feature context. The robust baseline and Isolation Forest score are not calibrated probabilities or production verdicts; neither is wired to automatic severity changes or response. Unit tests cover training limits, scoring, explanations, and invalid values.

**Latest validation:** Run [45303756562](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45303756562) passed on Ubuntu and Windows with the optional ML dependency, Python tests, syntax checks, and integration. Physical Npcap adapter capture and anomaly quality on representative network data still require local validation.


## 18. Optional local AI incident analyst milestone (implemented; cross-platform CI passed)

Added an optional Ollama-backed, read-only explanation workflow for persisted incidents.

- Added `backend/ai_analyst.py`, a standard-library client for the local Ollama chat API.
- The configured endpoint must be HTTP on a loopback host; remote URLs, embedded credentials, and URL paths are rejected.
- Incident context is restricted to an allowlist of persisted fields and bounded to 24 KB.
- The system prompt treats evidence, notes, hostnames, and logs as untrusted data, requests confidence/limitations, and prohibits shell commands, automatic blocking, or state changes.
- Wired the analyst into the application composition root and added loopback-only `POST /api/analyst/explain`.
- Added CLI `explain <incident_id>` and interactive menu option 7.
- Added unit, CLI, and API tests for prompt construction, data bounds, loopback validation, missing incidents, offline Ollama behavior, and advisory output.
- Added setup and safety documentation in `docs/LOCAL_AI_ANALYST.md`.
- No Python Ollama package, cloud API key, or paid inference service is required.

**Validation:** Cross-platform CI run [45303756562](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45303756562) passed on Linux and Windows. Actual model inference still requires the owner to install Ollama and pull a local model on the target PC. The AI explanation is advisory and is not a detection verdict.


## 19. CLI local-readiness diagnostics (completed; merged through PR #2)

The guided `doctor` command is being extended to diagnose the optional local AI analyst without making Ollama a required dependency.

- `OllamaAnalyst.diagnose()` performs a bounded GET to the configured loopback-only Ollama `/api/tags` endpoint.
- It distinguishes an unavailable local service, an unexpected response, a missing configured model, and a ready model.
- Missing Ollama or a missing model remains an optional capability warning; the rest of CyberGuard remains usable.
- `cyberguard doctor` reports the local AI status and provides the exact `ollama pull <model>` command when the model is missing.
- Unit tests cover ready, missing-model, and unavailable-service cases; CLI tests ensure the optional dependency does not make doctor fail.

**Validation:** PR CI run [45306544059](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45306544059) passed on Ubuntu and Windows. The merge commit's post-merge CI run [45307030414](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45307030414) also passed both platforms. Actual Ollama inference and Npcap capture remain PC-specific checks.


## 20. Leakage-aware ML evaluation workflow (implemented; merged through PR #3)

Added a reproducible binary evaluation path for the optional Isolation Forest:

- Reads the versioned five-feature flow CSV plus ground-truth label and capture/session group columns.
- Requires both benign and malicious observations and validates every feature value; malformed rows fail closed.
- Splits by whole capture/session groups, never by individual rows, and refuses to fall back to a leakage-prone random row split.
- Trains the anomaly model only on benign training observations and evaluates once on held-out groups.
- Reports accuracy, balanced accuracy, malicious precision/recall/F1, benign specificity, false-positive/negative rates, confusion matrix, sample/group counts, and mean/p95 inference latency.
- Writes a JSON report atomically and keeps datasets/model artifacts out of the repository.
- Documents dataset, label, grouping, contamination, and interpretation requirements in [docs/ML_EVALUATION.md](ML_EVALUATION.md).

**Validation:** PR CI run [45307123845](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45307123845) passed on Ubuntu and Windows, including the full Python suite and C++/SQLite integration. The merge commit is `6ff5369a1f174e6f45ac58c8d5caf388a089385e`; its post-merge run [45307730613](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45307730613) is running. No benchmark dataset is bundled, and no performance claim is made until the owner supplies a properly licensed, representative dataset.

## 21. Windows owner verification workflow (implementation in progress)

Add a safe, repeatable PowerShell entry point for validating CyberGuard on the owner's Windows PC:

- Detect required local tools and reuse the existing CMake generator, with an explicit generator override for a fresh build directory.
- Build the native C++20 target and run CTest.
- Compile Python sources and run the full backend unit suite.
- Check dashboard JavaScript syntax when Node.js is installed.
- Run simulator-to-SQLite integration and CLI doctor using an isolated temporary data directory; preserve the owner's normal incident database.
- Never install software, enable packet capture, change firewall rules, or perform active response automatically.

**Validation gate:** PowerShell syntax check on hosted Windows CI; cross-platform project CI green; owner runs the script on the target PC. Physical Npcap and Ollama checks remain separate opt-in validation.