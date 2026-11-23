# CyberGuard Engine — Upgrade Plan

**Status:** Traffic & Flow Engine v1, simulator integration, deterministic scenarios, and first port-scan heuristic implemented; cross-platform CI verification in progress.  
**Product direction:** AI-powered network security platform.  
**Initial environment:** Local network simulator and safe, reproducible attack scenarios.  
**Baseline branch:** `master`  
**Planning branch:** `research/cyberguard-upgrade-plan`

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

## 3. Repository baseline — findings from current master

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

### Confirmed architectural limitations

1. The native C++ simulation and browser dashboard are separate simulations with independent state.
2. The native engine models packets and devices in memory; it does not capture or send real network traffic.
3. The current model is packet-centric. ML-based network detection will need time-windowed flow aggregation and a stable feature schema.
4. Threat generation, detection, incidents, response, and AI functionality are not implemented.
5. The Python backend currently only serves static files; it is not an application API.
6. CMake downloads GoogleTest through FetchContent during test-enabled configuration.
7. The Python server binds to `0.0.0.0:8000`; before adding any API or sensitive data, local-development binding and safe deployment defaults must be reviewed.
8. The README uses a project-educational license badge, but repository metadata reports no declared license. Do not claim an open-source license until the owner chooses one.
9. A tracked `backend/__pycache__` directory appears in the repository listing. Its exact contents and impact must be reviewed before any cleanup.
10. Existing documentation and recorded test results are useful baseline evidence, but all tests must be rerun on the working environment before treating the current state as verified.

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

### Phase 0 — Planning and baseline
- Complete repository inventory and architecture review.
- Confirm build/test workflow and record baseline results.
- Define product requirements, data contracts, security boundaries, and acceptance criteria.
- No feature implementation until the owner asks to begin.

**Exit gate:** owner approves the implementation plan and first milestone.

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
- [ ] Traffic & Flow Engine v1 implementation and cross-platform CI validation.

The owner has explicitly asked to start the work. The first implementation milestone is baseline hardening: add regression coverage and fix the existing simulator and local-development safety issues before introducing flow aggregation, ML, or AI.

**Current CI run:** [CyberGuard CI run 1](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45159669668) — pending completion at the time this document was updated.

**Important:** The application source code and runtime behavior have not yet been changed. The upgrade branch currently contains planning/audit documentation and a CI workflow. No files have been deleted and `master` remains untouched.


## 11. Traffic & Flow Engine v1 (in progress)

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

Acceptance is pending hosted Linux and Windows CI for commit df1794c and the follow-up verification commit. No real network capture or live traffic generation is enabled.
