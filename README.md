# CyberGuard Engine

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://isocpp.org/)
[![CMake](https://img.shields.io/badge/CMake-3.20%2B-064F8C.svg)](https://cmake.org/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Local%20Simulation-success.svg)](https://github.com/mudassir-93/CYBERGUARD-ENGINE)
[![License](https://img.shields.io/badge/License-Not%20specified-lightgrey.svg)](https://github.com/mudassir-93/CYBERGUARD-ENGINE)

CyberGuard Engine is an educational, local-first network-security workspace built around a C++20 network simulator. It models packet routing and firewall enforcement, aggregates network flows, generates bounded threat scenarios, and runs explainable detection heuristics. An optional Python sensor can passively capture IPv4 packet metadata from a selected local interface.

This project is intended for learning, demonstration, and academic review. The simulator does not send real traffic. Optional live monitoring passively reads packet metadata from a selected interface; it does not modify or block traffic. The application is designed to run locally.

## Overview

The local application is composed of these components:

- A native C++ simulation for the network model, packet logic, and device behavior
- A browser dashboard for simulated topology, counters, firewall rules, and incident investigation
- A guided Python CLI for local setup checks, simulation runs, and incident workflows
- A one-command Windows verification script for the native build, C++/Python tests, dashboard syntax, and simulator-to-SQLite integration
- An object-oriented Python application layer that composes repositories, monitoring, simulation, and anomaly-analysis services
- An optional Python packet sensor for passive IPv4 metadata capture

The browser dashboard is served by a local Python API. It can display persisted incidents, invoke the native C++ simulator through a structured local process bridge, and optionally capture passive packet metadata from a selected local interface.

## What the project does

- Creates and validates packet objects
- Simulates source and destination device routing
- Models router and firewall behavior
- Tracks packet states such as created, routing, blocked, delivered, and dropped
- Uses ordered firewall rules to allow or deny traffic based on protocol and port
- Shows a live-style topology dashboard in the browser
- Aggregates packets into bidirectional five-tuple network flows
- Generates local-only normal, port-scan, brute-force, DoS-like, and internal host-sweep scenarios
- Detects port scans, repeated failed connections, high-volume traffic, and unusual internal host fan-out
- Optionally captures live IPv4 packet metadata and correlates conservative rolling-window detections into incidents
- Provides automated C++ tests for the implemented core logic

## Current project status

The implemented scope includes the C++ network simulator, flow aggregation, deterministic normal/suspicious traffic scenarios, first-generation detection rules, and the browser dashboard.

Completed foundations include:

- Project foundation, device model, packet routing, and firewall rule evaluation
- Flow aggregation, bounded threat scenarios, and explainable simulator detections
- SQLite incident management and native simulator-to-incident integration
- Optional passive IPv4 metadata monitoring with a dashboard capture workflow
- Local IOC catalog with explicit JSON import, incident enrichment, and append-only analyst notes
- Dependency-free median/MAD anomaly baseline and optional scikit-learn Isolation Forest training/scoring
- Leakage-aware, capture/session-grouped evaluation with precision, recall, F1, false-positive/negative rates, confusion matrix, and latency report
- Manual dashboard anomaly scoring through a loopback-only API endpoint
- Optional local Ollama incident explanations through the guided CLI and loopback-only API
- Loopback-only enforcement for all API reads and writes

Not implemented yet:

- production-grade network telemetry, calibrated detections, and IPv6/VLAN coverage
- analyst authentication, authorization, multi-tenant operations, and production deployment hardening
- calibrated ML risk scoring and validation against representative labeled traffic
- automated response or blocking actions
- SFML interface
- Docker deployment
- autonomous AI investigation or response

Detection rules are starter heuristics, not proof of compromise. Live capture inspects TCP SYN metadata but does not inspect authentication events, packet payloads, or process identity. See [docs/TRAFFIC_DETECTION.md](docs/TRAFFIC_DETECTION.md) for simulator thresholds and [docs/LIVE_MONITORING.md](docs/LIVE_MONITORING.md) for optional capture setup, detection limits, and permissions.

Object-oriented design, application composition, and dependency-injection conventions are documented in [docs/oop.md](docs/oop.md) and [docs/architecture.md](docs/architecture.md). The C++ simulator uses domain classes; the Python backend uses repositories, services, a composition root, and a guided CLI controller; the JavaScript dashboard uses five feature controllers. Declarative formats such as HTML/CSS/YAML remain declarative.

Detailed project status and roadmap notes are available in [docs/development-process.md](docs/development-process.md), [docs/architecture.md](docs/architecture.md), and [docs/oop.md](docs/oop.md).

## Repo structure

```text
include/           Public C++ headers for the core model and device interfaces
src/               C++ implementation and native console demo
tests/             Test suite and smoke checks
backend/           Local Python server that serves the visual dashboard
index.html         Default browser dashboard entry point
web/               Legacy static assets kept for reference; not the main route
build/             Generated build output
CMakeLists.txt     CMake project configuration
docs/              Project documentation and design notes
README.md          Project overview and usage guide
```

## Requirements

Before running the project, make sure the following tools are installed:

- CMake 3.20 or newer
- A C++20 compiler
- Python 3
- PowerShell or a terminal that can run the commands below
- Internet access during the first test-enabled configure so CMake can fetch GoogleTest

For Windows, a typical setup is:

- Visual Studio Build Tools or MinGW
- Python 3 installed and added to PATH
- CMake installed and added to PATH

## Quick start guide

### 1. Clone the project

```powershell
git clone https://github.com/mudassir-93/CYBERGUARD-ENGINE.git
cd CYBERGUARD-ENGINE

# Build and verify the project on Windows
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\verify-windows.ps1
```

### 2. Build the native C++ project manually (optional)

The one-command verification script above already configures and builds CyberGuard. If you prefer to build manually with MinGW, use a separate build directory:

```powershell
cmake -S . -B build-mingw -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCYBERGUARD_BUILD_TESTS=ON
cmake --build build-mingw --config Release
```

Use the generator supported by your installed toolchain and keep the same build directory for subsequent commands.

### 3. Run the tests manually (optional)

```powershell
ctest --test-dir build-mingw -C Release --output-on-failure
```

The native test suite covers packet behavior, routing, firewall decisions, flow aggregation, traffic scenarios, and all current detection heuristics.

### 4. Run the native demo

For a Visual Studio multi-configuration build:

```powershell
.\build\Release\CyberGuard.exe
```

For a single-configuration build created directly in `build` (for example, when CMake selects MinGW):

```powershell
.\build\CyberGuard.exe
```

For the separate manual MinGW build shown above:

```powershell
.\build-mingw\CyberGuard.exe
```

The console demo runs normal, port-scan, brute-force-pattern, DoS-like, and internal host-sweep scenarios. It aggregates packet outcomes into flows and prints explainable alerts. It never sends real network traffic.

### 5. Run the native-to-incident integration

After building the C++ executable, run the simulator and automatically import its actual detection output into SQLite:

```powershell
python backend/run_simulation.py
```

The dashboard also provides a **Run C++ simulation** action. It executes the local native binary, receives structured JSON Lines detections, and persists incidents. Set `CYBERGUARD_EXECUTABLE` if the executable is outside the standard build folders.

### 6. Use the guided CLI (optional)

From the repository root, open the interactive local workspace:

```powershell
python backend/cli.py
```

You can also run individual commands:

```powershell
python backend/cli.py doctor
python backend/cli.py dashboard
python backend/cli.py dashboard --port 8080
python backend/cli.py summary
python backend/cli.py incidents --status new --limit 20
python backend/cli.py show CG-INCIDENTID
python backend/cli.py status CG-INCIDENTID acknowledged
python backend/cli.py simulate
python backend/cli.py explain CG-INCIDENTID
```

The CLI works directly with the local SQLite store and native simulator bridge. It starts the dashboard server only when you explicitly run `dashboard`; that server binds to `127.0.0.1` and is not exposed to your LAN. Start with the setup check:

```powershell
python backend/cli.py doctor
```

The doctor report checks the SQLite database and native simulator, and reports optional Scapy, scikit-learn, and local Ollama readiness. Ollama is checked through its loopback-only `/api/tags` endpoint with a short timeout. If the configured model (default `llama3.2:3b`) is missing, the report prints the matching `ollama pull <model>` command. Missing optional tools do not prevent the core simulator and incident workspace from running.

Useful incident workflows:

```powershell
python backend/cli.py summary
python backend/cli.py incidents --status new --limit 20
python backend/cli.py show CG-INCIDENTID
python backend/cli.py status CG-INCIDENTID acknowledged
python backend/cli.py explain CG-INCIDENTID
```

The optional `explain` command sends bounded incident evidence only to a configured loopback Ollama service; it is read-only and advisory. Live packet capture remains a separate, optional dashboard workflow.

### 7. Open the browser dashboard

From the repository root:

```powershell
python backend/server.py
```

The server binds to `127.0.0.1` by default and enforces loopback-only access across all API routes (including reads and writes), as defense in depth. It should remain loopback-only:
the API has no authentication and is not safe to expose to a LAN or the public
internet. You can change the local port with `CYBERGUARD_PORT=8080` (use the
port you choose in the browser URL). Do not set `CYBERGUARD_HOST=0.0.0.0` for
normal use.

Then open this in your browser:

```text
http://localhost:8000/
```

The browser app shows a visual topology, statistics cards, rule controls, a demo sequence, incident management, and optional live network monitoring. Live capture requires the optional Scapy dependency plus Npcap/libpcap and suitable permissions; see [docs/LIVE_MONITORING.md](docs/LIVE_MONITORING.md). The browser's simulated firewall blocks TCP destination port 23 only inside the demo model.

## How to use the simulator

### Browser simulation

The browser interface lets you:

- choose a source and destination device
- choose a protocol and port
- send a packet manually
- observe whether the packet is delivered or blocked
- add or toggle firewall rules
- reset the simulation
- run a demo sequence across multiple endpoints

This interface is designed for visual explanation and quick testing, not for sending real traffic.

### Native C++ model

The C++ engine represents the underlying logic of:

- packet objects
- network ownership
- routing logic
- firewall rule matching
- device registration and online tracking

This is the project’s core implementation layer.

## Important notes

- The app is intended for local, educational use only.
- The C++ and browser simulators do not generate real network traffic. The optional live sensor passively observes metadata from an explicitly selected real network interface.
- The browser simulation does not share packet-routing state with the C++ program. The optional live sensor is a separate passive Python capture path and stores only metadata-derived detections.
- The project root URL is the default browser route.
- The legacy [web](web) folder is kept as reference material and is not the main entry point.

## Verification

The latest fully verified post-merge master commit is `6337babefba572d1a10e86c070ee5d864af66f8e`; Ubuntu and Windows both passed in run [45309651274](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45309651274). PR #7 has since merged as `d9c4d9508d87030fa849765dafb3cf078269277e`; its post-merge CI run [45310558781](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45310558781) is queued.

| Check | Verified master baseline |
| --- | --- |
| Windows CI job | Passed |
| Ubuntu CI job | Passed |
| C++ build and tests | Passed on both platforms |
| Python syntax and backend tests | Passed on both platforms |
| Dashboard JavaScript syntax | Passed on both platforms |
| C++ to SQLite integration | Passed on both platforms |

The CLI/Ollama readiness milestone is merged in [PR #2](https://github.com/mudassir-93/CYBERGUARD-ENGINE/pull/2), leakage-aware ML evaluation in [PR #3](https://github.com/mudassir-93/CYBERGUARD-ENGINE/pull/3), the Windows verification helper in [PR #4](https://github.com/mudassir-93/CYBERGUARD-ENGINE/pull/4), and the synthetic ML demo dataset in [PR #5](https://github.com/mudassir-93/CYBERGUARD-ENGINE/pull/5). The Windows script is covered by hosted CI; running it on the owner's PC remains pending. The guided CLI dashboard-launch command is merged in [PR #7](https://github.com/mudassir-93/CYBERGUARD-ENGINE/pull/7); it binds only to loopback and starts only on explicit user request.

Physical packet capture still requires host-specific Npcap/libpcap, a supported adapter, and suitable permissions. The optional ML model also requires evaluation against representative, trusted traffic before operational use. See [docs/LIVE_MONITORING.md](docs/LIVE_MONITORING.md) and [docs/THREAT_INTELLIGENCE.md](docs/THREAT_INTELLIGENCE.md).

## Screenshots

The browser dashboard presents a simulated network with device cards, packet counters, firewall controls, and live event output.

![CyberGuard dashboard overview](https://via.placeholder.com/1200x700?text=CyberGuard+Dashboard)

![CyberGuard firewall controls](https://via.placeholder.com/1200x500?text=Firewall+Rules+and+Event+Stream)

> These are placeholder visual previews for GitHub presentation. You can replace them with real screenshots from your local environment later.

## Project documentation

For deeper technical details, use the docs folder:

- [docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md)
- [docs/ML_EVALUATION.md](docs/ML_EVALUATION.md)
- [examples/synthetic-flow-demo.csv](examples/synthetic-flow-demo.csv)
- [docs/development-process.md](docs/development-process.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/oop.md](docs/oop.md)

## Troubleshooting

### Browser does not open

- Make sure Python 3 is installed and available on PATH
- Run the server from the repository root
- Check that port 8000 is free
- If needed, stop any other process using port 8000 before starting the app

### CMake build fails

- Confirm that your compiler supports C++20
- Confirm that CMake is installed and available in PATH
- Use a compatible generator for your environment

### Tests fail

- Rebuild the project and rerun the test command
- Check whether a recent code change affected the router or firewall logic
- Review the project docs to confirm the current implemented scope

## Summary

CyberGuard Engine is a clean, local-first simulation project for learning how routing, packet flow, and firewall decisions work in a basic network model. It is organized so a user can clone the repository, build the C++ engine, run tests, and open the browser visualization with minimal setup.


## Live network monitoring foundation

Optional passive IPv4 capture is available through the Live network monitoring dashboard panel. It detects TCP SYN port-scan patterns, high packet rates, and internal private-host fan-out using rolling windows. It deliberately does not infer failed logins from packet metadata. Install `requirements-live.txt` and follow [docs/LIVE_MONITORING.md](docs/LIVE_MONITORING.md) for Npcap/libpcap and permissions.

## Incident management milestone

CyberGuard includes a local SQLite-backed incident workspace. Start it with `python backend/server.py`, then open `http://127.0.0.1:8000`. The dashboard can generate local demo detections, correlate repeated signals, preserve evidence, filter incidents, and manage analyst statuses. See [docs/INCIDENT_MANAGEMENT.md](docs/INCIDENT_MANAGEMENT.md) for API contracts and limitations.


## Threat intelligence and investigation

The local SQLite workspace supports explicit imports of IP/domain/file-hash indicators with source attribution, confidence, severity, tags, and expiry. Incident detail includes exact-match IOC enrichment and append-only analyst notes. No external feed is fetched and no indicator triggers blocking. The dashboard includes a manual JSON import panel. See [docs/THREAT_INTELLIGENCE.md](docs/THREAT_INTELLIGENCE.md).

A dependency-free robust median/MAD anomaly baseline is available with `python backend/ml_anomaly.py`. An optional scikit-learn Isolation Forest can be trained locally after `python -m pip install -r requirements-ml.txt` using `python backend/ml_isolation_forest.py path/to/trusted-baseline.csv`. For labeled CSV evaluation, run `python backend/ml_evaluate.py examples/synthetic-flow-demo.csv --group-column capture_id --output reports/demo-evaluation.json`. The bundled 144-row sample is synthetic demonstration data, not a benchmark. The evaluator keeps capture/session groups disjoint between training and test data and reports false positives, false negatives, F1, balanced accuracy, and inference latency. See [docs/ML_EVALUATION.md](docs/ML_EVALUATION.md) for the CSV contract and limitations. Set `CYBERGUARD_ANOMALY_MODEL` before starting the server to enable the dashboard's local telemetry scoring panel. Both models provide explainable context, not calibrated probabilities or production verdicts.


## Application architecture

The application uses object-oriented components across the native and service layers. The Python backend is composed through `CyberGuardApplication`, with repository and adapter objects injected into the HTTP server. The browser dashboard uses feature controllers: `NetworkSimulatorController`, `IncidentDashboardController`, `LiveMonitorController`, `ThreatIntelController`, and `AnomalyDashboardController`. Stateless validation and calculation helpers remain pure functions where that is simpler and clearer. See [docs/oop.md](docs/oop.md) and [docs/architecture.md](docs/architecture.md).


## Optional local AI incident analyst

CyberGuard can explain a persisted incident using a local Ollama model without a cloud API key. Install Ollama and pull a model (default: `llama3.2:3b`), then use `python backend/cli.py explain CG-INCIDENTID` or the interactive menu's option 7. The loopback-only API also exposes `POST /api/analyst/explain`. This feature is advisory only: it cannot change incident state, run commands, or block traffic. See [docs/LOCAL_AI_ANALYST.md](docs/LOCAL_AI_ANALYST.md) for setup, configuration, and limitations.
