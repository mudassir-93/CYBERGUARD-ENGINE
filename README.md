# CyberGuard Engine

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://isocpp.org/)
[![CMake](https://img.shields.io/badge/CMake-3.20%2B-064F8C.svg)](https://cmake.org/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Local%20Simulation-success.svg)](https://github.com/mudassir-93/CYBERGUARD-ENGINE)
[![License](https://img.shields.io/badge/License-Project%20Educational-lightgrey.svg)](https://github.com/mudassir-93/CYBERGUARD-ENGINE)

CyberGuard Engine is an educational, local-first network-security workspace built around a C++20 network simulator. It models packet routing and firewall enforcement, aggregates network flows, generates bounded threat scenarios, and runs explainable detection heuristics. An optional Python sensor can passively capture IPv4 packet metadata from a selected local interface.

This project is intended for learning, demonstration, and academic review. The simulator does not send real traffic. Optional live monitoring passively reads packet metadata from a selected interface; it does not modify or block traffic. The application is designed to run locally.

## Overview

CyberGuard combines two separate simulation layers:

- A native C++ simulation for the actual network model, packet logic, and device behavior
- A browser dashboard for a visual presentation of the simulated network, counters, firewall rules, and traffic flow

The browser dashboard is served by a local Python API. It can display persisted incidents and invoke the native C++ simulator through a structured local process bridge; it does not capture live network traffic.

## What the project does

- Creates and validates packet objects
- Simulates source and destination device routing
- Models router and firewall behavior
- Tracks packet states such as created, routing, blocked, delivered, and dropped
- Uses ordered firewall rules to allow or deny traffic based on protocol and port
- Shows a live-style topology dashboard in the browser
- Aggregates packets into bidirectional five-tuple network flows\n- Generates local-only normal, port-scan, brute-force, DoS-like, and internal host-sweep scenarios\n- Detects port scans, repeated failed connections, high-volume traffic, and unusual internal host fan-out\n- Optionally captures live IPv4 packet metadata and correlates conservative rolling-window detections into incidents\n- Provides automated C++ tests for the implemented core logic

## Current project status

The implemented scope includes the C++ network simulator, flow aggregation, deterministic normal/suspicious traffic scenarios, first-generation detection rules, and the browser dashboard.

Completed phases include:

- Project foundation
- Device model and ownership
- Packet creation and routing
- Firewall rule evaluation
- Browser console for demonstration and manual testing

Not implemented yet:

- production-grade network telemetry, calibrated detections, and IPv6/VLAN coverage
- authentication, authorization, multi-tenant operations, and production deployment hardening
- ML-based anomaly detection and calibrated risk scoring
- automated response or blocking actions
- SFML interface
- Docker deployment
- AI-based automation

Detection rules are starter heuristics, not proof of compromise. They do not inspect authentication events, packet payloads, TCP flags, or process identity. See [docs/TRAFFIC_DETECTION.md](docs/TRAFFIC_DETECTION.md) for simulator thresholds and [docs/LIVE_MONITORING.md](docs/LIVE_MONITORING.md) for optional capture setup, detection limits, and permissions.\n\nDetailed project status and roadmap notes are available in [docs/development-process.md](docs/development-process.md), [docs/architecture.md](docs/architecture.md), and [docs/oop.md](docs/oop.md).

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
```

### 2. Build the native C++ project

From the repo root in PowerShell:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCYBERGUARD_BUILD_TESTS=ON
cmake --build build
```

If you are using a different compiler or generator, replace the generator command with the one supported by your toolchain.

### 3. Run the tests

```powershell
ctest --test-dir build --output-on-failure
```

The native test suite covers packet behavior, routing, firewall decisions, flow aggregation, traffic scenarios, and all current detection heuristics.

### 4. Run the native demo

```powershell
.\build\CyberGuard.exe
```

The console demo runs normal, port-scan, brute-force-pattern, DoS-like, and internal host-sweep scenarios. It aggregates packet outcomes into flows and prints explainable alerts. It never sends real network traffic.

### 5. Run the native-to-incident integration

After building the C++ executable, run the simulator and automatically import its actual detection output into SQLite:

```powershell
python backend/run_simulation.py
```

The dashboard also provides a **Run C++ simulation** action. It executes the local native binary, receives structured JSON Lines detections, and persists incidents. Set `CYBERGUARD_EXECUTABLE` if the executable is outside the standard build folders.

### 6. Open the browser dashboard

From the repository root:

```powershell
python backend/server.py
```

The server binds to `127.0.0.1` by default so it is available only on this
machine. To intentionally expose the demo to your local network, set
`CYBERGUARD_HOST=0.0.0.0` before starting it. You can also change the port with
`CYBERGUARD_PORT=8080` (use the port you choose in the browser URL).

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
- No real network traffic is generated.
- The browser simulation does not share packet-routing state with the C++ program. The optional live sensor is a separate passive Python capture path and stores only metadata-derived detections.
- The project root URL is the default browser route.
- The legacy [web](web) folder is kept as reference material and is not the main entry point.

## Verification

The native validation run for the implemented core passed its recorded test set, and the console demo produced the expected local behavior:

```text
Packets Created:   3
Delivered:         2
Blocked:           1
Dropped:           0
```

## Screenshots

The browser dashboard presents a simulated network with device cards, packet counters, firewall controls, and live event output.

![CyberGuard dashboard overview](https://via.placeholder.com/1200x700?text=CyberGuard+Dashboard)

![CyberGuard firewall controls](https://via.placeholder.com/1200x500?text=Firewall+Rules+and+Event+Stream)

> These are placeholder visual previews for GitHub presentation. You can replace them with real screenshots from your local environment later.

## Project documentation

For deeper technical details, use the docs folder:

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


## Live network monitoring foundation\n\nOptional passive IPv4 capture is available through the Live network monitoring dashboard panel. It detects TCP SYN port-scan patterns, high packet rates, and internal private-host fan-out using rolling windows. It deliberately does not infer failed logins from packet metadata. Install `requirements-live.txt` and follow [docs/LIVE_MONITORING.md](docs/LIVE_MONITORING.md) for Npcap/libpcap and permissions.\n\n## Incident management milestone

CyberGuard includes a local SQLite-backed incident workspace. Start it with `python backend/server.py`, then open `http://127.0.0.1:8000`. The dashboard can generate local demo detections, correlate repeated signals, preserve evidence, filter incidents, and manage analyst statuses. See [docs/INCIDENT_MANAGEMENT.md](docs/INCIDENT_MANAGEMENT.md) for API contracts and limitations.
