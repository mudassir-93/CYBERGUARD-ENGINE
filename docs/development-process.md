# CyberGuard Development and Verification

This guide describes the source tree, completed scope, build and test commands,
browser demo, and remaining roadmap based on the current repository.

## Source Tree

```text
include/core/       Packet, network, and abstract device interfaces
include/devices/    Router, firewall, server, and workstation interfaces
src/core/           Packet and network implementation
src/devices/        Device implementations
src/main.cpp        Native console demonstration
tests/              Smoke and GoogleTest coverage
backend/            Python application, service, repository, and HTTP layers
index.html          Default browser dashboard entry point
web/                Legacy static browser assets kept for reference; not the default route
docs/               Architecture, OOP, and this project guide
CMakeLists.txt      C++20 targets and test configuration
```

## Implemented Scope

| Work | Current state |
| --- | --- |
| C++20 project, core library, console executable | Implemented |
| Packet value type and validation | Implemented |
| Router, firewall, server, workstation | Implemented |
| Network ownership, lookup, routing, counters | Implemented |
| Unit and smoke tests | Implemented for the current core |
| Static browser console | Implemented as an independent simulation |
| Simulated threat generation and heuristic detection | Implemented (starter rules) |
| Optional passive IPv4 capture foundation | Implemented (Scapy adapter; host driver/permissions required) |
| SQLite incident management workspace | Implemented (local-only) |
| Local threat-intelligence catalog and incident IOC enrichment | Implemented (manual JSON import; exact matches) |
| Analyst investigation notes and evidence timeline | Implemented (append-only local notes) |
| Explainable anomaly baseline | Implemented (median/MAD statistical baseline) |
| Optional Isolation Forest pipeline | Implemented (scikit-learn; local training/scoring; uncalibrated) |
| Dashboard anomaly scoring | Implemented (configured local model; explicit analyst-triggered scoring) |
| API network boundary | Implemented (all API reads/writes loopback-only) |
| OOP backend composition root | Implemented (application owns services; HTTP handler uses dependency injection) |
| OOP native simulator bridge | Implemented (SimulationBridge encapsulates executable discovery, execution, and JSONL ingestion) |
| OOP ML inference | Implemented (IsolationForestAnalyzer owns the loaded model and scoring interface) |\n| Guided local CLI | Implemented (interactive menu, setup checks, simulation, incident list/detail/status commands) |
| Automated defensive response / blocking | Not implemented |
| Automated external threat-feed polling / TAXII | Not implemented |
| Calibrated production ML risk scoring | Not implemented |
| Simulation/scenario engine and stress runner | Not implemented |
| SFML interface, Docker, AI | Not implemented |
| GitHub Actions baseline CI | Added on the upgrade branch; Linux and Windows checks configured |

The first three development phases are represented by the implemented
foundation, devices/network ownership, and packet/routing/firewall behavior.
Testing and the browser console are cross-cutting additions, not completion of
the planned GoogleTest or SFML phases in their entirety. Detection and incident
management are implemented as local-first foundations; automated response and
AI-driven analysis are not implemented.

## Requirements

- CMake 3.20 or newer
- A compiler with C++20 support (the commands below use MinGW GCC and the
  `MinGW Makefiles` generator)
- Internet access when configuring tests for the first time; CMake fetches
  GoogleTest 1.14.0 through `FetchContent`
- Python 3 to serve the dashboard and local incident API
- Optional live capture: install `requirements-live.txt`, Npcap on Windows or libpcap on Linux, and suitable capture permissions

## Build and Run the Native Program

Run these commands from the repository root in PowerShell:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCYBERGUARD_BUILD_TESTS=ON
cmake --build build
.\build\CyberGuard.exe
```

The native demo creates a router, firewall, server, and two workstations. The
server opens ports 80 and 443, and the firewall blocks TCP destination port 23.
Its demonstration sends three packets: two are delivered and one is blocked.

## Run Tests

```powershell
ctest --test-dir build --output-on-failure
```

The earlier verified CI milestone records 32/32 C++ tests passing on both
Ubuntu and Windows. The OOP backend composition, simulator bridge, and browser controller refactors add new Python coverage and require a fresh confirmed CI run. Coverage includes packet validation, routing, firewall
decisions, flow aggregation, scenario bounds, threat detection, and regression
checks for offline devices, IP validation, and stale-route cleanup. The Python
backend suite records 30/30 tests passing on both platforms. The workflow also
checks Python syntax, dashboard JavaScript syntax, and the C++-to-SQLite
integration. The browser application is organized into five OOP controllers for
the network simulator, incidents, live monitoring, threat intelligence, and
anomaly-scoring UI. These counts describe the completed CI run for commit
`0f82a957`; consult the latest Actions run for any later commit.

## Use the Guided CLI\n\nRun the interactive local workspace from the repository root:\n\n```powershell\npython backend/cli.py\n```\n\nAvailable commands include:\n\n```powershell\npython backend/cli.py doctor\npython backend/cli.py summary\npython backend/cli.py incidents --status new --severity high\npython backend/cli.py show CG-INCIDENTID\npython backend/cli.py status CG-INCIDENTID acknowledged\npython backend/cli.py simulate\n```\n\nThe CLI accesses the local SQLite repositories directly and runs the native simulator through the existing process bridge. It does not start an HTTP listener or enable active network response.\n\n## Run the Browser Simulator

Start the backend server from the repository root:

```powershell
python backend/server.py
```

Open `http://localhost:8000/`. The browser app provides manual packet controls,
an editable block/allow rule list, a deterministic demo sequence, pause/resume,
reset, summary counters, and an event list. Pausing or resetting cancels any
remaining scheduled demo packets. The initial rule blocks TCP port
23; the demo sends TCP packets to ports 80, 443, and 23.

This UI executes its own JavaScript simulation. It shares neither state nor
packet-routing calls with the C++ executable. The optional live-monitoring panel
uses a separate passive Python capture adapter and persists metadata-derived
detections; see [LIVE_MONITORING.md](LIVE_MONITORING.md). The topology's Internet
icon remains a visual boundary, not a network device or external connection.

## Development Phases and Next Work

| Phase | Scope from project roadmap | State in this repository |
| --- | --- | --- |
| 1 | Project foundation | Complete |
| 2 | Network devices and ownership | Complete |
| 3 | Packets, routing, firewall rules | Complete |
| 4 | Simulated threat types | Implemented (bounded scenarios and starter heuristics) |
| 5 | Detection and alerts | Implemented (starter rules; no calibrated ML risk scoring) |
| 6 | Incident management | Implemented (local SQLite workflow; no automated response) |
| 7 | Simulation and scenario engine | Not implemented |
| 8 | SFML visualization | Not implemented; browser UI is separate |
| 9 | GoogleTest | Tests cover the current core; future features need tests |
| 10 | Docker | Not implemented |
| 11 | GitHub Actions | Baseline Linux/Windows CI added on the upgrade branch |
| 12 | Documentation and polish | Documentation is being maintained |

Live monitoring is an optional passive sensor foundation. Further product work
should focus on capture reliability, richer protocol coverage, calibrated
thresholds, and safe deployment controls without turning the product into an IPS.
The OOP refactor milestone covers the Python application composition and the
five browser feature controllers. It was verified by GitHub Actions on both
Ubuntu and Windows at code commit `7787c798`: 32/32 C++ tests and 51/51 Python
tests passed on each platform; Python compilation, `node --check app.js`, and
the C++-to-SQLite integration also passed.
For packet flow and class ownership, see [architecture.md](architecture.md)
and [oop.md](oop.md).

## Change and Verification Workflow

For a code change, inspect its owning class and callers, make a narrow change,
add or update tests, build the affected targets, and run the relevant tests.
Run the complete CTest suite after changes to shared routing or device
contracts. Update these documents when behavior, commands, or scope changes.
Report checks that could not run instead of treating them as successful.

## Threat Intelligence and Anomaly Baseline

See [THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md) for the JSON IOC import contract, incident enrichment, analyst notes API, and robust anomaly baseline trainer. These features remain local-first and perform no automated response. The baseline requires representative trusted CSV data and is not a calibrated probability.
