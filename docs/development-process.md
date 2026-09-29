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
backend/            Python server that hosts the browser app from the repo root
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
| Threat generation and threat detection | Not implemented |
| Incident management and defensive response | Not implemented |
| Simulation/scenario engine and stress runner | Not implemented |
| SFML interface, Docker, GitHub Actions, AI | Not implemented |

The first three development phases are represented by the implemented
foundation, devices/network ownership, and packet/routing/firewall behavior.
Testing and the browser console are cross-cutting additions, not completion of
the planned GoogleTest or SFML phases in their entirety. No placeholder threat,
detection, incident, response, Docker, or AI code is present.

## Requirements

- CMake 3.20 or newer
- A compiler with C++20 support (the commands below use MinGW GCC and the
  `MinGW Makefiles` generator)
- Internet access when configuring tests for the first time; CMake fetches
  GoogleTest 1.14.0 through `FetchContent`
- Python 3 to serve the static browser files

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

The registered suite contains 12 tests: a smoke test plus GoogleTest cases
covering packet properties and validation, router forwarding, first-match and
disabled firewall rules, server service acceptance, and network routing,
duplicate identifiers, removal, and online-device counts. The recorded
verified run passed all 12 tests.

## Run the Browser Simulator

Start the backend server from the repository root:

```powershell
python backend/server.py
```

Open `http://localhost:8000/`. The browser app provides manual packet controls,
an editable block/allow rule list, a deterministic demo sequence, pause/resume,
reset, summary counters, and an event list. The initial rule blocks TCP port
23; the demo sends TCP packets to ports 80, 443, and 23.

This UI executes its own JavaScript simulation. It shares neither state nor
packet-routing calls with the C++ executable. The topology's Internet icon is a
visual boundary, not a network device or an external connection.

## Development Phases and Next Work

| Phase | Scope from project roadmap | State in this repository |
| --- | --- | --- |
| 1 | Project foundation | Complete |
| 2 | Network devices and ownership | Complete |
| 3 | Packets, routing, firewall rules | Complete |
| 4 | Simulated threat types | Not implemented |
| 5 | Detection, risk scoring, alerts | Not implemented |
| 6 | Incidents and response | Not implemented |
| 7 | Simulation and scenario engine | Not implemented |
| 8 | SFML visualization | Not implemented; browser UI is separate |
| 9 | GoogleTest | Tests cover the current core; future features need tests |
| 10 | Docker | Not implemented |
| 11 | GitHub Actions | Not implemented |
| 12 | Documentation and polish | Documentation is being maintained |

The next feature phase should be selected explicitly before implementation.
Keep all traffic and threat behavior simulated and internal to the application.
For packet flow and class ownership, see [architecture.md](architecture.md)
and [oop.md](oop.md).

## Change and Verification Workflow

For a code change, inspect its owning class and callers, make a narrow change,
add or update tests, build the affected targets, and run the relevant tests.
Run the complete CTest suite after changes to shared routing or device
contracts. Update these documents when behavior, commands, or scope changes.
Report checks that could not run instead of treating them as successful.