# CyberGuard Engine

CyberGuard Engine is an educational C++20 project for modeling packet flow through a small network. It includes a native simulation with automated tests and a separate browser-based network console. Both simulations are local and do not send real network traffic.

## What Is Implemented

- Packet creation, IPv4 and port validation, and packet status tracking
- Router, firewall, server, and workstation device classes
- In-memory routing, ordered allow/block firewall rules, and network statistics
- CMake build, console demonstration, and 12 tests for the implemented core
- Browser dashboard with a live topology, five workstations, manual packet controls, firewall rules, counters, event stream, and demo traffic

The browser simulation is an independent JavaScript model; it does not share runtime state with the native C++ program.

## Project Status

Phases 1-3 are implemented: project foundation, network devices, and packet routing with firewall behavior. Testing and the browser console are supporting work, not completion of all later roadmap phases. Threat detection, incident response, SFML, Docker, and AI functionality are not implemented.

See [docs/development-process.md](docs/development-process.md) for the phase status, workflow, verification notes, and remaining scope. See [docs/architecture.md](docs/architecture.md) and [docs/oop.md](docs/oop.md) for implementation details.

## Project Layout

```text
include/       Public core and device headers
src/           C++ implementation and console demo
tests/         Smoke and GoogleTest suites
web/           Static browser simulation
docs/          Development, architecture, and OOP documentation
CMakeLists.txt Build and test configuration
```

## Requirements

- CMake 3.20 or newer
- A C++20 compiler
- Internet access during the first test-enabled configure to fetch GoogleTest
- Python 3 to run the browser console

The native commands below use MinGW Makefiles and expect `cmake` and `g++` on `PATH`. Use a compatible CMake generator if you use another compiler.

## Build and Test

Run from the repository root in PowerShell:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCYBERGUARD_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
.\build\CyberGuard.exe
```

The native demo sends three packets: two are delivered and TCP destination port 23 is blocked.

## Run the Browser Console

```powershell
python -m http.server 5173 --directory web
```

Open [http://localhost:5173/](http://localhost:5173/). The browser demo sends five packets across the displayed workstations; its default firewall rule blocks TCP port 23.

## Verification

The recorded native verification passed all 12 registered tests. The console demo reported:

```text
Packets Created:   3
Delivered:         2
Blocked:           1
Dropped:           0
```