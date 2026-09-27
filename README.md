# CyberGuard Engine

CyberGuard Engine is an educational C++20 project that simulates packet flow through a small, rule-controlled network. It combines a native simulation and automated tests with a browser-based console for visual inspection. All traffic is simulated locally; the project does not send packets over a real network.

## Features

- Polymorphic network-device model with routers, firewalls, servers, and workstations
- Packet lifecycle and input validation for IP addresses and ports
- Router route-table checks and packet-forwarding statistics
- Ordered firewall rules with allow/block decisions by source, destination, protocol, and destination port
- Server services that accept traffic only on configured ports
- Network counters for created, delivered, blocked, and dropped packets
- GoogleTest coverage for packet, device, firewall, and network behavior
- Browser console with network topology, manual packet controls, editable firewall rules, event stream, and deterministic demo sequence

## Project Layout

```text
include/       Public core and device headers
src/           C++ simulation implementation and console demo
tests/         Smoke and GoogleTest suites
web/           Static browser simulation
docs/          Architecture, OOP, and development-process documentation
CMakeLists.txt CMake build configuration
```

## Development Process and Roadmap

The project is developed in small phases with scope boundaries, focused tests, and build verification. Phases 1-3, core tests, and the separately requested browser console are complete. Threat detection, incident response, SFML, Docker, and AI remain outside the current implementation scope.

See [docs/development-process.md](docs/development-process.md) for the phase-by-phase history, remaining roadmap, feature workflow, definition of done, and verification record. Architecture and OOP details are in [docs/architecture.md](docs/architecture.md) and [docs/oop.md](docs/oop.md).

## Requirements

- CMake 3.20 or newer
- A C++20 compiler
- Internet access on the first test-enabled configure, so CMake can fetch GoogleTest
- Python 3 for the static browser server

The build commands below use MinGW Makefiles and assume `cmake` and `g++` are available on `PATH`. Other CMake generators can be used with a compatible compiler.

## Build, Test, and Run

From the repository root in PowerShell:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCYBERGUARD_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
.\build\CyberGuard.exe
```

The console demo creates three packets: two reach configured server services, while TCP destination port 23 is blocked by the firewall.

## Browser Simulation

Start the static web server from the repository root:

```powershell
python -m http.server 5173 --directory web
```

Open [http://localhost:5173/](http://localhost:5173/). The interface supports manually routing packets, adding and toggling firewall rules, running the demo sequence, pausing the stream, and resetting the simulation. Its model runs entirely in the browser and is a visual companion to the native C++ implementation.

## Verified Result

The project was built with CMake and MinGW GCC, all 12 registered tests passed, and the native demo produced:

```text
Packets Created:   3
Delivered:         2
Blocked:           1
Dropped:           0
```

The browser demo produces the same two-delivered, one-blocked outcome.# CyberGuard Engine

CyberGuard Engine is a C++20 network simulation project for modeling packet flow, firewall enforcement, routing behavior, and basic server/workstation activity in a controlled environment. The project is designed as a clear educational and demonstration system for understanding how a small internal network behaves under allowed and blocked traffic.

## Overview

This project simulates a local network made up of:

- Router
- Firewall
- Server
- Workstations
- Packet lifecycle tracking

It demonstrates the core phases of packet handling:

- packet creation
- routing through the network
- firewall filtering
- delivery or blocking
- network-level statistics reporting

## Included features

- Device abstraction and polymorphism for network nodes
- Packet validation for IP addresses and port numbers
- Router route table simulation and forwarding checks
- Firewall rules for blocking or allowing traffic by protocol and port
- Server port simulation and service availability checks
- Network statistics for delivered, blocked, and dropped packets
- Browser-based visual console for live traffic simulation
- Unit tests for the core logic using GoogleTest

## Project structure

- `include/` — public headers for core and device classes
- `src/` — implementation files for the simulation logic
- `tests/` — automated validation tests
- `web/` — browser-based visual simulation UI
- `docs/` — architecture and object-oriented design notes
- `CMakeLists.txt` — build configuration

## Verified build and test status

The project has been validated with a native CMake build and test run.

Current verified result:

- 12/12 automated tests passed
- Packet simulation successfully routed traffic and blocked unauthorized access

## Run locally

### Native C++ build

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
ctest --test-dir build --output-on-failure
.\build\CyberGuard.exe
```

### Browser simulation

```powershell
python -m http.server 5173 --directory web
```

Then open:

```text
http://localhost:5173/
```

## Example behavior

The simulation includes a deterministic demo sequence:

- PC-01 -> Server on TCP:80 -> Delivered
- PC-02 -> Server on TCP:443 -> Delivered
- PC-01 -> Server on TCP:23 -> Blocked by firewall

## Notes

This project intentionally models network behavior without performing real external network communication. It is designed to be understandable, testable, and visualizable as a learning-focused network defense simulation.
