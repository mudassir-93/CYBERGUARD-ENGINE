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

The browser demo produces the same two-delivered, one-blocked outcome.