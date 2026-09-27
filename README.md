# CyberGuard Engine

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
