# CyberGuard Development Process and Roadmap

This document records how CyberGuard has been developed, what is currently
implemented, how changes are verified, and which roadmap work remains deferred.
It supplements [architecture.md](architecture.md) and [oop.md](oop.md).

## Project Scope

CyberGuard is an educational C++20 simulation. Packets, devices, firewall
decisions, and browser events are simulated locally. The project does not
generate real network traffic or perform real attacks.

The current implementation covers the foundational network engine and a
separately requested browser visualization. Threat generation, detection,
incident response, SFML, Docker, and AI features are not implemented in this
scope.

## How Work Is Done

Each feature follows a small, verifiable loop:

1. Confirm the requested scope and the phase boundary. Do not implement later
   roadmap features without authorization.
2. Inspect the existing classes, call sites, tests, and documentation.
3. Describe the intended behavior and identify the owning abstraction.
4. Update the smallest relevant public interface and implementation.
5. Add or update tests for normal behavior, failure cases, and relevant edges.
6. Build the affected targets and run the focused tests, then the full suite
   when practical.
7. Run the native demo and/or browser flow when the change affects those
   surfaces.
8. Review architecture, ownership, resource handling, and the final diff.
9. Update documentation and publish only the requested, verified work.

Do not call a feature complete just because code was written. Completion
requires working code, a successful build, passing relevant tests, a modular
design, and documentation updates where behavior or usage changed. If a
required check cannot run, state the blocker and do not report it as passed.

## Development History

### Phase 1: Project Foundation - Complete

- Inspected the repository and established the CMake/C++20 project structure.
- Added the core library target, a basic executable, initial network/device
  abstractions, and a smoke test.
- Verified the foundation before expanding the simulation.

### Phase 2: Network Devices and Ownership - Complete

- Implemented the abstract `NetworkDevice` contract and concrete `Router`,
  `Firewall`, `Server`, and `Workstation` devices.
- Implemented `Network` ownership, device lookup/removal, route setup, packet
  orchestration, and network statistics.

### Phase 3: Packets, Routing, and Firewall Rules - Complete

- Implemented packet properties, IP/port validation, and packet lifecycle
  statuses.
- Added router forwarding, ordered firewall allow/block rules, server service
  checks, and delivery/drop/block accounting.
- Added tests for packet, router, firewall, server, and network behavior.

### Browser Console: Requested Companion - Complete

- Added a static browser interface for topology, manual packet routing,
  firewall rule management, simulation controls, counters, and event history.
- The browser implementation is an independent local simulation, not a web
  frontend connected to the C++ executable and not a replacement for the
  planned SFML interface.

## Roadmap Status

The numbered phases below follow the original project roadmap. Testing and the
browser console were also delivered as cross-cutting work rather than being
held until their original roadmap slots.

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Project setup, CMake, Git, basic executable | Complete |
| 2 | Network devices and network container | Complete |
| 3 | Packet lifecycle, packet routing, firewall rules | Complete |
| 4 | Simulated threat types | Deferred |
| 5 | Detection engine, risk scoring, alerts | Deferred |
| 6 | Incident management and defensive response | Deferred |
| 7 | Simulation engine, event/scenario system, stress tests | Deferred |
| 8 | SFML visualization | Deferred; browser console is a separate requested deliverable |
| 9 | GoogleTest | Core tests implemented and passing; future features need their own tests |
| 10 | Docker | Deferred |
| 11 | GitHub Actions CI | Deferred |
| 12 | Documentation and polish | In progress |

Deferred means not part of the delivered implementation. It does not imply
that a placeholder implementation exists. In particular, there is no threat
generator, `DetectionEngine`, `IncidentManager`, `ResponseEngine`, SFML layer,
Docker setup, or AI feature in the current scope.

## Verification Record

The verified native environment used CMake with MinGW GCC. The project
configured and built, all 12 registered tests passed, and the console demo
reported three packets created, two delivered, one blocked, and zero dropped.

The browser demo was also opened and exercised in a local browser. Its
deterministic sequence produced two delivered packets and one blocked packet.
The browser view is served from the `web/` directory and sends no external
traffic.

## Reproduce the Checks

From the repository root in PowerShell:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCYBERGUARD_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
.\build\CyberGuard.exe
```

To run the browser companion:

```powershell
python -m http.server 5173 --directory web
```

Then open `http://localhost:5173/`.