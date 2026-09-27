# CyberGuard Architecture and Completed Phases

CyberGuard is a self-contained network simulation. It performs no real network
communication.

## Completed Work by Phase

### Phase 1: Project Foundation

- Established the C++20 project structure, CMake core library, and executable.
- Added the initial `NetworkDevice` abstraction, minimal `Network`, and smoke
  test.

### Phase 2: Network Devices and Ownership

- Implemented `Router`, `Firewall`, `Server`, and `Workstation` as concrete
  `NetworkDevice` types.
- Implemented network device ownership, lookup, removal, route setup, and
  network-level statistics.

### Phase 3: Packets, Routing, and Firewall Rules

- Added validated packets and explicit packet lifecycle statuses.
- Added simulated routing, ordered allow/block firewall rules, server service
  checks, and delivered/blocked/dropped packet accounting.

### Cross-Cutting Deliverables

- Added GoogleTest coverage for packets, devices, and network behavior; all 12
  registered tests passed in the verified build.
- Added a browser-based console for visualizing and interacting with a separate
  local simulation. It is not the planned SFML interface and does not connect
  to the C++ process.

Threat generation, detection, incident response, the simulation/scenario
engine, SFML, Docker, and AI are not included in these completed phases. See
[development-process.md](development-process.md) for the complete roadmap and
deferred-phase status.

## Phase 2 Network Architecture

Phase 2's network model remains the architecture described below.

```text
Network
  |
  +-- owns unique_ptr<NetworkDevice>
       |
       +-- Router       -> route table and forwarding statistics
       +-- Firewall     -> ordered simulated filtering rules
       +-- Server       -> simulated open service ports
       +-- Workstation  -> deterministic packet creation and endpoint stats

Packet lifecycle:
CREATED -> ROUTING -> ALLOWED -> DELIVERED
                    \\-> BLOCKED
       \\-> DROPPED when a route or destination is unavailable
```

`Network` coordinates packet flow. It validates that source and destination
devices exist, sends packets through the router and firewall when present, and
delivers them to the destination device. Devices retain only their own state
and behavior.

The `CyberGuardCore` library contains all Phase 2 logic. The console
application and tests depend on the library; no graphical or network runtime
dependency is involved.