# CyberGuard Architecture

CyberGuard is a C++20 educational simulation. The native application models
packets and devices in memory; it does not open sockets or send network traffic.
Live capture is a separate optional Python component, not part of the C++ simulator.
The browser console is a separate JavaScript simulation and does not call the
C++ library. The optional Python live sensor uses Scapy to passively observe IPv4
packet metadata from one selected interface and sends heuristic detections to
the same SQLite incident store.

## Components

```text
CyberGuard executable (src/main.cpp)
                 |
                 v
        CyberGuardCore library
        +--------+---------+
        |                  |
      Packet             Network
                           |
                           +-- owns NetworkDevice instances
                               +-- Router
                               +-- Firewall
                               +-- Server
                               +-- Workstation

CyberGuardTests and CyberGuardSmokeTest also link to CyberGuardCore.
The default browser app is served from the repository root via `backend/server.py`. The Python runtime is composed by `backend/application.py`; the HTTP handler receives a `CyberGuardApplication` instance through dependency injection. The application owns the incident repository, IOC repository, live monitor, anomaly model lifecycle, and native simulator bridge.
Legacy files under web/ are kept as reference assets and are not the main entry route.
```

`Network` owns devices in a `std::vector<std::unique_ptr<NetworkDevice>>`.
Device identifiers are looked up by name or IP address. Adding a null device
or a device with an identifier already present throws `std::invalid_argument`.
Device IP addresses are validated as IPv4 when a device is constructed.
Removal accepts either identifier, removes the removed device's route from each
router, and refreshes the remaining router entries.

## Native Packet Flow

`Network::routePacket` coordinates one packet through these stages:

1. Increment the network's created-packet counter.
2. Find a source and destination by packet IP address. If either is missing,
   or the source device is offline, mark the packet `DROPPED` and increment
   the dropped counter.
3. Set the packet to `ROUTING`. If a router exists, call its receive and
   forwarding operations. A failed router step drops the packet.
4. If a firewall exists, inspect the packet. A blocked packet increments the
   blocked counter and is not sent to its destination.
5. Ask the destination device to receive the packet. A rejection drops it;
   success marks it `DELIVERED` and increments the delivered counter.

The packet statuses available in `Packet.hpp` are `CREATED`, `ROUTING`,
`ALLOWED`, `BLOCKED`, `DELIVERED`, and `DROPPED`. `ALLOWED` is set by an
accepting firewall; without a firewall, routing can proceed directly to the
destination.

```text
CREATED
  +-- missing source or destination --------------------------> DROPPED
  +-- ROUTING
       +-- router failure ------------------------------------> DROPPED
       +-- firewall block ------------------------------------> BLOCKED
       +-- destination rejects packet ------------------------> DROPPED
       +-- destination accepts packet ------------------------> DELIVERED
```

The network uses the first router and first firewall found in its device list.
When devices are added or removed, `Network` refreshes router entries for
currently registered destinations. Removing a device also removes its stale
route from each router before refreshing the remaining entries. Routing is a
simple in-memory model, not a topology-aware routing protocol; `Network`
separately rejects unknown destinations before consulting the router.

## Device Responsibilities

- `Router` records received, forwarded, and dropped packet counts and forwards
  only when it is online and has a route for the destination IP.
- `Firewall` checks enabled rules in insertion order. The first matching rule
  decides; if none match, the packet is allowed. Rules can optionally match
  source IP, destination IP, protocol, and destination port.
- `Server` accepts a packet only when it is online, addressed to its own IP,
  and the destination port is an open simulated service.
- `Workstation` can create packets and accept packets addressed to its IP.

## Packet Data and Validation

`Packet` stores an ID, source/destination IPv4 addresses, source/destination
ports, protocol (`TCP`, `UDP`, or `ICMP`), size, timestamp, and mutable status.
Construction rejects malformed IPv4 addresses (including empty trailing
octets), ports above 65535, and a zero packet size. Device constructors use
the same IPv4 validation. Port zero is representable by the C++ model.

## Boundaries and Limitations

- The C++ simulator and browser demo do not send real network traffic. The optional Python live sensor passively captures packet metadata when explicitly started and supported by the host.
- The native C++ simulator and the browser simulator maintain separate state and
  separate logic; browser changes do not update the C++ process.
- The browser topology is a presentation model. Its Internet symbol is not a
  registered C++ device.
- The project serves the browser UI from the repository root on
  `http://localhost:8000/` through the backend server, while the legacy `web/`
  folder remains non-primary reference content.
- Detection rules and incident management are implemented as local-first
  foundations; automated response, calibrated ML risk scoring, SFML, Docker,
  and AI automation remain out of scope.

See [oop.md](oop.md) for class design and ownership details, and
[development-process.md](development-process.md) for build, test, and browser
instructions.

## Python Application Object Graph

```text
create_server()
    |
    +-- CyberGuardHandler
    |       |
    |       +-- injected CyberGuardApplication
    |
    +-- CyberGuardApplication
            +-- IncidentStore (SQLite repository)
            +-- ThreatIntelStore (SQLite IOC/notes repository)
            +-- LiveTrafficMonitor
            |       +-- DetectionWindowEngine
            +-- SimulationBridge
            +-- local anomaly model lifecycle/cache
```

The application object is the composition root: it creates or receives dependencies,
owns their lifecycle, and exposes use-case operations to the HTTP layer. This keeps
the request handler from constructing repositories or relying on module-level
mutable service globals. The native simulator bridge is an object with injectable
process execution, allowing its orchestration to be tested without launching a
real executable.


## Browser Application Object Graph

```text
app.js
  +-- NetworkSimulatorController
  +-- IncidentDashboardController
  +-- LiveMonitorController
  |      +-- IncidentDashboardController (injected)
  +-- ThreatIntelController
  |      +-- IncidentDashboardController (injected)
  +-- AnomalyDashboardController
```

The JavaScript controllers own their feature-specific UI state, DOM references, event handlers, and async API interactions. The live-monitor and threat-intelligence controllers receive the incident controller as a dependency when they need to refresh the incident view. The browser simulator remains an independent presentation simulation; it does not call the native C++ network engine.
