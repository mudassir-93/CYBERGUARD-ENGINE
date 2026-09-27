dependency is involved.
# CyberGuard Architecture

CyberGuard is a C++20 educational simulation. The native application models
packets and devices in memory; it does not open sockets or send network traffic.
The browser console is a separate JavaScript simulation and does not call the
C++ library.

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
web/ is an independent static browser application.
```

`Network` owns devices in a `std::vector<std::unique_ptr<NetworkDevice>>`.
Device identifiers are looked up by name or IP address. Adding a null device
or a device with an identifier already present throws `std::invalid_argument`.
Removal accepts either identifier and refreshes the router's synthetic route
entries.

## Native Packet Flow

`Network::routePacket` coordinates one packet through these stages:

1. Increment the network's created-packet counter.
2. Find a source and destination by packet IP address. If either is missing,
        mark the packet `DROPPED` and increment the dropped counter.
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
When devices are added or removed, `Network` calls its route-refresh routine,
which adds direct entries whose next hop is the destination IP itself. It does
not clear entries for removed devices. Routing is a simple in-memory model,
not a topology-aware routing protocol; `Network` separately rejects unknown
destinations before consulting the router.

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
Construction rejects malformed IPv4 addresses, ports above 65535, and a zero
packet size. Port zero is representable by the C++ model.

## Boundaries and Limitations

- No component sends, receives, or captures real network traffic.
- The native C++ simulator and `web/` simulator maintain separate state and
       separate logic; browser changes do not update the C++ process.
- The browser topology is a presentation model. Its Internet symbol is not a
       registered C++ device.
- The current project has no threat generator, detection engine, incident
       manager, response engine, scenario engine, SFML UI, Docker setup, or AI.

See [oop.md](oop.md) for class design and ownership details, and
[development-process.md](development-process.md) for build, test, and browser
instructions.