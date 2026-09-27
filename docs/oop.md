# CyberGuard Object-Oriented Design

This document describes the classes and ownership relationships implemented
under `include/` and `src/`. It covers the native C++ simulation; the browser
app in `web/` is implemented separately in JavaScript.

## Inheritance and Abstraction

`NetworkDevice` is an abstract base class. It stores a device name, IPv4
address string, and online flag, and declares virtual operations for type,
packet reception, and status.

```text
                 NetworkDevice
             /       |        |       \
         Router   Firewall  Server  Workstation
```

The four concrete device classes are siblings. Each overrides the common
virtual operations with its own behavior; `Network` can store all of them
through `std::unique_ptr<NetworkDevice>`.

## Class Responsibilities

### `Packet`

`Packet` is a value object containing its ID, source and destination IPs and
ports, protocol, payload size, timestamp, and current status. The constructor
validates the IPv4 address format, rejects ports above 65535, and rejects a
zero size. Its status is changed as the network processes the packet.

### `NetworkDevice`

The base class owns common identity and online state. It is non-copyable and
movable. The virtual destructor allows safe destruction through a base-class
pointer.

### `Router`

The router owns a destination-to-next-hop map and counters for received,
forwarded, and dropped packets. `Network` adds direct destination-IP entries
when devices are registered. `forwardPacket` checks online state and route
presence; it does not implement real network forwarding.

### `Firewall`

The firewall owns an ordered vector of `FirewallRule` values and inspection,
allow, and block counters. A rule can optionally constrain source IP,
destination IP, protocol, and destination port. Disabled rules do not match.
The first matching rule decides the result; the default when no rule matches
is allow.

### `Server`

The server stores open simulated service ports in an `std::unordered_set` and
tracks received, accepted, and rejected packets. It rejects packets when it is
offline, the packet is addressed to another IP, or the destination service is
closed.

### `Workstation`

The workstation creates `Packet` values using its own IP as the source and can
receive packets addressed to itself. It tracks sent, received, and dropped
counts.

### `Network`

`Network` owns devices, prevents null or duplicate device identifiers, finds
and removes devices by name or IP, refreshes router entries, routes packets,
and exposes device and packet statistics. Packet routing is coordinated by
passing a `Packet&`; the network does not take ownership of packets.

## Encapsulation and Ownership

- Device state such as rule lists, service ports, route entries, and counters
  is private to its owning class.
- `Network` owns device lifetimes using `std::unique_ptr`; its `findDevice`
  methods return non-owning observer pointers.
- `Network` is non-copyable and movable, avoiding accidental duplicate
  ownership of devices.
- `Packet` is passed by reference during routing so status changes are visible
  to the caller without transferring packet ownership.
- Read-only accessors expose collections and statistics where required by the
  console and tests.

## Composition

```text
Network
  +-- vector<unique_ptr<NetworkDevice>>
  +-- NetworkStatistics

Packet -- passed by reference to Network and device operations
```

`Network` composes owned devices and network-level statistics. Routers,
firewalls, servers, and workstations each maintain their own device-specific
state. The console application assembles these objects; it does not own a
separate simulation engine abstraction.

## Deliberate Scope

There are no `Threat`, `DetectionEngine`, `IncidentManager`, or
`ResponseEngine` classes in the current code. The browser UI is not an SFML
view and is not connected to the C++ object graph. See
[architecture.md](architecture.md) for packet-flow behavior and
[development-process.md](development-process.md) for the project status.