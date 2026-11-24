# Object-Oriented Design in CyberGuard

This project uses object-oriented programming to model a small network as a set of cooperating objects. The design is not a generic threat-detection system; it is a focused simulation of packet routing, firewall decisions, and device behavior in a network.

## 1. Core OOP Concepts Used

### Abstraction
The project hides internal complexity behind a simple device interface.

`NetworkDevice` is an abstract base class. It stores the device identity and online state, and it defines the common operations all devices must support:

- `getType()`
- `receivePacket(Packet&)`
- `getStatus()`

This lets the system work with many device types without needing to know the exact class at every point.

### Inheritance
The concrete device types inherit from the same base class:

```text
NetworkDevice
├── Router
├── Firewall
├── Server
└── Workstation
```

Each child class adds its own data and behavior while sharing the same common interface.

Example:

- `Router` adds a routing table and forwarding counters.
- `Firewall` adds a rules list and inspection logic.
- `Server` adds service ports and accept/reject handling.
- `Workstation` adds packet creation and endpoint counters.

### Encapsulation
Each class keeps its own data private and exposes only the operations that should be used externally.

Examples from the project:

- `Packet` stores source/destination IPs, ports, protocol, size, timestamp, and status, and only exposes getters/setters.
- `Router` stores `routingTable_` privately and exposes `addRoute()`, `hasRoute()`, and `forwardPacket()`.
- `Firewall` keeps `rules_` private and exposes `addRule()`, `clearRules()`, and `inspectPacket()`.
- `Server` hides open service ports in `openServices_` and only exposes the relevant service operations.

This protects the internal state and prevents invalid direct manipulation.

### Polymorphism
The most important polymorphic behavior in the project is that a single `Network` can hold different device types in one collection:

```cpp
std::vector<std::unique_ptr<NetworkDevice>> devices_;
```

Then the system calls the same interface on each object:

```cpp
device->receivePacket(packet)
```

This works because `Router`, `Firewall`, `Server`, and `Workstation` all override the same virtual methods inherited from `NetworkDevice`.

So even though each device behaves differently, the network treats them consistently.

### Composition
The system also uses composition heavily.

`Network` is not a subclass of the devices; it is an object that owns them. It contains:

- a collection of devices
- a statistics record for packet counts

This is a classic composition relationship:

```text
Network
└── owns many NetworkDevice objects
```

Likewise:

- `Firewall` owns a list of `FirewallRule` objects
- `Router` owns a routing table map
- `Server` owns a set of open service ports
- `Packet` is a data object passed between devices

## 2. Main Classes and Their Roles

### `Packet`
`Packet` is the data object used throughout the simulation.

It contains:

- source IP and destination IP
- source port and destination port
- protocol
- payload size
- timestamp
- status

It validates input such as IP format and port ranges, which makes the object more reliable.

### `NetworkDevice`
This is the abstract base class for every device in the network. It defines the shared identity and lifecycle behavior:

- name
- IP address
- online/offline status
- common virtual interface

This is the foundation of the OOP structure.

### `Router`
`Router` represents the forwarding element in the network.

It stores a routing table and tracks:

- packets received
- packets forwarded
- packets dropped

Its `receivePacket()` method accepts a packet and updates routing state; `forwardPacket()` checks whether the destination is in the router table.

### `Firewall`
`Firewall` enforces rules.

It contains a list of `FirewallRule` objects and evaluates each incoming packet against the list. A rule can match:

- source IP
- destination IP
- protocol
- port

If a rule blocks the packet, the packet status becomes `BLOCKED` and the firewall denies it.

### `Server`
`Server` represents a service endpoint.

It stores open ports and verifies whether a packet is addressed to a valid listening service. It then counts:

- packets received
- accepted packets
- rejected packets

### `Workstation`
`Workstation` acts as an endpoint that creates and receives packets.

It can:

- create packets from its own IP
- send packets to other devices
- receive packets addressed to itself
- track packets sent, received, and dropped

### `Network`
`Network` is the coordinator of the simulation.

It is responsible for:

- adding and removing devices
- preventing duplicate names or IPs
- finding devices by name or IP
- refreshing router routes
- routing packets through the system
- updating packet state and statistics

This is the central object that glues the different device objects together.

## 3. OOP Example in This Project

The design uses polymorphism and abstraction in the route flow:

```cpp
PacketStatus Network::routePacket(Packet& packet) {
    const NetworkDevice* source = findDevice(packet.getSourceIp());
    NetworkDevice* destination = findDevice(packet.getDestinationIp());

    Router* router = nullptr;
    Firewall* firewall = nullptr;
    for (const auto& device : devices_) {
        if (router == nullptr) {
            router = dynamic_cast<Router*>(device.get());
        }
        if (firewall == nullptr) {
            firewall = dynamic_cast<Firewall*>(device.get());
        }
    }

    if (router != nullptr && (!router->receivePacket(packet) || !router->forwardPacket(packet))) {
        ...
    }

    if (firewall != nullptr && !firewall->receivePacket(packet)) {
        ...
    }

    if (!destination->receivePacket(packet)) {
        ...
    }

    return packet.getStatus();
}
```

This is a good demonstration of OOP because:

- the exact device type is hidden behind the base class
- each device responds to the same interface in a different way
- the network can coordinate behavior without tightly coupling to each concrete class

## 4. Why This Design Is Good OOP

This project follows solid object-oriented principles because:

- each class has one clear responsibility
- shared behavior is centralized in a base class
- each device behaves differently through overriding methods
- the network owns the object graph instead of using global variables
- data is protected using private state and public interfaces

## 5. Short Professor-Friendly Explanation

If you need to explain it in a few sentences, say:

> This project uses object-oriented programming to model a small network as interacting objects. A base class called `NetworkDevice` defines the common behavior for all devices, while specialized classes like `Router`, `Firewall`, `Server`, and `Workstation` inherit from it and override the behavior to match their roles. The `Network` class organizes these devices, routes packets, and tracks statistics, which demonstrates abstraction, inheritance, polymorphism, encapsulation, and composition in a practical C++ system.

## 6. Scope Note

This OOP design intentionally stays within the implemented project scope. It models networking behavior, rule evaluation, and packet flow, but does not include the unrelated detection, incident-management, or AI modules that were explicitly excluded from the project phase plan.

The C++ object model is only one layer of the application. The Python backend also uses service and repository objects; it must not be described as entirely procedural or as entirely OOP without qualification. The browser layer uses JavaScript objects/classes where they improve state ownership and behavior organization. HTML, CSS, JSON, YAML, and build configuration remain declarative formats and are not converted into artificial classes.

## 7. Backend Application Composition and Dependency Injection

The backend now has an explicit composition root in `backend/application.py`:

- `CyberGuardApplication` owns the incident repository, threat-intelligence repository, live-monitor service, simulation runner, and interface provider.
- `create_application()` constructs the default runtime object graph or an isolated test instance.
- `create_server()` injects one application instance into the HTTP server.
- `CyberGuardHandler` delegates application work through that injected instance instead of accessing module-level global service objects.
- The application owns lifecycle cleanup and the cached local anomaly model.

This is composition and dependency injection: services can be replaced with test doubles without changing the HTTP handler. It also avoids hidden process-wide mutable service state.

## 8. OOP Refactoring Standard for Future Work

New application logic should follow these rules:

1. Give each class one cohesive responsibility; avoid giant manager classes.
2. Keep state private or behind a narrow public interface.
3. Inject repositories, external adapters, clocks, and model loaders when they need to be replaceable in tests.
4. Keep domain rules separate from HTTP, SQLite, Scapy, filesystem, and model-library details.
5. Prefer composition over inheritance unless a genuine substitutable "is-a" relationship exists.
6. Use small pure functions for stateless validation, normalization, and mathematical calculations. OOP does not require wrapping every helper in a class.
7. Do not create classes for HTML, CSS, JSON, YAML, or CI configuration.
8. Add tests around class behavior, object lifecycle, and dependency boundaries.

The backend refactor is incremental. Existing repositories and sensor components already contain classes; small stateless validation, normalization, and mathematical helpers remain pure functions where a class would add no value.

The browser application is now organized into five feature controllers:
- `NetworkSimulatorController` owns simulator state, firewall rules, packet routing, counters, and demo-sequence lifecycle.
- `IncidentDashboardController` owns incident rendering, filtering, status updates, evidence inspection, and analyst-note workflows.
- `LiveMonitorController` owns capture-interface selection, start/stop controls, status polling, and incident refresh coordination through an injected incident controller.
- `ThreatIntelController` owns IOC import and delegates incident refresh to the incident controller.
- `AnomalyDashboardController` owns the analyst-triggered local anomaly-scoring interaction.

Each controller owns its DOM references and event wiring; callbacks are bound to their controller instance. The page-level composition at the end of `app.js` constructs the controllers and injects cross-feature dependencies. HTML and CSS remain declarative presentation assets.

The actual C++ code structure lives in the `include/` and `src/` folders; backend application composition lives in `backend/application.py`; the browser UI is a separate presentation layer.

## 9. Browser Controller Object Graph

```text
app.js composition root
  +-- NetworkSimulatorController
  +-- IncidentDashboardController
  |      +-- incident list / status / evidence / notes
  +-- LiveMonitorController
  |      +-- injected IncidentDashboardController
  +-- ThreatIntelController
  |      +-- injected IncidentDashboardController
  +-- AnomalyDashboardController
```

The browser controllers own feature state and event lifecycle. They call the existing local HTTP API for persistence and monitoring; they do not duplicate backend repositories or ML logic.
