# CYBERGUARD — AI Development Instructions

## 1. Project Overview

Build **CyberGuard**, a standalone open-source **C++20 cybersecurity simulation engine** designed as a university-level OOP project and portfolio-quality software project.

The primary goal is to demonstrate strong C++ Object-Oriented Programming through a realistic cybersecurity simulation.

CyberGuard must:

- Simulate a small computer network.
- Simulate normal network traffic.
- Generate simulated cyber threats.
- Detect suspicious behavior.
- Calculate threat/risk scores.
- Create and track security incidents.
- Allow simulated defensive responses.
- Visualize the network and events using **SFML**.
- Include automated tests.
- Use **CMake** as the build system.
- Support **Docker** for reproducible headless builds/tests.
- Be maintained as a clean **GitHub open-source project**.

### Important Scope Rule

This is a **simulation and educational project**.

Do NOT implement real-world offensive cybersecurity tooling, real packet injection, real credential attacks, exploit execution, malware, persistence, credential theft, or anything intended to attack external systems.

All attacks must be simulated internally using fictional/generated data.

---

# 2. Core Technology Stack

Use:

- **C++20**
- **CMake**
- **SFML 3.x** for graphical visualization
- **GoogleTest** for automated testing
- **nlohmann/json** for scenario/configuration files where useful
- **spdlog** or a lightweight custom logger for logging
- **Docker** for headless build/test environments
- **Git + GitHub**
- **GitHub Actions** for CI

Do not introduce React, FastAPI, PostgreSQL, Redis, cloud infrastructure, or external AI APIs unless explicitly requested later.

The first version must remain a self-contained C++ application.

---

# 3. Engineering Principles

Follow these rules throughout development.

## Code Quality

Write:

- readable C++20
- modular code
- small focused classes
- meaningful names
- RAII
- smart pointers where ownership requires them
- const-correctness
- appropriate STL containers
- exception handling where appropriate
- no unnecessary global variables
- no duplicated logic

Avoid:

- giant classes
- giant functions
- hard-coded magic values
- unnecessary singletons
- raw owning pointers
- copy-pasted code
- tightly coupling the simulator to SFML
- putting all logic inside `main.cpp`

---

# 4. Architecture

Use a layered architecture.

```text
                 CYBERGUARD
                     |
        +------------+------------+
        |            |            |
        v            v            v
      CORE        SIMULATION    SECURITY
        |            |            |
        |            |       +----+----+
        |            |       |         |
        v            v       v         v
     Network      Scenarios Detection Incidents
     Packet       Events     Threats   Response
        |            |          |
        +------------+----------+
                     |
                     v
                  SFML UI
```

Keep the simulation/security engine independent from SFML as much as practical.

The core engine should be usable in **headless mode** for tests and Docker.

---

# 5. Recommended Project Structure

Create this structure:

```text
CyberGuard/
│
├── include/
│   ├── core/
│   │   ├── Packet.hpp
│   │   ├── Network.hpp
│   │   └── NetworkDevice.hpp
│   │
│   ├── devices/
│   │   ├── Router.hpp
│   │   ├── Firewall.hpp
│   │   ├── Server.hpp
│   │   └── Workstation.hpp
│   │
│   ├── threats/
│   │   ├── Threat.hpp
│   │   ├── PortScan.hpp
│   │   ├── BruteForce.hpp
│   │   ├── TrafficSpike.hpp
│   │   └── SuspiciousPacket.hpp
│   │
│   ├── detection/
│   │   ├── DetectionEngine.hpp
│   │   └── RiskScorer.hpp
│   │
│   ├── incidents/
│   │   ├── Incident.hpp
│   │   └── IncidentManager.hpp
│   │
│   ├── response/
│   │   └── ResponseEngine.hpp
│   │
│   ├── simulation/
│   │   ├── SimulationEngine.hpp
│   │   ├── ScenarioManager.hpp
│   │   └── EventGenerator.hpp
│   │
│   ├── logging/
│   │   └── Logger.hpp
│   │
│   └── graphics/
│       ├── Renderer.hpp
│       ├── NetworkView.hpp
│       └── UIManager.hpp
│
├── src/
│   ├── core/
│   ├── devices/
│   ├── threats/
│   ├── detection/
│   ├── incidents/
│   ├── response/
│   ├── simulation/
│   ├── logging/
│   ├── graphics/
│   └── main.cpp
│
├── tests/
│   ├── PacketTests.cpp
│   ├── NetworkTests.cpp
│   ├── FirewallTests.cpp
│   ├── ThreatTests.cpp
│   ├── DetectionTests.cpp
│   ├── IncidentTests.cpp
│   └── SimulationTests.cpp
│
├── assets/
│   ├── fonts/
│   └── textures/
│
├── scenarios/
│   ├── normal.json
│   ├── port_scan.json
│   ├── brute_force.json
│   ├── traffic_spike.json
│   └── server_attack.json
│
├── docs/
│   ├── architecture.md
│   ├── oop.md
│   ├── simulation.md
│   └── testing.md
│
├── CMakeLists.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
├── LICENSE
├── .gitignore
└── .github/
    └── workflows/
        └── ci.yml
```

Adjust the structure if a better architectural decision is justified, but keep the project modular.

---

# 6. OOP Requirements

OOP is one of the most important grading requirements.

The project must clearly demonstrate:

## Encapsulation

Keep internal state private/protected and expose controlled interfaces.

Example:

```cpp
class NetworkDevice {
private:
    std::string name;
    std::string ipAddress;
    bool online;

public:
    NetworkDevice(...);

    const std::string& getName() const;
    const std::string& getIpAddress() const;
    bool isOnline() const;

    void setOnline(bool value);

    virtual void processPacket(const Packet& packet) = 0;
    virtual std::string getType() const = 0;

    virtual ~NetworkDevice() = default;
};
```

## Abstraction

Create abstract base classes where appropriate.

Examples:

```text
NetworkDevice
Threat
```

## Inheritance

Use inheritance meaningfully.

```text
NetworkDevice
├── Router
├── Firewall
├── Server
└── Workstation
```

```text
Threat
├── PortScan
├── BruteForce
├── TrafficSpike
└── SuspiciousPacket
```

## Polymorphism

The engine should be able to operate on base-class references/pointers.

Example:

```cpp
std::vector<std::unique_ptr<NetworkDevice>> devices;
```

and:

```cpp
for (const auto& device : devices) {
    device->processPacket(packet);
}
```

Do not create inheritance only for the sake of showing inheritance. Each derived class should have meaningful behavior.

## Composition

Use composition for relationships such as:

```text
SimulationEngine
 ├── Network
 ├── DetectionEngine
 ├── IncidentManager
 └── ResponseEngine
```

## Aggregation

The network can contain references/ownership of devices and simulation entities where appropriate.

## Templates / STL

Use templates and STL naturally where useful.

Examples:

- `std::vector`
- `std::unordered_map`
- `std::queue`
- `std::optional`
- `std::variant`
- `std::unique_ptr`
- `std::shared_ptr` only when genuinely needed
- custom generic utilities/templates where they improve the design

---

# 7. Core Classes

Implement these incrementally.

## Packet

Represents a simulated network packet.

Possible properties:

```text
source IP
destination IP
source port
destination port
protocol
size
timestamp
packet type
suspicious flag
```

Example:

```cpp
enum class Protocol {
    TCP,
    UDP,
    ICMP
};
```

---

# 8. NetworkDevice

Abstract base class.

Derived classes:

### Router

Responsibilities:

- forward simulated packets
- maintain routing behavior
- report network status

### Firewall

Responsibilities:

- inspect packets
- apply simulated rules
- allow/block traffic
- generate security events

### Server

Responsibilities:

- receive packets
- simulate services
- track connections
- expose simulated service ports

### Workstation

Responsibilities:

- generate normal traffic
- receive traffic
- participate in attack scenarios

---

# 9. Threat System

Create an abstract:

```cpp
class Threat {
public:
    virtual ~Threat() = default;

    virtual void execute(SimulationContext& context) = 0;
    virtual std::string getName() const = 0;
    virtual int getBaseSeverity() const = 0;
};
```

Implement simulated threats.

## PortScan

Simulate repeated attempts to contact multiple ports.

Example:

```text
PC-01
 ↓
Port 21
Port 22
Port 23
Port 80
Port 443
Port 8080
```

The engine should recognize the abnormal pattern.

## BruteForce

Simulate repeated failed login events.

Do not perform real authentication attacks.

Example:

```text
Failed Login
Failed Login
Failed Login
Failed Login
Failed Login

→ Suspicious Authentication Activity
```

## TrafficSpike

Generate an unusual increase in simulated packet volume.

## SuspiciousPacket

Generate packets with suspicious simulated characteristics.

---

# 10. Detection Engine

Create a dedicated `DetectionEngine`.

It should:

1. receive events/packets
2. inspect patterns
3. identify suspicious behavior
4. classify threats
5. calculate risk
6. generate detection events

Example:

```text
Packet/Event
     ↓
Analyzer
     ↓
Pattern Detection
     ↓
Threat Classification
     ↓
Risk Score
     ↓
Security Alert
```

Do not mix detection logic into the UI.

---

# 11. Risk Scoring

Create a simple explainable risk model.

For example:

```text
0–29   LOW
30–59  MEDIUM
60–79  HIGH
80–100 CRITICAL
```

The exact thresholds can be configurable.

Risk can consider:

- event frequency
- severity
- affected device
- number of targets
- repetition
- abnormal traffic volume

Make the score deterministic enough for testing.

Example:

```text
Threat: Port Scan
Targets: 8
Packets: 120
Severity: HIGH

Risk Score: 82
Classification: CRITICAL
```

---

# 12. Incident System

Create:

```text
Incident
IncidentManager
```

An incident should contain information such as:

```text
ID
timestamp
threat type
source
target
severity
risk score
status
events
description
```

Possible states:

```cpp
enum class IncidentStatus {
    DETECTED,
    INVESTIGATING,
    CONTAINED,
    RESOLVED
};
```

---

# 13. Response Engine

The user should be able to perform simulated defensive actions.

Examples:

```text
[1] Investigate
[2] Block Source
[3] Isolate Device
[4] Resolve Incident
```

These actions affect the simulated network state.

Example:

```text
Port Scan Detected
       ↓
User selects BLOCK SOURCE
       ↓
Firewall rule created
       ↓
Future packets blocked
       ↓
Threat becomes contained
```

Everything remains simulated.

---

# 14. Simulation Engine

Create a central:

```cpp
SimulationEngine
```

Responsibilities:

- manage simulation state
- advance simulation time
- generate events
- route packets
- execute threats
- invoke detection
- update incidents
- notify the renderer

The simulation should support:

```text
NORMAL
MANUAL
SCENARIO
STRESS_TEST
```

---

# 15. Scenario System

Scenarios should be reproducible.

Example:

```text
Scenario: Server Attack

T+00s  Normal network traffic
T+05s  Port scan begins
T+10s  Suspicious packets detected
T+15s  Security alert generated
T+20s  Incident created
T+25s  User blocks source
T+30s  Attack contained
T+35s  Incident resolved
```

Store scenario definitions in JSON where practical.

Do not make JSON parsing part of the core security logic.

---

# 16. SFML Visualization

Use SFML to create a clean cybersecurity simulation interface.

The UI should feel like a **network simulation / SOC-style visualization**, not a generic form application.

Suggested layout:

```text
+------------------------------------------------------+
|                  CYBERGUARD                          |
|             CYBERSECURITY SIMULATOR                 |
+------------------------------------------------------+
|                                                      |
|        INTERNET                                      |
|           ●                                          |
|           |                                          |
|        [ROUTER]                                      |
|           |                                          |
|       [FIREWALL]                                     |
|        /    |    \                                   |
|       /     |     \                                  |
|   [PC-01] [SERVER] [PC-02]                           |
|                                                      |
|   ●───────▶───────●                                  |
|       PACKET                                         |
|                                                      |
+------------------------------------------------------+
| Threats | Events | Risk | Simulation Time           |
+------------------------------------------------------+
```

Visual states:

- healthy
- warning
- suspicious
- compromised
- offline

Use animations for:

- packet movement
- blocked packets
- alerts
- threat detection
- device isolation

Keep the visual design clean and professional.

---

# 17. Controls

Provide keyboard/mouse controls.

Suggested:

```text
SPACE  → pause/resume
N      → normal mode
M      → manual mode
S      → scenario mode
T      → trigger test threat
R      → reset simulation
ESC    → exit
```

Also provide graphical buttons where practical.

---

# 18. Event System

Use a clean event model.

Possible event types:

```text
PacketCreated
PacketForwarded
PacketBlocked
ThreatDetected
IncidentCreated
DeviceIsolated
FirewallRuleAdded
IncidentResolved
```

Consider:

```cpp
enum class EventType {
    PACKET_CREATED,
    PACKET_BLOCKED,
    THREAT_DETECTED,
    INCIDENT_CREATED,
    DEVICE_ISOLATED,
    INCIDENT_RESOLVED
};
```

Events should contain structured information.

---

# 19. Logging

Implement structured logs.

Example:

```text
[INFO] Simulation started
[INFO] Packet generated: PC-01 -> Server
[WARN] Suspicious traffic detected
[ALERT] Port scan detected from 192.168.1.11
[ALERT] Incident #004 created
[ACTION] Source blocked by firewall
[INFO] Incident #004 contained
```

Logs should be useful for debugging and demonstration.

---

# 20. Testing

Use GoogleTest.

Tests must cover the core logic.

Minimum tests:

### Packet Tests

- packet creation
- packet properties
- protocol handling

### Firewall Tests

- allowed packet
- blocked packet
- rule matching

### Threat Tests

- threat creation
- severity
- simulated execution

### Detection Tests

- normal traffic should not trigger false alerts unnecessarily
- repeated login failures trigger detection
- port scan pattern triggers detection
- traffic spike triggers detection

### Incident Tests

- incident creation
- status transitions
- containment
- resolution

### Simulation Tests

- simulation starts
- events are generated
- scenarios execute
- reset works

Tests must not depend on graphical rendering.

---

# 21. Headless Mode

The engine should support running without SFML graphics.

Example:

```bash
CyberGuard --headless
```

Possible output:

```text
CYBERGUARD HEADLESS SIMULATION

Scenario: Port Scan

Events: 150
Threats Detected: 1
Incidents Created: 1
Packets Blocked: 42
Final Risk Score: 87
Status: CONTAINED
```

This is important because:

- automated tests can run without graphics
- Docker can run the engine
- GitHub Actions can test it
- future servers/automation can use the engine

---

# 22. Stress Test

Implement a stress-test mode.

Example:

```text
Events generated: 100000
Events processed: 100000
Threats detected: 8421
Incidents created: 127
Packets blocked: 52340

Processing time: 1.84 seconds
Events/second: 54347
```

Measure performance using:

```cpp
std::chrono
```

Do not generate real network traffic.

Everything must remain internal simulation data.

---

# 23. CMake

Use modern CMake.

Prefer:

```bash
cmake -S . -B build
cmake --build build
```

Use separate targets where appropriate.

Example architecture:

```text
CyberGuardCore
CyberGuardApp
CyberGuardTests
```

The core library should contain simulation/security logic.

The graphical application should depend on the core library.

Tests should depend on the core library.

Conceptually:

```text
              CyberGuardCore
                /        \
               /          \
              v            v
       CyberGuardApp   CyberGuardTests
           |
          SFML
```

---

# 24. Docker

Create a Docker environment for the **headless engine and testing**.

The container should:

- install required C++ build tools
- configure CMake
- build the project
- run tests
- optionally execute the headless simulator

Do not require an X11/Windows GUI environment inside Docker for the first version.

Example workflow:

```bash
docker build -t cyberguard .
docker run --rm cyberguard
```

And eventually:

```bash
docker compose run --rm cyberguard-tests
```

---

# 25. GitHub

Prepare the project as an open-source repository.

Repository should contain:

```text
README.md
LICENSE
CONTRIBUTING.md
.gitignore
docs/
tests/
src/
include/
Dockerfile
CMakeLists.txt
```

Use meaningful commits.

Examples:

```text
chore: initialize project
feat: add network device abstraction
feat: implement router and server
feat: implement firewall simulation
feat: add packet system
feat: add threat hierarchy
feat: add detection engine
feat: add incident management
feat: add SFML visualization
test: add detection engine tests
build: add Docker support
ci: add GitHub Actions pipeline
docs: add architecture documentation
```

---

# 26. GitHub Actions

Create CI that:

```text
Push / Pull Request
        ↓
Checkout repository
        ↓
Install dependencies
        ↓
Configure CMake
        ↓
Build
        ↓
Run GoogleTests
        ↓
Run headless smoke test
        ↓
Build Docker image
        ↓
PASS / FAIL
```

Do not make CI dependent on graphical rendering.

---

# 27. README Requirements

The README must eventually contain:

## CyberGuard

Short project description.

## Features

List major features.

## Architecture

Include an ASCII architecture diagram.

## OOP Concepts

Explicitly explain where:

- abstraction
- inheritance
- polymorphism
- encapsulation
- composition
- aggregation

are used.

## Build

Show Windows/Linux build instructions.

## Run

Show graphical and headless commands.

## Docker

Show Docker commands.

## Testing

Show test commands.

## Screenshots

Add screenshots once the UI exists.

## Project Structure

Explain the important folders.

## Roadmap

Show completed and planned features.

## License

Use an appropriate open-source license.

---

# 28. Development Strategy

IMPORTANT:

**Do NOT generate the entire project in one giant response or one giant code generation step.**

Build incrementally.

Use this order:

```text
PHASE 1
Project setup
↓
CMake
↓
Git
↓
Basic executable

PHASE 2
NetworkDevice
↓
Router
↓
Firewall
↓
Server
↓
Workstation
↓
Network

PHASE 3
Packet
↓
Packet routing
↓
Firewall rules

PHASE 4
Threat abstraction
↓
PortScan
↓
BruteForce
↓
TrafficSpike
↓
SuspiciousPacket

PHASE 5
DetectionEngine
↓
RiskScorer
↓
Alerts

PHASE 6
Incident
↓
IncidentManager
↓
ResponseEngine

PHASE 7
SimulationEngine
↓
Event system
↓
ScenarioManager
↓
Stress testing

PHASE 8
SFML visualization

PHASE 9
GoogleTest

PHASE 10
Docker

PHASE 11
GitHub Actions

PHASE 12
Documentation + polish
```

---

# 29. Mandatory Development Workflow

For every feature:

```text
1. Explain the design
2. Create/update header
3. Create/update source
4. Compile
5. Run tests
6. Fix errors
7. Add/modify tests
8. Run again
9. Check architecture
10. Commit the feature
```

Never silently skip compilation or testing.

When modifying existing code:

- inspect the existing architecture first
- preserve working functionality
- avoid unnecessary rewrites
- explain important architectural changes

---

# 30. Definition of Done

A feature is NOT complete just because the code was written.

A feature is complete only when:

```text
[ ] Code implemented
[ ] Compiles successfully
[ ] Tests added
[ ] Tests pass
[ ] No obvious memory/resource issues
[ ] Architecture remains modular
[ ] Documentation updated if necessary
[ ] Git commit created
```

---

# 31. Final Expected Demo

The finished project should be able to demonstrate something like:

```text
====================================================
                 CYBERGUARD
          CYBERSECURITY SIMULATOR
====================================================

Network:

             INTERNET
                 |
              ROUTER
                 |
             FIREWALL
            /    |    \
         PC-01 SERVER  PC-02

----------------------------------------------------
SIMULATION
----------------------------------------------------

Normal traffic...
Normal traffic...
Normal traffic...

[!] Port scan detected from PC-01

Threat: PORT SCAN
Severity: HIGH
Risk Score: 84

Incident #004 created.

User action:
> Block Source

Firewall rule added.

Packets blocked: 37

Threat status: CONTAINED
Incident status: RESOLVED

----------------------------------------------------
STATISTICS
----------------------------------------------------

Events:             1,482
Packets:            1,201
Threats detected:   4
Incidents:          3
Packets blocked:    87
Security score:     91%
----------------------------------------------------
```

The graphical version should visualize the same process.

---

# 32. What NOT to Do

Do not turn this into:

- student management system
- library management system
- banking management system
- CRUD application
- simple console menu project
- fake "AI" chatbot
- real hacking tool
- real network scanner
- malware
- exploit framework
- credential attack tool

The identity of the project should remain:

> **A C++ Object-Oriented Cybersecurity Simulation Engine with Visual Network Simulation.**

---

# 33. Priority

When making implementation decisions, prioritize:

1. Correct C++ OOP
2. Clean architecture
3. Working simulation
4. Testability
5. Visual quality
6. Performance
7. Docker reproducibility
8. GitHub/open-source quality
9. Documentation

Do not sacrifice architecture merely to add flashy features.

---

# 34. AI Coding Agent Instructions

You are acting as the **senior C++ software engineer** for this project.

Before changing code:

- inspect the repository
- understand existing classes
- identify dependencies
- avoid breaking existing functionality

When implementing a feature:

1. State what you are going to build.
2. Explain which classes/files are affected.
3. Implement it.
4. Build the project.
5. Run relevant tests.
6. Fix compilation/test failures.
7. Summarize what changed.
8. Suggest the next logical milestone.

Do not ask for confirmation for every tiny implementation decision.

Make reasonable engineering decisions yourself.

However, if a decision would fundamentally change the architecture or project scope, stop and explain the trade-off before proceeding.

Always favor a maintainable, educational, modular C++ implementation over a quick hack.

---

# 35. First Task

Start with **Phase 1 only**.

Do NOT implement the entire simulator yet.

Perform these tasks:

```text
1. Inspect the current repository.
2. Create the CyberGuard project structure.
3. Create CMakeLists.txt.
4. Create a basic C++20 executable.
5. Create the core library target.
6. Create the initial NetworkDevice abstraction.
7. Add a minimal Network class.
8. Create a clean main.cpp.
9. Add a basic smoke test.
10. Build the project.
11. Run the test.
12. Make sure the project works before continuing.
```

The first successful output should be similar to:

```text
====================================
        CYBERGUARD ENGINE
====================================

Network initialized.

Devices: 0
Threats: 0
Incidents: 0

Engine initialized successfully.
```

After Phase 1 is complete and verified, proceed to the next phase **one milestone at a time**.

---

# Project Philosophy

CyberGuard should feel like a small real software-engineering project rather than a classroom code dump.

The final result should demonstrate:

```text
C++ OOP
   +
Cybersecurity Concepts
   +
Simulation
   +
Graphics
   +
Testing
   +
CMake
   +
Docker
   +
GitHub
```

Build it carefully, test it continuously, and keep the architecture clean.
