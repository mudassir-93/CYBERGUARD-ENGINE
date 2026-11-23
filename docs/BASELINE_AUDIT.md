# CyberGuard Baseline Audit

**Audited ref:** `master` at `d46fcb6c9e150a86aee1867f73003a13e0118bc4`  
**Audit branch:** `research/cyberguard-upgrade-plan`  
**Audit type:** Static source and repository inspection  
**Runtime verification:** Pending first CI run; do not treat source inspection as a passing test run.

## 1. Repository inventory

The repository currently contains:

- C++20/CMake native simulator and console demonstration.
- Core packet, network, and abstract device types.
- Router, firewall, server, and workstation implementations.
- GoogleTest unit tests and a small smoke test.
- A standalone browser simulation using root-level `index.html`, `app.js`, and `dashboard.css`.
- A Python standard-library HTTP server that serves the repository root.
- Architecture, OOP, and development-process documentation.
- A legacy `web/` copy of browser assets.
- A tracked Python bytecode file at `backend/__pycache__/server.cpython-313.pyc`.

No production API, flow aggregator, threat scenario engine, detection engine, incident manager, ML pipeline, threat-intelligence adapter, or AI integration is present in the audited baseline.

## 2. Architecture and data-flow findings

### Native C++ simulator

The C++ model is an in-memory simulation. It does not open sockets, capture packets, or transmit network traffic. The native network routes a `Packet` through the first registered Router and Firewall it finds, then asks the destination device to receive it.

The current `Packet` model contains a single packet's source/destination IPv4 addresses, ports, protocol, size, timestamp, ID, and status. It does not represent a bidirectional connection or an aggregated flow. A future detection pipeline therefore needs a separate, versioned flow record and an aggregation window rather than treating individual packet fields as a ready-made ML feature vector.

### Browser dashboard

The browser dashboard keeps its own JavaScript device catalogue, rules, counters, and event list. It does not call the C++ library or a backend API. Its displayed topology is a visual model; the Internet entry is not a live network connection.

### Python server

`backend/server.py` currently uses Python's standard-library static HTTP server. It serves the repository root and binds to `0.0.0.0:8000`. There is no API, authentication, persistence, or application service in this backend yet.

## 3. Correctness risks to address with regression tests

These are findings from reading the current source. They are not claims that runtime tests have already reproduced them.

| Priority | Area | Finding | Required regression coverage |
|---|---|---|---|
| High | Source availability | `Network::routePacket` checks that a source exists but does not reject an offline source device. | Sending from an offline workstation must not be delivered; counters and packet status must be consistent. |
| High | Workstation packet creation | `Workstation::createPacket` increments its dropped counter when offline but still increments sent count and returns a normal packet. | Define and test the offline contract; an offline workstation must not report a successful send. |
| Medium | Router route lifecycle | `Network::refreshRouterRoutes` only adds routes; it never removes entries for deleted devices. | Removing a device must remove its route; re-adding it must behave deterministically. |
| Medium | IPv4 validation | `Packet::validateIpAddress` can exit after a final dot without parsing an empty final octet, so a trailing-dot address may be accepted. | Reject `10.0.0.1.`, repeated separators, empty octets, and out-of-range octets. |
| Medium | Device identity | `NetworkDevice` stores its IP address without validating it, and `Network::addDevice` does not validate the device's address. | Reject malformed device IPs and ambiguous name/IP identity. |
| Medium | Browser demo lifecycle | The demo schedules multiple packets with `setTimeout`; reset and pause do not cancel an already scheduled sequence. | Reset/pause during a running demo must not allow stale scheduled packets to mutate the reset/paused state. |
| Medium | Local server exposure | The static server binds to all network interfaces by default. | Default to loopback for local development; require explicit opt-in for LAN exposure. |

### Additional design observations

- The network uses the first Router and first Firewall in device insertion order. This is currently a simple single-router/single-firewall model, not a general topology engine.
- Firewall rules are evaluated in insertion order and the first matching rule decides; no match defaults to allow. This policy must be explicit in future product UX and tests.
- Packet port zero is accepted by the C++ model. Decide whether that remains a valid simulation value by protocol and scenario rather than changing it casually.
- The packet constructor validates ports through `validatePort` and then repeats a redundant range check.
- The existing test suite does not cover offline source behavior, route removal, invalid device IPs, trailing-dot IPs, or browser demo cancellation.
- The smoke test uses C++ `assert`; assertions can be disabled in release builds, so it should remain a smoke check rather than the only correctness test.

## 4. Repository hygiene and release concerns

1. `backend/__pycache__/server.cpython-313.pyc` is tracked. Future Python bytecode and cache directories should be ignored. Removing the existing tracked bytecode should be a separate, reviewable cleanup.
2. `.gitignore` currently only excludes the C++ build directory and Visual Studio user files; it does not exclude Python caches, virtual environments, local environment files, model artifacts, datasets, or runtime databases.
3. The README contains placeholder screenshots hosted at `via.placeholder.com`; they should be replaced with actual screenshots before a public product release.
4. The README shows a project-educational license badge, but no root `LICENSE` file is present in the audited tree. The owner must choose a license; do not assume MIT or another open-source license.
5. CMake fetches GoogleTest 1.14.0 through `FetchContent` using a tag URL without a content hash. A future supply-chain hardening pass should pin and verify the dependency artifact.
6. The dashboard imports Google Fonts from an external host. The UI should degrade gracefully without internet access if local-first operation is a requirement.

## 5. Baseline CI introduced on the upgrade branch

Workflow: `.github/workflows/ci.yml`

The workflow is configured to:
- Build the C++20 project on Ubuntu and Windows runners.
- Run CTest on both platforms.
- Syntax-check `backend/server.py`.
- Syntax-check root `app.js` with Node.js.
- Run on pushes to `master`, `research/**`, and `feature/**`, and on pull requests targeting `master`.

First run: [CyberGuard CI run 1](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45159669668)

The run must finish before recording a pass/fail result. A successful hosted build is useful baseline evidence, but it does not replace local Windows validation of the complete user workflow.

## 6. Recommended first implementation milestone

Before building ML or AI features, harden and test the existing simulation contract:

1. Add regression tests for offline sources and workstations.
2. Fix route removal so router state reflects the current device set.
3. Correct strict IPv4 validation and validate device addresses.
4. Make browser demo sequences cancellable and reset-safe.
5. Default the Python server to loopback, with explicit host/port configuration.
6. Add Python cache, virtual environment, local database, dataset, and model-artifact ignores without deleting existing tracked files in the same change.
7. Re-run Linux and Windows CI, then ask the owner to run the documented local Windows workflow.

Only after this milestone is green should the flow/traffic schema and threat-scenario engine be introduced.

## 7. Safety and scope

All initial scenarios remain simulated and local to the application. Do not add real packet capture, third-party scanning, autonomous blocking, or destructive network actions as part of this baseline-hardening milestone.
