# CyberGuard Engine

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://isocpp.org/)
[![CMake](https://img.shields.io/badge/CMake-3.20%2B-064F8C.svg)](https://cmake.org/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Local%20Simulation-success.svg)](https://github.com/mudassir-93/CYBERGUARD-ENGINE)
[![License](https://img.shields.io/badge/License-Project%20Educational-lightgrey.svg)](https://github.com/mudassir-93/CYBERGUARD-ENGINE)

CyberGuard Engine is a small, educational network-security simulation project built in C++ and designed to model packet flow, routing decisions, and firewall rule enforcement in a safe, local-only environment.

This project is intended for learning, demonstration, and academic review. It does not send real traffic, it does not connect to external services, and it is designed to run fully on a local machine.

## Overview

CyberGuard combines two separate simulation layers:

- A native C++ simulation for the actual network model, packet logic, and device behavior
- A browser dashboard for a visual presentation of the simulated network, counters, firewall rules, and traffic flow

The browser app is independent from the C++ engine and is meant to behave like a visual interface for the simulation, not a live network service.

## What the project does

- Creates and validates packet objects
- Simulates source and destination device routing
- Models router and firewall behavior
- Tracks packet states such as created, routing, blocked, delivered, and dropped
- Uses ordered firewall rules to allow or deny traffic based on protocol and port
- Shows a live-style topology dashboard in the browser
- Provides automated C++ tests for the implemented core logic

## Current project status

The implemented scope covers the core foundation, device model, packet flow, firewall rules, and the browser dashboard.

Completed phases include:

- Project foundation
- Device model and ownership
- Packet creation and routing
- Firewall rule evaluation
- Browser console for demonstration and manual testing

Not implemented yet:

- threat generation and detection
- incident response systems
- scenario engine
- SFML interface
- Docker deployment
- AI-based automation

Detailed project status and roadmap notes are available in [docs/development-process.md](docs/development-process.md), [docs/architecture.md](docs/architecture.md), and [docs/oop.md](docs/oop.md).

## Repo structure

```text
include/           Public C++ headers for the core model and device interfaces
src/               C++ implementation and native console demo
tests/             Test suite and smoke checks
backend/           Local Python server that serves the visual dashboard
index.html         Default browser dashboard entry point
web/               Legacy static assets kept for reference; not the main route
build/             Generated build output
CMakeLists.txt     CMake project configuration
docs/              Project documentation and design notes
README.md          Project overview and usage guide
```

## Requirements

Before running the project, make sure the following tools are installed:

- CMake 3.20 or newer
- A C++20 compiler
- Python 3
- PowerShell or a terminal that can run the commands below
- Internet access during the first test-enabled configure so CMake can fetch GoogleTest

For Windows, a typical setup is:

- Visual Studio Build Tools or MinGW
- Python 3 installed and added to PATH
- CMake installed and added to PATH

## Quick start guide

### 1. Clone the project

```powershell
git clone https://github.com/mudassir-93/CYBERGUARD-ENGINE.git
cd CYBERGUARD-ENGINE
```

### 2. Build the native C++ project

From the repo root in PowerShell:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCYBERGUARD_BUILD_TESTS=ON
cmake --build build
```

If you are using a different compiler or generator, replace the generator command with the one supported by your toolchain.

### 3. Run the tests

```powershell
ctest --test-dir build --output-on-failure
```

This project currently verifies the native core logic through a test suite that covers packet behavior, routing, firewall decisions, and device handling.

### 4. Run the native demo

```powershell
.\build\CyberGuard.exe
```

The console demo simulates packet routing and shows how traffic is either delivered or blocked by the firewall rule set.

### 5. Open the browser dashboard

From the repository root:

```powershell
python backend/server.py
```

Then open this in your browser:

```text
http://localhost:8000/
```

The browser app shows a visual topology, statistics cards, rule controls, and a demo sequence. By default, it blocks TCP destination port 23.

## How to use the simulator

### Browser simulation

The browser interface lets you:

- choose a source and destination device
- choose a protocol and port
- send a packet manually
- observe whether the packet is delivered or blocked
- add or toggle firewall rules
- reset the simulation
- run a demo sequence across multiple endpoints

This interface is designed for visual explanation and quick testing, not for sending real traffic.

### Native C++ model

The C++ engine represents the underlying logic of:

- packet objects
- network ownership
- routing logic
- firewall rule matching
- device registration and online tracking

This is the project’s core implementation layer.

## Important notes

- The app is intended for local, educational use only.
- No real network traffic is generated.
- The browser simulation does not share state with the C++ program.
- The project root URL is the default browser route.
- The legacy [web](web) folder is kept as reference material and is not the main entry point.

## Verification

The native validation run for the implemented core passed its recorded test set, and the console demo produced the expected local behavior:

```text
Packets Created:   3
Delivered:         2
Blocked:           1
Dropped:           0
```

## Screenshots

The browser dashboard presents a simulated network with device cards, packet counters, firewall controls, and live event output.

![CyberGuard dashboard overview](https://via.placeholder.com/1200x700?text=CyberGuard+Dashboard)

![CyberGuard firewall controls](https://via.placeholder.com/1200x500?text=Firewall+Rules+and+Event+Stream)

> These are placeholder visual previews for GitHub presentation. You can replace them with real screenshots from your local environment later.

## Project documentation

For deeper technical details, use the docs folder:

- [docs/development-process.md](docs/development-process.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/oop.md](docs/oop.md)

## Troubleshooting

### Browser does not open

- Make sure Python 3 is installed and available on PATH
- Run the server from the repository root
- Check that port 8000 is free
- If needed, stop any other process using port 8000 before starting the app

### CMake build fails

- Confirm that your compiler supports C++20
- Confirm that CMake is installed and available in PATH
- Use a compatible generator for your environment

### Tests fail

- Rebuild the project and rerun the test command
- Check whether a recent code change affected the router or firewall logic
- Review the project docs to confirm the current implemented scope

## Summary

CyberGuard Engine is a clean, local-first simulation project for learning how routing, packet flow, and firewall decisions work in a basic network model. It is organized so a user can clone the repository, build the C++ engine, run tests, and open the browser visualization with minimal setup.
