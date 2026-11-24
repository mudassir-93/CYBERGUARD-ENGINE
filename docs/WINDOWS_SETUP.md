# Windows Local Setup and Verification

This guide is for the first local Windows validation after cloning CyberGuard.

## Prerequisites

Install and make available on PATH:

- Git
- Python 3.10 or newer
- CMake 3.20 or newer
- A C++20 toolchain supported by CMake (Visual Studio 2022 Build Tools is recommended; MinGW or Ninja can also work when configured correctly)
- Node.js is recommended for the dashboard JavaScript syntax check

The first CMake configure may need internet access to fetch GoogleTest. The verification script does not install software or change your global machine configuration.

## One-command verification

Open PowerShell in the repository root and run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\verify-windows.ps1
```

The script reuses an existing CMake generator when the build cache exists; otherwise it lets CMake choose the default generator for the installed toolchain. If you use MinGW explicitly, pass `-Generator "MinGW Makefiles"` (and use a fresh build directory if an existing cache uses another generator). It then:

1. Configures and builds the C++20 project
2. Runs CTest
3. Compiles the Python backend and tests
4. Runs the complete Python backend test suite
5. Checks dashboard JavaScript syntax when Node.js is installed
6. Runs the C++-to-SQLite integration using a temporary data directory
7. Runs `cyberguard doctor` to report local readiness

The temporary integration database is created under the Windows temporary directory and removed by the script. Your normal CyberGuard incident database is not used by the integration test.

## Optional capabilities

The core simulator and incident workspace do not require the following:

- Passive capture: `python -m pip install -r requirements-live.txt`, Npcap, and appropriate capture permissions
- ML training/evaluation: `python -m pip install -r requirements-ml.txt`
- Local AI analyst: install Ollama separately and pull the configured model

The `doctor` report identifies missing optional dependencies. The verification script does not install Npcap, Ollama, or ML packages automatically.

## Troubleshooting

- If CMake cannot find a compiler, install Visual Studio 2022 Build Tools with the C++ desktop workload, then reopen PowerShell.
- If an existing `build` directory was created with a different compiler, remove that build directory yourself only after confirming it contains no files you need, or choose a new directory: `.\scripts\verify-windows.ps1 -BuildDirectory build-msvc`.
- If Python is not found, add its installation and Scripts directories to PATH.
- If the JavaScript check is skipped, install Node.js and reopen PowerShell.
- Physical Npcap capture and real Ollama inference still require separate tests on the actual target PC.

The script never enables live capture, sends real network traffic, changes firewall rules, or performs automated response.
