# CyberGuard Development and Verification

This guide reflects the current `master` baseline after PRs #1 through #6. The Windows one-command verification helper is merged and passes hosted Windows CI; running it on the owner's PC remains pending. The guided dashboard-launch CLI command is in progress.

## Source tree

- `include/`, `src/`, `tests/`: C++20 simulator, device model, flow aggregation, scenarios, detection, and native tests.
- `backend/`: Python application composition, repositories, incident services, live sensor, anomaly analysis, Ollama adapter, guided CLI, and loopback HTTP server.
- `index.html`, `app.js`, `dashboard.css`: primary browser dashboard and its feature controllers.
- `web/`: legacy browser assets retained for reference.
- `docs/`: architecture, data contracts, safety boundaries, setup, and milestone tracker.
- `scripts/`: owner-run verification helpers; no automatic capture or active response.
- `examples/`: synthetic, clearly labeled demonstration datasets; never use these as real-world benchmarks.

## Implemented scope

| Area | Current state |
|---|---|
| C++20 network simulator and device model | Implemented; simulation is in-memory |
| Flow aggregation and bounded scenarios | Implemented |
| Explainable deterministic detection rules | Implemented starter heuristics |
| SQLite incident lifecycle and evidence | Implemented, local-only |
| Passive IPv4 packet metadata sensor | Optional Scapy adapter; Npcap/libpcap and permissions required |
| Local IOC catalog and analyst notes | Implemented; explicit imports, exact-match enrichment |
| Robust anomaly baseline and Isolation Forest | Implemented as experimental local analysis, not calibrated verdicts |
| Leakage-aware ML evaluation | Implemented; capture/session-grouped holdout and security metrics, awaiting representative owner data |
| Local Ollama incident explanation | Optional, read-only, advisory |
| Guided CLI | Implemented: doctor, summary, incidents, show, status, simulate, explain, and explicit loopback dashboard launch |
| Dashboard | Implemented; simulator UI and C++ engine remain separate state domains |
| Remote multi-user authentication/authorization | Not implemented |
| Automatic blocking or response | Not implemented and out of scope for initial local release |
| Production-calibrated detection | Not implemented |

## Requirements

- CMake 3.20+
- A C++20 compiler
- Python 3.10+ (CI currently validates with Python 3.12)
- Node.js for the dashboard JavaScript syntax check
- Optional live capture: `python -m pip install -r requirements-live.txt`, Npcap on Windows or libpcap on Linux, and suitable capture permissions
- Optional ML tools: `python -m pip install -r requirements-ml.txt`
- Optional local AI: Ollama plus the configured model (default `llama3.2:3b`)

## Build on Windows (PowerShell)

Run from the repository root:

```powershell
cmake -S . -B build -DCYBERGUARD_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

If using MinGW, configure with `-G "MinGW Makefiles"` and use the matching build directory consistently.

## Verify the Windows installation

From PowerShell in the repository root, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\verify-windows.ps1
```

The merged helper builds the native project, runs C++ and Python tests, checks dashboard syntax when Node.js is installed, executes simulator-to-SQLite integration in a temporary data directory, and runs the local doctor report. See [WINDOWS_SETUP.md](WINDOWS_SETUP.md).

## Run the guided CLI

```powershell
python backend/cli.py
```

Useful direct commands:

```powershell
python backend/cli.py doctor
python backend/cli.py summary
python backend/cli.py incidents --status new --severity high
python backend/cli.py show CG-INCIDENTID
python backend/cli.py status CG-INCIDENTID acknowledged
python backend/cli.py simulate
python backend/cli.py explain CG-INCIDENTID
```

The `doctor` command checks the local SQLite database, native simulator executable, optional Scapy and scikit-learn packages, and the optional Ollama endpoint/model. Missing optional dependencies are reported as not ready; they do not disable the simulator or incident workspace. If Ollama is running but the configured model is missing, doctor prints the corresponding `ollama pull <model>` command.

The CLI talks to local repositories and the native process bridge. It does not start an HTTP listener. The AI explanation command sends bounded incident fields only to a loopback Ollama service and is advisory; it cannot change incident state or take response actions.

## Run the dashboard

```powershell
python backend/server.py
```

Open `http://127.0.0.1:8000/`. The server is loopback-only and unauthenticated. Do not expose it to a LAN or the public internet. The browser simulation is independent of the native C++ simulator. Optional live monitoring uses a separate passive Python sensor; see [LIVE_MONITORING.md](LIVE_MONITORING.md).

## Tests and CI

The GitHub Actions workflow builds and tests the C++ project on Ubuntu and Windows, compiles the Python backend, runs the backend unittest suite, checks dashboard JavaScript syntax, and executes the C++-to-SQLite integration. The latest verified post-merge master run is [45309651274](https://github.com/mudassir-93/CYBERGUARD-ENGINE/actions/runs/45309651274); Ubuntu and Windows both passed. Follow-up branch changes must pass a fresh PR CI run before integration.

Local checks:

```powershell
python -m py_compile backend/*.py
python -m unittest discover -s backend/tests -v
node --check app.js
python backend/run_simulation.py
```

The C++ build and CTest commands are listed above. Report checks that cannot be run on the current machine rather than marking them passed.

## Known limitations and next work

- Live capture requires a supported adapter, Npcap/libpcap, and suitable host permissions. The actual Windows adapter path still needs owner-PC validation.
- The live sensor observes limited IPv4 metadata; it does not inspect payloads, process identity, or authentication outcomes.
- Rule thresholds are starter heuristics. Validate false positives and false negatives using representative, labeled traffic before making operational claims.
- Isolation Forest scores are not calibrated probabilities. The grouped evaluation helper requires labeled CSV data with capture/session IDs; no benchmark dataset is bundled. See [ML_EVALUATION.md](ML_EVALUATION.md). The new evaluation workflow requires a capture/session group column and reports false-positive/negative metrics; see [ML_EVALUATION.md](ML_EVALUATION.md).
- The local AI analyst is optional and depends on Ollama being installed and the selected model being pulled.
- The API has no authentication/authorization and is not suitable for remote or multi-user use.
- No automatic blocking, firewall changes, or disruptive response is performed.

## Development workflow

1. Start from the latest `master` and create a focused feature branch.
2. Preserve a dated safety reference before risky integration work.
3. Make a dependency-aware change and add regression tests.
4. Run relevant tests locally, then use GitHub Actions on both Ubuntu and Windows.
5. Update README, architecture/setup docs, and `docs/UPGRADE_PLAN.md` when behavior or status changes.
6. Open a PR and merge only after reviewing the exact head SHA and green CI.
7. Keep the pre-change safety reference and feature branch for recovery; never force-push or delete user content.

See [architecture.md](architecture.md), [oop.md](oop.md), [LOCAL_AI_ANALYST.md](LOCAL_AI_ANALYST.md), [LIVE_MONITORING.md](LIVE_MONITORING.md), [ML_EVALUATION.md](ML_EVALUATION.md), and [UPGRADE_PLAN.md](UPGRADE_PLAN.md).
