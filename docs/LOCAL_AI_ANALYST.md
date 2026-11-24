# Local AI Incident Analyst

CyberGuard can ask an optional local Ollama model to explain an existing incident.
The analyst is an advisory feature: it reads persisted incident evidence and
returns text. It does not change incident state, execute commands, fetch remote
threat feeds, or perform response actions.

## Requirements

- Install Ollama locally: https://ollama.com/
- Start the local Ollama service.
- Pull a model that fits the available machine, for example:

```powershell
ollama pull llama3.2:3b
```

The default model is `llama3.2:3b`. No Python Ollama package or cloud API key
is required; CyberGuard uses Python's standard library to call the local HTTP API.

## Configuration

Optional environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CYBERGUARD_OLLAMA_URL` | `http://127.0.0.1:11434` | Local Ollama HTTP endpoint |
| `CYBERGUARD_OLLAMA_MODEL` | `llama3.2:3b` | Installed Ollama model tag |
| `CYBERGUARD_OLLAMA_TIMEOUT` | `45` | Request timeout in seconds (1–180) |

The endpoint must use HTTP on a loopback host (127.0.0.1, ::1, or localhost).
Non-loopback URLs are rejected to prevent incident evidence being sent to a
remote host by configuration mistake. Model names are limited to 200 characters.

## Use the CLI

Create or select an incident, then run:

```powershell
python backend/cli.py incidents
python backend/cli.py explain CG-INCIDENTID
```

The interactive menu also provides **7. Explain incident with local AI**.

If Ollama is stopped or the configured model is not installed, the command
returns a clear setup error. All other CyberGuard features remain available.

## API

The loopback-only API exposes:

```http
POST /api/analyst/explain
Content-Type: application/json

{"incident_id":"CG-INCIDENTID"}
```

A successful response contains the model tag and explanation text. The route
uses the same loopback-client restriction as the other API endpoints.

## Safety and limitations

- Only a bounded allowlist of incident fields is sent to the local model.
- Incident JSON is limited to 24,000 UTF-8 bytes before it is sent.
- Evidence, notes, hostnames, and log strings are untrusted data, not model
  instructions. The system prompt explicitly tells the model to ignore embedded
  instructions.
- The Ollama response is read with a 16,385-byte cap; anything larger than
  16,384 bytes is rejected before JSON parsing.
- Model configuration and timeout values are validated, including rejection of
  non-finite timeouts and booleans.
- The response is not a detection verdict. It may be incomplete or incorrect;
  verify claims against source telemetry and incident evidence.
- IOC matches and starter heuristics do not prove compromise.
- The model is not allowed to perform shell commands, network actions, blocking,
  firewall changes, or incident status updates.
- The model runs on the user's machine. Local inference quality and speed depend
  on the selected model and available hardware.
- Do not expose the unauthenticated CyberGuard API beyond loopback. The analyst
  endpoint is not a substitute for authentication or multi-user authorization.
