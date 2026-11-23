# Live Network Monitoring Foundation

## Scope

Live monitoring is an optional, passive IPv4 metadata sensor. It is separate from
the deterministic C++ simulator and does not alter firewall rules, block
traffic, inspect payload contents, or attempt automated response. The existing
incident workspace receives normalized detections in SQLite.

## Enable the optional capture dependency

Install the regular CyberGuard requirements first (Python 3; the existing
project has no mandatory third-party Python dependencies), then:

\`\`\`powershell
python -m pip install -r requirements-live.txt
\`\`\`

Packet capture also requires a supported capture driver and permission:

- Windows: install Npcap using its official installer. Use an elevated terminal
  if the selected adapter/driver requires it.
- Linux: install the distribution's libpcap package and grant the process
  suitable capture permissions (for example, a narrowly scoped
  \`CAP_NET_RAW\`/capture setup). Avoid running the whole application as root
  unless your environment specifically requires it.

If Scapy, Npcap/libpcap, or permissions are unavailable, the rest of CyberGuard
continues to work and the live-monitoring API reports the reason.

## Start

Run \`python backend/server.py\`, open \`http://127.0.0.1:8000\`, select a
network interface in **Live network monitoring**, and choose **Start capture**.
Only one capture session can run in this local process. Stop it from the same
panel.

The API is local and unauthenticated. Keep the server bound to loopback; do not
expose it to an untrusted network.

## API

- \`GET /api/live/status\` — capture state and counters.
- \`GET /api/live/interfaces\` — interfaces visible to Scapy.
- \`POST /api/live/start\` — JSON body \`{"interface":"<interface name>"}\`.
- \`POST /api/live/stop\` — stop the active capture.

## Detection behavior and limits

The sensor extracts IPv4 source/destination, protocol, TCP/UDP destination
port, TCP SYN flag, and packet length. Packet payloads are not persisted.

- Port scan: distinct TCP SYN destination ports from one source to one
  destination in a 60-second rolling window (default threshold 10).
- High packet rate: at least 100 packets from one source to one destination
  in a 10-second rolling window.
- Internal host fan-out: one private source contacting at least 3 distinct
  private destinations in 60 seconds.

These are explainable starter heuristics, not calibrated detections. A packet
capture cannot establish whether an application login succeeded or failed, so
live brute-force alerts are deliberately not inferred. The existing simulated
brute-force scenario remains simulation-only. NAT, asymmetric routing, packet
offload, interface selection, IPv6, VLAN decoding, and capture drops can affect
what is observed. A high packet rate is not by itself proof of a DoS attack.

This is a development foundation, not a production network sensor or IPS.
