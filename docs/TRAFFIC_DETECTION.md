# Traffic Generation and Port Scan Detection

## Packet lifecycle integration
Every call to Network::routePacket records the packet in Network's FlowManager after its final routing outcome is known, including delivered, firewall-blocked, and dropped packets. Consumers inspect the read-only manager with getFlowManager().

## Scenario generator
TrafficScenarioGenerator provides deterministic normal traffic (five packets to simulated HTTP/HTTPS services) and a sequential TCP port-scan scenario across a selected destination-port range. These are in-memory simulator packets; no sockets are opened and no real network traffic is sent.

## Port-scan rule
PortScanDetector groups directed flow observations by source and destination IP. It alerts when one source reaches at least the configured number of distinct destination ports within the configured timestamp window. Defaults are 10 ports in 60 timestamp-seconds. Threshold and window are configurable.

This is a transparent heuristic, not an ML classifier. Legitimate service discovery may trigger it; tune thresholds for the environment.

## Run
Build and run the native CyberGuard executable. It executes normal traffic, simulates a scan of ports 1-12, aggregates flows, and prints the alert.

## Limitations
- In-memory only; flow expiry and bounded retention are future work.
- Detection uses flow first-seen timestamps; SYN-only semantics require TCP flag modeling.
- No real packet capture, host discovery, or live network integration is enabled.


## Additional explainable threat heuristics

The next local-simulation milestone adds three deterministic detectors over the same flow records:

- **Repeated connection failures (brute-force pattern):** groups failed or dropped attempts by source, destination, destination port, and protocol. Default threshold: 5 failures in 60 timestamp-seconds. This is a connection-failure heuristic, not proof of password guessing; authentication events are not modeled yet.
- **High-volume traffic (DoS-like pattern):** groups packet and byte counts by source/destination pair and flags a flow group meeting the packet threshold within the configured window. Defaults: 100 packets in 10 timestamp-seconds. This is not a bandwidth-exhaustion or distributed-DDoS classifier.
- **Internal host fan-out (lateral-movement pattern):** flags one source contacting at least 3 distinct RFC1918 private IPv4 destinations within 60 timestamp-seconds. This is a behavioral signal, not proof of compromise.

`TrafficScenarioGenerator` now exposes bounded, deterministic `runBruteForce`, `runDenialOfService`, and `runLateralMovement` scenarios. Each accepts a maximum of 10,000 packets/attempts (or 100 lateral destinations), operates only on in-memory simulator packets, and opens no sockets.

## Detection limitations

Flow records aggregate packets by bidirectional five-tuple. These initial rules use aggregate first/last timestamps and packet outcomes; they do not inspect payloads, authentication results, TCP flags, or process identity. They are explainable starter heuristics and should be tuned against normal baseline traffic before being treated as operational detections.
