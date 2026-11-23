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
