# CyberGuard Network Flow Schema v1

## Purpose
The simulator emits individual packets. Detection features need a stable connection-level view, so FlowManager aggregates observations into bidirectional five-tuples.

## Flow identity
A flow is keyed by protocol (TCP, UDP, ICMP), endpoint A IPv4 address and port, and endpoint B IPv4 address and port. Endpoints are sorted lexicographically by IPv4 address then port, so request and response packets resolve to the same flow. Directional counters are canonical A-to-B and B-to-A, not guaranteed client/server roles.

## Fields
| Field | Meaning |
|---|---|
| endpointAIp, endpointAPort | Canonically ordered endpoint A |
| endpointBIp, endpointBPort | Canonically ordered endpoint B |
| protocol | Packet protocol enum |
| firstSeen, lastSeen | Minimum and maximum observed timestamps |
| packetCount, totalBytes | Total packets and bytes |
| aToBPackets, aToBBytes | Traffic from endpoint A to B |
| bToAPackets, bToABytes | Traffic from endpoint B to A |
| deliveredPackets | Packets observed with DELIVERED status |
| blockedPackets | Packets observed with BLOCKED status |
| droppedPackets | Packets observed with DROPPED status |

Duration is lastSeen minus firstSeen. Rates are zero for zero-duration flows; otherwise they are calculated using the caller's timestamp unit. The simulator currently uses seconds. Out-of-order observations update min/max timestamps without negative duration.

## Limitations
- In-memory aggregation only; no idle-flow timeout or session expiry yet.
- Flows remain until clear() is called.
- TCP lifecycle state, retransmissions, payload parsing, and application protocol identification are not modeled.
- This is simulator data, not real network packet capture.
- FlowManager is independent of Network. Callers decide when to observe a packet, preferably after final routing status is known.
