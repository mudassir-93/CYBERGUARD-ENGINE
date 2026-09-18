# CyberGuard Phase 2 Architecture

Phase 2 is a self-contained simulated network. It performs no real network
communication.

```text
Network
  |
  +-- owns unique_ptr<NetworkDevice>
       |
       +-- Router       -> route table and forwarding statistics
       +-- Firewall     -> ordered simulated filtering rules
       +-- Server       -> simulated open service ports
       +-- Workstation  -> deterministic packet creation and endpoint stats

Packet lifecycle:
CREATED -> ROUTING -> ALLOWED -> DELIVERED
                    \-> BLOCKED
       \-> DROPPED when a route or destination is unavailable
```

`Network` coordinates packet flow. It validates that source and destination
devices exist, sends packets through the router and firewall when present, and
delivers them to the destination device. Devices retain only their own state
and behavior.

The `CyberGuardCore` library contains all Phase 2 logic. The console
application and tests depend on the library; no graphical or network runtime
dependency is involved.