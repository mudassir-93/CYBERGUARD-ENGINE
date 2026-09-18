# CyberGuard Phase 2 OOP Design

## Abstraction

`NetworkDevice` defines the common identity, online state, packet reception,
type, and status contract for simulated devices.

## Inheritance and polymorphism

`Router`, `Firewall`, `Server`, and `Workstation` inherit from
`NetworkDevice`. `Network` stores them as `std::unique_ptr<NetworkDevice>` and
uses virtual packet reception and status operations. Device-specific behavior
is implemented in each derived class.

## Encapsulation

Device counters, routing tables, firewall rules, and server services are
private. Callers use focused methods and read-only statistics accessors.

## Composition and RAII

`Network` owns its devices with `std::unique_ptr`, so device lifetime is tied to
the network and no raw owning pointers are used. `Packet` is passed by
reference while the network coordinates its lifecycle.

## Class relationship

```text
              NetworkDevice
              /     |      \
             /      |       \
         Router  Firewall  Server
                              \
                           Workstation
```

The four concrete device types are siblings. The diagram's final branch is a
layout aid, not an inheritance relationship between `Server` and
`Workstation`.