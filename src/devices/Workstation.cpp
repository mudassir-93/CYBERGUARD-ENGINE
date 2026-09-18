#include "devices/Workstation.hpp"

#include <utility>

namespace cyberguard {

Workstation::Workstation(std::string name, std::string ipAddress)
    : NetworkDevice(std::move(name), std::move(ipAddress)) {}

Packet Workstation::createPacket(std::uint64_t id,
                                 std::string destinationIp,
                                 std::uint16_t destinationPort,
                                 Protocol protocol,
                                 std::uint32_t size,
                                 std::uint64_t timestamp,
                                 std::uint16_t sourcePort) {
    if (!isOnline()) {
        ++packetsDropped_;
    }

    ++packetsSent_;
    return Packet(id,
                  getIpAddress(),
                  std::move(destinationIp),
                  sourcePort,
                  destinationPort,
                  protocol,
                  size,
                  timestamp);
}

std::size_t Workstation::getPacketsSent() const noexcept {
    return packetsSent_;
}

std::size_t Workstation::getPacketsReceived() const noexcept {
    return packetsReceived_;
}

std::size_t Workstation::getPacketsDropped() const noexcept {
    return packetsDropped_;
}

std::string Workstation::getType() const {
    return "Workstation";
}

bool Workstation::receivePacket(Packet& packet) {
    if (!isOnline() || packet.getDestinationIp() != getIpAddress()) {
        ++packetsDropped_;
        return false;
    }

    ++packetsReceived_;
    return true;
}

std::string Workstation::getStatus() const {
    return isOnline() ? "ONLINE" : "OFFLINE";
}

} // namespace cyberguard