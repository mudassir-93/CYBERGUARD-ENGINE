#pragma once

#include "core/NetworkDevice.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace cyberguard {

class Workstation final : public NetworkDevice {
public:
    Workstation(std::string name, std::string ipAddress);

    [[nodiscard]] Packet createPacket(std::uint64_t id,
                                      std::string destinationIp,
                                      std::uint16_t destinationPort,
                                      Protocol protocol,
                                      std::uint32_t size,
                                      std::uint64_t timestamp,
                                      std::uint16_t sourcePort = 49152);

    [[nodiscard]] std::size_t getPacketsSent() const noexcept;
    [[nodiscard]] std::size_t getPacketsReceived() const noexcept;
    [[nodiscard]] std::size_t getPacketsDropped() const noexcept;

    [[nodiscard]] std::string getType() const override;
    [[nodiscard]] bool receivePacket(Packet& packet) override;
    [[nodiscard]] std::string getStatus() const override;

private:
    std::size_t packetsSent_{0};
    std::size_t packetsReceived_{0};
    std::size_t packetsDropped_{0};
};

} // namespace cyberguard