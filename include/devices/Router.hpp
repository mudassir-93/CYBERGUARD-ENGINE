#pragma once

#include "core/NetworkDevice.hpp"

#include <cstddef>
#include <string>
#include <unordered_map>

namespace cyberguard {

class Router final : public NetworkDevice {
public:
    Router(std::string name, std::string ipAddress);

    void addRoute(std::string destinationIp, std::string nextHop);
    [[nodiscard]] bool hasRoute(const std::string& destinationIp) const;
    [[nodiscard]] bool forwardPacket(const Packet& packet);

    [[nodiscard]] std::size_t getPacketsReceived() const noexcept;
    [[nodiscard]] std::size_t getPacketsForwarded() const noexcept;
    [[nodiscard]] std::size_t getPacketsDropped() const noexcept;

    [[nodiscard]] std::string getType() const override;
    [[nodiscard]] bool receivePacket(Packet& packet) override;
    [[nodiscard]] std::string getStatus() const override;

private:
    std::unordered_map<std::string, std::string> routingTable_;
    std::size_t packetsReceived_{0};
    std::size_t packetsForwarded_{0};
    std::size_t packetsDropped_{0};
};

} // namespace cyberguard