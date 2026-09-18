#pragma once

#include "core/NetworkDevice.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>

namespace cyberguard {

class Server final : public NetworkDevice {
public:
    Server(std::string name, std::string ipAddress);

    void openService(std::uint16_t port);
    void closeService(std::uint16_t port);
    [[nodiscard]] bool hasOpenService(std::uint16_t port) const;

    [[nodiscard]] std::size_t getPacketsReceived() const noexcept;
    [[nodiscard]] std::size_t getPacketsAccepted() const noexcept;
    [[nodiscard]] std::size_t getPacketsRejected() const noexcept;

    [[nodiscard]] std::string getType() const override;
    [[nodiscard]] bool receivePacket(Packet& packet) override;
    [[nodiscard]] std::string getStatus() const override;

private:
    std::unordered_set<std::uint16_t> openServices_;
    std::size_t packetsReceived_{0};
    std::size_t packetsAccepted_{0};
    std::size_t packetsRejected_{0};
};

} // namespace cyberguard