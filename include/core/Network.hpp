#pragma once

#include "core/NetworkDevice.hpp"

#include <cstddef>
#include <memory>
#include <string_view>
#include <vector>

namespace cyberguard {

struct NetworkStatistics {
    std::size_t packetsCreated{0};
    std::size_t packetsDelivered{0};
    std::size_t packetsBlocked{0};
    std::size_t packetsDropped{0};
};

class Network {
public:
    Network() = default;
    ~Network() = default;

    Network(const Network&) = delete;
    Network& operator=(const Network&) = delete;
    Network(Network&&) = default;
    Network& operator=(Network&&) = default;

    void addDevice(std::unique_ptr<NetworkDevice> device);
    [[nodiscard]] bool removeDevice(std::string_view identifier);
    [[nodiscard]] NetworkDevice* findDevice(std::string_view identifier) noexcept;
    [[nodiscard]] const NetworkDevice* findDevice(std::string_view identifier) const noexcept;
    [[nodiscard]] PacketStatus routePacket(Packet& packet);
    [[nodiscard]] PacketStatus sendPacket(Packet& packet);

    [[nodiscard]] std::size_t getDeviceCount() const noexcept;
    [[nodiscard]] std::size_t getOnlineDeviceCount() const noexcept;
    [[nodiscard]] const std::vector<std::unique_ptr<NetworkDevice>>& getDevices() const noexcept;
    [[nodiscard]] const NetworkStatistics& getStatistics() const noexcept;

private:
    void refreshRouterRoutes();

    std::vector<std::unique_ptr<NetworkDevice>> devices_;
    NetworkStatistics statistics_;
};

} // namespace cyberguard