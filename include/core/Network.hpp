#pragma once

#include "core/NetworkDevice.hpp"

#include <cstddef>
#include <memory>
#include <vector>

namespace cyberguard {

class Network {
public:
    Network() = default;
    ~Network() = default;

    Network(const Network&) = delete;
    Network& operator=(const Network&) = delete;
    Network(Network&&) = default;
    Network& operator=(Network&&) = default;

    void addDevice(std::unique_ptr<NetworkDevice> device);
    [[nodiscard]] std::size_t getDeviceCount() const noexcept;

private:
    std::vector<std::unique_ptr<NetworkDevice>> devices_;
};

} // namespace cyberguard