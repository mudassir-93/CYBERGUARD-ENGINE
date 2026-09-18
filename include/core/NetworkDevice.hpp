#pragma once

#include "core/Packet.hpp"

#include <string>

namespace cyberguard {

class NetworkDevice {
public:
    NetworkDevice(std::string name, std::string ipAddress);
    virtual ~NetworkDevice() = default;

    NetworkDevice(const NetworkDevice&) = delete;
    NetworkDevice& operator=(const NetworkDevice&) = delete;
    NetworkDevice(NetworkDevice&&) = default;
    NetworkDevice& operator=(NetworkDevice&&) = default;

    [[nodiscard]] const std::string& getName() const noexcept;
    [[nodiscard]] const std::string& getIpAddress() const noexcept;
    [[nodiscard]] bool isOnline() const noexcept;

    void setOnline(bool online) noexcept;

    [[nodiscard]] virtual std::string getType() const = 0;
    [[nodiscard]] virtual bool receivePacket(Packet& packet) = 0;
    [[nodiscard]] virtual std::string getStatus() const = 0;

private:
    std::string name_;
    std::string ipAddress_;
    bool online_{true};
};

} // namespace cyberguard