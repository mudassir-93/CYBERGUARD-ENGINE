#include "core/Network.hpp"

#include <stdexcept>
#include <utility>

namespace cyberguard {

NetworkDevice::NetworkDevice(std::string name, std::string ipAddress)
    : name_(std::move(name)), ipAddress_(std::move(ipAddress)) {}

const std::string& NetworkDevice::getName() const noexcept {
    return name_;
}

const std::string& NetworkDevice::getIpAddress() const noexcept {
    return ipAddress_;
}

bool NetworkDevice::isOnline() const noexcept {
    return online_;
}

void NetworkDevice::setOnline(bool online) noexcept {
    online_ = online;
}

void Network::addDevice(std::unique_ptr<NetworkDevice> device) {
    if (!device) {
        throw std::invalid_argument("Network cannot contain a null device");
    }

    devices_.push_back(std::move(device));
}

std::size_t Network::getDeviceCount() const noexcept {
    return devices_.size();
}

} // namespace cyberguard