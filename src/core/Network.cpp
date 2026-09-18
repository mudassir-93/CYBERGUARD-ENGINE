#include "core/Network.hpp"

#include "devices/Firewall.hpp"
#include "devices/Router.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
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

    if (findDevice(device->getName()) != nullptr || findDevice(device->getIpAddress()) != nullptr) {
        throw std::invalid_argument("Network device name or IP address already exists");
    }

    devices_.push_back(std::move(device));
    refreshRouterRoutes();
}

bool Network::removeDevice(std::string_view identifier) {
    const auto iterator = std::find_if(
        devices_.begin(),
        devices_.end(),
        [identifier](const std::unique_ptr<NetworkDevice>& device) {
            return device->getName() == identifier || device->getIpAddress() == identifier;
        });

    if (iterator == devices_.end()) {
        return false;
    }

    devices_.erase(iterator);
    refreshRouterRoutes();
    return true;
}

NetworkDevice* Network::findDevice(std::string_view identifier) noexcept {
    for (const auto& device : devices_) {
        if (device->getName() == identifier || device->getIpAddress() == identifier) {
            return device.get();
        }
    }

    return nullptr;
}

const NetworkDevice* Network::findDevice(std::string_view identifier) const noexcept {
    for (const auto& device : devices_) {
        if (device->getName() == identifier || device->getIpAddress() == identifier) {
            return device.get();
        }
    }

    return nullptr;
}

PacketStatus Network::routePacket(Packet& packet) {
    ++statistics_.packetsCreated;

    const NetworkDevice* source = findDevice(packet.getSourceIp());
    NetworkDevice* destination = findDevice(packet.getDestinationIp());
    if (source == nullptr || destination == nullptr) {
        packet.setStatus(PacketStatus::DROPPED);
        ++statistics_.packetsDropped;
        return packet.getStatus();
    }

    packet.setStatus(PacketStatus::ROUTING);

    Router* router = nullptr;
    Firewall* firewall = nullptr;
    for (const auto& device : devices_) {
        if (router == nullptr) {
            router = dynamic_cast<Router*>(device.get());
        }
        if (firewall == nullptr) {
            firewall = dynamic_cast<Firewall*>(device.get());
        }
    }

    if (router != nullptr && (!router->receivePacket(packet) || !router->forwardPacket(packet))) {
        packet.setStatus(PacketStatus::DROPPED);
        ++statistics_.packetsDropped;
        return packet.getStatus();
    }

    if (firewall != nullptr && !firewall->receivePacket(packet)) {
        ++statistics_.packetsBlocked;
        return packet.getStatus();
    }

    if (!destination->receivePacket(packet)) {
        packet.setStatus(PacketStatus::DROPPED);
        ++statistics_.packetsDropped;
        return packet.getStatus();
    }

    packet.setStatus(PacketStatus::DELIVERED);
    ++statistics_.packetsDelivered;
    return packet.getStatus();
}

PacketStatus Network::sendPacket(Packet& packet) {
    return routePacket(packet);
}

std::size_t Network::getDeviceCount() const noexcept {
    return devices_.size();
}

std::size_t Network::getOnlineDeviceCount() const noexcept {
    return static_cast<std::size_t>(std::count_if(
        devices_.begin(),
        devices_.end(),
        [](const std::unique_ptr<NetworkDevice>& device) {
            return device->isOnline();
        }));
}

const std::vector<std::unique_ptr<NetworkDevice>>& Network::getDevices() const noexcept {
    return devices_;
}

const NetworkStatistics& Network::getStatistics() const noexcept {
    return statistics_;
}

void Network::refreshRouterRoutes() {
    for (const auto& device : devices_) {
        auto* router = dynamic_cast<Router*>(device.get());
        if (router == nullptr) {
            continue;
        }

        for (const auto& routeTarget : devices_) {
            router->addRoute(routeTarget->getIpAddress(), routeTarget->getIpAddress());
        }
    }
}

} // namespace cyberguard