#include "core/Network.hpp"
#include "core/Ipv4Address.hpp"
#include "devices/Firewall.hpp"
#include "devices/Router.hpp"
#include <algorithm>
#include <stdexcept>
#include <string>
#include <utility>
namespace cyberguard {
NetworkDevice::NetworkDevice(std::string name, std::string ipAddress) : name_(std::move(name)), ipAddress_(std::move(ipAddress)) { detail::validateIpv4Address(ipAddress_); }
const std::string& NetworkDevice::getName() const noexcept { return name_; }
const std::string& NetworkDevice::getIpAddress() const noexcept { return ipAddress_; }
bool NetworkDevice::isOnline() const noexcept { return online_; }
void NetworkDevice::setOnline(bool online) noexcept { online_ = online; }
void Network::addDevice(std::unique_ptr<NetworkDevice> device) {
    if (!device) throw std::invalid_argument("Network cannot contain a null device");
    if (findDevice(device->getName()) || findDevice(device->getIpAddress())) throw std::invalid_argument("Network device name or IP address already exists");
    devices_.push_back(std::move(device)); refreshRouterRoutes();
}
bool Network::removeDevice(std::string_view identifier) {
    const auto it = std::find_if(devices_.begin(), devices_.end(), [identifier](const auto& device) { return device->getName() == identifier || device->getIpAddress() == identifier; });
    if (it == devices_.end()) return false;
    const std::string removedIp = (*it)->getIpAddress();
    for (const auto& device : devices_) if (auto* router = dynamic_cast<Router*>(device.get())) router->removeRoute(removedIp);
    devices_.erase(it); refreshRouterRoutes(); return true;
}
NetworkDevice* Network::findDevice(std::string_view identifier) noexcept {
    for (const auto& device : devices_) if (device->getName() == identifier || device->getIpAddress() == identifier) return device.get();
    return nullptr;
}
const NetworkDevice* Network::findDevice(std::string_view identifier) const noexcept {
    for (const auto& device : devices_) if (device->getName() == identifier || device->getIpAddress() == identifier) return device.get();
    return nullptr;
}
PacketStatus Network::routePacket(Packet& packet) {
    ++statistics_.packetsCreated;
    const auto finish = [this, &packet](PacketStatus status) { flowManager_.observe(packet); return status; };
    const NetworkDevice* source = findDevice(packet.getSourceIp());
    NetworkDevice* destination = findDevice(packet.getDestinationIp());
    if (!source || !destination || !source->isOnline()) {
        packet.setStatus(PacketStatus::DROPPED); ++statistics_.packetsDropped; return finish(packet.getStatus());
    }
    packet.setStatus(PacketStatus::ROUTING);
    Router* router = nullptr; Firewall* firewall = nullptr;
    for (const auto& device : devices_) {
        if (!router) router = dynamic_cast<Router*>(device.get());
        if (!firewall) firewall = dynamic_cast<Firewall*>(device.get());
    }
    if (router && (!router->receivePacket(packet) || !router->forwardPacket(packet))) {
        packet.setStatus(PacketStatus::DROPPED); ++statistics_.packetsDropped; return finish(packet.getStatus());
    }
    if (firewall && !firewall->receivePacket(packet)) {
        ++statistics_.packetsBlocked; return finish(packet.getStatus());
    }
    if (!destination->receivePacket(packet)) {
        packet.setStatus(PacketStatus::DROPPED); ++statistics_.packetsDropped; return finish(packet.getStatus());
    }
    packet.setStatus(PacketStatus::DELIVERED); ++statistics_.packetsDelivered; return finish(packet.getStatus());
}
PacketStatus Network::sendPacket(Packet& packet) { return routePacket(packet); }
std::size_t Network::getDeviceCount() const noexcept { return devices_.size(); }
std::size_t Network::getOnlineDeviceCount() const noexcept { return static_cast<std::size_t>(std::count_if(devices_.begin(), devices_.end(), [](const auto& d) { return d->isOnline(); })); }
const std::vector<std::unique_ptr<NetworkDevice>>& Network::getDevices() const noexcept { return devices_; }
const NetworkStatistics& Network::getStatistics() const noexcept { return statistics_; }
const FlowManager& Network::getFlowManager() const noexcept { return flowManager_; }
void Network::refreshRouterRoutes() {
    for (const auto& device : devices_) {
        auto* router = dynamic_cast<Router*>(device.get()); if (!router) continue;
        for (const auto& target : devices_) router->addRoute(target->getIpAddress(), target->getIpAddress());
    }
}
} // namespace cyberguard
