#include "devices/Router.hpp"

#include <utility>

namespace cyberguard {

Router::Router(std::string name, std::string ipAddress)
    : NetworkDevice(std::move(name), std::move(ipAddress)) {}

void Router::addRoute(std::string destinationIp, std::string nextHop) {
    routingTable_[std::move(destinationIp)] = std::move(nextHop);
}

bool Router::hasRoute(const std::string& destinationIp) const {
    return routingTable_.contains(destinationIp);
}

bool Router::forwardPacket(const Packet& packet) {
    if (!isOnline() || !hasRoute(packet.getDestinationIp())) {
        ++packetsDropped_;
        return false;
    }

    ++packetsForwarded_;
    return true;
}

std::size_t Router::getPacketsReceived() const noexcept {
    return packetsReceived_;
}

std::size_t Router::getPacketsForwarded() const noexcept {
    return packetsForwarded_;
}

std::size_t Router::getPacketsDropped() const noexcept {
    return packetsDropped_;
}

std::string Router::getType() const {
    return "Router";
}

bool Router::receivePacket(Packet& packet) {
    if (!isOnline()) {
        return false;
    }

    ++packetsReceived_;
    packet.setStatus(PacketStatus::ROUTING);
    return true;
}

std::string Router::getStatus() const {
    return isOnline() ? "ONLINE" : "OFFLINE";
}

} // namespace cyberguard