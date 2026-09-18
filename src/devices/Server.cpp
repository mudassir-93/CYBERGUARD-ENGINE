#include "devices/Server.hpp"

#include <utility>

namespace cyberguard {

Server::Server(std::string name, std::string ipAddress)
    : NetworkDevice(std::move(name), std::move(ipAddress)) {}

void Server::openService(std::uint16_t port) {
    openServices_.insert(port);
}

void Server::closeService(std::uint16_t port) {
    openServices_.erase(port);
}

bool Server::hasOpenService(std::uint16_t port) const {
    return openServices_.contains(port);
}

std::size_t Server::getPacketsReceived() const noexcept {
    return packetsReceived_;
}

std::size_t Server::getPacketsAccepted() const noexcept {
    return packetsAccepted_;
}

std::size_t Server::getPacketsRejected() const noexcept {
    return packetsRejected_;
}

std::string Server::getType() const {
    return "Server";
}

bool Server::receivePacket(Packet& packet) {
    if (!isOnline() || packet.getDestinationIp() != getIpAddress()) {
        ++packetsRejected_;
        return false;
    }

    ++packetsReceived_;
    if (!hasOpenService(packet.getDestinationPort())) {
        ++packetsRejected_;
        return false;
    }

    ++packetsAccepted_;
    return true;
}

std::string Server::getStatus() const {
    return isOnline() ? "ONLINE" : "OFFLINE";
}

} // namespace cyberguard