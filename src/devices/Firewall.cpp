#include "devices/Firewall.hpp"

#include <utility>

namespace cyberguard {

bool FirewallRule::matches(const Packet& packet) const {
    if (!enabled) {
        return false;
    }

    if (sourceIp.has_value() && sourceIp.value() != packet.getSourceIp()) {
        return false;
    }
    if (destinationIp.has_value() && destinationIp.value() != packet.getDestinationIp()) {
        return false;
    }
    if (protocol.has_value() && protocol.value() != packet.getProtocol()) {
        return false;
    }
    if (port.has_value() && port.value() != packet.getDestinationPort()) {
        return false;
    }

    return true;
}

Firewall::Firewall(std::string name, std::string ipAddress)
    : NetworkDevice(std::move(name), std::move(ipAddress)) {}

void Firewall::addRule(FirewallRule rule) {
    rules_.push_back(std::move(rule));
}

void Firewall::clearRules() {
    rules_.clear();
}

bool Firewall::inspectPacket(Packet& packet) {
    if (!isOnline()) {
        packet.setStatus(PacketStatus::BLOCKED);
        return false;
    }

    ++packetsInspected_;
    for (const FirewallRule& rule : rules_) {
        if (!rule.matches(packet)) {
            continue;
        }

        if (rule.action == FirewallAction::BLOCK) {
            ++packetsBlocked_;
            packet.setStatus(PacketStatus::BLOCKED);
            return false;
        }

        ++packetsAllowed_;
        packet.setStatus(PacketStatus::ALLOWED);
        return true;
    }

    ++packetsAllowed_;
    packet.setStatus(PacketStatus::ALLOWED);
    return true;
}

std::size_t Firewall::getPacketsInspected() const noexcept {
    return packetsInspected_;
}

std::size_t Firewall::getPacketsAllowed() const noexcept {
    return packetsAllowed_;
}

std::size_t Firewall::getPacketsBlocked() const noexcept {
    return packetsBlocked_;
}

const std::vector<FirewallRule>& Firewall::getRules() const noexcept {
    return rules_;
}

std::string Firewall::getType() const {
    return "Firewall";
}

bool Firewall::receivePacket(Packet& packet) {
    return inspectPacket(packet);
}

std::string Firewall::getStatus() const {
    return isOnline() ? "ONLINE" : "OFFLINE";
}

} // namespace cyberguard