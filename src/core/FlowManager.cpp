#include "core/FlowManager.hpp"
#include <algorithm>
#include <string>
#include <utility>
namespace cyberguard {
namespace {
struct Endpoint {
    std::string ip;
    std::uint16_t port{0};
    [[nodiscard]] bool operator<(const Endpoint& other) const noexcept {
        return ip != other.ip ? ip < other.ip : port < other.port;
    }
};
const char* protocolName(Protocol protocol) noexcept {
    switch (protocol) {
    case Protocol::TCP: return "TCP";
    case Protocol::UDP: return "UDP";
    case Protocol::ICMP: return "ICMP";
    }
    return "UNKNOWN";
}
} // namespace
std::uint64_t NetworkFlow::duration() const noexcept {
    return lastSeen >= firstSeen ? lastSeen - firstSeen : 0;
}
double NetworkFlow::packetsPerSecond() const noexcept {
    const auto seconds = duration();
    return seconds == 0 ? 0.0 : static_cast<double>(packetCount) / static_cast<double>(seconds);
}
double NetworkFlow::bytesPerSecond() const noexcept {
    const auto seconds = duration();
    return seconds == 0 ? 0.0 : static_cast<double>(totalBytes) / static_cast<double>(seconds);
}
std::string FlowManager::makeKey(const Packet& packet) {
    Endpoint source{packet.getSourceIp(), packet.getSourcePort()};
    Endpoint destination{packet.getDestinationIp(), packet.getDestinationPort()};
    if (destination < source) std::swap(source, destination);
    return std::string(protocolName(packet.getProtocol())) + "|" +
           source.ip + ":" + std::to_string(source.port) + "|" +
           destination.ip + ":" + std::to_string(destination.port);
}
void FlowManager::observe(const Packet& packet) {
    Endpoint source{packet.getSourceIp(), packet.getSourcePort()};
    Endpoint destination{packet.getDestinationIp(), packet.getDestinationPort()};
    const bool sourceIsA = !(destination < source);
    if (!sourceIsA) std::swap(source, destination);
    auto [iterator, inserted] = flows_.try_emplace(makeKey(packet));
    auto& flow = iterator->second;
    if (inserted) {
        flow.endpointAIp = source.ip;
        flow.endpointAPort = source.port;
        flow.endpointBIp = destination.ip;
        flow.endpointBPort = destination.port;
        flow.protocol = packet.getProtocol();
        flow.firstSeen = packet.getTimestamp();
        flow.lastSeen = packet.getTimestamp();
    } else {
        flow.firstSeen = std::min(flow.firstSeen, packet.getTimestamp());
        flow.lastSeen = std::max(flow.lastSeen, packet.getTimestamp());
    }
    ++flow.packetCount;
    flow.totalBytes += packet.getSize();
    if (sourceIsA) {
        ++flow.aToBPackets;
        flow.aToBBytes += packet.getSize();
    } else {
        ++flow.bToAPackets;
        flow.bToABytes += packet.getSize();
    }
    switch (packet.getStatus()) {
    case PacketStatus::DELIVERED: ++flow.deliveredPackets; break;
    case PacketStatus::BLOCKED: ++flow.blockedPackets; break;
    case PacketStatus::DROPPED: ++flow.droppedPackets; break;
    default: break;
    }
}
std::size_t FlowManager::getFlowCount() const noexcept { return flows_.size(); }
const NetworkFlow* FlowManager::findFlow(const Packet& packet) const {
    const auto iterator = flows_.find(makeKey(packet));
    return iterator == flows_.end() ? nullptr : &iterator->second;
}
std::vector<NetworkFlow> FlowManager::getFlows() const {
    std::vector<NetworkFlow> result;
    result.reserve(flows_.size());
    for (const auto& entry : flows_) result.push_back(entry.second);
    return result;
}
void FlowManager::clear() noexcept { flows_.clear(); }
} // namespace cyberguard
