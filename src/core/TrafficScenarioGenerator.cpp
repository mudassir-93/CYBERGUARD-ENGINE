#include "core/TrafficScenarioGenerator.hpp"
#include <iterator>
#include <stdexcept>
namespace cyberguard {
namespace {
void record(ScenarioResult& r, PacketStatus s) {
    ++r.packetsSent;
    if (s == PacketStatus::DELIVERED) ++r.delivered;
    else if (s == PacketStatus::BLOCKED) ++r.blocked;
    else if (s == PacketStatus::DROPPED) ++r.dropped;
}
}
ScenarioResult TrafficScenarioGenerator::runNormalTraffic(Network& n, const std::string& src, const std::string& dst, std::uint64_t id, std::uint64_t time) {
    constexpr std::uint16_t ports[] = {80, 443, 80, 443, 80};
    ScenarioResult r;
    for (std::size_t i = 0; i < std::size(ports); ++i) {
        Packet p(id + i, src, dst, static_cast<std::uint32_t>(51000 + i), ports[i], Protocol::TCP, 512, time + i);
        record(r, n.sendPacket(p));
    }
    return r;
}
ScenarioResult TrafficScenarioGenerator::runPortScan(Network& n, const std::string& src, const std::string& dst, std::uint16_t first, std::uint16_t last, std::uint64_t id, std::uint64_t time) {
    if (first == 0 || last < first) throw std::invalid_argument("Port-scan range must be an ascending range of valid ports");
    ScenarioResult r; std::uint64_t offset = 0;
    for (std::uint32_t port = first; port <= last; ++port, ++offset) {
        Packet p(id + offset, src, dst, static_cast<std::uint32_t>(40000 + (offset % 20000)), port, Protocol::TCP, 64, time + offset);
        record(r, n.sendPacket(p));
    }
    return r;
}
} // namespace cyberguard
