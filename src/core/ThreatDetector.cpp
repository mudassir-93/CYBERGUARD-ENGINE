#include "core/ThreatDetector.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>

namespace cyberguard {
namespace {
struct BruteKey {
    std::string source;
    std::string destination;
    std::uint16_t port;
    Protocol protocol;
    bool operator<(const BruteKey& other) const noexcept {
        return std::tie(source, destination, port, protocol) <
               std::tie(other.source, other.destination, other.port, other.protocol);
    }
};
bool isPrivateIpv4(const std::string& ip) {
    unsigned int a=0,b=0,c=0,d=0;
    char tail=0;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u%c", &a,&b,&c,&d,&tail) != 4 ||
        a>255 || b>255 || c>255 || d>255) return false;
    return a==10 || (a==172 && b>=16 && b<=31) || (a==192 && b==168);
}
void validate(std::size_t threshold, std::uint64_t window) {
    if (threshold == 0) throw std::invalid_argument("Detection threshold must be positive");
    if (window == 0) throw std::invalid_argument("Detection window must be positive");
}
} // namespace

std::vector<BruteForceAlert> ThreatDetector::detectBruteForce(
    const std::vector<NetworkFlow>& flows, std::size_t threshold, std::uint64_t window) {
    validate(threshold, window);
    struct Aggregate { std::size_t failures{0}; std::uint64_t first{0}, last{0}; bool initialized{false}; };
    std::map<BruteKey, Aggregate> grouped;
    for (const auto& flow : flows) {
        auto add = [&](const std::string& src, const std::string& dst, std::uint16_t port,
                       std::size_t packets) {
            if (packets == 0) return;
            auto& item = grouped[{src,dst,port,flow.protocol}];
            if (!item.initialized) { item.first=flow.firstSeen; item.last=flow.lastSeen; item.initialized=true; }
            else { item.first=std::min(item.first,flow.firstSeen); item.last=std::max(item.last,flow.lastSeen); }
            item.failures += packets;
        };
        if (flow.aToBPackets) add(flow.endpointAIp,flow.endpointBIp,flow.endpointBPort,
                                  flow.blockedPackets+flow.droppedPackets);
        if (flow.bToAPackets) add(flow.endpointBIp,flow.endpointAIp,flow.endpointAPort,
                                  flow.blockedPackets+flow.droppedPackets);
    }
    std::vector<BruteForceAlert> alerts;
    for (const auto& [key,item] : grouped) {
        if (item.failures >= threshold && item.last >= item.first && item.last-item.first <= window)
            alerts.push_back({key.source,key.destination,key.port,item.failures,item.first,item.last});
    }
    return alerts;
}

std::vector<DenialOfServiceAlert> ThreatDetector::detectDenialOfService(
    const std::vector<NetworkFlow>& flows, std::size_t threshold, std::uint64_t window) {
    validate(threshold, window);
    struct Aggregate { std::size_t packets{0}; std::uint64_t bytes{0},first{0},last{0}; bool initialized{false}; };
    std::map<std::pair<std::string,std::string>,Aggregate> grouped;
    for (const auto& flow : flows) {
        auto add = [&](const std::string& src,const std::string& dst,std::size_t count) {
            if (!count) return;
            auto& item=grouped[{src,dst}];
            item.packets+=count;
            item.bytes+=flow.totalBytes;
            if (!item.initialized) { item.first=flow.firstSeen; item.last=flow.lastSeen; item.initialized=true; }
            else { item.first=std::min(item.first,flow.firstSeen); item.last=std::max(item.last,flow.lastSeen); }
        };
        if (flow.aToBPackets) add(flow.endpointAIp,flow.endpointBIp,flow.aToBPackets);
        if (flow.bToAPackets) add(flow.endpointBIp,flow.endpointAIp,flow.bToAPackets);
    }
    std::vector<DenialOfServiceAlert> alerts;
    for (const auto& [endpoints,item] : grouped)
        if (item.packets>=threshold && item.last>=item.first && item.last-item.first<=window)
            alerts.push_back({endpoints.first,endpoints.second,item.packets,item.bytes,item.first,item.last});
    return alerts;
}

std::vector<LateralMovementAlert> ThreatDetector::detectLateralMovement(
    const std::vector<NetworkFlow>& flows, std::size_t threshold, std::uint64_t window) {
    validate(threshold, window);
    struct Aggregate { std::set<std::string> destinations; std::uint64_t first{0},last{0}; bool initialized{false}; };
    std::map<std::string,Aggregate> grouped;
    for (const auto& flow : flows) {
        auto add=[&](const std::string& src,const std::string& dst) {
            if (!isPrivateIpv4(dst)) return;
            auto& item=grouped[src];
            item.destinations.insert(dst);
            if (!item.initialized) { item.first=flow.firstSeen; item.last=flow.lastSeen; item.initialized=true; }
            else { item.first=std::min(item.first,flow.firstSeen); item.last=std::max(item.last,flow.lastSeen); }
        };
        if (flow.aToBPackets) add(flow.endpointAIp,flow.endpointBIp);
        if (flow.bToAPackets) add(flow.endpointBIp,flow.endpointAIp);
    }
    std::vector<LateralMovementAlert> alerts;
    for (const auto& [source,item] : grouped)
        if (item.destinations.size()>=threshold && item.last>=item.first && item.last-item.first<=window)
            alerts.push_back({source,{item.destinations.begin(),item.destinations.end()},item.first,item.last});
    return alerts;
}
} // namespace cyberguard
