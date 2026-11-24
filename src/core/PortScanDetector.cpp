#include "core/PortScanDetector.hpp"
#include <algorithm>
#include <map>
#include <stdexcept>
#include <utility>
namespace cyberguard {
PortScanDetector::PortScanDetector(std::size_t threshold, std::uint64_t window) : minimumDistinctPorts_(threshold), observationWindowSeconds_(window) {
    if (threshold < 2) throw std::invalid_argument("Port-scan threshold must be at least two ports");
    if (window == 0) throw std::invalid_argument("Port-scan observation window must be positive");
}
std::vector<PortScanAlert> PortScanDetector::detect(const std::vector<NetworkFlow>& flows) const {
    struct Observation { std::uint16_t port; std::uint64_t timestamp; };
    using Pair = std::pair<std::string, std::string>;
    std::map<Pair, std::vector<Observation>> grouped;
    for (const auto& flow : flows) {
        if (flow.aToBPackets) grouped[{flow.endpointAIp, flow.endpointBIp}].push_back({flow.endpointBPort, flow.firstSeen});
        if (flow.bToAPackets) grouped[{flow.endpointBIp, flow.endpointAIp}].push_back({flow.endpointAPort, flow.firstSeen});
    }
    std::vector<PortScanAlert> alerts;
    for (auto& [endpoints, observations] : grouped) {
        std::sort(observations.begin(), observations.end(), [](const auto& a, const auto& b) { return a.timestamp < b.timestamp; });
        std::map<std::uint16_t, std::size_t> activeCounts;
        std::size_t left = 0;
        for (std::size_t right = 0; right < observations.size(); ++right) {
            ++activeCounts[observations[right].port];
            while (observations[right].timestamp - observations[left].timestamp > observationWindowSeconds_) {
                auto it = activeCounts.find(observations[left].port);
                if (--it->second == 0) activeCounts.erase(it);
                ++left;
            }
            if (activeCounts.size() >= minimumDistinctPorts_) {
                PortScanAlert alert;
                alert.sourceIp = endpoints.first; alert.destinationIp = endpoints.second;
                alert.firstSeen = observations[left].timestamp; alert.lastSeen = observations[right].timestamp;
                for (const auto& [port, count] : activeCounts) { (void)count; alert.destinationPorts.push_back(port); }
                alerts.push_back(std::move(alert)); break;
            }
        }
    }
    return alerts;
}
} // namespace cyberguard
