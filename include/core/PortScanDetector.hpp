#pragma once
#include "core/NetworkFlow.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
namespace cyberguard {
struct PortScanAlert {
    std::string sourceIp, destinationIp;
    std::vector<std::uint16_t> destinationPorts;
    std::uint64_t firstSeen{0}, lastSeen{0};
};
class PortScanDetector {
public:
    explicit PortScanDetector(std::size_t minimumDistinctPorts = 10, std::uint64_t observationWindowSeconds = 60);
    [[nodiscard]] std::vector<PortScanAlert> detect(const std::vector<NetworkFlow>& flows) const;
private:
    std::size_t minimumDistinctPorts_;
    std::uint64_t observationWindowSeconds_;
};
} // namespace cyberguard
