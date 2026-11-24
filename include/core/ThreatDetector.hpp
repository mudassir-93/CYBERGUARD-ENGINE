#pragma once
#include "core/NetworkFlow.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cyberguard {

struct BruteForceAlert {
    std::string sourceIp;
    std::string destinationIp;
    std::uint16_t destinationPort{0};
    std::size_t failedAttempts{0};
    std::uint64_t firstSeen{0};
    std::uint64_t lastSeen{0};
};

struct DenialOfServiceAlert {
    std::string sourceIp;
    std::string destinationIp;
    std::size_t packetCount{0};
    std::uint64_t totalBytes{0};
    std::uint64_t firstSeen{0};
    std::uint64_t lastSeen{0};
};

struct LateralMovementAlert {
    std::string sourceIp;
    std::vector<std::string> internalDestinations;
    std::uint64_t firstSeen{0};
    std::uint64_t lastSeen{0};
};

class ThreatDetector {
public:
    [[nodiscard]] static std::vector<BruteForceAlert> detectBruteForce(
        const std::vector<NetworkFlow>& flows,
        std::size_t minimumFailures = 5,
        std::uint64_t observationWindowSeconds = 60);

    [[nodiscard]] static std::vector<DenialOfServiceAlert> detectDenialOfService(
        const std::vector<NetworkFlow>& flows,
        std::size_t minimumPackets = 100,
        std::uint64_t observationWindowSeconds = 10);

    [[nodiscard]] static std::vector<LateralMovementAlert> detectLateralMovement(
        const std::vector<NetworkFlow>& flows,
        std::size_t minimumInternalDestinations = 3,
        std::uint64_t observationWindowSeconds = 60);
};

} // namespace cyberguard
