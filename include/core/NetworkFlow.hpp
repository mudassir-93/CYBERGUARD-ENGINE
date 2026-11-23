#pragma once
#include "core/Packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
namespace cyberguard {
// Bidirectional five-tuple. Endpoint A is lexicographically smaller by IP then port.
struct NetworkFlow {
    std::string endpointAIp;
    std::uint16_t endpointAPort{0};
    std::string endpointBIp;
    std::uint16_t endpointBPort{0};
    Protocol protocol{Protocol::TCP};
    std::uint64_t firstSeen{0};
    std::uint64_t lastSeen{0};
    std::size_t packetCount{0};
    std::uint64_t totalBytes{0};
    std::size_t aToBPackets{0};
    std::uint64_t aToBBytes{0};
    std::size_t bToAPackets{0};
    std::uint64_t bToABytes{0};
    std::size_t deliveredPackets{0};
    std::size_t blockedPackets{0};
    std::size_t droppedPackets{0};
    [[nodiscard]] std::uint64_t duration() const noexcept;
    [[nodiscard]] double packetsPerSecond() const noexcept;
    [[nodiscard]] double bytesPerSecond() const noexcept;
};
} // namespace cyberguard
