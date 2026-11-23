#pragma once
#include "core/Network.hpp"
#include <cstdint>
#include <string>
namespace cyberguard {
struct ScenarioResult { std::size_t packetsSent{0}, delivered{0}, blocked{0}, dropped{0}; };
class TrafficScenarioGenerator {
public:
    [[nodiscard]] static ScenarioResult runNormalTraffic(Network&, const std::string&, const std::string&, std::uint64_t, std::uint64_t);
    [[nodiscard]] static ScenarioResult runPortScan(Network&, const std::string&, const std::string&, std::uint16_t, std::uint16_t, std::uint64_t, std::uint64_t);
};
} // namespace cyberguard
