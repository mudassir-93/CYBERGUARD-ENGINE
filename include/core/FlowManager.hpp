#pragma once
#include "core/NetworkFlow.hpp"
#include <cstddef>
#include <map>
#include <string>
#include <vector>
namespace cyberguard {
class FlowManager {
public:
    void observe(const Packet& packet);
    [[nodiscard]] std::size_t getFlowCount() const noexcept;
    [[nodiscard]] const NetworkFlow* findFlow(const Packet& packet) const;
    [[nodiscard]] std::vector<NetworkFlow> getFlows() const;
    void clear() noexcept;
private:
    [[nodiscard]] static std::string makeKey(const Packet& packet);
    std::map<std::string, NetworkFlow> flows_;
};
} // namespace cyberguard
