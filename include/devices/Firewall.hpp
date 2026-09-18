#pragma once

#include "core/NetworkDevice.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cyberguard {

enum class FirewallAction {
    ALLOW,
    BLOCK
};

struct FirewallRule {
    FirewallAction action{FirewallAction::ALLOW};
    std::optional<std::string> sourceIp;
    std::optional<std::string> destinationIp;
    std::optional<Protocol> protocol;
    std::optional<std::uint16_t> port;
    bool enabled{true};

    [[nodiscard]] bool matches(const Packet& packet) const;
};

class Firewall final : public NetworkDevice {
public:
    Firewall(std::string name, std::string ipAddress);

    void addRule(FirewallRule rule);
    void clearRules();
    [[nodiscard]] bool inspectPacket(Packet& packet);

    [[nodiscard]] std::size_t getPacketsInspected() const noexcept;
    [[nodiscard]] std::size_t getPacketsAllowed() const noexcept;
    [[nodiscard]] std::size_t getPacketsBlocked() const noexcept;
    [[nodiscard]] const std::vector<FirewallRule>& getRules() const noexcept;

    [[nodiscard]] std::string getType() const override;
    [[nodiscard]] bool receivePacket(Packet& packet) override;
    [[nodiscard]] std::string getStatus() const override;

private:
    std::vector<FirewallRule> rules_;
    std::size_t packetsInspected_{0};
    std::size_t packetsAllowed_{0};
    std::size_t packetsBlocked_{0};
};

} // namespace cyberguard