#include "devices/Firewall.hpp"

#include <gtest/gtest.h>

namespace cyberguard {

TEST(FirewallTests, AppliesFirstMatchingRuleAndTracksStatistics) {
    Firewall firewall("FW", "10.0.0.2");
    firewall.addRule({FirewallAction::BLOCK, std::nullopt, std::nullopt,
                      Protocol::TCP, 23, true});
    firewall.addRule({FirewallAction::ALLOW, std::nullopt, std::nullopt,
                      Protocol::TCP, 80, true});

    Packet blocked(1, "10.0.0.20", "10.0.0.10", 1000, 23,
                   Protocol::TCP, 64, 1);
    Packet allowed(2, "10.0.0.20", "10.0.0.10", 1001, 80,
                   Protocol::TCP, 64, 2);

    EXPECT_FALSE(firewall.inspectPacket(blocked));
    EXPECT_EQ(blocked.getStatus(), PacketStatus::BLOCKED);
    EXPECT_TRUE(firewall.inspectPacket(allowed));
    EXPECT_EQ(allowed.getStatus(), PacketStatus::ALLOWED);
    EXPECT_EQ(firewall.getPacketsInspected(), 2U);
    EXPECT_EQ(firewall.getPacketsAllowed(), 1U);
    EXPECT_EQ(firewall.getPacketsBlocked(), 1U);
}

TEST(FirewallTests, DisabledRuleDoesNotMatch) {
    Firewall firewall("FW", "10.0.0.2");
    firewall.addRule({FirewallAction::BLOCK, std::nullopt, std::nullopt,
                      Protocol::TCP, 23, false});
    Packet packet(1, "10.0.0.20", "10.0.0.10", 1000, 23,
                  Protocol::TCP, 64, 1);

    EXPECT_TRUE(firewall.inspectPacket(packet));
}

} // namespace cyberguard