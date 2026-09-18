#include "devices/Router.hpp"

#include <gtest/gtest.h>

namespace cyberguard {

TEST(RouterTests, ForwardsKnownDestinationsAndDropsUnknownRoutes) {
    Router router("R1", "10.0.0.1");
    router.addRoute("10.0.0.10", "10.0.0.10");
    Packet known(1, "10.0.0.20", "10.0.0.10", 1, 80,
                 Protocol::TCP, 64, 1);
    Packet unknown(2, "10.0.0.20", "10.0.0.99", 1, 80,
                   Protocol::TCP, 64, 2);

    EXPECT_TRUE(router.receivePacket(known));
    EXPECT_TRUE(router.forwardPacket(known));
    EXPECT_TRUE(router.receivePacket(unknown));
    EXPECT_FALSE(router.forwardPacket(unknown));
    EXPECT_EQ(router.getPacketsReceived(), 2U);
    EXPECT_EQ(router.getPacketsForwarded(), 1U);
    EXPECT_EQ(router.getPacketsDropped(), 1U);
}

} // namespace cyberguard