#include "devices/Server.hpp"

#include <gtest/gtest.h>

namespace cyberguard {

TEST(ServerTests, AcceptsOpenServiceAndRejectsClosedService) {
    Server server("Server", "10.0.0.10");
    server.openService(80);
    Packet open(1, "10.0.0.20", "10.0.0.10", 1000, 80,
                Protocol::TCP, 64, 1);
    Packet closed(2, "10.0.0.20", "10.0.0.10", 1001, 22,
                  Protocol::TCP, 64, 2);

    EXPECT_TRUE(server.receivePacket(open));
    EXPECT_FALSE(server.receivePacket(closed));
    EXPECT_EQ(server.getPacketsReceived(), 2U);
    EXPECT_EQ(server.getPacketsAccepted(), 1U);
    EXPECT_EQ(server.getPacketsRejected(), 1U);
}

} // namespace cyberguard