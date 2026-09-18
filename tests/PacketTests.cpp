#include "core/Packet.hpp"

#include <gtest/gtest.h>

#include <stdexcept>

namespace cyberguard {

TEST(PacketTests, StoresPropertiesAndStartsCreated) {
    const Packet packet(42, "10.0.0.20", "10.0.0.10", 50000, 80,
                        Protocol::TCP, 512, 100);

    EXPECT_EQ(packet.getId(), 42U);
    EXPECT_EQ(packet.getSourceIp(), "10.0.0.20");
    EXPECT_EQ(packet.getDestinationIp(), "10.0.0.10");
    EXPECT_EQ(packet.getProtocol(), Protocol::TCP);
    EXPECT_EQ(packet.getStatus(), PacketStatus::CREATED);
}

TEST(PacketTests, StatusCanAdvanceDeterministically) {
    Packet packet(1, "10.0.0.1", "10.0.0.2", 1000, 80,
                  Protocol::TCP, 64, 1);

    packet.setStatus(PacketStatus::ROUTING);
    EXPECT_EQ(packet.getStatus(), PacketStatus::ROUTING);
    packet.setStatus(PacketStatus::DELIVERED);
    EXPECT_EQ(packet.getStatus(), PacketStatus::DELIVERED);
}

TEST(PacketTests, RejectsInvalidAddressAndSize) {
    EXPECT_THROW(Packet(1, "10.0.0", "10.0.0.2", 1, 80,
                        Protocol::TCP, 64, 1), std::invalid_argument);
    EXPECT_THROW(Packet(1, "10.0.0.1", "300.0.0.2", 1, 80,
                        Protocol::TCP, 64, 1), std::invalid_argument);
    EXPECT_THROW(Packet(1, "10.0.0.1", "10.0.0.2", 70000, 80,
                        Protocol::TCP, 64, 1), std::invalid_argument);
    EXPECT_THROW(Packet(1, "10.0.0.1", "10.0.0.2", 1, 80,
                        Protocol::TCP, 0, 1), std::invalid_argument);
}

} // namespace cyberguard