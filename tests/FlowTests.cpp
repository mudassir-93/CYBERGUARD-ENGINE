#include "core/FlowManager.hpp"
#include <gtest/gtest.h>
namespace cyberguard {
TEST(FlowManagerTests, AggregatesPacketsInBothDirections) {
    FlowManager manager;
    Packet outbound(1, "10.0.0.20", "10.0.0.10", 50000, 443, Protocol::TCP, 100, 10);
    outbound.setStatus(PacketStatus::DELIVERED);
    Packet response(2, "10.0.0.10", "10.0.0.20", 443, 50000, Protocol::TCP, 200, 12);
    response.setStatus(PacketStatus::DELIVERED);
    manager.observe(outbound);
    manager.observe(response);
    ASSERT_EQ(manager.getFlowCount(), 1U);
    const auto* flow = manager.findFlow(response);
    ASSERT_NE(flow, nullptr);
    EXPECT_EQ(flow->packetCount, 2U);
    EXPECT_EQ(flow->totalBytes, 300U);
    EXPECT_EQ(flow->aToBPackets + flow->bToAPackets, 2U);
    EXPECT_EQ(flow->deliveredPackets, 2U);
    EXPECT_EQ(flow->firstSeen, 10U);
    EXPECT_EQ(flow->lastSeen, 12U);
    EXPECT_EQ(flow->duration(), 2U);
    EXPECT_DOUBLE_EQ(flow->packetsPerSecond(), 1.0);
    EXPECT_DOUBLE_EQ(flow->bytesPerSecond(), 150.0);
}
TEST(FlowManagerTests, SeparatesDifferentPortsAndProtocols) {
    FlowManager manager;
    Packet https(1, "10.0.0.20", "10.0.0.10", 50000, 443, Protocol::TCP, 100, 1);
    Packet http(2, "10.0.0.20", "10.0.0.10", 50000, 80, Protocol::TCP, 100, 1);
    Packet udp(3, "10.0.0.20", "10.0.0.10", 50000, 443, Protocol::UDP, 100, 1);
    manager.observe(https); manager.observe(http); manager.observe(udp);
    EXPECT_EQ(manager.getFlowCount(), 3U);
}
TEST(FlowManagerTests, TracksOutcomesAndOutOfOrderTimestamps) {
    FlowManager manager;
    Packet delivered(1, "10.0.0.2", "10.0.0.1", 2000, 80, Protocol::TCP, 60, 20);
    delivered.setStatus(PacketStatus::DELIVERED);
    Packet blocked(2, "10.0.0.2", "10.0.0.1", 2000, 80, Protocol::TCP, 70, 15);
    blocked.setStatus(PacketStatus::BLOCKED);
    Packet dropped(3, "10.0.0.2", "10.0.0.1", 2000, 80, Protocol::TCP, 80, 25);
    dropped.setStatus(PacketStatus::DROPPED);
    manager.observe(delivered); manager.observe(blocked); manager.observe(dropped);
    const auto* flow = manager.findFlow(delivered);
    ASSERT_NE(flow, nullptr);
    EXPECT_EQ(flow->firstSeen, 15U);
    EXPECT_EQ(flow->lastSeen, 25U);
    EXPECT_EQ(flow->deliveredPackets, 1U);
    EXPECT_EQ(flow->blockedPackets, 1U);
    EXPECT_EQ(flow->droppedPackets, 1U);
    EXPECT_EQ(flow->totalBytes, 210U);
}
TEST(FlowManagerTests, ZeroDurationHasZeroRatesAndCanBeCleared) {
    FlowManager manager;
    Packet packet(1, "10.0.0.1", "10.0.0.2", 1000, 80, Protocol::UDP, 128, 5);
    manager.observe(packet);
    const auto* flow = manager.findFlow(packet);
    ASSERT_NE(flow, nullptr);
    EXPECT_EQ(flow->duration(), 0U);
    EXPECT_DOUBLE_EQ(flow->packetsPerSecond(), 0.0);
    EXPECT_DOUBLE_EQ(flow->bytesPerSecond(), 0.0);
    manager.clear();
    EXPECT_EQ(manager.getFlowCount(), 0U);
    EXPECT_EQ(manager.findFlow(packet), nullptr);
}
} // namespace cyberguard
