#include "core/Network.hpp"
#include "devices/Firewall.hpp"
#include "devices/Router.hpp"
#include "devices/Server.hpp"
#include "devices/Workstation.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>

namespace cyberguard {

class NetworkFixture : public ::testing::Test {
protected:
    void SetUp() override {
        network.addDevice(std::make_unique<Router>("Router", "10.0.0.1"));
        network.addDevice(std::make_unique<Firewall>("Firewall", "10.0.0.2"));
        network.addDevice(std::make_unique<Server>("Server", "10.0.0.10"));
        network.addDevice(std::make_unique<Workstation>("PC-01", "10.0.0.20"));

        auto* server = dynamic_cast<Server*>(network.findDevice("Server"));
        server->openService(80);
        server->openService(443);
    }

    Network network;
};

TEST_F(NetworkFixture, RoutesAllowedAndBlockedPackets) {
    auto* firewall = dynamic_cast<Firewall*>(network.findDevice("Firewall"));
    firewall->addRule({FirewallAction::BLOCK, std::nullopt, std::nullopt,
                       Protocol::TCP, 23, true});

    Packet allowed(1, "10.0.0.20", "10.0.0.10", 5000, 80,
                   Protocol::TCP, 64, 1);
    Packet blocked(2, "10.0.0.20", "10.0.0.10", 5001, 23,
                   Protocol::TCP, 64, 2);

    EXPECT_EQ(network.routePacket(allowed), PacketStatus::DELIVERED);
    EXPECT_EQ(network.routePacket(blocked), PacketStatus::BLOCKED);
    EXPECT_EQ(network.getStatistics().packetsCreated, 2U);
    EXPECT_EQ(network.getStatistics().packetsDelivered, 1U);
    EXPECT_EQ(network.getStatistics().packetsBlocked, 1U);
    EXPECT_EQ(network.getStatistics().packetsDropped, 0U);
}

TEST_F(NetworkFixture, DropsUnknownDestination) {
    Packet packet(1, "10.0.0.20", "10.0.0.99", 5000, 80,
                  Protocol::TCP, 64, 1);

    EXPECT_EQ(network.routePacket(packet), PacketStatus::DROPPED);
    EXPECT_EQ(network.getStatistics().packetsDropped, 1U);
}

TEST_F(NetworkFixture, DropsPacketsFromOfflineSources) {
    auto* source = dynamic_cast<Workstation*>(network.findDevice("PC-01"));
    ASSERT_NE(source, nullptr);
    source->setOnline(false);
    Packet packet(1, "10.0.0.20", "10.0.0.10", 5000, 80, Protocol::TCP, 64, 1);
    EXPECT_EQ(network.routePacket(packet), PacketStatus::DROPPED);
    EXPECT_EQ(network.getStatistics().packetsDropped, 1U);
    EXPECT_EQ(network.getStatistics().packetsDelivered, 0U);
}

TEST_F(NetworkFixture, RejectsInvalidDeviceIpAddresses) {
    EXPECT_THROW(network.addDevice(std::make_unique<Server>("Bad-IP", "10.0.0.99.")), std::invalid_argument);
}

TEST(WorkstationTests, OfflineWorkstationMarksCreatedPacketDropped) {
    Workstation workstation("PC-Offline", "10.0.0.30");
    workstation.setOnline(false);
    Packet packet = workstation.createPacket(1, "10.0.0.10", 80, Protocol::TCP, 64, 1);
    EXPECT_EQ(packet.getStatus(), PacketStatus::DROPPED);
    EXPECT_EQ(workstation.getPacketsSent(), 0U);
    EXPECT_EQ(workstation.getPacketsDropped(), 1U);
}

TEST_F(NetworkFixture, RejectsDuplicateDeviceIdentifiers) {
    EXPECT_THROW(network.addDevice(std::make_unique<Server>("Server", "10.0.0.50")),
                 std::invalid_argument);
    EXPECT_THROW(network.addDevice(std::make_unique<Server>("Other", "10.0.0.10")),
                 std::invalid_argument);
}

TEST_F(NetworkFixture, RemovesDevicesAndReportsOnlineCount) {
    EXPECT_EQ(network.getDeviceCount(), 4U);
    EXPECT_EQ(network.getOnlineDeviceCount(), 4U);
    auto* router = dynamic_cast<Router*>(network.findDevice("Router"));
    ASSERT_NE(router, nullptr);
    EXPECT_TRUE(router->hasRoute("10.0.0.20"));
    EXPECT_TRUE(network.removeDevice("PC-01"));
    EXPECT_FALSE(router->hasRoute("10.0.0.20"));
    EXPECT_FALSE(network.removeDevice("missing"));
    EXPECT_EQ(network.getDeviceCount(), 3U);
}

} // namespace cyberguard