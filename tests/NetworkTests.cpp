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

TEST_F(NetworkFixture, RejectsDuplicateDeviceIdentifiers) {
    EXPECT_THROW(network.addDevice(std::make_unique<Server>("Server", "10.0.0.50")),
                 std::invalid_argument);
    EXPECT_THROW(network.addDevice(std::make_unique<Server>("Other", "10.0.0.10")),
                 std::invalid_argument);
}

TEST_F(NetworkFixture, RemovesDevicesAndReportsOnlineCount) {
    EXPECT_EQ(network.getDeviceCount(), 4U);
    EXPECT_EQ(network.getOnlineDeviceCount(), 4U);
    EXPECT_TRUE(network.removeDevice("PC-01"));
    EXPECT_FALSE(network.removeDevice("missing"));
    EXPECT_EQ(network.getDeviceCount(), 3U);
}

} // namespace cyberguard