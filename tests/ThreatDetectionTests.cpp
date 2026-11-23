#include "core/ThreatDetector.hpp"
#include "core/TrafficScenarioGenerator.hpp"
#include "devices/Firewall.hpp"
#include "devices/Router.hpp"
#include "devices/Server.hpp"
#include "devices/Workstation.hpp"
#include <gtest/gtest.h>
#include <stdexcept>
#include <memory>

namespace cyberguard {
TEST(ThreatDetectionTests, DetectsRepeatedFailedConnectionsToOneService) {
    std::vector<NetworkFlow> flows;
    for (std::uint16_t i=0;i<6;++i) {
        NetworkFlow f;
        f.endpointAIp="10.0.0.20"; f.endpointAPort=static_cast<std::uint16_t>(50000+i);
        f.endpointBIp="10.0.0.10"; f.endpointBPort=22; f.protocol=Protocol::TCP;
        f.firstSeen=i; f.lastSeen=i; f.aToBPackets=1; f.packetCount=1; f.droppedPackets=1;
        flows.push_back(f);
    }
    const auto alerts=ThreatDetector::detectBruteForce(flows,5,60);
    ASSERT_EQ(alerts.size(),1U);
    EXPECT_EQ(alerts.front().sourceIp,"10.0.0.20");
    EXPECT_EQ(alerts.front().destinationPort,22);
    EXPECT_EQ(alerts.front().failedAttempts,6U);
}
TEST(ThreatDetectionTests, DoesNotFlagFailuresOutsideObservationWindow) {
    NetworkFlow f;
    f.endpointAIp="10.0.0.20"; f.endpointBIp="10.0.0.10";
    f.endpointBPort=22; f.protocol=Protocol::TCP; f.aToBPackets=5;
    f.droppedPackets=5; f.firstSeen=1; f.lastSeen=100;
    EXPECT_TRUE(ThreatDetector::detectBruteForce({f},5,30).empty());
}
TEST(ThreatDetectionTests, DetectsHighVolumeTrafficToOneDestination) {
    NetworkFlow f;
    f.endpointAIp="10.0.0.20"; f.endpointBIp="10.0.0.10";
    f.endpointAPort=40000; f.endpointBPort=80; f.protocol=Protocol::TCP;
    f.aToBPackets=120; f.packetCount=120; f.aToBBytes=120000;
    f.totalBytes=120000; f.firstSeen=10; f.lastSeen=18;
    const auto alerts=ThreatDetector::detectDenialOfService({f},100,10);
    ASSERT_EQ(alerts.size(),1U);
    EXPECT_EQ(alerts.front().packetCount,120U);
    EXPECT_EQ(alerts.front().totalBytes,120000U);
}
TEST(ThreatDetectionTests, DetectsOneHostContactingMultiplePrivateHosts) {
    std::vector<NetworkFlow> flows;
    for (int i=10;i<13;++i) {
        NetworkFlow f;
        f.endpointAIp="10.0.0.20"; f.endpointBIp="10.0.0."+std::to_string(i);
        f.endpointAPort=40000; f.endpointBPort=445; f.protocol=Protocol::TCP;
        f.aToBPackets=1; f.packetCount=1; f.firstSeen=1; f.lastSeen=3;
        flows.push_back(f);
    }
    const auto alerts=ThreatDetector::detectLateralMovement(flows,3,60);
    ASSERT_EQ(alerts.size(),1U);
    EXPECT_EQ(alerts.front().sourceIp,"10.0.0.20");
    EXPECT_EQ(alerts.front().internalDestinations.size(),3U);
}
TEST(ThreatDetectionTests, RejectsZeroThresholdsAndWindows) {
    EXPECT_THROW(ThreatDetector::detectBruteForce({},0,60),std::invalid_argument);
    EXPECT_THROW(ThreatDetector::detectDenialOfService({},100,0),std::invalid_argument);
    EXPECT_THROW(ThreatDetector::detectLateralMovement({},3,0),std::invalid_argument);
}

TEST(ThreatDetectionTests, EndToEndScenariosReachAllThreeDetectors) {
    Network network;
    network.addDevice(std::make_unique<Router>("Router","10.0.0.1"));
    network.addDevice(std::make_unique<Firewall>("Firewall","10.0.0.2"));
    network.addDevice(std::make_unique<Server>("Server","10.0.0.10"));
    network.addDevice(std::make_unique<Workstation>("PC-01","10.0.0.20"));
    auto* server=dynamic_cast<Server*>(network.findDevice("Server"));
    ASSERT_NE(server,nullptr);
    server->openService(80);

    const auto brute=TrafficScenarioGenerator::runBruteForce(network,"10.0.0.20","10.0.0.10",22,6,1000,1);
    EXPECT_EQ(brute.packetsSent,6U);
    const auto dos=TrafficScenarioGenerator::runDenialOfService(network,"10.0.0.20","10.0.0.10",80,120,2000,20);
    EXPECT_EQ(dos.packetsSent,120U);
    const auto lateral=TrafficScenarioGenerator::runLateralMovement(
        network,"10.0.0.20",{"10.0.0.10","10.0.0.11","10.0.0.12"},445,3000,40);
    EXPECT_EQ(lateral.packetsSent,3U);

    const auto flows=network.getFlowManager().getFlows();
    EXPECT_EQ(ThreatDetector::detectBruteForce(flows,5,60).size(),1U);
    EXPECT_EQ(ThreatDetector::detectDenialOfService(flows,100,10).size(),1U);
    EXPECT_EQ(ThreatDetector::detectLateralMovement(flows,3,60).size(),1U);
}
TEST(ThreatDetectionTests, ScenarioGeneratorsRejectUnboundedOrInvalidInput) {
    Network network;
    EXPECT_THROW(TrafficScenarioGenerator::runBruteForce(network,"10.0.0.1","10.0.0.2",22,0,1,1),std::invalid_argument);
    EXPECT_THROW(TrafficScenarioGenerator::runDenialOfService(network,"10.0.0.1","10.0.0.2",80,10001,1,1),std::invalid_argument);
    EXPECT_THROW(TrafficScenarioGenerator::runLateralMovement(network,"10.0.0.1",{},445,1,1),std::invalid_argument);
}
} // namespace cyberguard
