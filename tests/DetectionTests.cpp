#include "core/PortScanDetector.hpp"
#include "core/TrafficScenarioGenerator.hpp"
#include "devices/Firewall.hpp"
#include "devices/Router.hpp"
#include "devices/Server.hpp"
#include "devices/Workstation.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
namespace cyberguard {
TEST(PortScanDetectorTests, DetectsDistinctPortsFromOneSourceWithinWindow) {
    std::vector<NetworkFlow> flows;
    for (std::uint16_t port=1; port<=12; ++port) {
        NetworkFlow f; f.endpointAIp="10.0.0.20"; f.endpointAPort=static_cast<std::uint16_t>(40000+port);
        f.endpointBIp="10.0.0.10"; f.endpointBPort=port; f.protocol=Protocol::TCP;
        f.firstSeen=port; f.lastSeen=port; f.aToBPackets=1; f.packetCount=1; flows.push_back(f);
    }
    const auto alerts=PortScanDetector(10,60).detect(flows);
    ASSERT_EQ(alerts.size(),1U); EXPECT_EQ(alerts[0].sourceIp,"10.0.0.20");
    EXPECT_EQ(alerts[0].destinationIp,"10.0.0.10"); EXPECT_EQ(alerts[0].destinationPorts.size(),10U);
}
TEST(PortScanDetectorTests, IgnoresPortsOutsideWindowAndBelowThreshold) {
    std::vector<NetworkFlow> flows;
    for (std::uint16_t port=1; port<=10; ++port) {
        NetworkFlow f; f.endpointAIp="10.0.0.20"; f.endpointBIp="10.0.0.10";
        f.endpointBPort=port; f.firstSeen=port*100; f.aToBPackets=1; flows.push_back(f);
    }
    EXPECT_TRUE(PortScanDetector(10,30).detect(flows).empty());
    flows.resize(9); EXPECT_TRUE(PortScanDetector(10,6000).detect(flows).empty());
}
TEST(PortScanDetectorTests, RejectsInvalidThresholds) {
    EXPECT_THROW(PortScanDetector(1,60),std::invalid_argument);
    EXPECT_THROW(PortScanDetector(10,0),std::invalid_argument);
}
TEST(TrafficScenarioTests, NormalAndScanScenariosReachFlowDetection) {
    Network n; n.addDevice(std::make_unique<Router>("Router","10.0.0.1"));
    n.addDevice(std::make_unique<Firewall>("Firewall","10.0.0.2"));
    n.addDevice(std::make_unique<Server>("Server","10.0.0.10"));
    n.addDevice(std::make_unique<Workstation>("PC-01","10.0.0.20"));
    auto* server=dynamic_cast<Server*>(n.findDevice("Server")); ASSERT_NE(server,nullptr);
    server->openService(80); server->openService(443);
    const auto normal=TrafficScenarioGenerator::runNormalTraffic(n,"10.0.0.20","10.0.0.10",1,1);
    EXPECT_EQ(normal.packetsSent,5U); EXPECT_EQ(normal.delivered,5U);
    const auto scan=TrafficScenarioGenerator::runPortScan(n,"10.0.0.20","10.0.0.10",1,12,100,10);
    EXPECT_EQ(scan.packetsSent,12U); EXPECT_EQ(scan.dropped,12U);
    const auto alerts=PortScanDetector(10,60).detect(n.getFlowManager().getFlows());
    ASSERT_EQ(alerts.size(),1U); EXPECT_EQ(alerts.front().sourceIp,"10.0.0.20");
}
} // namespace cyberguard
