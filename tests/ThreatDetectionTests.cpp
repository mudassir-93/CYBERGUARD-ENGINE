#include "core/ThreatDetector.hpp"
#include <gtest/gtest.h>
#include <stdexcept>

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
} // namespace cyberguard
