#include "core/Network.hpp"
#include "core/PortScanDetector.hpp"
#include "core/ThreatDetector.hpp"
#include "core/TrafficScenarioGenerator.hpp"
#include "devices/Firewall.hpp"
#include "devices/Router.hpp"
#include "devices/Server.hpp"
#include "devices/Workstation.hpp"
#include <iostream>
#include <memory>
#include <optional>
#include <vector>

namespace {
void printScenario(const char* label, const cyberguard::ScenarioResult& result) {
    std::cout << label << ": " << result.packetsSent << " packets, "
              << result.delivered << " delivered, " << result.blocked << " blocked, "
              << result.dropped << " dropped\n";
}
}

int main() {
    std::cout << "====================================\n"
                 "        CYBERGUARD ENGINE\n"
                 "====================================\n\n"
                 "LOCAL NETWORK SECURITY SIMULATION\n\n";

    cyberguard::Network network;
    network.addDevice(std::make_unique<cyberguard::Router>("Router", "10.0.0.1"));
    network.addDevice(std::make_unique<cyberguard::Firewall>("Firewall", "10.0.0.2"));
    network.addDevice(std::make_unique<cyberguard::Server>("Server", "10.0.0.10"));
    network.addDevice(std::make_unique<cyberguard::Workstation>("PC-01", "10.0.0.20"));
    network.addDevice(std::make_unique<cyberguard::Workstation>("PC-02", "10.0.0.21"));

    auto* server = dynamic_cast<cyberguard::Server*>(network.findDevice("Server"));
    auto* firewall = dynamic_cast<cyberguard::Firewall*>(network.findDevice("Firewall"));
    server->openService(80);
    server->openService(443);
    firewall->addRule({cyberguard::FirewallAction::BLOCK, std::nullopt, std::nullopt,
                       cyberguard::Protocol::TCP, 23, true});

    std::cout << "Devices initialized: " << network.getDeviceCount() << "\n";
    printScenario("Normal traffic",
        cyberguard::TrafficScenarioGenerator::runNormalTraffic(network, "10.0.0.20", "10.0.0.10", 1, 1));
    printScenario("Simulated port scan",
        cyberguard::TrafficScenarioGenerator::runPortScan(network, "10.0.0.20", "10.0.0.10", 1, 12, 100, 10));
    printScenario("Simulated brute-force pattern",
        cyberguard::TrafficScenarioGenerator::runBruteForce(network, "10.0.0.20", "10.0.0.10", 22, 6, 200, 30));
    printScenario("Simulated DoS-like traffic",
        cyberguard::TrafficScenarioGenerator::runDenialOfService(network, "10.0.0.21", "10.0.0.10", 80, 120, 300, 40));
    printScenario("Simulated internal host sweep",
        cyberguard::TrafficScenarioGenerator::runLateralMovement(
            network, "10.0.0.20", {"10.0.0.10", "10.0.0.11", "10.0.0.12"}, 445, 500, 60));

    const auto flows = network.getFlowManager().getFlows();
    const auto scans = cyberguard::PortScanDetector(10, 60).detect(flows);
    const auto brute = cyberguard::ThreatDetector::detectBruteForce(flows);
    const auto dos = cyberguard::ThreatDetector::detectDenialOfService(flows);
    const auto lateral = cyberguard::ThreatDetector::detectLateralMovement(flows);

    std::cout << "\nFLOW SUMMARY\nObserved flows: " << network.getFlowManager().getFlowCount()
              << "\n\nDETECTION RESULTS\n";
    for (const auto& alert : scans)
        std::cout << "PORT SCAN: " << alert.sourceIp << " scanned " << alert.destinationIp
                  << " across " << alert.destinationPorts.size() << " distinct ports.\n";
    for (const auto& alert : brute)
        std::cout << "BRUTE-FORCE PATTERN: " << alert.sourceIp << " made " << alert.failedAttempts
                  << " failed attempts to " << alert.destinationIp << ':' << alert.destinationPort << ".\n";
    for (const auto& alert : dos)
        std::cout << "DOS-LIKE VOLUME: " << alert.sourceIp << " sent " << alert.packetCount
                  << " packets (" << alert.totalBytes << " bytes) to " << alert.destinationIp << ".\n";
    for (const auto& alert : lateral)
        std::cout << "INTERNAL HOST FAN-OUT: " << alert.sourceIp << " contacted "
                  << alert.internalDestinations.size() << " private destinations.\n";

    const auto& stats = network.getStatistics();
    std::cout << "\nTOTALS\nPackets: " << stats.packetsCreated
              << " | Delivered: " << stats.packetsDelivered
              << " | Blocked: " << stats.packetsBlocked
              << " | Dropped: " << stats.packetsDropped << "\n";
    return 0;
}
