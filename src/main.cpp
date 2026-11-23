#include "core/Network.hpp"
#include "core/PortScanDetector.hpp"
#include "core/TrafficScenarioGenerator.hpp"
#include "devices/Firewall.hpp"
#include "devices/Router.hpp"
#include "devices/Server.hpp"
#include "devices/Workstation.hpp"
#include <iostream>
#include <memory>
#include <optional>
namespace {
void printScenario(const char* label,const cyberguard::ScenarioResult& r) {
 std::cout<<label<<": "<<r.packetsSent<<" packets, "<<r.delivered<<" delivered, "<<r.blocked<<" blocked, "<<r.dropped<<" dropped\n";
}
}
int main() {
 std::cout<<"====================================\n        CYBERGUARD ENGINE\n====================================\n\nLOCAL NETWORK SECURITY SIMULATION\n\n";
 cyberguard::Network network;
 network.addDevice(std::make_unique<cyberguard::Router>("Router","10.0.0.1"));
 network.addDevice(std::make_unique<cyberguard::Firewall>("Firewall","10.0.0.2"));
 network.addDevice(std::make_unique<cyberguard::Server>("Server","10.0.0.10"));
 network.addDevice(std::make_unique<cyberguard::Workstation>("PC-01","10.0.0.20"));
 auto* server=dynamic_cast<cyberguard::Server*>(network.findDevice("Server"));
 auto* firewall=dynamic_cast<cyberguard::Firewall*>(network.findDevice("Firewall"));
 server->openService(80); server->openService(443);
 firewall->addRule({cyberguard::FirewallAction::BLOCK,std::nullopt,std::nullopt,cyberguard::Protocol::TCP,23,true});
 std::cout<<"Devices initialized: "<<network.getDeviceCount()<<"\n";
 const auto normal=cyberguard::TrafficScenarioGenerator::runNormalTraffic(network,"10.0.0.20","10.0.0.10",1,1);
 printScenario("Normal traffic",normal);
 const auto scan=cyberguard::TrafficScenarioGenerator::runPortScan(network,"10.0.0.20","10.0.0.10",1,12,100,10);
 printScenario("Simulated port scan",scan);
 const auto alerts=cyberguard::PortScanDetector(10,60).detect(network.getFlowManager().getFlows());
 std::cout<<"\nFLOW SUMMARY\nObserved flows: "<<network.getFlowManager().getFlowCount()<<"\nPORT SCAN DETECTION\n";
 if(alerts.empty()) std::cout<<"No port scan detected.\n";
 for(const auto& alert:alerts) std::cout<<"ALERT: "<<alert.sourceIp<<" scanned "<<alert.destinationIp<<" across "<<alert.destinationPorts.size()<<" distinct ports (window "<<alert.firstSeen<<"-"<<alert.lastSeen<<").\n";
 const auto& stats=network.getStatistics();
 std::cout<<"\nTOTALS\nPackets: "<<stats.packetsCreated<<" | Delivered: "<<stats.packetsDelivered<<" | Blocked: "<<stats.packetsBlocked<<" | Dropped: "<<stats.packetsDropped<<"\n";
 return alerts.empty()?1:0;
}
