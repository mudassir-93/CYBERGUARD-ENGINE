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
#include <string>
#include <vector>
namespace {
void printScenario(const char* label,const cyberguard::ScenarioResult& r){std::cout<<label<<": "<<r.packetsSent<<" packets, "<<r.delivered<<" delivered, "<<r.blocked<<" blocked, "<<r.dropped<<" dropped\n";}
std::string escapeJson(const std::string& value){std::string out;for(unsigned char c:value){switch(c){case '"':out+="\\\"";break;case '\\':out+="\\\\";break;case '\n':out+="\\n";break;case '\r':out+="\\r";break;case '\t':out+="\\t";break;default:out+=c<0x20?'?':static_cast<char>(c);}}return out;}
void emit(const std::string& type,const std::string& src,const std::string& dst,unsigned port,const std::string& summary,const std::string& evidence){
 std::cout<<"{\"type\":\""<<type<<"\",\"source_ip\":\""<<escapeJson(src)<<"\",\"destination_ip\":\""<<escapeJson(dst)<<"\",\"protocol\":\"TCP\",";
 if(port)std::cout<<"\"destination_port\":"<<port<<",";
 std::cout<<"\"summary\":\""<<escapeJson(summary)<<"\",\"evidence\":"<<evidence<<"}\n";
}
void emitAll(const std::vector<cyberguard::PortScanAlert>& scans,const std::vector<cyberguard::BruteForceAlert>& brute,const std::vector<cyberguard::DenialOfServiceAlert>& dos,const std::vector<cyberguard::LateralMovementAlert>& lateral){
 for(const auto&a:scans){std::string ports="[";for(std::size_t i=0;i<a.destinationPorts.size();++i){if(i)ports+=",";ports+=std::to_string(a.destinationPorts[i]);}ports+="]";
 emit("port_scan",a.sourceIp,a.destinationIp,0,"Source contacted multiple destination ports","{\"distinct_ports\":"+std::to_string(a.destinationPorts.size())+",\"ports\":"+ports+",\"window_seconds\":"+std::to_string(a.lastSeen-a.firstSeen)+",\"source\":\"cpp_simulator\"}");}
 for(const auto&a:brute)emit("brute_force",a.sourceIp,a.destinationIp,a.destinationPort,"Repeated failed connection attempts to one service","{\"failed_attempts\":"+std::to_string(a.failedAttempts)+",\"window_seconds\":"+std::to_string(a.lastSeen-a.firstSeen)+",\"source\":\"cpp_simulator\"}");
 for(const auto&a:dos)emit("dos",a.sourceIp,a.destinationIp,0,"High-volume packet burst toward one destination","{\"packet_count\":"+std::to_string(a.packetCount)+",\"total_bytes\":"+std::to_string(a.totalBytes)+",\"window_seconds\":"+std::to_string(a.lastSeen-a.firstSeen)+",\"source\":\"cpp_simulator\"}");
 for(const auto&a:lateral){std::string dests="[";for(std::size_t i=0;i<a.internalDestinations.size();++i){if(i)dests+=",";dests+="\""+escapeJson(a.internalDestinations[i])+"\"";}dests+="]";
 const auto dst=a.internalDestinations.empty()?std::string{}:a.internalDestinations.front();
 emit("lateral_movement",a.sourceIp,dst,0,"Internal host contacted multiple private network destinations","{\"distinct_internal_destinations\":"+std::to_string(a.internalDestinations.size())+",\"destinations\":"+dests+",\"window_seconds\":"+std::to_string(a.lastSeen-a.firstSeen)+",\"source\":\"cpp_simulator\"}");}
}
}
int main(int argc,char**argv){
 const bool jsonl=argc==2&&std::string(argv[1])=="--jsonl";
 if(argc>1&&!jsonl){std::cerr<<"Usage: CyberGuard [--jsonl]\n";return 2;}
 if(!jsonl)std::cout<<"====================================\n        CYBERGUARD ENGINE\n====================================\n\nLOCAL NETWORK SECURITY SIMULATION\n\n";
 cyberguard::Network network;
 network.addDevice(std::make_unique<cyberguard::Router>("Router","10.0.0.1"));
 network.addDevice(std::make_unique<cyberguard::Firewall>("Firewall","10.0.0.2"));
 network.addDevice(std::make_unique<cyberguard::Server>("Server","10.0.0.10"));
 network.addDevice(std::make_unique<cyberguard::Workstation>("PC-01","10.0.0.20"));
 network.addDevice(std::make_unique<cyberguard::Workstation>("PC-02","10.0.0.21"));
 auto* server=dynamic_cast<cyberguard::Server*>(network.findDevice("Server"));
 auto* firewall=dynamic_cast<cyberguard::Firewall*>(network.findDevice("Firewall"));
 server->openService(80);server->openService(443);
 firewall->addRule({cyberguard::FirewallAction::BLOCK,std::nullopt,std::nullopt,cyberguard::Protocol::TCP,23,true});
 if(!jsonl)std::cout<<"Devices initialized: "<<network.getDeviceCount()<<"\n";
 const auto normal=cyberguard::TrafficScenarioGenerator::runNormalTraffic(network,"10.0.0.20","10.0.0.10",1,1);
 const auto scanRun=cyberguard::TrafficScenarioGenerator::runPortScan(network,"10.0.0.20","10.0.0.10",1,12,100,10);
 const auto bruteRun=cyberguard::TrafficScenarioGenerator::runBruteForce(network,"10.0.0.20","10.0.0.10",22,6,200,30);
 const auto dosRun=cyberguard::TrafficScenarioGenerator::runDenialOfService(network,"10.0.0.21","10.0.0.10",80,120,300,40);
 const auto lateralRun=cyberguard::TrafficScenarioGenerator::runLateralMovement(network,"10.0.0.20",{"10.0.0.10","10.0.0.11","10.0.0.12"},445,500,50);
 if(!jsonl){printScenario("Normal traffic",normal);printScenario("Simulated port scan",scanRun);printScenario("Simulated brute-force pattern",bruteRun);printScenario("Simulated DoS-like traffic",dosRun);printScenario("Simulated internal host sweep",lateralRun);}
 const auto flows=network.getFlowManager().getFlows();
 const auto scans=cyberguard::PortScanDetector(10,60).detect(flows);
 const auto brute=cyberguard::ThreatDetector::detectBruteForce(flows);
 const auto dos=cyberguard::ThreatDetector::detectDenialOfService(flows);
 const auto lateral=cyberguard::ThreatDetector::detectLateralMovement(flows);
 if(jsonl){emitAll(scans,brute,dos,lateral);return 0;}
 std::cout<<"\nFLOW SUMMARY\nObserved flows: "<<network.getFlowManager().getFlowCount()<<"\n\nDETECTION RESULTS\n";
 for(const auto&a:scans)std::cout<<"PORT SCAN: "<<a.sourceIp<<" scanned "<<a.destinationIp<<" across "<<a.destinationPorts.size()<<" distinct ports.\n";
 for(const auto&a:brute)std::cout<<"BRUTE-FORCE PATTERN: "<<a.sourceIp<<" made "<<a.failedAttempts<<" failed attempts to "<<a.destinationIp<<':'<<a.destinationPort<<".\n";
 for(const auto&a:dos)std::cout<<"DOS-LIKE VOLUME: "<<a.sourceIp<<" sent "<<a.packetCount<<" packets ("<<a.totalBytes<<" bytes) to "<<a.destinationIp<<".\n";
 for(const auto&a:lateral)std::cout<<"INTERNAL HOST FAN-OUT: "<<a.sourceIp<<" contacted "<<a.internalDestinations.size()<<" private destinations.\n";
 const auto&stats=network.getStatistics();
 std::cout<<"\nTOTALS\nPackets: "<<stats.packetsCreated<<" | Delivered: "<<stats.packetsDelivered<<" | Blocked: "<<stats.packetsBlocked<<" | Dropped: "<<stats.packetsDropped<<"\n";
 return 0;
}
