#include "core/Network.hpp"
#include "devices/Firewall.hpp"
#include "devices/Router.hpp"
#include "devices/Server.hpp"
#include "devices/Workstation.hpp"

#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

namespace {

std::string packetResult(cyberguard::PacketStatus status) {
    switch (status) {
    case cyberguard::PacketStatus::DELIVERED:
        return "DELIVERED";
    case cyberguard::PacketStatus::BLOCKED:
        return "BLOCKED BY FIREWALL";
    case cyberguard::PacketStatus::DROPPED:
        return "DROPPED";
    default:
        return "UNFINISHED";
    }
}

void printPacketResult(const cyberguard::Packet& packet, const std::string& sourceName) {
    std::cout << "Packet #" << packet.getId() << "\n"
              << sourceName << " -> " << packet.getDestinationIp() << "\n"
              << "TCP :" << packet.getDestinationPort() << "\n"
              << "Result: " << packetResult(packet.getStatus()) << "\n\n";
}

} // namespace

int main() {
    std::cout << "====================================\n"
              << "        CYBERGUARD ENGINE\n"
              << "====================================\n\n"
              << "Initializing network...\n\n";

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
    firewall->addRule({
        cyberguard::FirewallAction::BLOCK,
        std::nullopt,
        std::nullopt,
        cyberguard::Protocol::TCP,
        23,
        true
    });

    for (const auto& device : network.getDevices()) {
        std::cout << device->getType() << "       " << device->getIpAddress()
                  << "      " << device->getStatus() << "\n";
    }

    std::cout << "\n------------------------------------\n"
              << "PACKET SIMULATION\n"
              << "------------------------------------\n\n";

    cyberguard::Packet packet1(1, "10.0.0.20", "10.0.0.10", 50001, 80,
                               cyberguard::Protocol::TCP, 512, 1);
    network.routePacket(packet1);
    printPacketResult(packet1, "PC-01");

    cyberguard::Packet packet2(2, "10.0.0.21", "10.0.0.10", 50002, 443,
                               cyberguard::Protocol::TCP, 512, 2);
    network.routePacket(packet2);
    printPacketResult(packet2, "PC-02");

    cyberguard::Packet packet3(3, "10.0.0.20", "10.0.0.10", 50003, 23,
                               cyberguard::Protocol::TCP, 512, 3);
    network.routePacket(packet3);
    printPacketResult(packet3, "PC-01");

    const auto& statistics = network.getStatistics();
    std::cout << "------------------------------------\n"
              << "NETWORK STATISTICS\n"
              << "------------------------------------\n\n"
              << "Packets Created:   " << statistics.packetsCreated << "\n"
              << "Delivered:         " << statistics.packetsDelivered << "\n"
              << "Blocked:           " << statistics.packetsBlocked << "\n"
              << "Dropped:           " << statistics.packetsDropped << "\n\n"
              << "CyberGuard simulation completed.\n";

    return 0;
}