#include "core/Network.hpp"

#include <iostream>

int main() {
    const cyberguard::Network network;

    std::cout << "====================================\n"
              << "        CYBERGUARD ENGINE\n"
              << "====================================\n\n"
              << "Network initialized.\n\n"
              << "Devices: " << network.getDeviceCount() << "\n"
              << "Threats: 0\n"
              << "Incidents: 0\n\n"
              << "Engine initialized successfully.\n";

    return 0;
}