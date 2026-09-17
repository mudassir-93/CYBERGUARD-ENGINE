#include "core/Network.hpp"

#include <cassert>

int main() {
    const cyberguard::Network network;
    assert(network.getDeviceCount() == 0);
    return 0;
}