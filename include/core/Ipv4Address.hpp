#pragma once

#include <charconv>
#include <stdexcept>
#include <string>
#include <string_view>

namespace cyberguard::detail {

inline void validateIpv4Address(const std::string& ipAddress) {
    if (ipAddress.empty()) {
        throw std::invalid_argument("IP address cannot be empty");
    }

    std::size_t start = 0;
    int octetCount = 0;
    while (true) {
        const std::size_t end = ipAddress.find('.', start);
        const std::size_t length = end == std::string::npos
            ? ipAddress.size() - start
            : end - start;
        if (length == 0 || length > 3) {
            throw std::invalid_argument("Invalid IPv4 address: " + ipAddress);
        }

        const std::string_view octet(ipAddress.data() + start, length);
        int value = 0;
        const auto [pointer, error] = std::from_chars(octet.data(), octet.data() + octet.size(), value);
        if (error != std::errc{} || pointer != octet.data() + octet.size() || value < 0 || value > 255) {
            throw std::invalid_argument("Invalid IPv4 address: " + ipAddress);
        }

        ++octetCount;
        if (end == std::string::npos) break;
        start = end + 1;
        if (start == ipAddress.size()) {
            throw std::invalid_argument("Invalid IPv4 address: " + ipAddress);
        }
    }

    if (octetCount != 4) {
        throw std::invalid_argument("Invalid IPv4 address: " + ipAddress);
    }
}

} // namespace cyberguard::detail
