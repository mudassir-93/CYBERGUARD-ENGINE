#include "core/Packet.hpp"

#include <charconv>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace cyberguard {

Packet::Packet(std::uint64_t id,
               std::string sourceIp,
               std::string destinationIp,
               std::uint32_t sourcePort,
               std::uint32_t destinationPort,
               Protocol protocol,
               std::uint32_t size,
               std::uint64_t timestamp)
    : id_(id),
      sourceIp_(std::move(sourceIp)),
      destinationIp_(std::move(destinationIp)),
            sourcePort_(validatePort(sourcePort)),
            destinationPort_(validatePort(destinationPort)),
      protocol_(protocol),
      size_(size),
      timestamp_(timestamp) {
    validateIpAddress(sourceIp_);
    validateIpAddress(destinationIp_);

    if (sourcePort > 65535 || destinationPort > 65535) {
        throw std::invalid_argument("Packet port must be between 0 and 65535");
    }
    if (size_ == 0) {
        throw std::invalid_argument("Packet size must be greater than zero");
    }
}

std::uint64_t Packet::getId() const noexcept {
    return id_;
}

const std::string& Packet::getSourceIp() const noexcept {
    return sourceIp_;
}

const std::string& Packet::getDestinationIp() const noexcept {
    return destinationIp_;
}

std::uint16_t Packet::getSourcePort() const noexcept {
    return sourcePort_;
}

std::uint16_t Packet::getDestinationPort() const noexcept {
    return destinationPort_;
}

Protocol Packet::getProtocol() const noexcept {
    return protocol_;
}

std::uint32_t Packet::getSize() const noexcept {
    return size_;
}

std::uint64_t Packet::getTimestamp() const noexcept {
    return timestamp_;
}

PacketStatus Packet::getStatus() const noexcept {
    return status_;
}

void Packet::setStatus(PacketStatus status) noexcept {
    status_ = status;
}

void Packet::validateIpAddress(const std::string& ipAddress) {
    if (ipAddress.empty()) {
        throw std::invalid_argument("IP address cannot be empty");
    }

    std::size_t start = 0;
    int octetCount = 0;

    while (start < ipAddress.size()) {
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
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }

    if (octetCount != 4) {
        throw std::invalid_argument("Invalid IPv4 address: " + ipAddress);
    }
}

    std::uint16_t Packet::validatePort(std::uint32_t port) {
        if (port > 65535) {
            throw std::invalid_argument("Packet port must be between 0 and 65535");
        }

        return static_cast<std::uint16_t>(port);
    }

} // namespace cyberguard