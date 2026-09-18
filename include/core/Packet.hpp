#pragma once

#include <cstdint>
#include <string>

namespace cyberguard {

enum class Protocol {
    TCP,
    UDP,
    ICMP
};

enum class PacketStatus {
    CREATED,
    ROUTING,
    ALLOWED,
    BLOCKED,
    DELIVERED,
    DROPPED
};

class Packet {
public:
    Packet(std::uint64_t id,
           std::string sourceIp,
           std::string destinationIp,
           std::uint32_t sourcePort,
           std::uint32_t destinationPort,
           Protocol protocol,
           std::uint32_t size,
           std::uint64_t timestamp);

    [[nodiscard]] std::uint64_t getId() const noexcept;
    [[nodiscard]] const std::string& getSourceIp() const noexcept;
    [[nodiscard]] const std::string& getDestinationIp() const noexcept;
    [[nodiscard]] std::uint16_t getSourcePort() const noexcept;
    [[nodiscard]] std::uint16_t getDestinationPort() const noexcept;
    [[nodiscard]] Protocol getProtocol() const noexcept;
    [[nodiscard]] std::uint32_t getSize() const noexcept;
    [[nodiscard]] std::uint64_t getTimestamp() const noexcept;
    [[nodiscard]] PacketStatus getStatus() const noexcept;

    void setStatus(PacketStatus status) noexcept;

private:
    static void validateIpAddress(const std::string& ipAddress);
    [[nodiscard]] static std::uint16_t validatePort(std::uint32_t port);

    std::uint64_t id_;
    std::string sourceIp_;
    std::string destinationIp_;
    std::uint16_t sourcePort_;
    std::uint16_t destinationPort_;
    Protocol protocol_;
    std::uint32_t size_;
    std::uint64_t timestamp_;
    PacketStatus status_{PacketStatus::CREATED};
};

} // namespace cyberguard