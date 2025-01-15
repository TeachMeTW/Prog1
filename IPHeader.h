#ifndef IPHEADER_H
#define IPHEADER_H

#include <stdint.h>

/*
 * Parse the IPv4 header from the packet.
 * Contains version/IHL, type of service, total length, identification, flags/fragment offset,
 * time to live, protocol, header checksum, source IP, and destination IP.
 */
struct IPHeader
{
    uint8_t  versionIHL;      // version (4 bits) + IHL (4 bits)
    uint8_t  typeOfService;
    uint16_t totalLength;     // Use ntohs()
    uint16_t identification;  // Use ntohs()
    uint16_t flagsFragment;   // Use ntohs()
    uint8_t  ttl;
    uint8_t  protocol;        // 1 = ICMP, 6 = TCP, 17 = UDP
    uint16_t headerChecksum;  // Use ntohs()
    uint32_t srcIP;           // Use ntohl()
    uint32_t destIP;          // Use ntohl()
};

#endif // IPHEADER_H
