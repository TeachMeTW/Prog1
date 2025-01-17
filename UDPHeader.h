#ifndef UDPHEADER_H
#define UDPHEADER_H

#include <stdint.h>

/*
 * Parse the UDP header from the packet.
 * Contains source port, destination port, length, and checksum.
 */
struct __attribute__((packed)) UDPHeader
{
    uint16_t srcPort;   // Use ntohs()
    uint16_t destPort;  // Use ntohs()
    uint16_t length;    // Use ntohs()
    uint16_t checksum;  // Use ntohs()
};

#endif // UDPHEADER_H
