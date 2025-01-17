#ifndef TCPHEADER_H
#define TCPHEADER_H

#include <stdint.h>

/*
 * Parse the TCP header from the packet.
 * Contains source port, destination port, sequence number, acknowledgment number,
 * offset/reserved, flags, window size, checksum, urgent pointer.
 */
struct __attribute__((packed)) TCPHeader {
    uint16_t srcPort;        // Use ntohs()
    uint16_t destPort;       // Use ntohs()
    uint32_t seqNumber;      // Use ntohl()
    uint32_t ackNumber;      // Use ntohl()
    uint8_t  dataOffset;     // top 4 bits
    uint8_t  flags;          // lower 6 bits or so, but treat as entire field for printing
    uint16_t window;         // Use ntohs()
    uint16_t checksum;       // Use ntohs()
    uint16_t urgentPointer;  // Use ntohs()
};

#endif // TCPHEADER_H
