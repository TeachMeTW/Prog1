#ifndef PSEUDOHEADER_H
#define PSEUDOHEADER_H

#include <stdint.h>

typedef struct {
    uint32_t srcIP;      // Source IP address
    uint32_t destIP;     // Destination IP address
    uint8_t reserved;    // Reserved field (always 0)
    uint8_t protocol;    // Protocol type (TCP = 6)
    uint16_t tcpLength;  // Length of the TCP header and data
} PseudoHeader;

#endif