#ifndef ICMPHEADER_H
#define ICMPHEADER_H

#include <stdint.h>

/*
 * Parse the ICMP header from the packet (for Echo requests/replies).
 * Contains type (8-bit), code (8-bit), checksum (16-bit), identifier (16-bit), and sequence number (16-bit).
 */
struct ICMPHeader
{
    uint8_t  icmpType;   // 8 = Echo Request, 0 = Echo Reply
    uint8_t  icmpCode;
    uint16_t icmpChecksum; // Use ntohs()
    uint16_t identifier;   // Use ntohs()
    uint16_t sequence;     // Use ntohs()
};

#endif // ICMPHEADER_H
