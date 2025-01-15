#ifndef ARPHEADER_H
#define ARPHEADER_H

#include <stdint.h>

/*
 * Parse the ARP header from the packet.
 * Contains hardware type, protocol type, hardware size, protocol size, operation,
 * sender MAC/IP, and target MAC/IP.
 */
struct ARPHeader
{
    uint16_t hType;      // Use ntohs()
    uint16_t pType;      // Use ntohs()
    uint8_t  hLen;
    uint8_t  pLen;
    uint16_t op;         // Use ntohs() -> 1 = request, 2 = reply
    uint8_t  senderMAC[6];
    uint8_t  senderIP[4];
    uint8_t  targetMAC[6];
    uint8_t  targetIP[4];
};

#endif // ARPHEADER_H
