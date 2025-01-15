#ifndef ETHERNETHEADER_H
#define ETHERNETHEADER_H

#include <stdint.h>

/*
 * Parse the Ethernet header from the packet.
 * Contains the destination MAC address, source MAC address, and the etherType field.
 */
struct EthernetHeader
{
    uint8_t  destMAC[6];
    uint8_t  srcMAC[6];
    uint16_t etherType; // Use ntohs() to convert this from network byte order
};

#endif // ETHERNETHEADER_H
