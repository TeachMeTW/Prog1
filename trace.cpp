#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include "EthernetHeader.h"
#include "ARPHeader.h"
#include "IPHeader.h"
#include "ICMPHeader.h"
#include "TCPHeader.h"
#include "UDPHeader.h"
#include "checksum.h"

/*
 * Print a MAC address in the format xx:xx:xx:xx:xx:xx.
 */
void printMAC(const uint8_t *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * Parse and display ARP header fields.
 */
void parseARPHeader(const ARPHeader *arp)
{
    printf("\tARP header\n");
    printf("\t\tOpcode: ");

    // Retrieve the 16-bit operation code (op) from the ARP header pointed to by 'arp',
    // converting it from network byte order to the host machine's byte order.
    // The operation code indicates the type of ARP message (e.g., request or reply).
    uint16_t op = ntohs(arp->op);

    if (op == 1) {
        printf("Request");
    } else if (op == 2) {
        printf("Reply");
    } else {
        printf("Unknown");
    }

    printf("\n\t\tSender MAC: ");
    printMAC(arp->senderMAC);

    // Copy the sender's IP address from the ARP header into the 'senderIP' structure.
    // The 'arp->senderIP' field contains the raw bytes of the sender's IP address.
    // 'memcpy' is used here to safely copy these bytes into the 'senderIP' structure -- remember lecture!
    // inet_ntoa convert to a human readable string
    struct in_addr senderIP;
    memcpy(&senderIP, arp->senderIP, sizeof(senderIP));
    printf("\n\t\tSender IP: %s", inet_ntoa(senderIP));

    printf("\n\t\tTarget MAC: ");
    printMAC(arp->targetMAC);

    // Ditto with target IP; same as above
    struct in_addr targetIP;
    memcpy(&targetIP, arp->targetIP, sizeof(targetIP));
    printf("\n\t\tTarget IP: %s\n\n", inet_ntoa(targetIP));
}

/*
 * Demonstrate ICMP checksum verification. The ICMP header's checksum
 * typically covers the entire ICMP message (header + data).
 */
void parseICMPHeader(const unsigned char *icmpData, uint32_t icmpLen)
{
    // Invalid Check
    if (icmpLen < sizeof(ICMPHeader)) {
        return;
    }

    const ICMPHeader *icmp = (const ICMPHeader *)icmpData;

    printf("\tICMP Header\n");
    printf("\t\tType: %u", icmp->icmpType);
    if (icmp->icmpType == 8) {
        printf(" (Echo Request)");
    } else if (icmp->icmpType == 0) {
        printf(" (Echo Reply)");
    }
    printf("\n\n");

    /*
     * Compute the ICMP checksum for demonstration:
     * 1. Make a local copy of the entire ICMP message.
     * 2. Zero out the checksum field in the copy.
     * 3. Run in_cksum over the copy.
     */
    unsigned char *icmpCopy = (unsigned char *)malloc(icmpLen);
    memcpy(icmpCopy, icmpData, icmpLen);

    ICMPHeader *icmpCopyHeader = (ICMPHeader *)icmpCopy;
    icmpCopyHeader->icmpChecksum = 0;

    unsigned short computedCsum = in_cksum((unsigned short *)icmpCopy, icmpLen);
    computedCsum = ntohs(computedCsum);
    
    free(icmpCopy);
    // uint16_t receivedICMPChecksum = ntohs(icmp->icmpChecksum);
}

/*
 * Parse and display TCP header fields (no checksum validation here, 
 * because TCP checksums need pseudo-header).
 */
void parseTCPHeader(const TCPHeader *tcp)
{
    printf("\tTCP Header\n");
    printf("\t\tSource Port = %u\n", ntohs(tcp->srcPort));
    printf("\t\tDest Port = %u\n", ntohs(tcp->destPort));
    printf("\t\tSeq = %u\n", ntohl(tcp->seqNumber));
    printf("\t\tAck = %u\n\n", ntohl(tcp->ackNumber));
}

/*
 * Parse and display UDP header fields (no checksum validation here, 
 * because UDP checksums need pseudo-header).
 */
void parseUDPHeader(const UDPHeader *udp)
{
    printf("\tUDP Header\n");
    printf("\t\tSource Port: %u\n", ntohs(udp->srcPort));
    printf("\t\tDest Port: ");
    uint16_t dport = ntohs(udp->destPort);
    if(dport == 53) {
        printf("DNS");
    } else {
        printf("%u", dport);
    }
    printf("\n");
    printf("\t\tLength = %u\n\n", ntohs(udp->length));
}

/*
 * Demonstrate IP header checksum verification.
 * Then parse the next protocol (ICMP, TCP, UDP).
 */
void parseIPHeader(const unsigned char *packetData, uint32_t remainingLength)
{
    // Check if valid IP Header
    if (remainingLength < sizeof(IPHeader)) {
        return;
    }

    // Interpret the raw packet data as an IP header by casting 'packetData' to 'const IPHeader *'.
    // This allows accessing fields of the IP header using the 'ip' pointer.
    const IPHeader *ip = (const IPHeader *)packetData;

    // Extract the header length from the 'versionIHL' field of the IP header.
    // The 'versionIHL' field contains both the IP version (upper 4 bits) and the header length (lower 4 bits).
    // Mask the lower 4 bits with 0x0F to isolate the header length value and multiply by 4
    // (since the length is represented in 32-bit words) to get the total length in bytes -- remember in class!
    uint8_t version = ip->versionIHL >> 4;
    uint8_t ipHeaderLen = (ip->versionIHL & 0x0F) * 4;

    // Check if the remaining length of the packet is smaller than the calculated IP header length.
    // If the packet is too short to contain a complete IP header, exit the function early.
    if (remainingLength < ipHeaderLen) {
        return;
    }

    // Break down the TOS field into Diffserv and ECN bits
    uint8_t tos = ip->typeOfService;
    uint8_t diffserv = tos >> 2;
    uint8_t ecn = tos & 0x03;

    struct in_addr srcAddr, dstAddr;
    srcAddr.s_addr = (ip->srcIP);
    dstAddr.s_addr = (ip->destIP);

    /*
     * Validate the IP header checksum:
     * 1. Copy just the IP header (ipHeaderLen bytes).
     * 2. Zero out the checksum field in the copy.
     * 3. Run in_cksum over the copy.
     */
    unsigned char *ipCopy = (unsigned char *)malloc(ipHeaderLen);
    memcpy(ipCopy, packetData, ipHeaderLen);

    // Zero out checksum in the copy
    IPHeader *ipHeaderCopy = (IPHeader *)ipCopy;
    ipHeaderCopy->headerChecksum = 0;

    // Calculate new checksum over the IP header
    unsigned short computedIPChecksum = in_cksum((unsigned short *)ipCopy, ipHeaderLen);
    computedIPChecksum = ntohs(computedIPChecksum);
    free(ipCopy);

    // Show original IP header checksum
    uint16_t ipHeaderChecksum = ntohs(ip->headerChecksum);

    printf("\tIP Header\n");
    printf("\t\tIP Version: %u\n", version);
    printf("\t\tHeader Len (bytes): %u\n", ipHeaderLen);
    printf("\t\tTOS subfields:\n");
    printf("\t\t   Diffserv bits: %u\n", diffserv);
    printf("\t\t   ECN bits: %u\n", ecn);
    printf("\t\tTTL: %u\n", ip->ttl);
    printf("\t\tProtocol: ");
    switch (ip->protocol) {
        case 1: printf("ICMP\n"); break;
        case 6: printf("TCP\n"); break;
        case 17: printf("UDP\n"); break;
        default: printf("%u\n", ip->protocol); break;
    }
    printf("\t\tChecksum: ");
    if (computedIPChecksum == ipHeaderChecksum) {
        printf("Correct (0x%04x)\n", ipHeaderChecksum);
    } else {
        printf("Incorrect (0x%04x)\n", ipHeaderChecksum);
    }
    printf("\t\tSender IP: %s\n", inet_ntoa(srcAddr));
    printf("\t\tDest IP: %s\n\n", inet_ntoa(dstAddr));

    // Move pointer past IP header
    const unsigned char *ipPayload = packetData + ipHeaderLen;
    uint32_t ipPayloadLen = remainingLength - ipHeaderLen;

    // Decide which protocol to parse
    switch (ip->protocol) {
        case 1:  // ICMP
            parseICMPHeader(ipPayload, ipPayloadLen);
            break;
        case 6:  // TCP
            if (ipPayloadLen >= sizeof(TCPHeader)) {
                parseTCPHeader((const TCPHeader *)ipPayload);
            }
            break;
        case 17: // UDP
            if (ipPayloadLen >= sizeof(UDPHeader)) {
                parseUDPHeader((const UDPHeader *)ipPayload);
            }
            break;
        default:
            printf("\tOther:  Protocol not supported.\n\n");
            break;
    }
}

/*
 * Parse Ethernet header fields, then pass the payload to the correct parser.
 */
void parseEthernetHeader(const unsigned char *packetData, uint32_t totalLength)
{
    // if length is less than what an ethernet header should be, its invalid
    if (totalLength < sizeof(EthernetHeader)) {
        return;
    }

    // Interpret the raw packet data as an Ethernet header.
    // Cast the pointer 'packetData' to a pointer of type 'const EthernetHeader *'.
    // Using 'const' signifies that the Ethernet header data should not be modified through 'eth'.
    const EthernetHeader *eth = (const EthernetHeader *)packetData;

    // Retrieve the 16-bit EtherType field from the Ethernet header pointed to by 'eth',
    // converting it from network byte order to the host machine's byte order.
    // This ensures that the value is interpreted correctly on the host.
    uint16_t etherType = ntohs(eth->etherType);

    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: ");
    printMAC(eth->destMAC);
    printf("\n\t\tSource MAC: ");
    printMAC(eth->srcMAC);
    printf("\n\t\tType: ");
    if(etherType == 0x0806) {
        printf("ARP");
    } else if(etherType == 0x0800) {
        printf("IP");
    } else {
        printf("0x%04x", etherType);
    }
    printf("\n\n");

    // Calculate the starting address of the payload by moving past the Ethernet header.
    // The Ethernet header's size is determined by sizeof(EthernetHeader).
    // 'payload' now points to the data following the Ethernet header.
    const unsigned char *payload = packetData + sizeof(EthernetHeader);

    // Calculate the remaining length of the packet after the Ethernet header.
    // Subtract the size of the Ethernet header from the total packet length (totalLength)
    // to determine how much data is available in the payload.
    uint32_t remainingLength = totalLength - sizeof(EthernetHeader);

    // Check EtherType and parse accordingly
    if (etherType == 0x0806) { // ARP
        if (remainingLength >= sizeof(ARPHeader)) {
            parseARPHeader((const ARPHeader *)payload);
        }
    } else if (etherType == 0x0800) { // IP
        parseIPHeader(payload, remainingLength);
    } else {
        printf("\tOTHER:  EtherType not handled 0_0.\n\n");
    }
}

/*
 * Main function. Reads packets from the pcap trace file, then calls parse functions.
 */
int main(int argc, char *argv[])
{
    // Input validation -- lets get the user to properly run trace
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <tracefile.pcap>\n", argv[0]);
        return 1;
    }

    // initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    // Attempt to open the pcap file for offline reading.
    // pcap_open_offline() takes the filename from argv[1] and an error buffer (errbuf).
    // It returns a pointer to a pcap_t structure which serves as a handle for the open pcap file.
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);

    // Check if the handle is NULL, which indicates that opening the pcap file failed.
    if (!handle) {
        // Print an error message to stderr including details from errbuf.
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        
        // Return a non-zero value to indicate that the program terminated with an error.
        return 1;
    }

    // pcap packet header and data; that structure described in class aka PDU
    struct pcap_pkthdr *header;
    const unsigned char *packetData;
    int res = 0;
    int packetCount = 0;

    // Continuously retrieve the next packet from the pcap handle until an error or end of file occurs.
    while ((res = pcap_next_ex(handle, &header, &packetData)) >= 0) {

        // If res == 0, it indicates that there was a timeout or no packet was ready yet.
        // In an offline context, this usually means the packet wasn't available yet.
        if (res == 0) {
            // Skip to the next iteration of the loop to try fetching another packet.
            continue;
        }

        // At this point, res > 0, meaning a packet has been successfully retrieved.
        packetCount++;
        printf("\nPacket number: %d  Packet Len: %d\n\n", packetCount, header->len);

        // Parse the Ethernet header from the packet data.
        // The function 'parseEthernetHeader' takes the raw packet data and its length as arguments.
        parseEthernetHeader(packetData, header->len);
    }

    pcap_close(handle);
    return 0;
}
