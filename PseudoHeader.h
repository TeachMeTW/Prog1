#ifndef PSEUDO_HEADER_H
#define PSEUDO_HEADER_H

#include <stdint.h>

struct __attribute__((packed)) pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_length;
};

#endif