#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Declaration for the in_cksum function. */
unsigned short in_cksum(unsigned short *addr, int len);

#ifdef __cplusplus
}
#endif

#endif // CHECKSUM_H
