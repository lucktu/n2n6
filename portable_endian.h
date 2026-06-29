/* portable_endian.h - Portable endian handling for Speck implementation */
#ifndef _PORTABLE_ENDIAN_H
#define _PORTABLE_ENDIAN_H

#include <stdint.h>

#if defined(_WIN32)
#include <stdlib.h>
#include <winsock2.h>

/* Windows byte order conversion function */
static inline uint16_t bswap_16(uint16_t x) {
    return (x << 8) | (x >> 8);
}

static inline uint32_t bswap_32(uint32_t x) {
    return (bswap_16(x) << 16) | bswap_16(x >> 16);
}

static inline uint64_t bswap_64(uint64_t x) {
    return (bswap_32(x) << 32) | bswap_32(x >> 32);
}

#define htole64(x) (x)
#define le64toh(x) (x)
#define htole32(x) (x)
#define le32toh(x) (x)
#define htobe32(x) bswap_32(x)
#define be32toh(x) bswap_32(x)
#define htobe16(x) bswap_16(x)
#define be16toh(x) bswap_16(x)

#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htole64(x) (x)
#define le64toh(x) (x)
#define htole32(x) (x)
#define le32toh(x) (x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define htobe16(x) OSSwapHostToBigInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#else
#include <byteswap.h>
#ifndef htole64
# if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define htole64(x) (x)
#  define le64toh(x) (x)
# elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define htole64(x) bswap_64(x)
#  define le64toh(x) bswap_64(x)
# else
#  error "Unknown byte order"
# endif
#endif
#endif

#endif /* _PORTABLE_ENDIAN_H */
