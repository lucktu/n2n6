/* (c) 2009 Richard Andrews <andrews@ntop.org>
 *
 * Contributions by:
 *    Luca Deri
 *    Lukasz Taczuk
 */

#if !defined( N2N_WIRE_H_ )
#define N2N_WIRE_H_

#include <stdlib.h>

#if defined(WIN32)
#include "win32/n2n_win32.h"

#if defined(__MINGW32__)
#include <stdint.h>
#endif /* #ifdef __MINGW32__ */

#else /* #if defined(WIN32) */
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h> /* AF_INET and AF_INET6 */
#endif /* #if defined(WIN32) */

#define N2N_PKT_VERSION                 2
#define N2N_DEFAULT_TTL                 2       /* can be forwarded twice at most */
#define N2N_COMMUNITY_SIZE              16
#define N2N_MAC_SIZE                    6
#define N2N_COOKIE_SIZE                 4
#define N2N_PKT_BUF_SIZE                4096    /* Peer capacity on edge */
#define N2N_TRANSFORM_BUF_SIZE          16384   /* Max payload for transop encode/decode, used as assembly buffer in transforms */
#define N2N_SN_PKTBUF_SIZE              2048    /* Peer capacity on supernode */
#define N2N_SOCKBUF_SIZE                64      /* string representation of INET or INET6 sockets */

typedef uint8_t n2n_community_t[N2N_COMMUNITY_SIZE];
typedef uint8_t n2n_mac_t[N2N_MAC_SIZE];
typedef uint8_t n2n_cookie_t[N2N_COOKIE_SIZE];

typedef char    n2n_sock_str_t[N2N_SOCKBUF_SIZE];       /* tracing string buffer */

typedef struct n2n_ip_subnet {
    uint32_t    net_addr;   /* Host order IP address. */
    uint8_t     net_bitlen; /* Subnet prefix length. */
} n2n_ip_subnet_t;

enum n2n_pc
{
    n2n_ping=0,                 /* Not used */
    n2n_register=1,             /* Register edge to edge */
    n2n_deregister=2,           /* Deregister this edge */
    n2n_packet=3,               /* PACKET data content */
    n2n_register_ack=4,         /* ACK of a registration from edge to edge */
    n2n_register_super=5,       /* Register edge to supernode */
    n2n_register_super_ack=6,   /* ACK from supernode to edge */
    n2n_register_super_nak=7,   /* NAK from supernode to edge - registration refused */
    n2n_federation=8,           /* Not used by edge */
    n2n_probe=9,                /* P2P hole-punch probe: edge->edge direct */
    n2n_probe_ack=10,           /* P2P hole-punch result: observed addr via supernode */
    n2n_peer_info=11,           /* Supernode pushes peer address to edge */
    n2n_query_peer=12           /* Edge asks supernode for peer address */
};

typedef enum n2n_pc n2n_pc_t;

#define N2N_FLAGS_OPTIONS               0x0080
#define N2N_FLAGS_SOCKET                0x0040
#define N2N_FLAGS_FROM_SUPERNODE        0x0020

/* The bits in flag that are the packet type */
#define N2N_FLAGS_TYPE_MASK             0x001f  /* 0 - 31 */
#define N2N_FLAGS_BITS_MASK             0xffe0

#define IPV4_SIZE                       4
#define IPV6_SIZE                       16


#define N2N_AUTH_TOKEN_SIZE             32      /* bytes */


#define N2N_EUNKNOWN                    -1
#define N2N_ENOTIMPL                    -2
#define N2N_EINVAL                      -3
#define N2N_ENOSPACE                    -4


typedef uint16_t n2n_flags_t;
typedef uint16_t n2n_transform_t;       /* Encryption, compression type. */
typedef uint32_t n2n_sa_t;              /* security association number */

struct n2n_sock
{
    uint8_t     family;         /* AF_INET or AF_INET6; or 0 if invalid */
    uint16_t    port;           /* host order */
    union
    {
    uint8_t     v6[IPV6_SIZE];  /* byte sequence */
    uint8_t     v4[IPV4_SIZE];  /* byte sequence */
    } addr;
};

typedef struct n2n_sock n2n_sock_t;

struct n2n_auth
{
    uint16_t    scheme;                         /* What kind of auth */
    uint16_t    toksize;                        /* Size of auth token */
    uint8_t     token[N2N_AUTH_TOKEN_SIZE];     /* Auth data interpreted based on scheme */
};

typedef struct n2n_auth n2n_auth_t;


struct n2n_common
{
    /* int                 version; */
    uint8_t             ttl;
    n2n_pc_t            pc;
    n2n_flags_t         flags;
    n2n_community_t     community;
};

typedef struct n2n_common n2n_common_t;

struct n2n_REGISTER
{
    n2n_cookie_t        cookie;         /* Link REGISTER and REGISTER_ACK */
    n2n_mac_t           srcMac;         /* MAC of registering party */
    n2n_mac_t           dstMac;         /* MAC of target edge */
    n2n_sock_t          sock;           /* LAN address for direct connect (set when N2N_FLAGS_SOCKET) */
    char                version[8];     /* edge version string */
    char                os_name[16];    /* operating system name */
};

typedef struct n2n_REGISTER n2n_REGISTER_t;

struct n2n_DEREGISTER
{
    n2n_mac_t           srcMac;         /* MAC of the edge going offline */
};

typedef struct n2n_DEREGISTER n2n_DEREGISTER_t;

struct n2n_REGISTER_ACK
{
    n2n_cookie_t        cookie;         /* Return cookie from REGISTER */
    n2n_mac_t           srcMac;         /* MAC of acknowledging party (supernode or edge) */
    n2n_mac_t           dstMac;         /* Reflected MAC of registering edge from REGISTER */
    n2n_sock_t          sock;           /* Supernode's view of edge socket (IP Addr, port) */
};

typedef struct n2n_REGISTER_ACK n2n_REGISTER_ACK_t;

struct n2n_PACKET
{
    n2n_mac_t           srcMac;
    n2n_mac_t           dstMac;
    n2n_sock_t          sock;
    n2n_transform_t     transform;
};

typedef struct n2n_PACKET n2n_PACKET_t;


/* Linked with n2n_register_super in n2n_pc_t. Only from edge to supernode. */
#define N2N_AFLAGS_LOCAL_SOCKET  0x0001  /* local_sock field is valid */

struct n2n_REGISTER_SUPER
{
    n2n_cookie_t        cookie;         /* Link REGISTER_SUPER and REGISTER_SUPER_ACK */
    n2n_mac_t           edgeMac;        /* MAC to register with edge sending socket */
    n2n_ip_subnet_t     dev_addr;       /* IP address of the tuntap adapter (net_addr=0 to request auto-assign) */
    n2n_auth_t          auth;           /* Authentication scheme and tokens */
    uint16_t            aflags;         /* additional flags (N2N_AFLAGS_*) */
    n2n_sock_t          local_sock;     /* LAN address for same-NAT direct connect */
};

typedef struct n2n_REGISTER_SUPER n2n_REGISTER_SUPER_t;


/* Capability flags for n2n_REGISTER_SUPER_ACK.sn_caps */
#define N2N_SN_CAPS_IPV4   0x01  /* supernode has IPv4 listener */
#define N2N_SN_CAPS_IPV6   0x02  /* supernode has IPv6 listener */

/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
struct n2n_REGISTER_SUPER_ACK
{
    n2n_cookie_t        cookie;         /* Return cookie from REGISTER_SUPER */
    n2n_mac_t           edgeMac;        /* MAC registered to edge sending socket */
    n2n_ip_subnet_t     dev_addr;       /* Assigned IP address */
    uint16_t            lifetime;       /* How long the registration will live */
    n2n_sock_t          sock;           /* Sending sockets associated with edgeMac */

    uint8_t             num_sn;         /* Number of backup supernodes */
    n2n_sock_t          sn_bak;         /* Socket of the first backup supernode */

    /* Appended after sn_bak for forward/backward compatibility.
     * Old edges ignore extra bytes; old supernodes leave sn_caps=0 (unknown). */
    uint8_t             sn_caps;        /* N2N_SN_CAPS_* bitmask: supernode IP capability */
    char                sn_version[24]; /* Supernode version string (e.g., "2.3_6.3_r239_483723e") */
};

typedef struct n2n_REGISTER_SUPER_ACK n2n_REGISTER_SUPER_ACK_t;


/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
struct n2n_REGISTER_SUPER_NAK
{
    n2n_cookie_t        cookie;         /* Return cookie from REGISTER_SUPER */
};

typedef struct n2n_REGISTER_SUPER_NAK n2n_REGISTER_SUPER_NAK_t;


/* PROBE: sent directly edge->edge to open NAT mapping and let peer observe src addr */
struct n2n_PROBE
{
    n2n_mac_t           srcMac;     /* sender MAC */
    n2n_mac_t           dstMac;     /* target MAC */
};
typedef struct n2n_PROBE n2n_PROBE_t;

/* PROBE_ACK: sent via supernode, carries the observed public addr of the probe sender */
struct n2n_PROBE_ACK
{
    n2n_mac_t           srcMac;         /* MAC of edge that sent the PROBE */
    n2n_mac_t           dstMac;         /* MAC of edge that observed the PROBE */
    n2n_sock_t          observed_addr;  /* public IP:port observed by dstMac */
};
typedef struct n2n_PROBE_ACK n2n_PROBE_ACK_t;

size_t encode_PROBE( uint8_t * base, size_t * idx, const n2n_common_t * common, const n2n_PROBE_t * probe );
size_t decode_PROBE( n2n_PROBE_t * probe, const n2n_common_t * cmn, const uint8_t * base, size_t * rem, size_t * idx );
size_t encode_PROBE_ACK( uint8_t * base, size_t * idx, const n2n_common_t * common, const n2n_PROBE_ACK_t * ack );
size_t decode_PROBE_ACK( n2n_PROBE_ACK_t * ack, const n2n_common_t * cmn, const uint8_t * base, size_t * rem, size_t * idx );



struct n2n_buf
{
    uint8_t *   data;
    size_t      size;
};

typedef struct n2n_buf n2n_buf_t;

size_t encode_uint8( uint8_t * base,
                  size_t * idx,
                  const uint8_t v );

size_t decode_uint8( uint8_t * out,
                  const uint8_t * base,
                  size_t * rem,
                  size_t * idx );

size_t encode_uint16( uint8_t * base,
                   size_t * idx,
                   const uint16_t v );

size_t decode_uint16( uint16_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

size_t encode_uint32( uint8_t * base,
                   size_t * idx,
                   const uint32_t v );

size_t decode_uint32( uint32_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

size_t encode_buf( uint8_t * base,
                size_t * idx,
                const void * p,
                size_t s);

size_t decode_buf( uint8_t * out,
                size_t bufsize,
                const uint8_t * base,
                size_t * rem,
                size_t * idx );

size_t encode_mac( uint8_t * base,
                size_t * idx,
                const n2n_mac_t m );

size_t decode_mac( uint8_t * out, /* of size N2N_MAC_SIZE. This clearer than passing a n2n_mac_t */
                const uint8_t * base,
                size_t * rem,
                size_t * idx );

ssize_t encode_common( uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common );

ssize_t decode_common( n2n_common_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

ssize_t encode_sock( uint8_t * base,
                 size_t * idx,
                 const n2n_sock_t * sock );

ssize_t decode_sock( n2n_sock_t * sock,
                 const uint8_t * base,
                 size_t * rem,
                 size_t * idx );

size_t encode_REGISTER( uint8_t * base,
                     size_t * idx,
                     const n2n_common_t * common,
                     const n2n_REGISTER_t * reg );

size_t decode_REGISTER( n2n_REGISTER_t * pkt,
                     const n2n_common_t * cmn, /* info on how to interpret it */
                     const uint8_t * base,
                     size_t * rem,
                     size_t * idx );

size_t encode_DEREGISTER( uint8_t * base,
                     size_t * idx,
                     const n2n_common_t * common,
                     const n2n_DEREGISTER_t * reg );

size_t decode_DEREGISTER( n2n_DEREGISTER_t * pkt,
                     const n2n_common_t * cmn,
                     const uint8_t * base,
                     size_t * rem,
                     size_t * idx );

size_t encode_REGISTER_SUPER( uint8_t * base,
                           size_t * idx,
                           const n2n_common_t * common,
                           const n2n_REGISTER_SUPER_t * reg );

size_t decode_REGISTER_SUPER( n2n_REGISTER_SUPER_t * pkt,
                           const n2n_common_t * cmn, /* info on how to interpret it */
                           const uint8_t * base,
                           size_t * rem,
                           size_t * idx );

size_t encode_REGISTER_ACK( uint8_t * base,
                         size_t * idx,
                         const n2n_common_t * common,
                         const n2n_REGISTER_ACK_t * reg );

size_t decode_REGISTER_ACK( n2n_REGISTER_ACK_t * pkt,
                         const n2n_common_t * cmn, /* info on how to interpret it */
                         const uint8_t * base,
                         size_t * rem,
                         size_t * idx );

size_t encode_REGISTER_SUPER_ACK( uint8_t * base,
                               size_t * idx,
                               const n2n_common_t * cmn,
                               const n2n_REGISTER_SUPER_ACK_t * reg );

size_t decode_REGISTER_SUPER_ACK( n2n_REGISTER_SUPER_ACK_t * reg,
                               const n2n_common_t * cmn, /* info on how to interpret it */
                               const uint8_t * base,
                               size_t * rem,
                               size_t * idx );

int fill_sockaddr( struct sockaddr * addr,
                   size_t addrlen,
                   const n2n_sock_t * sock );

size_t encode_PACKET( uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common,
                   const n2n_PACKET_t * pkt );

size_t decode_PACKET( n2n_PACKET_t * pkt,
                   const n2n_common_t * cmn, /* info on how to interpret it */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

/* PEER_INFO: supernode -> edge, push a peer's address */
#define N2N_AFLAGS_IPV6_SOCKET     0x0002  /* sock6 field is valid */
#define N2N_AFLAGS_PUNCH_REQUEST   0x0004  /* QUERY_PEER triggered, edge should start punching */
#define N2N_AFLAGS_SAME_LAN_AS_SN  0x0008  /* peer is in same LAN as supernode, replace IP with SN's public IP */
typedef struct n2n_PEER_INFO {
    uint16_t   aflags;       /* N2N_AFLAGS_LOCAL_SOCKET if sockets[1] valid, N2N_AFLAGS_IPV6_SOCKET if sock6 valid, N2N_AFLAGS_PUNCH_REQUEST if should punch, N2N_AFLAGS_SAME_LAN_AS_SN if same LAN as SN */
    n2n_mac_t  mac;
    n2n_sock_t sockets[2];  /* [0]=public IPv4, [1]=LAN (if aflags set) */
    n2n_sock_t sock6;       /* IPv6 public address (if N2N_AFLAGS_IPV6_SOCKET set) */
    char       version[8];  /* peer edge version string (optional, may be empty) */
    char       os_name[16]; /* peer OS name (optional, may be empty) */
} n2n_PEER_INFO_t;

size_t encode_PEER_INFO( uint8_t * base, size_t * idx,
                         const n2n_common_t * common,
                         const n2n_PEER_INFO_t * pkt );

size_t decode_PEER_INFO( n2n_PEER_INFO_t * pkt,
                         const n2n_common_t * cmn,
                         const uint8_t * base,
                         size_t * rem, size_t * idx );

/* QUERY_PEER: edge -> supernode, ask for peer's public address */
typedef struct n2n_QUERY_PEER {
    n2n_mac_t  srcMac;
    n2n_mac_t  targetMac;
} n2n_QUERY_PEER_t;

size_t encode_QUERY_PEER( uint8_t * base, size_t * idx,
                          const n2n_common_t * common,
                          const n2n_QUERY_PEER_t * pkt );

size_t decode_QUERY_PEER( n2n_QUERY_PEER_t * pkt,
                          const n2n_common_t * cmn,
                          const uint8_t * base,
                          size_t * rem, size_t * idx );

#endif /* #if !defined( N2N_WIRE_H_ ) */

