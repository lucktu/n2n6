/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *               Richard Andrews <andrews@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 * Code contributions courtesy of:
 *    Babak Farrokhi <babak@farrokhi.net> [FreeBSD port]
 *    Lukasz Taczuk
 *
 */

#ifndef _N2N_H_
#define _N2N_H_

#if defined(__APPLE__) && defined(__MACH__)
#define _DARWIN_
#endif

/* Moved here to define _CRT_SECURE_NO_WARNINGS before all the including takes place */
#if defined(_WIN32)
#undef N2N_HAVE_DAEMON
#undef N2N_HAVE_SETUID

/* windows can't name an interface, but we can tell edge which to use */
#define N2N_CAN_NAME_IFACE 1

#else
/* Some capability defaults which can be reset for particular platforms. */
#define N2N_HAVE_DAEMON 1
#define N2N_HAVE_SETUID 1
#ifdef __linux__
#define N2N_CAN_NAME_IFACE 1
/* Instead of hardcoding N2N_HAS_CAPABILITIES, use HAVE_LIBCAP */
#endif
#endif

#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef _WIN32
#include <netdb.h>
#endif

#ifndef _MSC_VER
#include <getopt.h>
#endif /* #ifndef _MSC_VER */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <pthread.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
/* capability.h is only included when HAVE_LIBCAP is defined */
#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif /* HAVE_LIBCAP */
#endif /* #ifdef __linux__ */

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#endif /* #ifdef __FreeBSD__ */

#include <syslog.h>
#include <sys/wait.h>

#ifdef __sun__
#undef N2N_HAVE_DAEMON
#endif /* #ifdef __sun__ */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <ifaddrs.h>

#define closesocket(a) close(a)
#endif /* #ifndef _WIN32 */

#define ETH_ADDR_LEN 6

#if defined(_MSC_VER)
#pragma pack(push,1)
#endif
struct ether_hdr
{
    uint8_t  dhost[ETH_ADDR_LEN];
    uint8_t  shost[ETH_ADDR_LEN];
    /* higher layer protocol encapsulated */
    uint16_t type;
}
#if defined(__GNUC__)
__attribute__ ((__packed__));
#elif defined(_MSC_VER)
;
#pragma pack(pop)
#endif

typedef struct ether_hdr ether_hdr_t;

#include <string.h>
#include <stdarg.h>

#ifdef __GNUC__
#define _unused_ __attribute__((unused))
#else
#define _unused_
#endif

#ifdef WIN32
#include "win32/wintap.h"
#endif /* #ifdef _WIN32 */

#include "n2n_wire.h"

typedef struct route {
    int family;
    uint8_t dest[IPV6_SIZE];
    uint8_t prefixlen;
    uint8_t gateway[IPV6_SIZE];
} route;

#define N2N_MAX_TRANSFORMS      16

/* N2N_IFNAMSIZ is needed on win32 even if dev_name is not used after declaration */
#ifndef _WIN32
#define N2N_IFNAMSIZ            16 /* 15 chars * NULL */

typedef struct tuntap_dev {
  int             fd;
  uint8_t         mac_addr[6];
  uint32_t        ip_addr;
  uint8_t         ip_prefixlen;
  struct in6_addr ip6_addr;
  uint8_t         ip6_prefixlen;
  uint32_t        mtu;
  char            dev_name[N2N_IFNAMSIZ];
  uint8_t         routes_count;
  route*          routes;
} tuntap_dev;

#define SOCKET int
#endif /* #ifndef _WIN32 */

struct tuntap_config {
    /* device configuration */
    char* if_name;
    n2n_mac_t device_mac;
    const char* community_name;
    int mtu;
    /* ipv4 configuration */
    bool dyn_ip4;
    in_addr_t ip_addr;
    bool delay_ip_config; /* Windows: delay IP set until REGISTER_SUPER_ACK */
    uint8_t ip_prefixlen;
    /* ipv6 configuration */
    struct in6_addr ip6_addr;
    uint8_t ip6_prefixlen;
    uint8_t routes_count;
    route* routes;
};

#define QUICKLZ               1

/* N2N packet header indicators. */
#define MSG_TYPE_REGISTER               1
#define MSG_TYPE_DEREGISTER             2
#define MSG_TYPE_PACKET                 3
#define MSG_TYPE_REGISTER_ACK           4
#define MSG_TYPE_REGISTER_SUPER         5
#define MSG_TYPE_REGISTER_SUPER_ACK     6
#define MSG_TYPE_REGISTER_SUPER_NAK     7
#define MSG_TYPE_FEDERATION             8

/* Set N2N_COMPRESSION_ENABLED to 0 to disable lzo1x compression of ethernet
 * frames. Doing this will break compatibility with the standard n2n packet
 * format so do it only for experimentation. All edges must be built with the
 * same value if they are to understand each other. */
#define N2N_COMPRESSION_ENABLED 1

#define DEFAULT_MTU   1350

/** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[INET6_ADDRSTRLEN];

/** Common type used to hold stringified MAC addresses. */
#define N2N_MACSTR_SIZE 32
typedef char macstr_t[N2N_MACSTR_SIZE];

struct peer_info {
    struct peer_info *  next;
    n2n_community_t     community_name;
    n2n_mac_t           mac_addr;
    n2n_sock_t          sock;              /* IPv4 public address (family=0 if unavailable) */
    n2n_sock_t          sock6;             /* IPv6 public address (family=0 if unavailable) */
    int                 num_sockets;       /* 1=public only, 2=public+LAN */
    n2n_sock_t          sockets[2];        /* [0]=public (primary), [1]=LAN */
    uint8_t             connect_family;    /* AF_INET or AF_INET6 - how edge connected to supernode */
    time_t              last_seen;
    char                version[8];
    char                os_name[16];
    uint32_t            assigned_ip;
    time_t              punch_start_time;
    uint8_t             punch_failed;
    time_t              punch_reset_time;
    time_t              lan_punch_start;   /* when LAN punch started, 0=not started */
    uint8_t             lan_punch_done;    /* 1=LAN succeeded or timed out, proceed to WAN */
    time_t              last_probe_sent;   /* time last keepalive PROBE was sent */
    uint8_t             keepalive_fails;   /* consecutive keepalive failures */
    time_t              last_query_sent;   /* time last query_peer was sent, for rate-limiting */
    time_t              last_punch_probe;  /* time last PROBE was sent during hole-punch */
    uint8_t             punch_retry_count; /* number of punch retries, remove after max */
    uint8_t             register_retry_count; /* REGISTER retries after PROBE_ACK, max 3 */
    time_t              last_register_sent;   /* time last REGISTER was sent after PROBE_ACK */
    time_t              direct_seen;       /* time of last direct P2P communication with this peer; 0=never */
    n2n_sock_t          temp_local_sock;   /* dynamically selected best local IP for this peer */
    uint8_t             temp_local_sock_valid; /* 1 if temp_local_sock is valid */
    uint8_t             psp_logged;        /* 1 if PsP message already printed for current state */
    uint8_t             p2p_logged;        /* 1 if P2P direct message already printed for current state */
    uint8_t             p2p_is_lan;        /* 1=LAN P2P, set by edge.c at REGISTER_SUPER_ACK */
    uint8_t             same_lan_as_sn;    /* 1 if edge is in same LAN as supernode */
};

struct n2n_edge; /* forward declaration, defined below */
typedef struct n2n_edge         n2n_edge_t;


/* ************************************** */

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__
#define TRACE_DEBUG     4, __FILE__, __LINE__

/* ************************************** */

#define SUPERNODE_IP    "127.0.0.1"
#define SUPERNODE_PORT  7654

/* ************************************** */

#ifndef max
#define max(a, b) ((a < b) ? b : a)
#endif

#ifndef min
#define min(a, b) ((a > b) ? b : a)
#endif

/* ************************************** */

/* Variables */
/* extern TWOFISH *tf; */
extern int traceLevel;
extern bool useSyslog;
extern bool useSystemd;
extern const uint8_t broadcast_addr[6];
extern const uint8_t multicast_addr[6];

/* Functions */
extern void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...);
extern time_t n2n_now(void);
extern int  tuntap_open(tuntap_dev *device, struct tuntap_config* config);
extern ssize_t tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, size_t len);
extern ssize_t tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, size_t len);
extern void tuntap_close(struct tuntap_dev *tuntap);
extern void tuntap_get_address(struct tuntap_dev *tuntap);
extern int set_ipaddress(const tuntap_dev* device, int static_address);

extern SOCKET open_socket(uint16_t local_port, int bind_any);
extern SOCKET open_socket6(uint16_t local_port, int bind_any);
#ifndef _WIN32
extern SOCKET open_socket_unix(const char* path, mode_t access);
#endif // _WIN32

extern char* macaddr_str(macstr_t buf, const n2n_mac_t mac);
extern char * sock_to_cstr( n2n_sock_str_t out,
                            const n2n_sock_t * sock );

extern uint32_t ip4_prefixlen_to_netmask(uint8_t prefixlen);

extern int sock_equal( const n2n_sock_t * a,
                       const n2n_sock_t * b );

extern uint8_t is_multi_broadcast(const uint8_t * dest_mac);
extern char* msg_type2str(uint16_t msg_type);
extern void hexdump(const uint8_t * buf, size_t len);

void print_n2n_version();


/* Operations on peer_info lists. */
struct peer_info * find_peer_by_mac( struct peer_info * list,
                                     const n2n_mac_t mac );
void   peer_list_add( struct peer_info * * list,
                      struct peer_info * element );
size_t peer_list_size( const struct peer_info * list );
size_t purge_peer_list( struct peer_info ** peer_list,
                        time_t purge_before );
size_t clear_peer_list( struct peer_info ** peer_list );
size_t purge_expired_registrations( struct peer_info ** peer_list );

/* version.c */
extern char *n2n_sw_version, *n2n_sw_osName, *n2n_sw_buildDate;

/* Full definition of struct n2n_edge - needed by bypass and edge internals */
#include "n2n_transforms.h"
#include "bypass.h"

#define N2N_EDGE_SN_HOST_SIZE   48
typedef char n2n_sn_name_t[N2N_EDGE_SN_HOST_SIZE];

#define N2N_EDGE_NUM_SUPERNODES 3
#define N2N_EDGE_SUP_ATTEMPTS   3

#ifndef N2N_PATHNAME_MAXLEN
#define N2N_PATHNAME_MAXLEN     256
#endif

/* Transop indices */
#define N2N_TRANSOP_NULL_IDX    0
#define N2N_TRANSOP_TF_IDX      1
#define N2N_TRANSOP_AESCBC_IDX  2
#define N2N_TRANSOP_CC20_IDX    3
#define N2N_TRANSOP_SPECK_IDX   4

struct n2n_edge
{
    int                 daemon;
    uint8_t             re_resolve_supernode_ip;

    n2n_sock_t          supernode;
    n2n_sock_t          supernode_alt;

    size_t              sn_idx;
    size_t              sn_num;
    n2n_sn_name_t       sn_ip_array[N2N_EDGE_NUM_SUPERNODES];
    int                 sn_af;
    int                 sn_wait;

    n2n_community_t     community_name;
    char                keyschedule[N2N_PATHNAME_MAXLEN];
    int                 null_transop;
    char                supernode_version[16];

    SOCKET              udp_sock;
    SOCKET              udp_sock6;
    SOCKET              mgmt_sock;

    tuntap_dev          device;
    int                 dyn_ip_mode;
    int                 allow_routing;
    int                 drop_multicast;

    n2n_trans_op_t      transop[N2N_MAX_TRANSFORMS];
    size_t              tx_transop_idx;

    struct peer_info *  known_peers;
    struct peer_info *  pending_peers;
#ifdef _WIN32
    CRITICAL_SECTION    peers_lock;
#endif
    time_t              last_register_req;
    size_t              register_lifetime;
    time_t              last_p2p;
    time_t              last_sup;
    size_t              sup_attempts;
    n2n_cookie_t        last_cookie;
    uint8_t             sn_ack_count;
    uint8_t             sn_ipv4_support;
    uint8_t             sn_ipv6_support;

    time_t              start_time;

    n2n_sock_t          my_public_sock;

    n2n_sock_t          local_sock;
    int                 local_sock_ena;

    n2n_sock_t          local_socks[3];
    int                 local_socks_count;

    /* UPnP/NAT-PMP */
    uint16_t            upnp_mapped_port;

    n2n_sock_t          last_resolved_supernode;
    time_t              last_resolve_check;

    /* Statistics */
    size_t              tx_p2p;
    size_t              rx_p2p;
    size_t              tx_sup;
    size_t              rx_sup;
    size_t              super_tx_bytes;
    size_t              super_rx_bytes;
    size_t              p2p_tx_bytes;
    size_t              p2p_rx_bytes;

#ifdef _WIN32
    volatile int        keep_running;
#endif

    /* Rate-limiting for P2P/PsP log messages */
    uint8_t             last_p2p_log_mac[N2N_MAC_SIZE];
    n2n_sock_t          last_p2p_log_addr;
    uint8_t             last_psp_log_mac[N2N_MAC_SIZE];

    /* Bypass module */
    bypass_context_t   *bp;
    uint16_t            bp_proxy_port;
    uint8_t             bp_user_disabled; /* set by -x flag before bp is allocated */

    /* Cached PACKET header template for send_packet2net.
     * Pre-built common + PACKET fields (everything before payload). */
    uint8_t             cached_pkt_hdr[N2N_PKT_BUF_SIZE];
    uint16_t            cached_hdr_len;
    uint8_t             cached_hdr_valid;   /* header is cached */
    size_t              cached_tx_transop;
    /* Cached destination for send_PACKET (separate flag from header cache) */
    uint8_t             cached_dst_valid;   /* destination is cached */
    n2n_mac_t           cached_dst_mac;
    n2n_sock_t          cached_dst_sock;
    time_t              cached_dst_time;    /* when destination was cached */
    int                 cached_dst_is_peer;
};

#endif /* _N2N_H_ */