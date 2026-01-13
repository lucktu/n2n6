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
    int mtu;
    /* ipv4 configuration */
    bool dyn_ip4;
    in_addr_t ip_addr;
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

#define DEFAULT_MTU   1400

/** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[INET6_ADDRSTRLEN];

/** Common type used to hold stringified MAC addresses. */
#define N2N_MACSTR_SIZE 32
typedef char macstr_t[N2N_MACSTR_SIZE];

struct peer_info {
    struct peer_info *  next;
    n2n_community_t     community_name;
    n2n_mac_t           mac_addr;
    n2n_sock_t          sock;
    time_t              last_seen;
    char                version[8];
    char                os_name[16];
    uint32_t            assigned_ip;
};

struct n2n_edge; /* defined in edge.c */
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

#endif /* _N2N_H_ */