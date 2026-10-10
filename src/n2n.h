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

/* WebSocket support (pure C, no external deps).
 * Include after SOCKET and socket headers are defined. */
#include "ws.h"

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

/* Set N2N_COMPRESSION_ENABLED to 0 to disable lzo1x compression — breaks
 * standard packet format, experimentation only. */
#define N2N_COMPRESSION_ENABLED 1

#define DEFAULT_MTU   1350

/** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[INET6_ADDRSTRLEN];

/** Common type used to hold stringified MAC addresses. */
#define N2N_MACSTR_SIZE 32
typedef char macstr_t[N2N_MACSTR_SIZE];

/* NAT type from dual-sn reflection (mapping compare + helper-socket bounce + brother N2NF) */
#define N2N_NAT_UNKNOWN        0
#define N2N_NAT_SYMMETRIC      2
#define N2N_NAT_FULL_CONE      3  /* N2NF probe from a never-contacted brother got through */
#define N2N_NAT_RESTRICTED     4  /* addr-restr: helper bounce got through (incl. full cone w/o brother) */
#define N2N_NAT_PORT_RESTRICT  5  /* no bounce despite requests */

/* Shared display name for a N2N_NAT_* value ("unknown" when not measured). */
#define N2N_NAT_NAME(t) ( (t) == N2N_NAT_FULL_CONE ? "full-cone" : \
                          (t) == N2N_NAT_RESTRICTED ? "addr-restr" : \
                          (t) == N2N_NAT_PORT_RESTRICT ? "port-restr" : \
                          (t) == N2N_NAT_SYMMETRIC ? "symmetric" : "unknown" )

/* NAT type <-> aflags bits: REGISTER_SUPER carries the edge's own type,
 * PEER_INFO carries a peer's type to edges for mgmt display. */
#define N2N_NAT_AFLAGS(t) ( (t) == N2N_NAT_FULL_CONE ? N2N_AFLAGS_NAT_FULL_CONE : \
                            (t) == N2N_NAT_RESTRICTED ? N2N_AFLAGS_NAT_RESTRICTED : \
                            (t) == N2N_NAT_PORT_RESTRICT ? N2N_AFLAGS_NAT_PORT_RESTRICT : \
                            (t) == N2N_NAT_SYMMETRIC ? N2N_AFLAGS_NAT_SYMMETRIC : 0 )
#define N2N_NAT_FROM_AFLAGS(a) ( ((a) & N2N_AFLAGS_NAT_RESTRICTED) ? N2N_NAT_RESTRICTED : \
                                 ((a) & N2N_AFLAGS_NAT_PORT_RESTRICT) ? N2N_NAT_PORT_RESTRICT : \
                                 ((a) & N2N_AFLAGS_NAT_FULL_CONE) ? N2N_NAT_FULL_CONE : \
                                 ((a) & N2N_AFLAGS_NAT_SYMMETRIC) ? N2N_NAT_SYMMETRIC : N2N_NAT_UNKNOWN )

/* NAT types reachable without punching: only full-cone (NAT1) / restricted-cone
 * (NAT2) qualify as community relay; stricter kinds fall back to the plain SN relay. */
#define N2N_NAT_RELAY_CAPABLE(t) ( (t) == N2N_NAT_FULL_CONE || \
                                   (t) == N2N_NAT_RESTRICTED )

struct peer_info {
    struct peer_info *  next;
    n2n_community_t     community_name;
    n2n_mac_t           mac_addr;
    n2n_sock_t          sock;              /* IPv4 public address (family=0 if unavailable) */
    n2n_sock_t          sock6;             /* IPv6 public address (family=0 if unavailable) */
    int                 num_sockets;       /* 1=public only, 2=public+LAN */
    n2n_sock_t          sockets[2];        /* [0]=public (primary), [1]=LAN */
    uint8_t             nat_type;          /* N2N_NAT_* as reported by the edge (0 if not reported) */
    time_t              last_nat_push;     /* sn: last time this edge's nat_type was pushed to the community */
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
    uint8_t             punch_retry_count; /* number of punch retries, remove after max */
    uint8_t             punch_round;       /* current 2s punch round (0-based), reset on start_punch */
    time_t              punch_round_time;  /* round anchor for the 2s punch cadence */
    time_t              direct_seen;       /* time of last direct P2P communication with this peer; 0=never */
    time_t              p2p_est_time;      /* time P2P was established (set_peer_operational); for transition grace */
    uint8_t             last_p2p_log_mac[N2N_MAC_SIZE]; /* per-peer P2P log dedup key */
    n2n_sock_t          last_p2p_log_addr;
    n2n_sock_t          temp_local_sock;   /* dynamically selected best local IP for this peer */
    uint8_t             temp_local_sock_valid; /* 1 if temp_local_sock is valid */
    uint8_t             p2p_is_lan;        /* 1=LAN P2P, set by edge.c at REGISTER_SUPER_ACK */
    uint8_t             same_lan_as_sn;    /* 1 if edge is in same LAN as supernode */
    time_t              relay_adv_time;    /* sn: last time this edge was advertised as the relay (throttle) */
    time_t              sn_fwd_first;      /* sn: first time this edge's unicast data was relayed via SN (0=never); gates community-relay announcement */
    uint8_t             last_fwd_mac[N2N_MAC_SIZE]; /* sn: last unicast peer this edge's data was relayed to (communicating-pair tracking) */
    time_t              last_fwd_time;     /* sn: time of that last relayed unicast (0=never) */
    uint8_t             relay_willing;     /* sn: edge's relay stance: 0=refuse,1=default,2=willing,3=force */
    time_t              relay_adv_live;    /* sn: last time this peer was advertised AS the community relay (0=never) */
    /* Compact packet protocol support (version 0xE5 header) */
    uint8_t             compact_capable;   /* 1=understands compact format, 0=legacy/unknown */
    uint16_t            transform_id;      /* transform ID learned from PACKET headers (for SN legacy conversion) */
    /* WebSocket: non-NULL means this edge is connected via WS, forwarding uses ws_send instead of UDP sendto */
    ws_conn_t *         ws;
};

/* Hard-NAT punch pair: two edges coordinate 2s punch rounds; SN hands each the other's latest address (PUNCH) */
#define PUNCH_PAIR_MAX  64    /* max simultaneous hard-NAT punch pairs */
#define PUNCH_PAIR_HOLD 10    /* sec: drop a pair whose edges both stopped round-querying */
#define PUNCH_SYNC_MIN_DIFF_MS 10 /* ms: round-latency differences below this are noise */
#define PUNCH_SYNC_MAX_DIFF_MS 1000 /* ms: larger gaps mean hopelessly asymmetric routes, skip compensation */
struct sn_punch_pair {
    struct sn_punch_pair * next;
    n2n_community_t     community;
    n2n_mac_t           edge_a;         /* canonical order: lower MAC first */
    n2n_mac_t           edge_b;
    time_t              a_reg;          /* last round REGISTER_SUPER time of edge_a */
    time_t              b_reg;          /* last round REGISTER_SUPER time of edge_b */
    time_t              last_exchanged; /* last handoff exchange time (0 = none yet) */
    time_t              last_activity;  /* last QUERY touching this pair (purge key) */
    /* Round-start sync: defer the near side so both punch together. */
    int64_t             sync_send_ms;   /* ms: first handoff send time (measurement start) */
    int64_t             sync_reg_a_ms;  /* ms: edge_a's first registration after the start */
    int64_t             sync_reg_b_ms;  /* ms: edge_b's first registration after the start */
    int64_t             sync_delay_ms;  /* ms: compensation delay applied to the near side */
    int                 sync_near_a;    /* 1: edge_a is the near side (gets the delayed send) */
    int                 sync_armed;     /* 1: delay measured, compensation active */
    int64_t             defer_due_ms;   /* ms: due time of the pending near-side send (0 = none) */
    n2n_mac_t           defer_self;     /* pending send: recipient */
    n2n_mac_t           defer_other;    /* pending send: peer to describe */
};

struct n2n_edge; /* forward declaration, defined below */
typedef struct n2n_edge         n2n_edge_t;

/* Main loop tick: 10 ms = KCP 100 Hz + select(0) poll; avoids WSAEventSelect
 * whose non-blocking UDP flip would break SO_SNDBUF back-pressure. */
#define N2N_MAINLOOP_TICK_MS    10


/* ************************************** */

#define TRACE_ERROR     0
#define TRACE_WARNING   1
#define TRACE_NORMAL    2
#define TRACE_INFO      3
#define TRACE_DEBUG     4

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
extern void _traceEvent(int eventTraceLevel, char* file, int line, char * format, ...);
#define traceEvent(level, ...) \
    do { \
        if ((int)(level) <= traceLevel) \
            _traceEvent((int)(level), __FILE__, __LINE__, __VA_ARGS__); \
    } while(0)
extern time_t n2n_now(void);
extern int  tuntap_open(tuntap_dev *device, struct tuntap_config* config);
extern ssize_t tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, size_t len);
extern ssize_t tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, size_t len);
extern void tuntap_close(struct tuntap_dev *tuntap);
extern void tuntap_get_address(struct tuntap_dev *tuntap);
#ifdef _WIN32
/* Overlapped TAP reader driven from the main loop; never call GetOverlappedResult on a pending IRP */
extern ssize_t tuntap_read_begin_overlapped(struct tuntap_dev *tuntap);
extern ssize_t tuntap_read_complete_overlapped(struct tuntap_dev *tuntap);
#endif
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
int query_mgmt(uint16_t mgmt_port);


/* Operations on peer_info lists. */
struct peer_info * find_peer_by_mac( struct peer_info * list,
                                    const n2n_mac_t mac );
struct peer_info * find_peer_by_sock( struct peer_info * list,
                                      const struct sockaddr * sa );
void   peer_list_add( struct peer_info * * list,
                      struct peer_info * element );
size_t peer_list_size( const struct peer_info * list );
size_t purge_peer_list( struct peer_info ** peer_list,
                        time_t purge_before );
size_t clear_peer_list( struct peer_info ** peer_list );
size_t purge_expired_registrations( struct peer_info ** peer_list );

/* version.c */
extern char *n2n_sw_version, *n2n_sw_version_full, *n2n_sw_osName, *n2n_sw_buildDate;

/* Full definition of struct n2n_edge - needed by bypass and edge internals */
#include "n2n_transforms.h"
#include "bypass.h"

#define N2N_EDGE_SN_HOST_SIZE   48
typedef char n2n_sn_name_t[N2N_EDGE_SN_HOST_SIZE];

#define N2N_EDGE_NUM_SUPERNODES 3
#define N2N_EDGE_SUP_ATTEMPTS   3

#define N2N_AUTH_SIZE           32

#define MAX_BROTHER_SNS         16

/* Brother-SN direction (probing never crosses it):
 * MY_BIG = it registered ME as its little brother; MY_LITTLE = my configured little brother */
#define N2N_BROTHER_ROLE_MY_BIG      1
#define N2N_BROTHER_ROLE_MY_LITTLE   2

typedef struct {
    n2n_sock_t   sock;         /* current socket of this brother SN (IPv4 or IPv6, whichever arrives first) */
    n2n_sock_t   sock6;        /* IPv6 socket of this brother SN (optional, family=0 if not seen on v6) */
    n2n_sock_t   adv_sock;     /* advertised to ask_backup lookups: the big brother's
                                  registration source port IS its real service port. v4 */
    n2n_sock_t   adv_sock6;    /* same as adv_sock, v6 family (or reg.own_ipv6) */
    time_t       seen;         /* last registration time (0 = never, not counted in num_brothers) */
    time_t       seen6;        /* last v6 registration time */
    n2n_mac_t    mac;          /* MAC of the brother SN (all-zero = invalid) */
    uint8_t      role;         /* N2N_BROTHER_ROLE_* : direction of the relationship */
    char         version[8];   /* version string this brother sent in its brother_reg */
    char         os_name[16];  /* OS name this brother sent in its brother_reg */
} n2n_brother_entry_t;

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
    n2n_sock_t          sn_query;       /* fixed query channel (sn2): always asks sn1's newest address here */
    uint8_t             sn_query_index; /* index into sn_ip_array of the query channel (sn2) */
    uint8_t             sn_backup_index; /* index into sn_ip_array of the failover target */
    n2n_sock_t          sn1_probe_addr; /* last address we probed sn1 at while on the failover target */
    uint8_t             sn_probe_cookie[N2N_COOKIE_SIZE]; /* shared cookie for Phase-3 failback probes; the ACK path tells them apart by sender */
    uint8_t             sn_probe_cookie_valid;
    uint8_t             sn1_ever_ok;    /*=1 once sn1 accepted a registration/answered us;
                                          gate: only then ask sn2 for sn1's NEW address */

    size_t              sn_idx;
    size_t              sn_num;
    n2n_sn_name_t       sn_ip_array[N2N_EDGE_NUM_SUPERNODES];
    n2n_auth_t          sn_tokens[N2N_EDGE_NUM_SUPERNODES];
    int                 token_configured;
    int                 sn_af;
    int                 sn_wait;

    n2n_community_t     community_name;
    n2n_community_t     community_name_full;  /* full name before truncation for local display */
    char                keyschedule[N2N_PATHNAME_MAXLEN];
    int                 null_transop;
    char                supernode_version[32];

    SOCKET              udp_sock;
    SOCKET              udp_sock6;
    SOCKET              mgmt_sock;

    uint16_t            local_port; /* user-specified UDP port, 0 = any */

    /* WebSocket client (edge side, -w flag): relay via WS when UDP is blocked, disable P2P */
    int                 use_ws;
    ws_conn_t           ws_conn;
    time_t              ws_last_reconnect;
    time_t              ws_last_ping;   /* last app-level WS ping (keep proxy/NAT alive) */

    tuntap_dev          device;
    int                 dyn_ip_mode;
    int                 allow_routing;
    int                 drop_multicast;

    n2n_trans_op_t      transop[N2N_MAX_TRANSFORMS];
    size_t              tx_transop_idx;

    /* Destination cache for the P2P send path: a hit avoids the per-packet
     * peer-table scan. Accessed inside PEERS_LOCK. */
    uint8_t             cached_dst_valid;
    uint8_t             cached_dst_is_peer;
    n2n_mac_t           cached_dst_mac;
    n2n_sock_t          cached_dst_sock;
    time_t              cached_dst_time;

    /* Relay client: dual-send relay+supernode until proven, then relay-only; cleared on direct P2P */
    n2n_mac_t           relay_mac;
    n2n_sock_t          relay_sock;
    uint8_t             relay_valid;
    time_t              relay_last_reg;
    time_t              relay_proven;       /* last time a frame was received THROUGH the relay; 0=never */
    time_t              relay_last_ack;     /* last relay REGISTER ACK; liveness, decoupled from data traffic */

    /* Relay server: this edge forwards PACKETs for peers that registered to
     * it (mini-SN). Only NAT1 + public address self-enables. */
    uint8_t             relay_mode;

    /* Relay server member table: peers registered to this relay for forwarding
     * (NAT1, sockets from the REGISTER transport). Separate from P2P tables. */
    struct peer_info *  relay_peers;

    /* No relay ACK for RELAY_ACK_SECS => relay dead, fall back to SN, retry later */
    time_t              relay_probe_next;       /* when to retry a dead relay */
    uint8_t             relay_giveup;           /* 1=relay deemed dead, stay on SN until retry */
    uint8_t             relay_willing;          /* advertised to SN for relay selection: 0/1/2/3 */

    struct peer_info *  known_peers;
    struct peer_info *  pending_peers;
#ifdef _WIN32
    CRITICAL_SECTION    peers_lock;
#endif
    time_t              last_register_req;
    time_t              last_primary_probe; /* last heartbeat sent to primary (on backup) */
    size_t              register_lifetime;
    time_t              last_p2p;
    time_t              last_sup;
    size_t              sup_attempts;
    uint8_t             sn_all_failed;
    uint8_t             sn_ask_backup;
    n2n_mac_t           sn1_mac;        /* MAC of the SN the edge is currently registered with. */
    n2n_sock_t          sn1_v6;         /* sn1's IPv6 address (as reported by sn1 in the ACK). */
    uint8_t             sn_ack_backup[N2N_EDGE_NUM_SUPERNODES]; /* indices whose entry came from the sn1 ACK (backup). */
    uint8_t             sn_ak_parsed;   /* sn1's ACK backup string parsed (learnt or already present) */
    char                sn_bak_masked[N2N_EDGE_SN_HOST_SIZE]; /* ACK-learned brother: masked display copy ('*' + tail) */
    uint8_t             sn_relay_fails;   /* consecutive relay send failures, reset on success */
    n2n_cookie_t        last_cookie;
    uint8_t             sn_ack_count;
    uint8_t             sn_ipv4_support;
    uint8_t             sn_ipv6_support;

    time_t              start_time;

    n2n_sock_t          my_public_sock;

    /* NAT detection: twin probes to the SN's two ports + helper-socket bounce for cone sub-types */
    uint8_t             nat_type;       /* N2N_NAT_* */
    n2n_sock_t          nat_seen_sn1;   /* edge addr observed by sn1 (family=0 if none) */
    n2n_sock_t          nat_seen_sn2;   /* twin probe MAIN-port echo (also sn2 query ACK in failover) */
    n2n_sock_t          nat_seen_sn2_alt; /* alt-port echo: equal public ports prove per-IP mapping reuse */
    n2n_sock_t          nat_seen_sn_cross; /* echo from a distinct public IP; confirmatory only (NAT3 varies port per destination) */
    time_t              nat_probe_time; /* last one-shot symmetric check attempt */
    uint8_t             nat_probe_pending; /* 1 while awaiting ACKs of the NAT probe */
    uint8_t             nat_probe_cross;   /* 1: cross-IP probe to sn2 fired this round; routes its ACK to nat_seen_sn_cross */
    uint8_t             nat_bounce_seen;   /* a helper-port delivery got through: not port-restricted */
    uint8_t             fc_seen;        /* "N2NF" from the never-contacted sn2 got through */
    uint8_t             fc_window;      /* 1 until the first packet is sent to sn2 */
    time_t              fc_arm_time;    /* last (re-)arm of the stranger window; the one-shot symmetric check spends it 12s later */
    uint8_t             nat_sym_tries;  /* attempts spent on the one-shot symmetric check */
    uint8_t             nat_final;      /* 1: verdict frozen, twin check spent (cleared on restart / mapping change) */
    uint8_t             nat_reprobe;    /* one-shot: next sn1 registration re-triggers the brother's N2NF probe */
    uint8_t             punch_round_reg; /* one-shot: next registration carries the punch-round flag */
    time_t              nat_revert_at;  /* mgmt "n" fixed-port: rebind the local port at this time (0 = none) */
    time_t              nat_refresh_start; /* mgmt "n" refresh start; hard cap forces freeze/restore even if sn2 never answers */
    uint8_t             nat_rebuild_tries; /* rebuilds already run; capped so a sick environment eventually freezes */
    uint8_t             nat_suppress_remap; /* one-shot: next ACK-remap only updates
                                           my_public_sock, keeps the fresh NAT verdict */
    time_t              nat_autorecover_at; /* last automatic UDP socket rebuild (every
                                           supernode silent); 0 = never */

    n2n_sock_t          own_ipv6;       /* routable global IPv6, reported for IPv6 hole-punching; family==0 if none */

    n2n_sock_t          local_sock;
    int                 local_sock_ena;

    n2n_sock_t          local_socks[3];
    int                 local_socks_count;

    /* UPnP/NAT-PMP */
    uint16_t            upnp_mapped_port;

    time_t              last_resolve_check;

    /* HTTP redirect (pure socket, no curl/wget) */
    char                http_redirect_url[N2N_EDGE_SN_HOST_SIZE];
    time_t              last_http_check;
    n2n_sock_t          last_http_supernode;

    /* "f" sync: lock mgmt input, take IP snapshot, compare vs PEER_INFO from SN */
    int                 peer_sync_active;     /* 1 = sync in progress, mgmt locked */
    time_t              peer_sync_time;       /* when sync started, for 2s timeout */
    uint32_t            peer_sync_ips[256];   /* snapshot of local assigned_ips */
    uint16_t            peer_sync_ips_count;  /* number of IPs in snapshot */

    /* Gaming mode (-G): actively probe peers to trigger P2P hole-punching */
    int                 enable_gaming_mode;
    int                 gaming_started;

    /* Statistics */
    size_t              tx_p2p;
    size_t              rx_p2p;
    size_t              tx_sup;
    size_t              rx_sup;
    size_t              super_tx_bytes;
    size_t              super_rx_bytes;
    size_t              p2p_tx_bytes;
    size_t              p2p_rx_bytes;

    volatile int        keep_running;

    /* Bypass module */
    bypass_context_t   *bp;
    uint16_t            bp_proxy_port;
    uint8_t             bp_user_disabled; /* set by -x flag before bp is allocated */

};

#endif /* _N2N_H_ */