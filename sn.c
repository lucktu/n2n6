/* Supernode for n2n-2.x */

/* (c) 2009 Richard Andrews <andrews@ntop.org>
 *
 * Contributions by:
 *    Lukasz Taczuk
 *    Struan Bartlett
 */


#include "n2n.h"
#include "n2n_transforms.h"
#include "n2n_wire.h"
#include <fcntl.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define SOCKET_INVALID INVALID_SOCKET
#define CLOSE_SOCKET(s) closesocket(s)
#else
#include <sys/select.h>
#include <arpa/inet.h>
#define SOCKET_INVALID -1
#define CLOSE_SOCKET(s) close(s)
#endif

#define N2N_SN_LPORT_DEFAULT SUPERNODE_PORT
#define N2N_SN_MGMT_PORT     5646

/* Transform indices - same as edge.c */
#define N2N_TRANSOP_NULL_IDX    0
#define N2N_TRANSOP_TF_IDX      1
#define N2N_TRANSOP_AESCBC_IDX  2
#define N2N_TRANSOP_SPECK_IDX   3

#ifndef _WIN32
#include <poll.h>
#endif

static unsigned int count_communities(struct peer_info *edges);
static uint32_t next_assigned_ip = 0x0a400002; /* 10.64.0.2 */

struct sn_stats
{
    size_t errors;              /* Number of errors encountered. */
    size_t reg_super;           /* Number of REGISTER_SUPER requests received. */
    size_t reg_super_nak;       /* Number of REGISTER_SUPER requests declined. */
    size_t fwd;                 /* Number of messages forwarded. */
    size_t broadcast;           /* Number of messages broadcast to a community. */
    time_t last_fwd;            /* Time when last message was forwarded. */
    time_t last_reg_super;      /* Time when last REGISTER_SUPER was received. */
};

typedef struct sn_stats sn_stats_t;

struct n2n_sn
{
    time_t              start_time;     /* Used to measure uptime. */
    sn_stats_t          stats;
    int                 daemon;         /* If non-zero then daemonise. */
    uint16_t            lport;          /* Local UDP port to bind to. */
    uint16_t            mgmt_port;      /* Managing UDP ports */
    SOCKET              sock;           /* Main socket for UDP traffic with edges. */
    SOCKET              sock6;
    SOCKET              mgmt_sock;      /* management socket. */
    struct peer_info *  edges;          /* Link list of registered edges. */
    n2n_trans_op_t      transop[N2N_MAX_TRANSFORMS];
    int                 ipv4_available; /* 0=unavailable, 1=available */
    int                 ipv6_available; /* 0=unavailable, 1=available */
};

typedef struct n2n_sn n2n_sn_t;

static void collect_community_peers(n2n_sn_t * sss,
                                   const n2n_community_t community,
                                   n2n_REGISTER_SUPER_ACK_t * ack)
{
    struct peer_info * scan = sss->edges;
    int count = 0;

    while (scan && count < 16) {
        /* Only include valid peers with assigned IPs, non-zero MACs, and valid public IPs */
        if (memcmp(scan->community_name, community, N2N_COMMUNITY_SIZE) == 0 &&
            scan->assigned_ip != 0 &&
            memcmp(scan->mac_addr, "\x00\x00\x00\x00\x00\x00", 6) != 0 &&
            scan->sock.family != 0 && /* Check for valid socket family */
            scan->sock.port != 0) {   /* Check for valid port */

            memcpy(ack->peer_macs[count], scan->mac_addr, N2N_MAC_SIZE);
            ack->peer_ips[count] = htonl(scan->assigned_ip);
            ack->peer_pub_ips[count] = scan->sock;
            count++;
        }
        scan = scan->next;
    }

    ack->peer_count = count;
}

static int update_edge( n2n_sn_t * sss,
                        const n2n_mac_t edgeMac,
                        const n2n_community_t community,
                        const n2n_sock_t * sender_sock,
                        time_t now,
                        const char * version,
                        const char * os_name,
                        uint8_t request_ip,
                        uint32_t requested_ip );

static int try_forward( n2n_sn_t * sss,
                        const n2n_common_t * cmn,
                        const n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktsize );

static int try_broadcast( n2n_sn_t * sss,
                          const n2n_common_t * cmn,
                          const n2n_mac_t srcMac,
                          const uint8_t * pktbuf,
                          size_t pktsize );


/* IPv4 connectivity test */
static int test_ipv4_connectivity() {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return 0;

    u_long mode = 1; /* 1 = non-blocking */
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in test_addr;
    memset(&test_addr, 0, sizeof(test_addr));
    test_addr.sin_family = AF_INET;
    test_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &test_addr.sin_addr);

    int connect_result = connect(sock, (struct sockaddr*)&test_addr, sizeof(test_addr));

    if (connect_result == 0) {
        closesocket(sock);
        return 1;
    }

    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(sock);
        return 0;
    }
#else
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in test_addr;
    memset(&test_addr, 0, sizeof(test_addr));
    test_addr.sin_family = AF_INET;
    test_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &test_addr.sin_addr);

    int connect_result = connect(sock, (struct sockaddr*)&test_addr, sizeof(test_addr));

    if (connect_result == 0) {
        close(sock);
        return 1;
    }

    if (errno != EINPROGRESS) {
        close(sock);
        return 0;
    }
#endif

    fd_set write_fds;
    struct timeval timeout = {1, 0};
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);

    int result = select(sock + 1, NULL, &write_fds, NULL, &timeout);

    if (result > 0) {
        int error = 0;
        socklen_t len = sizeof(error);
#ifdef _WIN32
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
        closesocket(sock);
#else
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
        close(sock);
#endif
        return (error == 0);
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return 0;
}

/* IPv6 connectivity test */
static int test_ipv6_connectivity() {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return 0;

    u_long mode = 1; /* 1 = non-blocking */
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in6 test_addr;
    memset(&test_addr, 0, sizeof(test_addr));
    test_addr.sin6_family = AF_INET6;
    test_addr.sin6_port = htons(53);
    inet_pton(AF_INET6, "2001:4860:4860::8888", &test_addr.sin6_addr);

    int connect_result = connect(sock, (struct sockaddr*)&test_addr, sizeof(test_addr));

    if (connect_result == 0) {
        closesocket(sock);
        return 1;
    }

    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(sock);
        return 0;
    }
#else
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in6 test_addr;
    memset(&test_addr, 0, sizeof(test_addr));
    test_addr.sin6_family = AF_INET6;
    test_addr.sin6_port = htons(53);
    inet_pton(AF_INET6, "2001:4860:4860::8888", &test_addr.sin6_addr);

    int connect_result = connect(sock, (struct sockaddr*)&test_addr, sizeof(test_addr));

    if (connect_result == 0) {
        close(sock);
        return 1;
    }

    if (errno != EINPROGRESS) {
        close(sock);
        return 0;
    }
#endif

    fd_set write_fds;
    struct timeval timeout = {1, 0};
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);

    int result = select(sock + 1, NULL, &write_fds, NULL, &timeout);

    if (result > 0) {
        int error = 0;
        socklen_t len = sizeof(error);
#ifdef _WIN32
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
        closesocket(sock);
#else
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
        close(sock);
#endif
        return (error == 0);
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return 0;
}

/** Initialise the supernode structure */
static int init_sn( n2n_sn_t * sss )
{
#ifdef WIN32
    initWin32();
#endif
    memset( sss, 0, sizeof(n2n_sn_t) );

    sss->daemon = 1; /* By defult run as a daemon. */
    sss->lport = N2N_SN_LPORT_DEFAULT;
    sss->mgmt_port = N2N_SN_MGMT_PORT;
    sss->sock = -1;
    sss->sock6 = -1;
    sss->mgmt_sock = -1;
    sss->edges = NULL;
    /* Initialize transforms - required to decode encrypted packets */
    transop_null_init(    &(sss->transop[N2N_TRANSOP_NULL_IDX]) );
    transop_twofish_init( &(sss->transop[N2N_TRANSOP_TF_IDX])  );
    transop_aes_init( &(sss->transop[N2N_TRANSOP_AESCBC_IDX])  );
    transop_speck_init( &(sss->transop[N2N_TRANSOP_SPECK_IDX]) );

    return 0; /* OK */
}

/** Deinitialise the supernode structure and deallocate any memory owned by
 *  it. */
static void deinit_sn( n2n_sn_t * sss )
{
    if (sss->sock >= 0)
    {
        closesocket(sss->sock);
    }
    sss->sock = -1;

    if (sss->sock6 >= 0)
    {
        closesocket(sss->sock6);
    }
    sss->sock6 = -1;

    if ( sss->mgmt_sock >= 0 )
    {
        closesocket(sss->mgmt_sock);
    }
    sss->mgmt_sock = -1;

    purge_peer_list( &(sss->edges), 0xffffffff );

#ifdef _WIN32
    WSACleanup();
#endif
}


/** Determine the appropriate lifetime for new registrations.
 *
 *  If the supernode has been put into a pre-shutdown phase then this lifetime
 *  should not allow registrations to continue beyond the shutdown point.
 */
static uint16_t reg_lifetime( n2n_sn_t * sss )
{
    return 120;
}


/** Update the edge table with the details of the edge which contacted the
 *  supernode. */
static int update_edge( n2n_sn_t * sss,
                        const n2n_mac_t edgeMac,
                        const n2n_community_t community,
                        const n2n_sock_t * sender_sock,
                        time_t now,
                        const char * version,
                        const char * os_name,
                        uint8_t request_ip,
                        uint32_t requested_ip )
{
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;
    struct peer_info *  scan;

    traceEvent( TRACE_DEBUG, "update_edge for %s %s",
                macaddr_str( mac_buf, edgeMac ),
                sock_to_cstr( sockbuf, sender_sock ) );

    scan = find_peer_by_mac( sss->edges, edgeMac );

    if ( NULL == scan )
    {
        /* Not known */

        scan = (struct peer_info*)calloc(1, sizeof(struct peer_info)); /* deallocated in purge_expired_registrations */

        if (request_ip) {
            uint32_t assigned_ip;
            if (requested_ip != 0) {
                assigned_ip = ntohl(requested_ip);
                traceEvent(TRACE_INFO, "Using requested IP 10.64.0.%u for edge %s",
                           assigned_ip & 0xFF, macaddr_str(mac_buf, edgeMac));
            } else {
                assigned_ip = next_assigned_ip++;
                traceEvent(TRACE_INFO, "Auto-assigning IP 10.64.0.%u to edge %s",
                           assigned_ip & 0xFF, macaddr_str(mac_buf, edgeMac));
                if ((assigned_ip & 0xFF) > 254) {
                    next_assigned_ip = 0x0a400002;
                }
            }
            scan->assigned_ip = assigned_ip;
        }

        memcpy(scan->community_name, community, sizeof(n2n_community_t) );
        memcpy(&(scan->mac_addr), edgeMac, sizeof(n2n_mac_t));
        memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));

        if (version) {
            strncpy(scan->version, version, sizeof(scan->version) - 1);
            scan->version[sizeof(scan->version) - 1] = '\0';
        } else {
            strcpy(scan->version, "unknown");
        }
        if (os_name) {
            strncpy(scan->os_name, os_name, sizeof(scan->os_name) - 1);
            scan->os_name[sizeof(scan->os_name) - 1] = '\0';
        } else {
            strcpy(scan->os_name, "unknown");
        }

        /* insert this guy at the head of the edges list */
        scan->next = sss->edges;     /* first in list */
        sss->edges = scan;           /* head of list points to new scan */

        traceEvent( TRACE_INFO, "update_edge created   %s ==> %s",
                    macaddr_str( mac_buf, edgeMac ),
                    sock_to_cstr( sockbuf, sender_sock ) );
    }
    else
    {
        /* Known */
        if ( (0 != memcmp(community, scan->community_name, sizeof(n2n_community_t))) ||
             (0 != sock_equal(sender_sock, &(scan->sock) )) )
        {
            memcpy(scan->community_name, community, sizeof(n2n_community_t) );
            memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));

            if (version) {
                strncpy(scan->version, version, sizeof(scan->version) - 1);
                scan->version[sizeof(scan->version) - 1] = '\0';
            }
            if (os_name) {
                strncpy(scan->os_name, os_name, sizeof(scan->os_name) - 1);
                scan->os_name[sizeof(scan->os_name) - 1] = '\0';
            }

            traceEvent( TRACE_INFO, "update_edge updated   %s ==> %s",
                        macaddr_str( mac_buf, edgeMac ),
                        sock_to_cstr( sockbuf, sender_sock ) );
        }
        else
        {
            traceEvent( TRACE_DEBUG, "update_edge unchanged %s ==> %s",
                        macaddr_str( mac_buf, edgeMac ),
                        sock_to_cstr( sockbuf, sender_sock ) );
        }

    }

    scan->last_seen = now;
    return 0;
}


/** Send a datagram to the destination embodied in a n2n_sock_t.
 *
 *  @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_sock(n2n_sn_t * sss,
                           const n2n_sock_t * sock,
                           const uint8_t * pktbuf,
                           size_t pktsize)
{
    n2n_sock_str_t      sockbuf;

    if ( AF_INET == sock->family )
    {
        struct sockaddr_in udpsock;

        udpsock.sin_family = AF_INET;
        udpsock.sin_port = htons( sock->port );
        memcpy( &(udpsock.sin_addr), &(sock->addr.v4), IPV4_SIZE );

        traceEvent( TRACE_DEBUG, "sendto_sock %lu to %s",
                    pktsize,
                    sock_to_cstr( sockbuf, sock ) );

        return sendto( sss->sock, pktbuf, pktsize, 0,
                       (const struct sockaddr *)&udpsock, sizeof(struct sockaddr_in) );
    }
    else if ( AF_INET6 == sock->family )
    {
        struct sockaddr_in6 udpsock = { 0 };

        udpsock.sin6_family = AF_INET6;
        udpsock.sin6_port = htons( sock->port );
        memcpy( &(udpsock.sin6_addr), &(sock->addr.v6), IPV6_SIZE );

        traceEvent( TRACE_DEBUG, "sendto_sock6 %lu to %s",
                    pktsize,
                    sock_to_cstr( sockbuf, sock ) );

        return sendto( sss->sock6, pktbuf, pktsize, 0,
                       (const struct sockaddr *)&udpsock, sizeof(struct sockaddr_in6) );
    }
    else
    {
        errno = EAFNOSUPPORT;
        return -1;
    }
}


/** Try to forward a message to a unicast MAC. If the MAC is unknown then
 *  broadcast to all edges in the destination community.
 */
static int try_forward( n2n_sn_t * sss,
                        const n2n_common_t * cmn,
                        const n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktsize )
{
    struct peer_info *  scan;
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;

    scan = find_peer_by_mac( sss->edges, dstMac );

    if ( NULL != scan )
    {
        ssize_t data_sent_len;
        data_sent_len = sendto_sock( sss, &(scan->sock), pktbuf, pktsize );

        if ( data_sent_len == pktsize )
        {
            ++(sss->stats.fwd);
            traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s",
                       pktsize,
                       sock_to_cstr( sockbuf, &(scan->sock) ),
                       macaddr_str(mac_buf, scan->mac_addr));
        }
        else
        {
            ++(sss->stats.errors);
#ifdef _WIN32
            DWORD err = WSAGetLastError();
            W32_ERROR(err, error);
            traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %ls)",
                       pktsize,
                       sock_to_cstr( sockbuf, &(scan->sock) ),
                       macaddr_str(mac_buf, scan->mac_addr),
                       err, error );
            W32_ERROR_FREE(error);
#else
            traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %s)",
                       pktsize,
                       sock_to_cstr( sockbuf, &(scan->sock) ),
                       macaddr_str(mac_buf, scan->mac_addr),
                       errno, strerror(errno) );
#endif
        }
    }
    else
    {
        traceEvent( TRACE_DEBUG, "try_forward unknown MAC" );

        /* Not a known MAC so drop. */
    }

    return 0;
}


/** Try and broadcast a message to all edges in the community.
 *
 *  This will send the exact same datagram to zero or more edges registered to
 *  the supernode.
 */
static int process_mgmt( n2n_sn_t * sss,
                         const struct sockaddr * sender_sock,
                         socklen_t sender_sock_len,
                         const uint8_t * mgmt_buf,
                         size_t mgmt_size,
                         time_t now)
{
    char resbuf[N2N_SN_PKTBUF_SIZE];
    size_t ressize = 0;
    ssize_t r;
    struct peer_info *list;
    n2n_community_t communities[256];
    struct peer_info *community_edges[256];
    int community_counts[256];
    int num_communities = 0;
    uint32_t num_edges = 0;

    traceEvent( TRACE_DEBUG, "process_mgmt" );

    /* Send header */
    ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                      "  id  mac                virt_ip          wan_ip                                           ver      os\n");
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                       "---n2n6---------------------------------------------------------------------------------------------n2n6---\n");

    r = sendto(sss->mgmt_sock, resbuf, ressize, 0,
               sender_sock, sender_sock_len);
    if (r <= 0) return -1;

    /* First pass: collect all unique communities and their edges */
    list = sss->edges;
    while (list) {
        /* Check if this community already exists */
        int found = 0;
        for (int i = 0; i < num_communities; i++) {
            if (memcmp(communities[i], list->community_name, sizeof(n2n_community_t)) == 0) {
                /* Add edge to existing community */
                struct peer_info *new_edge = malloc(sizeof(struct peer_info));
                if (!new_edge) {
                    for (int j = 0; j < num_communities; j++) {
                        struct peer_info *temp = community_edges[j];
                        while (temp) {
                            struct peer_info *next = temp->next;
                            free(temp);
                            temp = next;
                        }
                    }
                    traceEvent(TRACE_ERROR, "malloc failed for new_edge in process_mgmt");
                    return -1;
                }
                memcpy(new_edge, list, sizeof(struct peer_info));
                new_edge->next = community_edges[i];
                community_edges[i] = new_edge;
                community_counts[i]++;
                found = 1;
                break;
            }
        }

        if (!found && num_communities < 256) {
            /* New community */
            memcpy(communities[num_communities], list->community_name, sizeof(n2n_community_t));
            community_edges[num_communities] = malloc(sizeof(struct peer_info));
            if (!community_edges[num_communities]) {
                for (int j = 0; j < num_communities; j++) {
                    struct peer_info *temp = community_edges[j];
                    while (temp) {
                        struct peer_info *next = temp->next;
                        free(temp);
                        temp = next;
                    }
                }
                traceEvent(TRACE_ERROR, "malloc failed for community_edges[%d] in process_mgmt", num_communities);
                return -1;
            }
            memcpy(community_edges[num_communities], list, sizeof(struct peer_info));
            community_edges[num_communities]->next = NULL;
            community_counts[num_communities] = 1;
            num_communities++;
        }

        num_edges++;
        list = list->next;
    }

    /* Second pass: display edges grouped by community */
    uint32_t displayed_edges = 0;
    for (int i = 0; i < num_communities; i++) {
        /* Send community name */
        ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE, "%s\n", communities[i]);
        r = sendto(sss->mgmt_sock, resbuf, ressize, 0,
                  sender_sock, sender_sock_len);
        if (r <= 0) return -1;

        /* Send all edges in this community */
        struct peer_info *edge = community_edges[i];
        int id = 1;
        while (edge) {
            macstr_t mac_buf;
            n2n_sock_str_t sock_buf;
            const char *version = (edge->version[0] != '\0') ? edge->version : "unknown";
            const char *os_name = (edge->os_name[0] != '\0') ? edge->os_name : "unknown";

            /* MAC address validation */
            uint8_t *mac = edge->mac_addr;
            int is_valid_mac = 1;

            /* Check for zero MAC */
            if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
                mac[3] == 0 && mac[4] == 0 && mac[5] == 0) {
                is_valid_mac = 0;
            }

            /* Check for broadcast MAC */
            if (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
                mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF) {
                is_valid_mac = 0;
            }

            /* Check for locally administered MAC (00:01:00:xx:xx:xx pattern) */
            if (mac[0] == 0x00 && mac[1] == 0x01 && mac[2] == 0x00) {
                is_valid_mac = 0;
            }

            /* Skip invalid MAC addresses - don't display them at all */
            if (!is_valid_mac) {
                struct peer_info *temp = edge;
                edge = edge->next;
                free(temp);
                continue;
            }

            displayed_edges++;

            struct in_addr a;
            a.s_addr = htonl(edge->assigned_ip);
            const char *ip_str = (edge->assigned_ip != 0) ? inet_ntoa(a) : "-";
            ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                              "  %2u  %-17s  %-15s  %-47s  %-7s  %s\n",
                              id++,
                              macaddr_str(mac_buf, edge->mac_addr),
                              ip_str,
                              sock_to_cstr(sock_buf, &edge->sock),
                              version,
                              os_name);

            r = sendto(sss->mgmt_sock, resbuf, ressize, 0,
                      sender_sock, sender_sock_len);
            if (r <= 0) return -1;

            struct peer_info *temp = edge;
            edge = edge->next;
            free(temp);
        }
    }

    num_edges = displayed_edges;

    /* Send footer and statistics */
    ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                      "---n2n6---------------------------------------------------------------------------------------------n2n6---\n");

    time_t uptime = now - sss->start_time;
    int days = uptime / 86400;
    int hours = (uptime % 86400) / 3600;

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                       "uptime %dd_%dh | edges %u | cmnts %u | reg_nak %u | errs %u | last_reg %lus ago | last_fwd %lus ago\n",
                       days, hours,
                       num_edges,
                       num_communities,
                       (unsigned int)sss->stats.reg_super_nak,
                       (unsigned int)sss->stats.errors,
                       (long unsigned int)(now - sss->stats.last_reg_super),
                       (long unsigned int)(now - sss->stats.last_fwd));

    const char* ip_support;
    if (sss->ipv4_available && sss->ipv6_available) {
        ip_support = "IPv4+IPv6";
    } else if (sss->ipv4_available) {
        ip_support = "IPv4 only";
    } else if (sss->ipv6_available) {
        ip_support = "IPv6 only";
    } else {
        ip_support = "None";
    }

    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                       "broadcast %u | reg_sup %u | fwd %u | ip_support: %s | time: %s\n",
                       (unsigned int) sss->stats.broadcast,
                       (unsigned int)sss->stats.reg_super,
                       (unsigned int) sss->stats.fwd,
                       ip_support,
                       time_buf);

    r = sendto(sss->mgmt_sock, resbuf, ressize, 0,
              sender_sock, sender_sock_len);
    if (r <= 0) return -1;

    return 0;
}

static int try_broadcast( n2n_sn_t * sss,
                          const n2n_common_t * cmn,
                          const n2n_mac_t srcMac,
                          const uint8_t * pktbuf,
                          size_t pktsize )
{
    struct peer_info *  scan;
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;

    traceEvent( TRACE_DEBUG, "try_broadcast" );

    scan = sss->edges;
    while(scan != NULL)
    {
        if( 0 == (memcmp(scan->community_name, cmn->community, sizeof(n2n_community_t)) )
            && (0 != memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) ) )
        {
            ssize_t data_sent_len;

            data_sent_len = sendto_sock(sss, &(scan->sock), pktbuf, pktsize);

            if(data_sent_len != pktsize)
            {
                ++(sss->stats.errors);
                /* Error handling code... */
            }
            else
            {
                ++(sss->stats.broadcast);
                traceEvent(TRACE_DEBUG, "multicast %lu to %s %s",
                           pktsize,
                           sock_to_cstr( sockbuf, &(scan->sock) ),
                           macaddr_str( mac_buf, scan->mac_addr));
            }
        }

        scan = scan->next;
    }

    return 0;
}

static unsigned int count_communities(struct peer_info *edges)
{
    struct peer_info *list = edges;
    n2n_community_t communities[256];
    unsigned int count = 0;

    while (list && count < 256) {
        int found = 0;
        for (unsigned int i = 0; i < count; i++) {
            if (memcmp(communities[i], list->community_name, sizeof(n2n_community_t)) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            memcpy(communities[count], list->community_name, sizeof(n2n_community_t));
            count++;
        }
        list = list->next;
    }

    return count;
}


/** Examine a datagram and determine what to do with it.
 *
 */
static int process_udp( n2n_sn_t * sss,
                        const struct sockaddr * sender_sock,
												socklen_t sender_sock_len,
                        const uint8_t * udp_buf,
                        size_t udp_size,
                        time_t now)
{
    n2n_common_t        cmn; /* common fields in the packet header */
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    uint8_t             from_supernode;
    macstr_t            mac_buf;
    macstr_t            mac_buf2;
    n2n_sock_str_t      sockbuf;


    traceEvent( TRACE_DEBUG, "process_udp(%lu)", udp_size );

    /* Use decode_common() to determine the kind of packet then process it:
     *
     * REGISTER_SUPER adds an edge and generate a return REGISTER_SUPER_ACK
     *
     * REGISTER, REGISTER_ACK and PACKET messages are forwarded to their
     * destination edge. If the destination is not known then PACKETs are
     * broadcast.
     */

    rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */
    if ( decode_common(&cmn, udp_buf, &rem, &idx) < 0 )
    {
        traceEvent( TRACE_DEBUG, "Failed to decode common section" );
        return -1; /* failed to decode packet */
    }

    msg_type = cmn.pc; /* packet code */
    from_supernode= cmn.flags & N2N_FLAGS_FROM_SUPERNODE;

    if ( cmn.ttl < 1 )
    {
        traceEvent( TRACE_WARNING, "Expired TTL" );
        return 0; /* Don't process further */
    }

    --(cmn.ttl); /* The value copied into all forwarded packets. */

    if ( msg_type == MSG_TYPE_PACKET )
    {
        /* PACKET from one edge to another edge via supernode. */

        /* pkt will be modified in place and recoded to an output of potentially
         * different size due to addition of the socket.*/
        n2n_PACKET_t                    pkt;
        n2n_common_t                    cmn2;
        uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;
        int                             unicast; /* non-zero if unicast */
        const uint8_t *                 rec_buf; /* either udp_buf or encbuf */


        sss->stats.last_fwd=now;
        decode_PACKET( &pkt, &cmn, udp_buf, &rem, &idx );

        unicast = (0 == is_multi_broadcast(pkt.dstMac) );

        traceEvent( TRACE_DEBUG, "Rx PACKET (%s) %s -> %s %s",
                    (unicast?"unicast":"multicast"),
                    macaddr_str( mac_buf, pkt.srcMac ),
                    macaddr_str( mac_buf2, pkt.dstMac ),
                    (from_supernode?"from sn":"local") );

        if ( !from_supernode )
        {
            memcpy( &cmn2, &cmn, sizeof( n2n_common_t ) );

            /* We are going to add socket even if it was not there before */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            if (sender_sock->sa_family == AF_INET) {
                struct sockaddr_in* sock = (struct sockaddr_in*) sender_sock;
                pkt.sock.family = AF_INET;
                pkt.sock.port = ntohs(sock->sin_port);
                memcpy( pkt.sock.addr.v4, &(sock->sin_addr), IPV4_SIZE );
            } else if (sender_sock->sa_family == AF_INET6) {
                struct sockaddr_in6* sock = (struct sockaddr_in6*) sender_sock;
                pkt.sock.family = AF_INET6;
                pkt.sock.port = ntohs(sock->sin6_port);
                memcpy( pkt.sock.addr.v6, &(sock->sin6_addr), IPV6_SIZE );
            }

            rec_buf = encbuf;

            /* Re-encode the header. */
            encode_PACKET( encbuf, &encx, &cmn2, &pkt );

            /* Copy the original payload unchanged */
            encode_buf( encbuf, &encx, (udp_buf + idx), (udp_size - idx ) );
        }
        else
        {
            /* Already from a supernode. Nothing to modify, just pass to
             * destination. */

            traceEvent( TRACE_DEBUG, "Rx PACKET fwd unmodified" );

            rec_buf = udp_buf;
            encx = udp_size;
        }

        /* Common section to forward the final product. */
        if ( unicast )
        {
            try_forward( sss, &cmn, pkt.dstMac, rec_buf, encx );
        }
        else
        {
            try_broadcast( sss, &cmn, pkt.srcMac, rec_buf, encx );
        }
    }/* MSG_TYPE_PACKET */
    else if ( msg_type == MSG_TYPE_REGISTER )
    {
        /* Forwarding a REGISTER from one edge to the next */

        n2n_REGISTER_t                  reg;
        n2n_common_t                    cmn2;
        uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;
        int                             unicast; /* non-zero if unicast */
        const uint8_t *                 rec_buf; /* either udp_buf or encbuf */

        sss->stats.last_fwd=now;
        decode_REGISTER( &reg, &cmn, udp_buf, &rem, &idx );

        unicast = (0 == is_multi_broadcast(reg.dstMac) );

        if ( unicast )
        {
        traceEvent( TRACE_DEBUG, "Rx REGISTER %s -> %s %s",
                    macaddr_str( mac_buf, reg.srcMac ),
                    macaddr_str( mac_buf2, reg.dstMac ),
                    ((cmn.flags & N2N_FLAGS_FROM_SUPERNODE)?"from sn":"local") );

        if ( 0 != (cmn.flags & N2N_FLAGS_FROM_SUPERNODE) )
        {
            memcpy( &cmn2, &cmn, sizeof( n2n_common_t ) );

            /* We are going to add socket even if it was not there before */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            if (sender_sock->sa_family == AF_INET) {
                struct sockaddr_in* sock = (struct sockaddr_in*) sender_sock;
                reg.sock.family = AF_INET;
                reg.sock.port = ntohs(sock->sin_port);
                memcpy( reg.sock.addr.v4, &(sock->sin_addr), IPV4_SIZE );
            } else if (sender_sock->sa_family == AF_INET6) {
                struct sockaddr_in6* sock = (struct sockaddr_in6*) sender_sock;
                reg.sock.family = AF_INET6;
                reg.sock.port = ntohs(sock->sin6_port);
                memcpy( reg.sock.addr.v6, &(sock->sin6_addr), IPV6_SIZE );
            }

            rec_buf = encbuf;

            /* Re-encode the header. */
            encode_REGISTER( encbuf, &encx, &cmn2, &reg );

            /* Copy the original payload unchanged */
            encode_buf( encbuf, &encx, (udp_buf + idx), (udp_size - idx ) );
        }
        else
        {
            /* Already from a supernode. Nothing to modify, just pass to
             * destination. */

            rec_buf = udp_buf;
            encx = udp_size;
        }

        try_forward( sss, &cmn, reg.dstMac, rec_buf, encx ); /* unicast only */
        }
        else
        {
            traceEvent( TRACE_ERROR, "Rx REGISTER with multicast destination" );
        }

    }
    else if ( msg_type == MSG_TYPE_REGISTER_ACK )
    {
        traceEvent( TRACE_DEBUG, "Rx REGISTER_ACK (NOT IMPLEMENTED) Should not be via supernode" );
    }
    else if ( msg_type == MSG_TYPE_REGISTER_SUPER )
    {
        n2n_REGISTER_SUPER_t            reg;
        n2n_REGISTER_SUPER_ACK_t        ack;
        n2n_common_t                    cmn2;
        uint8_t                         ackbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;

        /* Edge requesting registration with us.  */

        sss->stats.last_reg_super=now;
        ++(sss->stats.reg_super);
        decode_REGISTER_SUPER( &reg, &cmn, udp_buf, &rem, &idx );

        cmn2.ttl = N2N_DEFAULT_TTL;
        cmn2.pc = n2n_register_super_ack;
        cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
        memcpy( cmn2.community, cmn.community, sizeof(n2n_community_t) );

        memcpy( &(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t) );
        memcpy( ack.edgeMac, reg.edgeMac, sizeof(n2n_mac_t) );
        ack.lifetime = reg_lifetime( sss );

        if (sender_sock->sa_family == AF_INET) {
            struct sockaddr_in* sock = (struct sockaddr_in*) sender_sock;
            ack.sock.family = AF_INET;
            ack.sock.port = ntohs(sock->sin_port);
            memcpy( ack.sock.addr.v4, &(sock->sin_addr), IPV4_SIZE );
        } else if (sender_sock->sa_family == AF_INET6) {
            struct sockaddr_in6* sock = (struct sockaddr_in6*) sender_sock;
            ack.sock.family = AF_INET6;
            ack.sock.port = ntohs(sock->sin6_port);
            memcpy( ack.sock.addr.v6, &(sock->sin6_addr), IPV6_SIZE );
        }

        ack.num_sn=0; /* No backup */
        memset( &(ack.sn_bak), 0, sizeof(n2n_sock_t) );

        traceEvent( TRACE_DEBUG, "Rx REGISTER_SUPER for %s %s",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ) );

        update_edge( sss, reg.edgeMac, cmn.community, &(ack.sock), now,
                     reg.version, reg.os_name, reg.request_ip, reg.requested_ip );

        strncpy(ack.version, n2n_sw_version, sizeof(ack.version) - 1);
        strncpy(ack.os_name, n2n_sw_osName, sizeof(ack.os_name) - 1);

        /* Set IP support capability flags */
        ack.sn_ipv4_support = (sss->ipv4_available ? 1 : 0);
        ack.sn_ipv6_support = (sss->ipv6_available ? 1 : 0);

        /* Collect community member information */
        if (reg.request_ip) {
            collect_community_peers(sss, cmn.community, &ack);

            /* Set assigned IP */
            struct peer_info *edge_peer = find_peer_by_mac(sss->edges, reg.edgeMac);
            if (edge_peer && edge_peer->assigned_ip) {
                ack.assigned_ip = htonl(edge_peer->assigned_ip);
            }
        }

        encode_REGISTER_SUPER_ACK( ackbuf, &encx, &cmn2, &ack );

		      /* Select the correct socket based on the address family */
		      volatile SOCKET send_sock = (sender_sock->sa_family == AF_INET6) ? sss->sock6 : sss->sock;
	      	volatile socklen_t sock_len = (sender_sock->sa_family == AF_INET6) ?
                           sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

	      	sendto( send_sock, ackbuf, encx, 0,
              	(struct sockaddr *)sender_sock, sock_len );

        traceEvent( TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s %s",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ) );

    }
    return 0;
}


/** Help message to print if the command line arguments are not valid. */
static void help(int argc, char * const argv[])
{
    print_n2n_version();
    printf("\n");

    printf("Usage: supernode -l <lport>\n");
    printf("\n");

    fprintf( stderr, "-l <lport>\tSet UDP main listen port to <lport>\n" );
    fprintf( stderr, "-4|-6     \tIP mode: -4 (IPv4 only), -6 (IPv6 only), both/none (dual-stack)\n" );
 #ifndef _WIN32
    fprintf( stderr, "-t <port>\tSet management UDP port to <port> (default 5646)\n" );
#endif
#if defined(N2N_HAVE_DAEMON)
    fprintf( stderr, "-f        \tRun in foreground.\n" );
#endif /* #if defined(N2N_HAVE_DAEMON) */
    fprintf( stderr, "-v        \tIncrease verbosity. Can be used multiple times.\n" );
    fprintf( stderr, "-h        \tThis help message.\n" );
    fprintf( stderr, "\n" );
}

static int run_loop( n2n_sn_t * sss );

/* *********************************************** */

static const struct option long_options[] = {
  { "foreground",      no_argument,       NULL, 'f' },
  { "local-port",      required_argument, NULL, 'l' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { "ipv4",            no_argument,       NULL, '4' },
  { "ipv6",            no_argument,       NULL, '6' },
  { NULL,              0,                 NULL,  0  }
};

/** Main program entry point from kernel. */
int main( int argc, char * const argv[] )
{
    int lport_specified = 0;

    n2n_sn_t sss;
    bool ipv4 = true, ipv6 = true;

#ifndef _WIN32
    /* stdout is connected to journald, so don't print data/time */
    if ( getenv( "JOURNAL_STREAM" ) )
        useSystemd = true;
#endif

#if _WIN32
    SetConsoleOutputCP(65001);

    if (scm_startup(L"supernode") == 1) {
        /* supernode is running as a service, so quit */
        return 0;
    }

    if ( !IsWindows7OrGreater() ) {
        traceEvent( TRACE_ERROR, "This Windows Version is not supported. Windows 7 or newer is required." );
        return 1;
    }
#endif

    init_sn( &sss );

    {
        int opt;

        while((opt = getopt_long(argc, argv, "ft:l:46vh", long_options, NULL)) != -1)
        {
            switch (opt)
            {
            case 'l': /* local-port */
                sss.lport = atoi(optarg);
																lport_specified = 1;
                break;
            case 't':
#ifndef _WIN32
						sss.mgmt_port = atoi(optarg);
						if (sss.mgmt_port == 0) {
								traceEvent(TRACE_ERROR, "Invalid management port: %s", optarg);
								exit(-1);
						}
#endif
                break;
            case 'f': /* foreground */
                sss.daemon = 0;
                break;
            case '4':
                ipv4 = true;
                break;
            case '6':
                ipv6 = true;
                break;
            case 'h': /* help */
                help(argc, argv);
                exit(0);
            case 'v': /* verbose */
                ++traceLevel;
                break;
            }
        }

    }

    if (!lport_specified) {
        traceEvent(TRACE_ERROR, "Error: Listen port is required (-l <port>)");
        help(argc, argv);
        exit(1);
    }

    traceEvent( TRACE_DEBUG, "traceLevel is %d", traceLevel);

    int ipv4_available = 0, ipv6_available = 0;

    if (ipv4) {
        sss.sock = open_socket(sss.lport, 1 /*bind ANY*/ );
        if (sss.sock != -1) {
            ipv4_available = 1;
        } else {
            traceEvent( TRACE_WARNING, "IPv4 socket failed, continuing without IPv4" );
            sss.sock = -1;
        }
    }

    if (ipv6) {
        sss.sock6 = open_socket6(sss.lport, 1 /*bind ANY*/ );
        if (sss.sock6 != -1) {
            ipv6_available = 1;
        } else {
            traceEvent( TRACE_WARNING, "IPv6 socket failed, continuing without IPv6" );
            sss.sock6 = -1;
        }
    }

    /* Verify actual connectivity */
    if (ipv4_available && test_ipv4_connectivity()) {
        traceEvent( TRACE_NORMAL, "IPv4 connectivity confirmed" );
    } else if (ipv4_available) {
        traceEvent( TRACE_WARNING, "IPv4 socket available but no external connectivity" );
        ipv4_available = 0;
    }

    if (ipv6_available && test_ipv6_connectivity()) {
        traceEvent( TRACE_NORMAL, "IPv6 connectivity confirmed" );
    } else if (ipv6_available) {
        traceEvent( TRACE_WARNING, "IPv6 socket available but no external connectivity" );
        ipv6_available = 0;
    }

    /* At least one socket must be available */
    if (!ipv4_available && !ipv6_available) {
        traceEvent( TRACE_ERROR, "No IP sockets available, exiting" );
        exit(-2);
    }

    /* Set the actual availability fields */
    sss.ipv4_available = ipv4_available;
    sss.ipv6_available = ipv6_available;

    /* Display actual running mode */
    if (ipv4_available && ipv6_available) {
        traceEvent( TRACE_NORMAL, "Supernode running in dual-stack mode (IPv4+IPv6)" );
    } else if (ipv4_available) {
        traceEvent( TRACE_NORMAL, "Supernode running in IPv4 only mode" );
    } else if (ipv6_available) {
        traceEvent( TRACE_NORMAL, "Supernode running in IPv6 only mode" );
    }

#ifndef _WIN32
        sss.mgmt_sock = open_socket(sss.mgmt_port, 0 /* bind LOOPBACK */ );
#endif // _WIN32
    if ( -1 == sss.mgmt_sock )
    {
#ifdef _WIN32
        W32_ERROR(WSAGetLastError(), error);
        traceEvent( TRACE_ERROR, "Failed to open management socket. %ls", error );
        W32_ERROR_FREE(error);
#else
        traceEvent( TRACE_ERROR, "Failed to open management socket. %s", strerror(errno) );
#endif
        exit(-2);
    }
#ifndef _WIN32
        traceEvent( TRACE_NORMAL, "supernode is listening on UDP %u (management)", sss.mgmt_port );
#endif // _WIN32
    traceEvent(TRACE_NORMAL, "supernode started");

#if defined(N2N_HAVE_DAEMON)
    if (sss.daemon)
    {
        useSyslog = true; /* traceEvent output now goes to syslog. */
        if ( -1 == daemon( 0, 0 ) )
        {
            traceEvent( TRACE_ERROR, "Failed to become daemon." );
            exit(-5);
        }
    }
#endif /* #if defined(N2N_HAVE_DAEMON) */

    return run_loop(&sss);
}

/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
static int run_loop( n2n_sn_t * sss )
{
    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE];
    int keep_running=1;
    fd_set socket_mask;
    struct timeval wait_time;
    int max_sock = 0;

    sss->start_time = time(NULL);

    while(keep_running)
    {
        int rc;
        ssize_t bread;
        time_t now=0;

        FD_ZERO(&socket_mask);
        max_sock = 0;

        if (sss->sock != -1) {
            FD_SET(sss->sock, &socket_mask);
            max_sock = max(max_sock, sss->sock);
        }

        if (sss->sock6 != -1) {
            FD_SET(sss->sock6, &socket_mask);
            max_sock = max(max_sock, sss->sock6);
        }

        FD_SET(sss->mgmt_sock, &socket_mask);
        max_sock = max(max_sock, sss->mgmt_sock);

        wait_time.tv_sec = 10; /* 10-second timeout */
        wait_time.tv_usec = 0;

        rc = select(max_sock+1, &socket_mask, NULL, NULL, &wait_time);

        now = time(NULL);

        if(rc > 0)
        {
            if (sss->sock != -1 && FD_ISSET(sss->sock, &socket_mask)) {
                struct sockaddr_storage udp_sender_sock;
                socklen_t udp_sender_len = sizeof(udp_sender_sock);

                bread = recvfrom(sss->sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0,
                               (struct sockaddr *)&udp_sender_sock, &udp_sender_len);

                if (bread > 0) {
                    process_udp( sss, (struct sockaddr*) &udp_sender_sock, udp_sender_len,
                                pktbuf, bread, now );
                }
            }

            if (sss->sock6 != -1 && FD_ISSET(sss->sock6, &socket_mask)) {
                struct sockaddr_storage udp6_sender_sock;
                socklen_t udp6_sender_len = sizeof(udp6_sender_sock);

                bread = recvfrom(sss->sock6, pktbuf, N2N_SN_PKTBUF_SIZE, 0,
                               (struct sockaddr *)&udp6_sender_sock, &udp6_sender_len);

                if (bread > 0) {
                    process_udp( sss, (struct sockaddr*) &udp6_sender_sock, udp6_sender_len,
                                pktbuf, bread, now );
                }
            }

            if (FD_ISSET(sss->mgmt_sock, &socket_mask)) {
                struct sockaddr_storage mgmt_sender_sock;
                socklen_t mgmt_sender_len = sizeof(mgmt_sender_sock);

                bread = recvfrom(sss->mgmt_sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0,
                               (struct sockaddr *)&mgmt_sender_sock, &mgmt_sender_len);

                if (bread > 0) {
                    if (process_mgmt(sss, (struct sockaddr*)&mgmt_sender_sock,
                                    mgmt_sender_len, pktbuf, bread, now) < 0) {
                        traceEvent(TRACE_ERROR, "process_mgmt failed");
                    }
                }
            }
        }
        else
        {
            traceEvent( TRACE_DEBUG, "timeout" );
        }

        purge_expired_registrations( &(sss->edges) );
    }

    deinit_sn( sss );
    return 0;
}
