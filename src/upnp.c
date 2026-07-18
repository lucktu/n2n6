/* upnp.c - Local NAT-PMP/PCP and UPnP IGD implementation for n2n
 *
 * Protocols supported (in priority order):
 *   1. PCP        RFC 6887 - modern NAT-PMP successor, port 5351
 *   2. NAT-PMP    RFC 6886 - simple UDP, port 5351
 *   3. UPnP IGD2  WANIPConnection:2 - newer routers
 *   4. UPnP IGD1  WANIPConnection:1 / WANPPPConnection:1 - fallback
 *
 * Features:
 *   - Auto port-conflict detection (GetSpecificPortMappingEntry)
 *   - Auto port retry on conflict (up to UPNP_PORT_RETRY_MAX attempts)
 *   - No external library dependencies
 *   - Supports Linux, macOS/BSD, Windows
 */

#include "upnp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <mswsock.h>
#  include <iphlpapi.h>
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "ws2_32.lib")
#  define close(s)               closesocket(s)
#  define strncasecmp(a,b,n)     _strnicmp(a,b,n)
/* Fallback if SIO_UDP_CONNRESET is not defined by the SDK */
#  ifndef SIO_UDP_CONNRESET
#    define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#  endif
typedef int ssize_t;
typedef int socklen_t;
#else
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/select.h>
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <netdb.h>
#endif

/* ------------------------------------------------------------------ */
/* Internal constants                                                   */
/* ------------------------------------------------------------------ */

#define NATPMP_PORT           5351
#define NATPMP_TIMEOUT_MS     100    /* initial timeout, doubles each retry */
#define NATPMP_RETRIES        2

#define PCP_PORT              5351   /* same port as NAT-PMP */
#define PCP_TIMEOUT_MS        100
#define PCP_RETRIES           2
#define PCP_NONCE_LEN         12

#define SSDP_ADDR             "239.255.255.250"
#define SSDP_PORT             1900
#define SSDP_TIMEOUT_MS       1000
#define UPNP_HTTP_TIMEOUT_SEC 5

#define UPNP_PORT_RETRY_MAX   10    /* max port candidates on conflict */

/* Renew when 80% of lease time has elapsed */
#define UPNP_RENEW_THRESHOLD  (UPNP_LEASE_TIME * 4 / 5)

/* ------------------------------------------------------------------ */
/* Utility: get default gateway IPv4 address                            */
/* ------------------------------------------------------------------ */

static int get_default_gateway(struct in_addr *gw_addr)
{
#ifdef _WIN32
    MIB_IPFORWARDROW route;
    memset(&route, 0, sizeof(route));
    if (GetBestRoute(0, 0, &route) != NO_ERROR)
        return -1;
    gw_addr->s_addr = route.dwForwardNextHop;
    return 0;

#elif defined(__linux__)
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;
    char line[256];
    /* skip header line */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    while (fgets(line, sizeof(line), f)) {
        char iface[16];
        unsigned long dest, gw;
        unsigned int flags;
        if (sscanf(line, "%15s %lx %lx %x", iface, &dest, &gw, &flags) == 4) {
            /* RTF_UP=0x1, RTF_GATEWAY=0x2 */
            if (dest == 0 && (flags & 0x3) == 0x3 && gw != 0) {
                gw_addr->s_addr = (uint32_t)gw;
                fclose(f);
                return 0;
            }
        }
    }
    fclose(f);
    return -1;

#else
    /* macOS / BSD: use sysctl to query the routing table for the default gateway.
     * Falls back to x.x.x.1 heuristic only if sysctl fails. */
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if_dl.h>
    {
        /* Use CTL_NET / PF_ROUTE / 0 / AF_INET / NET_RT_FLAGS / RTF_GATEWAY */
        int mib[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY };
        size_t needed = 0;
        if (sysctl(mib, 6, NULL, &needed, NULL, 0) == 0 && needed > 0) {
            char *buf = malloc(needed);
            if (buf && sysctl(mib, 6, buf, &needed, NULL, 0) == 0) {
                char *end = buf + needed;
                struct rt_msghdr *rtm;
                for (char *p = buf; p < end; p += rtm->rtm_msglen) {
                    rtm = (struct rt_msghdr*)p;
                    if (!(rtm->rtm_flags & RTF_GATEWAY)) continue;
                    struct sockaddr *sa = (struct sockaddr*)(rtm + 1);
                    /* First sockaddr is dst, second is gateway */
                    /* Skip dst sockaddr (aligned) */
                    size_t sa_len = sa->sa_len ? ((sa->sa_len + sizeof(long)-1) & ~(sizeof(long)-1)) : sizeof(long);
                    sa = (struct sockaddr*)((char*)sa + sa_len);
                    if (sa->sa_family == AF_INET) {
                        gw_addr->s_addr = ((struct sockaddr_in*)sa)->sin_addr.s_addr;
                        free(buf);
                        return 0;
                    }
                }
            }
            free(buf);
        }
    }
    /* Fallback: connect trick + x.x.x.1 heuristic */
    {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) return -1;
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
        dst.sin_port = htons(53);
        if (connect(s, (struct sockaddr*)&dst, sizeof(dst)) != 0) {
            close(s); return -1;
        }
        struct sockaddr_in me;
        socklen_t melen = sizeof(me);
        if (getsockname(s, (struct sockaddr*)&me, &melen) != 0) {
            close(s); return -1;
        }
        close(s);
        uint32_t local = ntohl(me.sin_addr.s_addr);
        gw_addr->s_addr = htonl((local & 0xFFFFFF00) | 1);
        return 0;
    }
#endif
}

/* ------------------------------------------------------------------ */
/* Utility: get local outbound IPv4 address                             */
/* ------------------------------------------------------------------ */

static void get_local_ip(char *buf, size_t buflen)
{
    strncpy(buf, "0.0.0.0", buflen - 1);
    buf[buflen - 1] = '\0';

    int s = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
    dst.sin_port = htons(53);

    if (connect(s, (struct sockaddr*)&dst, sizeof(dst)) == 0) {
        struct sockaddr_in me;
        socklen_t melen = sizeof(me);
        if (getsockname(s, (struct sockaddr*)&me, &melen) == 0)
            inet_ntop(AF_INET, &me.sin_addr, buf, (socklen_t)buflen);
    }
    close(s);
}

/* ------------------------------------------------------------------ */
/* NAT-PMP (RFC 6886)                                                   */
/* ------------------------------------------------------------------ */

#pragma pack(push,1)
typedef struct {
    uint8_t  version;       /* must be 0 */
    uint8_t  opcode;        /* 1 = UDP map request */
    uint16_t reserved;
    uint16_t internal_port;
    uint16_t external_port; /* 0 = let gateway choose */
    uint32_t lifetime;      /* seconds; 0 = delete */
} natpmp_map_req_t;

typedef struct {
    uint8_t  version;
    uint8_t  opcode;        /* 129 = UDP map response */
    uint16_t result_code;   /* 0 = success */
    uint32_t epoch;
    uint16_t internal_port;
    uint16_t external_port;
    uint32_t lifetime;
} natpmp_map_resp_t;
#pragma pack(pop)

/* del=0: add mapping; del=1: remove mapping (lifetime=0) */
static int natpmp_map(uint16_t internal_port, uint16_t external_port,
                      uint16_t *mapped_port, int del)
{
    struct in_addr gw;
    if (get_default_gateway(&gw) != 0)
        return UPNP_ERR_NOTFOUND;

    int sock = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return UPNP_ERR_SOCKET;

#ifdef _WIN32
    {
        /* Prevent WSAECONNRESET error spam when ICMP port-unreachable
         * arrives on this UDP socket. */
        DWORD bytesReturned = 0;
        BOOL newBehavior = FALSE;
        WSAIoctl(sock, SIO_UDP_CONNRESET, &newBehavior, sizeof(newBehavior),
                 NULL, 0, &bytesReturned, NULL, NULL);
    }
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family  = AF_INET;
    addr.sin_addr    = gw;
    addr.sin_port    = htons(NATPMP_PORT);

    natpmp_map_req_t req;
    memset(&req, 0, sizeof(req));
    req.version       = 0;
    req.opcode        = 1; /* UDP */
    req.internal_port = htons(internal_port);
    req.external_port = del ? 0 : htons(external_port);
    req.lifetime      = del ? 0 : htonl(UPNP_LEASE_TIME);

    int timeout_ms = NATPMP_TIMEOUT_MS;
    int ret = UPNP_ERR_TIMEOUT;

    for (int i = 0; i < NATPMP_RETRIES; i++) {
        sendto(sock, (const char*)&req, sizeof(req), 0,
               (struct sockaddr*)&addr, sizeof(addr));

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET((unsigned)sock, &fds);
        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
            natpmp_map_resp_t resp;
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(sock, (char*)&resp, sizeof(resp), 0,
                                 (struct sockaddr*)&from, &fromlen);
            if (n >= (ssize_t)sizeof(resp)          &&
                from.sin_addr.s_addr == gw.s_addr   &&
                resp.version == 0                   &&
                resp.opcode  == 129                 &&
                ntohs(resp.result_code) == 0) {
                if (mapped_port)
                    *mapped_port = ntohs(resp.external_port);
                ret = UPNP_OK;
                break;
            }
        }
        timeout_ms *= 2;
    }

    close(sock);
    return ret;
}

/* ------------------------------------------------------------------ */
/* PCP (RFC 6887) - Port Control Protocol                               */
/* ------------------------------------------------------------------ */

#pragma pack(push,1)
typedef struct {
    uint8_t  version;           /* 2 */
    uint8_t  opcode;            /* 1 = MAP */
    uint16_t reserved;
    uint32_t lifetime;
    uint8_t  client_ip[16];     /* IPv4-mapped: ::ffff:a.b.c.d */
} pcp_req_hdr_t;

typedef struct {
    uint8_t  protocol;          /* 17 = UDP */
    uint8_t  reserved[3];
    uint8_t  nonce[PCP_NONCE_LEN];
    uint16_t internal_port;
    uint16_t external_port;     /* 0 = let gateway choose */
    uint8_t  ext_ip[16];        /* suggested external IP, zeros = any */
} pcp_map_req_t;

typedef struct {
    uint8_t  version;
    uint8_t  opcode;            /* 0x81 = MAP response */
    uint8_t  reserved;
    uint8_t  result_code;       /* 0 = SUCCESS */
    uint32_t lifetime;
    uint32_t epoch;
    uint8_t  reserved2[12];
} pcp_resp_hdr_t;

typedef struct {
    uint8_t  protocol;
    uint8_t  reserved[3];
    uint8_t  nonce[PCP_NONCE_LEN];
    uint16_t internal_port;
    uint16_t external_port;
    uint8_t  ext_ip[16];
} pcp_map_resp_t;
#pragma pack(pop)

static int pcp_map(uint16_t internal_port, uint16_t external_port,
                   uint16_t *mapped_port, int del)
{
    struct in_addr gw;
    if (get_default_gateway(&gw) != 0)
        return UPNP_ERR_NOTFOUND;

    int sock = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return UPNP_ERR_SOCKET;

#ifdef _WIN32
    {
        DWORD bytesReturned = 0;
        BOOL newBehavior = FALSE;
        WSAIoctl(sock, SIO_UDP_CONNRESET, &newBehavior, sizeof(newBehavior),
                 NULL, 0, &bytesReturned, NULL, NULL);
    }
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr   = gw;
    addr.sin_port   = htons(PCP_PORT);

    /* Build PCP MAP request */
    pcp_req_hdr_t hdr;
    pcp_map_req_t map;
    memset(&hdr, 0, sizeof(hdr));
    memset(&map, 0, sizeof(map));

    hdr.version  = 2;
    hdr.opcode   = 1; /* MAP */
    hdr.lifetime = del ? 0 : htonl(UPNP_LEASE_TIME);

    /* Fill client IP as IPv4-mapped IPv6: ::ffff:local_ip */
    char local_ip_str[INET_ADDRSTRLEN] = "0.0.0.0";
    get_local_ip(local_ip_str, sizeof(local_ip_str));
    struct in_addr local_in;
    inet_pton(AF_INET, local_ip_str, &local_in);
    hdr.client_ip[10] = 0xff;
    hdr.client_ip[11] = 0xff;
    memcpy(&hdr.client_ip[12], &local_in.s_addr, 4);

    map.protocol      = 17; /* UDP */
    map.internal_port = htons(internal_port);
    map.external_port = del ? 0 : htons(external_port);
    /* Generate simple nonce from local port + time */
    {
        uint32_t t = (uint32_t)time(NULL);
        memcpy(map.nonce,      &t,             4);
        memcpy(map.nonce + 4,  &internal_port, 2);
        memcpy(map.nonce + 6,  &external_port, 2);
        map.nonce[8]  = 0xA2;
        map.nonce[9]  = 0x3B;
        map.nonce[10] = (uint8_t)(t >> 8);
        map.nonce[11] = (uint8_t)(t >> 16);
    }

    /* Concatenate header + map opcode-specific data */
    uint8_t pkt[sizeof(hdr) + sizeof(map)];
    memcpy(pkt,             &hdr, sizeof(hdr));
    memcpy(pkt + sizeof(hdr), &map, sizeof(map));

    int timeout_ms = PCP_TIMEOUT_MS;
    int ret = UPNP_ERR_TIMEOUT;

    for (int i = 0; i < PCP_RETRIES; i++) {
        sendto(sock, (const char*)pkt, sizeof(pkt), 0,
               (struct sockaddr*)&addr, sizeof(addr));

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET((unsigned)sock, &fds);
        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
            uint8_t rbuf[sizeof(pcp_resp_hdr_t) + sizeof(pcp_map_resp_t)];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(sock, (char*)rbuf, sizeof(rbuf), 0,
                                 (struct sockaddr*)&from, &fromlen);
            if (n >= (ssize_t)(sizeof(pcp_resp_hdr_t) + sizeof(pcp_map_resp_t))) {
                pcp_resp_hdr_t *rh = (pcp_resp_hdr_t*)rbuf;
                pcp_map_resp_t *rm = (pcp_map_resp_t*)(rbuf + sizeof(pcp_resp_hdr_t));
                if (from.sin_addr.s_addr == gw.s_addr &&
                    rh->version == 2 &&
                    rh->opcode  == 0x81 &&
                    rh->result_code == 0 &&
                    memcmp(rm->nonce, map.nonce, PCP_NONCE_LEN) == 0) {
                    if (mapped_port)
                        *mapped_port = ntohs(rm->external_port);
                    ret = UPNP_OK;
                    break;
                }
            }
        }
        timeout_ms *= 2;
    }

    close(sock);
    return ret;
}

/* SSDP searches: try IGD2 first, fallback to IGD1 */
static const char SSDP_SEARCH_IGD2[] =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 1\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n"
    "\r\n";

static const char SSDP_SEARCH_IGD1[] =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 1\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n";

/* Extract HTTP header value (case-insensitive). Returns 0 on success. */
static int extract_header(const char *buf, const char *header,
                           char *out, size_t out_len)
{
    size_t hlen = strlen(header);
    const char *p = buf;
    while (*p) {
        if (strncasecmp(p, header, hlen) == 0) {
            p += hlen;
            while (*p == ' ' || *p == '\t') p++;
            const char *end = p;
            while (*end && *end != '\r' && *end != '\n') end++;
            size_t len = (size_t)(end - p);
            if (len >= out_len) len = out_len - 1;
            memcpy(out, p, len);
            out[len] = '\0';
            return 0;
        }
        while (*p && *p != '\n') p++;
        if (*p) p++;
    }
    return -1;
}

/* Parse http://host[:port]/path. Returns 0 on success. */
static int parse_url(const char *url, char *host, size_t host_len,
                     uint16_t *port, char *path, size_t path_len)
{
    const char *p = url;
    if (strncasecmp(p, "http://", 7) == 0) p += 7;

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    size_t hlen;
    if (colon && (!slash || colon < slash)) {
        hlen = (size_t)(colon - p);
        *port = (uint16_t)atoi(colon + 1);
    } else {
        hlen = slash ? (size_t)(slash - p) : strlen(p);
        *port = 80;
    }
    if (hlen == 0 || hlen >= host_len) return -1; /* malformed */
    memcpy(host, p, hlen);
    host[hlen] = '\0';

    if (slash) {
        strncpy(path, slash, path_len - 1);
        path[path_len - 1] = '\0';
    } else {
        strncpy(path, "/", path_len - 1);
    }
    return 0;
}

/* Blocking TCP request with connect timeout. Returns bytes received (>=0) or negative error. */
static int tcp_request(const char *host, uint16_t port,
                       const char *request, size_t req_len,
                       char *response, size_t resp_max)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return UPNP_ERR_NOTFOUND;

    int sock = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return UPNP_ERR_SOCKET; }

    /* Non-blocking connect with select() timeout so we don't hang on
     * unreachable gateways (e.g. after WiFi switch). */
#ifdef _WIN32
    {
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
    }
#else
    {
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    int conn_ret = connect(sock, res->ai_addr, (socklen_t)res->ai_addrlen);
    if (conn_ret != 0) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
        if (errno != EINPROGRESS)
#endif
        {
            freeaddrinfo(res); close(sock);
            return UPNP_ERR_TIMEOUT;
        }
        /* Wait for connect to complete within timeout */
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET((unsigned)sock, &wfds);
        struct timeval tv;
        tv.tv_sec  = UPNP_HTTP_TIMEOUT_SEC;
        tv.tv_usec = 0;
        if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
            freeaddrinfo(res); close(sock);
            return UPNP_ERR_TIMEOUT;
        }
        /* Verify connect succeeded (no pending error) */
        {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR,
#ifdef _WIN32
                       (char*)&so_error,
#else
                       &so_error,
#endif
                       &len);
            if (so_error != 0) {
                freeaddrinfo(res); close(sock);
                return UPNP_ERR_TIMEOUT;
            }
        }
    }
    freeaddrinfo(res);

    /* Restore blocking mode */
#ifdef _WIN32
    {
        u_long mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
    }
#else
    {
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags >= 0) fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    }
#endif

    /* Set timeouts for recv/send */
#ifdef _WIN32
    {
        DWORD toms = UPNP_HTTP_TIMEOUT_SEC * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&toms, sizeof(toms));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&toms, sizeof(toms));
    }
#else
    {
        struct timeval tv = { UPNP_HTTP_TIMEOUT_SEC, 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
#endif

    /* Send full request */
    size_t sent = 0;
    while (sent < req_len) {
        ssize_t n = send(sock, (const char*)request + sent,
                         (int)(req_len - sent), 0);
        if (n < 0) { close(sock); return UPNP_ERR_SOCKET; }
        if (n == 0) break; /* connection closed by peer */
        sent += (size_t)n;
    }

    /* Receive response */
    size_t total = 0;
    while (total < resp_max - 1) {
        ssize_t n = recv(sock, response + total,
                         (int)(resp_max - 1 - total), 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    response[total] = '\0';
    close(sock);
    return (int)total;
}

/* Fetch device description XML and extract the IGD control URL.
 * Returns 0 on success. */
static int upnp_get_control_url(const char *desc_url,
                                char *ctrl_host, size_t ctrl_host_len,
                                uint16_t *ctrl_port,
                                char *ctrl_path, size_t ctrl_path_len)
{
    char host[128], path[256];
    uint16_t port;
    if (parse_url(desc_url, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return UPNP_ERR_NOTFOUND;

    char req[512];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.0\r\nHost: %s:%u\r\nConnection: close\r\n\r\n",
             path, host, (unsigned)port);

    /* 16 KB is enough for any reasonable device description */
    char *resp = (char*)malloc(16384);
    if (!resp) return UPNP_ERR_NOTFOUND;

    int n = tcp_request(host, port, req, strlen(req), resp, 16384);
    if (n <= 0) { free(resp); return UPNP_ERR_NOTFOUND; }

    /* Search for WANIPConnection or WANPPPConnection controlURL.
     * Check v2 service types first (IGD2), then v1 (IGD1). */
    const char *svc_names[] = {
        "WANIPConnection:2", "WANPPPConnection:2",
        "WANIPConnection",   "WANPPPConnection",
        NULL
    };
    char found_ctrl[256] = {0};

    for (int i = 0; svc_names[i]; i++) {
        char *svc = strstr(resp, svc_names[i]);
        if (!svc) continue;
        char *ctrl = strstr(svc, "<controlURL>");
        if (!ctrl) continue;
        ctrl += strlen("<controlURL>");
        char *end = strstr(ctrl, "</controlURL>");
        if (!end) continue;
        size_t len = (size_t)(end - ctrl);
        if (len >= sizeof(found_ctrl)) len = sizeof(found_ctrl) - 1;
        memcpy(found_ctrl, ctrl, len);
        found_ctrl[len] = '\0';
        break;
    }
    free(resp);

    if (found_ctrl[0] == '\0') return UPNP_ERR_NOTFOUND;

    /* controlURL may be relative or absolute */
    char full_url[512];
    if (strncasecmp(found_ctrl, "http://", 7) == 0) {
        strncpy(full_url, found_ctrl, sizeof(full_url) - 1);
        full_url[sizeof(full_url) - 1] = '\0';
    } else {
        snprintf(full_url, sizeof(full_url), "http://%s:%u%s%s",
                 host, (unsigned)port,
                 found_ctrl[0] == '/' ? "" : "/",
                 found_ctrl);
    }

    return parse_url(full_url, ctrl_host, ctrl_host_len,
                     ctrl_port, ctrl_path, ctrl_path_len);
}

/* Send a UPnP SOAP action. Returns UPNP_OK on HTTP 200. */
static int upnp_soap_action(const char *ctrl_host, uint16_t ctrl_port,
                            const char *ctrl_path,
                            const char *service_type,
                            const char *action,
                            const char *body_args)
{
    /* SOAP envelope: ~300 bytes fixed + body_args */
    char soap_body[2048];
    int soap_len = snprintf(soap_body, sizeof(soap_body),
             "<?xml version=\"1.0\"?>"
             "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""
             " s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
             "<s:Body><u:%s xmlns:u=\"%s\">%s</u:%s></s:Body>"
             "</s:Envelope>",
             action, service_type, body_args, action);
    if (soap_len < 0 || soap_len >= (int)sizeof(soap_body))
        return UPNP_ERR_RESPONSE; /* body too large */

    char soapaction[256];
    snprintf(soapaction, sizeof(soapaction), "\"%s#%s\"", service_type, action);

    /* HTTP headers + body: headers ~200 bytes, body up to 2048 */
    char req[4096];
    int req_len = snprintf(req, sizeof(req),
             "POST %s HTTP/1.0\r\n"
             "Host: %s:%u\r\n"
             "Content-Type: text/xml; charset=\"utf-8\"\r\n"
             "SOAPAction: %s\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             ctrl_path, ctrl_host, (unsigned)ctrl_port,
             soapaction, soap_len, soap_body);
    if (req_len < 0 || req_len >= (int)sizeof(req))
        return UPNP_ERR_RESPONSE; /* request too large */

    char resp[2048];
    int n = tcp_request(ctrl_host, ctrl_port, req, (size_t)req_len,
                        resp, sizeof(resp));
    if (n <= 0) return UPNP_ERR_TIMEOUT;

    /* Verify HTTP 200 OK */
    if (strncmp(resp, "HTTP/1.", 7) != 0) return UPNP_ERR_RESPONSE;
    int code = atoi(resp + 9); /* skip "HTTP/1.x " */
    return (code == 200) ? UPNP_OK : UPNP_ERR_RESPONSE;
}

/* ------------------------------------------------------------------ */
/* UPnP IGD - discovery cache and map/unmap                             */
/* ------------------------------------------------------------------ */

/* Cached IGD control endpoint from last successful SSDP discovery.
 * Reset to empty string to force re-discovery. */
static char     s_ctrl_host[128] = {0};
static uint16_t s_ctrl_port      = 0;
static char     s_ctrl_path[256] = {0};

static int upnp_discover(void)
{
    if (s_ctrl_host[0] != '\0') return UPNP_OK; /* use cached result */

    int sock = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return UPNP_ERR_SOCKET;

    /* Bind SSDP socket to the local IP of the default route interface and
     * set IP_MULTICAST_IF so multicast M-SEARCH packets go out via the
     * physical NIC. Without this, Windows may route multicast to the TAP
     * virtual interface and SSDP discovery fails (~50% success rate). */
    {
        char local_ip[INET_ADDRSTRLEN] = "0.0.0.0";
        get_local_ip(local_ip, sizeof(local_ip));
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port   = 0;
        inet_pton(AF_INET, local_ip, &local_addr.sin_addr);
        bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr));
        setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF,
                   (const char*)&local_addr.sin_addr,
                   sizeof(local_addr.sin_addr));
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char*)&yes, sizeof(yes));

#ifdef _WIN32
    {
        DWORD bytesReturned = 0;
        BOOL newBehavior = FALSE;
        WSAIoctl(sock, SIO_UDP_CONNRESET, &newBehavior, sizeof(newBehavior),
                 NULL, 0, &bytesReturned, NULL, NULL);
    }
#endif

    /* Disable multicast loopback so we don't receive our own M-SEARCH
     * packets. On Windows this can waste select() cycles and cause
     * discovery to miss router responses. */
    {
        uint8_t loop = 0;
        setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   (const char*)&loop, sizeof(loop));
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, SSDP_ADDR, &dest.sin_addr);
    dest.sin_port = htons(SSDP_PORT);

    /* Send IGD2 search first, then IGD1 - routers respond to whichever they support */
    sendto(sock, SSDP_SEARCH_IGD2, strlen(SSDP_SEARCH_IGD2), 0,
           (struct sockaddr*)&dest, sizeof(dest));
    sendto(sock, SSDP_SEARCH_IGD1, strlen(SSDP_SEARCH_IGD1), 0,
           (struct sockaddr*)&dest, sizeof(dest));

    char buf[2048];
    char location[512] = {0};
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET((unsigned)sock, &fds);
    tv.tv_sec  = SSDP_TIMEOUT_MS / 1000;
    tv.tv_usec = (SSDP_TIMEOUT_MS % 1000) * 1000;

    while (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        if (extract_header(buf, "LOCATION:", location, sizeof(location)) == 0)
            break;
        FD_ZERO(&fds);
        FD_SET((unsigned)sock, &fds);
        tv.tv_sec  = 0;
        tv.tv_usec = 200000;
    }
    close(sock);

    if (location[0] == '\0') return UPNP_ERR_NOTFOUND;

    return upnp_get_control_url(location,
                                s_ctrl_host, sizeof(s_ctrl_host),
                                &s_ctrl_port,
                                s_ctrl_path, sizeof(s_ctrl_path));
}

/* Check if an external port is already mapped by someone else.
 * Returns UPNP_OK if port is FREE or already mapped to this host,
 * UPNP_ERR_RESPONSE if occupied by another host, other on error. */
static int upnp_igd_check_port(uint16_t external_port, const char *svc_type)
{
    char args[256];
    snprintf(args, sizeof(args),
             "<NewRemoteHost></NewRemoteHost>"
             "<NewExternalPort>%u</NewExternalPort>"
             "<NewProtocol>UDP</NewProtocol>",
             (unsigned)external_port);

    /* GetSpecificPortMappingEntry returns 200 if mapping exists, fault if not */
    char soap_body[2048];
    int soap_len = snprintf(soap_body, sizeof(soap_body),
             "<?xml version=\"1.0\"?>"
             "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""
             " s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
             "<s:Body><u:GetSpecificPortMappingEntry xmlns:u=\"%s\">%s"
             "</u:GetSpecificPortMappingEntry></s:Body></s:Envelope>",
             svc_type, args);
    if (soap_len <= 0 || soap_len >= (int)sizeof(soap_body))
        return UPNP_ERR_RESPONSE;

    char soapaction[256];
    snprintf(soapaction, sizeof(soapaction),
             "\"%s#GetSpecificPortMappingEntry\"", svc_type);

    char req[4096];
    int req_len = snprintf(req, sizeof(req),
             "POST %s HTTP/1.0\r\n"
             "Host: %s:%u\r\n"
             "Content-Type: text/xml; charset=\"utf-8\"\r\n"
             "SOAPAction: %s\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n\r\n%s",
             s_ctrl_path, s_ctrl_host, (unsigned)s_ctrl_port,
             soapaction, soap_len, soap_body);
    if (req_len <= 0 || req_len >= (int)sizeof(req))
        return UPNP_ERR_RESPONSE;

    char resp[2048];
    int n = tcp_request(s_ctrl_host, s_ctrl_port, req, (size_t)req_len,
                        resp, sizeof(resp));
    if (n <= 0) return UPNP_ERR_TIMEOUT;

    if (strncmp(resp, "HTTP/1.", 7) != 0) return UPNP_ERR_RESPONSE;
    int code = atoi(resp + 9);

    if (code != 200)
        return UPNP_OK; /* 500/fault = no such entry = port is free */

    /* Port is mapped: check if it's mapped to this host - if so, treat as free
     * (we can overwrite our own mapping without conflict). */
    char local_ip[INET_ADDRSTRLEN] = "0.0.0.0";
    get_local_ip(local_ip, sizeof(local_ip));

    /* Extract NewInternalClient from response body */
    const char *tag = "NewInternalClient>";
    const char *p = strstr(resp, tag);
    if (p) {
        p += strlen(tag);
        const char *end = strchr(p, '<');
        if (end) {
            char mapped_ip[INET_ADDRSTRLEN] = {0};
            size_t len = (size_t)(end - p);
            if (len >= sizeof(mapped_ip)) len = sizeof(mapped_ip) - 1;
            memcpy(mapped_ip, p, len);
            mapped_ip[len] = '\0';
            if (strcmp(mapped_ip, local_ip) == 0)
                return UPNP_OK; /* already mapped to us - reuse */
        }
    }

    return UPNP_ERR_RESPONSE; /* occupied by another host */
}

/* del=0: AddPortMapping with conflict detection; del=1: DeletePortMapping */
static int upnp_igd_map(uint16_t internal_port, uint16_t external_port,
                        uint16_t *mapped_port, int del)
{
    if (upnp_discover() != UPNP_OK) return UPNP_ERR_NOTFOUND;

    /* Get local IP only when adding a mapping */
    char local_ip[INET_ADDRSTRLEN] = "0.0.0.0";
    if (!del) get_local_ip(local_ip, sizeof(local_ip));

    /* Try WANIPConnection v2 first (IGD2), then v1, then WANPPPConnection */
    const char *svc_types[] = {
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        NULL
    };

    int ret = UPNP_ERR_RESPONSE;
    int max_svcs = del ? 1 : 3; /* deleting: only need 1 attempt */
    for (int i = 0; svc_types[i] && i < max_svcs; i++) {
        if (del) {
            char args[256];
            snprintf(args, sizeof(args),
                     "<NewRemoteHost></NewRemoteHost>"
                     "<NewExternalPort>%u</NewExternalPort>"
                     "<NewProtocol>UDP</NewProtocol>",
                     (unsigned)external_port);
            ret = upnp_soap_action(s_ctrl_host, s_ctrl_port, s_ctrl_path,
                                   svc_types[i], "DeletePortMapping", args);
        } else {
            /* Check if requested port is already occupied; if so, try next ports.
             * Reset try_port for each service type attempt. */
            uint16_t try_port = external_port;
            int found_free = 0;
            for (int attempt = 0; attempt < UPNP_PORT_RETRY_MAX; attempt++) {
                if (upnp_igd_check_port(try_port, svc_types[i]) == UPNP_OK) {
                    found_free = 1;
                    break;
                }
                try_port = (try_port < 65535) ? try_port + 1 : 1024;
            }
            if (!found_free) { ret = UPNP_ERR_RESPONSE; continue; }

            char args[512];
            snprintf(args, sizeof(args),
                     "<NewRemoteHost></NewRemoteHost>"
                     "<NewExternalPort>%u</NewExternalPort>"
                     "<NewProtocol>UDP</NewProtocol>"
                     "<NewInternalPort>%u</NewInternalPort>"
                     "<NewInternalClient>%s</NewInternalClient>"
                     "<NewEnabled>1</NewEnabled>"
                     "<NewPortMappingDescription>n2n-edge</NewPortMappingDescription>"
                     "<NewLeaseDuration>%u</NewLeaseDuration>",
                     (unsigned)try_port, (unsigned)internal_port,
                     local_ip, (unsigned)UPNP_LEASE_TIME);
            ret = upnp_soap_action(s_ctrl_host, s_ctrl_port, s_ctrl_path,
                                   svc_types[i], "AddPortMapping", args);
            if (ret == UPNP_OK && mapped_port)
                *mapped_port = try_port;
        }
        if (ret == UPNP_OK) break;
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int upnp_map_port(uint16_t internal_port, uint16_t external_port,
                  uint16_t *mapped_port)
{
    uint16_t ext = external_port ? external_port : internal_port;

    /* Priority: UPnP IGD (most common) > PCP > NAT-PMP */
    if (mapped_port) *mapped_port = ext;
    if (upnp_igd_map(internal_port, ext, mapped_port, 0) == UPNP_OK)
        return UPNP_OK;

    if (pcp_map(internal_port, ext, mapped_port, 0) == UPNP_OK)
        return UPNP_OK;

    if (natpmp_map(internal_port, ext, mapped_port, 0) == UPNP_OK)
        return UPNP_OK;

    return UPNP_ERR_NOTFOUND;
}

void upnp_unmap_port(uint16_t external_port)
{
    upnp_igd_map(external_port, external_port, NULL, 1);
    pcp_map(external_port, external_port, NULL, 1);
    natpmp_map(external_port, external_port, NULL, 1);
}

int upnp_renew_port(uint16_t internal_port, uint16_t external_port)
{
    /* Re-map with same ports to refresh the lease */
    uint16_t mapped = 0;
    return upnp_map_port(internal_port, external_port, &mapped);
}
