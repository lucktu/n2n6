/**
 * (C) 2026-27 - lucktu <lucktu.com>
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
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 * Code contributions courtesy of:
 * lucktu <lucktu@msn.com>
 *
 * See bypass.h for design overview.
 */

#include "n2n.h"
#include "bypass.h"

#if defined(__linux__) || defined(_WIN32)

#if defined(__linux__)

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>  /* SO_ORIGINAL_DST */
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* Platform-neutral socket error (Linux: just errno) */
#define BYPASS_ERRNO()          errno
#define BYPASS_EAGAIN           EAGAIN
#define BYPASS_EWOULDBLOCK      EWOULDBLOCK
#define BYPASS_STRERR(e)        strerror(e)

#elif defined(_WIN32)

#include "win32/windivert.h"
#include <errno.h>

/* Platform-neutral socket error */
#define BYPASS_ERRNO()          WSAGetLastError()
#define BYPASS_EAGAIN           WSAEWOULDBLOCK
#define BYPASS_EWOULDBLOCK      WSAEWOULDBLOCK
#define BYPASS_STRERR(e)        "WSA err"

/* Windows compatibility: POSIX shutdown constants */
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif
#ifndef SHUT_WR
#define SHUT_WR SD_SEND
#endif

/* MSG_DONTWAIT is Linux-specific. On Windows, non-blocking is set
 * via ioctlsocket(FIONBIO), so use 0 (no extra flags needed). */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

#endif /* OS-specific includes */

/* External function from edge.c */
extern ssize_t sendto_sock(SOCKET fd, const void *buf, size_t len, const n2n_sock_t *dest);

/* Zero MAC for bypass_encode/bypass_decode (no real MAC needed) */
static const uint8_t bypass_zero_mac[6] = {0, 0, 0, 0, 0, 0};

/* Forward declarations */
static void bypass_build_header(uint8_t *buf, uint8_t algo_idx,
                                 uint8_t flags, uint32_t conn_id);
static int bypass_sendto_nb(bypass_context_t *ctx, const uint8_t *buf, size_t len,
                             const n2n_sock_t *dst);
static bypass_peer_entry_t *bypass_alloc_peer(bypass_context_t *ctx);
struct peer_info *bypass_find_peer_info(struct n2n_edge *eee, uint32_t virt_ip_host);
static void bypass_conn_update_peer_last_seen(bypass_context_t *ctx, struct bypass_conn *c);
static void bypass_update_peer_last_seen(struct n2n_edge *eee, uint32_t virt_ip_host);

/* ===== KCP reliable transport ===== */

/** KCP output callback: encrypt a KCP segment and send via non-blocking UDP.
 *  Called by ikcp_flush() when KCP has data/acks to transmit.
 *  Returns len on success (KCP ignores the return value; RTO handles losses). */
static int bypass_kcp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
    struct bypass_conn *c = (struct bypass_conn *)user;
    bypass_context_t *ctx = (bypass_context_t *)c->user_data;
    bypass_build_header(c->pkt_buf, ctx->tx_transop_idx, BYPASS_FLAG_KCP, c->conn_id);
    size_t pkt_off = BYPASS_HEADER_SIZE;
    ssize_t elen = bypass_encode(ctx, c->pkt_buf + pkt_off,
                                  BYPASS_PKT_BUF_SIZE - pkt_off,
                                  (const uint8_t *)buf, (size_t)len, bypass_zero_mac);
    if (elen <= 0) return len;
    bypass_sendto_nb(ctx, c->pkt_buf, pkt_off + (size_t)elen, &c->peer_addr);
    return len;
}

/** Monotonic milliseconds for KCP timing (cross-platform). */
static IUINT64 bypass_monotonic_ms(void)
{
#ifdef _WIN32
    static ULONGLONG first = 0;
    ULONGLONG now = GetTickCount64();
    if (first == 0) first = now;
    return now - first;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (IUINT64)ts.tv_sec * 1000 + (IUINT64)ts.tv_nsec / 1000000;
#endif
}

/** KCP clock: milliseconds since connection start. */
static IUINT32 bypass_kcp_time(struct bypass_conn *c)
{
    IUINT64 now_ms = bypass_monotonic_ms();
    return (IUINT32)(now_ms - c->kcp_base);
}

/** Drain received KCP data to local socket.
 *  Reads all available segments from KCP receive buffer and writes them
 *  to the local TCP socket (or tx_buf if socket is congested).
 *  When tx_buf is full, stop draining — data stays in KCP's receive
 *  buffer. This naturally closes rcv_wnd, providing backpressure.
 *  Returns 1 if any data was drained, 0 otherwise. */
static int bypass_kcp_drain(bypass_context_t *ctx, struct bypass_conn *c)
{
    int drained = 0;
    while (c->tx_buf_len < BYPASS_TX_BUF_SIZE) {
        int peek = ikcp_peeksize(c->kcp);
        if (peek <= 0)
            break;
        int ret = ikcp_recv(c->kcp, (char *)c->agg_buf, (int)BYPASS_MAX_PAYLOAD);
        if (ret <= 0)
            break;
        drained = 1;

        ssize_t sent = send(c->local_sock, (const char *)c->agg_buf,
                            (size_t)ret, MSG_DONTWAIT);
        if (sent > 0) {
            c->rx_bytes += (size_t)sent;
            ctx->bp_rx_bytes += (size_t)sent;
            if ((size_t)sent < (size_t)ret) {
                size_t rem = (size_t)ret - (size_t)sent;
                if (c->tx_buf_len + rem <= BYPASS_TX_BUF_SIZE) {
                    memcpy(c->tx_buf + c->tx_buf_len, c->agg_buf + sent, rem);
                    c->tx_buf_len += rem;
                }
                break;
            }
        } else if (sent < 0 && (BYPASS_ERRNO() == BYPASS_EAGAIN || BYPASS_ERRNO() == BYPASS_EWOULDBLOCK)) {
            if (c->tx_buf_len + (size_t)ret <= BYPASS_TX_BUF_SIZE) {
                memcpy(c->tx_buf + c->tx_buf_len, c->agg_buf, (size_t)ret);
                c->tx_buf_len += (size_t)ret;
            }
            break;
        }
        if (sent <= 0 && (sent == 0 || (BYPASS_ERRNO() != BYPASS_EAGAIN && BYPASS_ERRNO() != BYPASS_EWOULDBLOCK)))
            break;
    }
    /* Tell KCP to send window update if we drained data */
    if (drained && c->kcp)
        c->kcp->probe |= 2;  /* IKCP_ASK_TELL */
    return drained;
}

/** Check if a peer is on the same LAN.
 *  Reads the authoritative p2p_is_lan flag set by edge.c at
 *  REGISTER_SUPER_ACK time, when the old n2n P2P path determined
 *  LAN vs WAN. This is the definitive source — bypass does not
 *  re-derive this state from sockets[] or subnets.
 *  Returns 1 if same LAN, 0 if WAN or undetermined. */
static int bypass_is_lan_peer(bypass_context_t *ctx, uint32_t virt_ip_host)
{
    struct peer_info *pi = bypass_find_peer_info(ctx->edge, virt_ip_host);
    if (!pi)
        return 0;
    return pi->p2p_is_lan;
}

/** Initialize KCP session for a connection after handshake completes.
 *  Must be called on both sides (initiator + responder).
 *  @param c  connection context
 *  @param is_lan  1 = LAN peer (aggressive MTU), 0 = WAN peer (frag-safe MTU) */
static void bypass_kcp_init(struct bypass_conn *c, int is_lan)
{
    c->kcp_base = bypass_monotonic_ms();
    c->kcp = ikcp_create(c->conn_id, (void *)c);
    ikcp_setoutput(c->kcp, bypass_kcp_output);
    /* nodelay=1: faster response (RTO_min=30ms instead of 100ms).
     * On WAN links with ~15ms RTT, the default 100ms RTO causes 100ms
     * stalls on every packet loss. With nodelay=1, RTO adapts faster and
     * loss recovery is ~3× quicker.
     * interval=10ms: flush every 10ms for responsive ACK.
     * resend=2: fast retransmit after 2 dup ACKs (avoids RTO on single loss).
     * nc=1: disable KCP's built-in congestion control (we manage window). */
    ikcp_nodelay(c->kcp, 1, 10, 2, 1);
    c->snd_wnd = 1024;
    ikcp_wndsize(c->kcp, c->snd_wnd, c->snd_wnd);
    if (is_lan) {
        /* LAN: MTU=8216 → ~4 KCP segments per 32KB TCP read.
         * Good balance of low overhead and reliable drain.
         * Only used when peer is on the same /24 subnet (true LAN). */
        ikcp_setmtu(c->kcp, KCP_MTU_LAN);
        c->max_read_limit = 0; /* use default = BYPASS_MAX_PAYLOAD */
    } else {
        /* WAN: small MTU (1400) → 1 IP fragment per UDP packet.
         * Eliminates fragment loss as a cause of stalling.
         * max_read_limit = MTU * BYPASS_READ_SEGMENTS. */
        ikcp_setmtu(c->kcp, KCP_MTU_WAN);
        c->max_read_limit = KCP_MTU_WAN * BYPASS_READ_SEGMENTS;
    }
}

/* ===== Bypass header building/parsing ===== */

static void bypass_build_header(uint8_t *buf, uint8_t algo_idx,
                                 uint8_t flags, uint32_t conn_id)
{
    buf[0] = BYPASS_MAGIC_0;
    buf[1] = BYPASS_MAGIC_1;
    buf[2] = BYPASS_MAGIC_2;
    buf[3] = 0x00;
    buf[4] = algo_idx;
    buf[5] = flags;
    buf[6] = (conn_id >> 24) & 0xFF;
    buf[7] = (conn_id >> 16) & 0xFF;
    buf[8] = (conn_id >> 8) & 0xFF;
    buf[9] = conn_id & 0xFF;
}

static int bypass_parse_header(const uint8_t *buf, size_t len,
                                uint8_t *algo_idx, uint8_t *flags,
                                uint32_t *conn_id)
{
    if (len < BYPASS_HEADER_SIZE)
        return -1;
    if (buf[0] != BYPASS_MAGIC_0 || buf[1] != BYPASS_MAGIC_1 ||
        buf[2] != BYPASS_MAGIC_2)
        return -1;
    if (algo_idx) *algo_idx = buf[4];
    if (flags)    *flags    = buf[5];
    if (conn_id)  *conn_id  = ((uint32_t)buf[6] << 24) |
                               ((uint32_t)buf[7] << 16) |
                               ((uint32_t)buf[8] << 8)  |
                               (uint32_t)buf[9];
    return 0;
}

/* Check if a UDP buffer starts with bypass magic */
int bypass_is_bypass_packet(const uint8_t *buf, size_t len)
{
    if (len < BYPASS_HEADER_SIZE)
        return 0;
    return (buf[0] == BYPASS_MAGIC_0 && buf[1] == BYPASS_MAGIC_1 &&
            buf[2] == BYPASS_MAGIC_2);
}

/* ===== Encryption / Decryption ===== */

/* Direct encrypt/decrypt using n2n transop, same as 700M version.
 * The chunk header (enc_len + plain_len) in the multi-chunk aggregation
 * format replaces the 2-byte length prefix, enabling direct encrypt/decrypt
 * without intermediate buffer and memcpy. */

ssize_t bypass_encode(bypass_context_t *ctx, uint8_t *out, size_t out_len,
                      const uint8_t *in, size_t in_len, const n2n_mac_t dst_mac)
{
    n2n_edge_t *eee = ctx->edge;
    size_t idx = ctx->tx_transop_idx;
    if (idx >= N2N_MAX_TRANSFORMS)
        return -1;
    return (ssize_t)eee->transop[idx].fwd(&eee->transop[idx],
                                           out, out_len,
                                           in, in_len,
                                           dst_mac);
}

ssize_t bypass_decode(bypass_context_t *ctx, uint8_t *out, size_t out_len,
                      const uint8_t *in, size_t in_len, uint8_t algo_idx)
{
    n2n_edge_t *eee = ctx->edge;
    if (algo_idx >= N2N_MAX_TRANSFORMS)
        return -1;
    return (ssize_t)eee->transop[algo_idx].rev(&eee->transop[algo_idx],
                                                out, out_len, in, in_len,
                                                bypass_zero_mac);
}

/* ===== Send bypass packet via n2n UDP socket ===== */

static int bypass_sendto(bypass_context_t *ctx, const uint8_t *buf, size_t len,
                          const n2n_sock_t *dst)
{
    n2n_edge_t *eee = ctx->edge;
    SOCKET sock = -1;
    if (dst->family == AF_INET6 && eee->udp_sock6 != -1)
        sock = eee->udp_sock6;
    else if (dst->family == AF_INET)
        sock = eee->udp_sock;
    if (sock == -1)
        return -1;
    int ret = (int)sendto_sock(sock, buf, len, dst);
    if (ret > 0)
        ++ctx->bp_tx_pkts;
    return ret;
}

/** Non-blocking sendto for bypass data packets.
 *  Uses MSG_DONTWAIT to avoid blocking the edge loop when UDP send buffer is full. */
static int bypass_sendto_nb(bypass_context_t *ctx, const uint8_t *buf, size_t len,
                             const n2n_sock_t *dst)
{
    n2n_edge_t *eee = ctx->edge;
    SOCKET sock = (dst->family == AF_INET6 && eee->udp_sock6 != -1)
                  ? eee->udp_sock6 : eee->udp_sock;
    if (sock == -1) return -1;

    struct sockaddr_in6 peer_addr;
    fill_sockaddr((struct sockaddr *)&peer_addr, sizeof(peer_addr), dst);
    socklen_t addr_len = (dst->family == AF_INET6)
                         ? sizeof(struct sockaddr_in6)
                         : sizeof(struct sockaddr_in);

    ssize_t sent = sendto(sock, (const char *)buf, len, MSG_DONTWAIT,
                           (struct sockaddr *)&peer_addr, addr_len);
    if (sent < 0) {
        if (BYPASS_ERRNO() == BYPASS_EAGAIN || BYPASS_ERRNO() == BYPASS_EWOULDBLOCK)
            return -2;
        return -1;
    }
    ++ctx->bp_tx_pkts;
    return (int)sent;
}

/* ===== Connection management ===== */

/** Find a peer entry by sender address.
 *  First tries exact match on peer_addr, then falls back to scanning
 *  edge's known_peers (handles NAT address changes).
 *  If state_filter is non-zero, only peers in that state are considered
 *  for the primary lookup (fallback always matches any state).
 *  Returns peer index or -1. */
static int bypass_find_peer_by_sender(bypass_context_t *ctx,
                                       const n2n_sock_t *sender,
                                       uint8_t state_filter)
{
    /* Primary: match by peer_addr in our peers[] table */
    for (int i = 0; i < BYPASS_MAX_PEERS; i++) {
        if (ctx->peers[i].virt_ip == 0)
            continue;
        if (state_filter && ctx->peers[i].state != state_filter)
            continue;
        if (sock_equal(&ctx->peers[i].peer_addr, sender) == 0)
            return i;
    }

    /* Fallback: look up sender in edge's known_peers.
     * This handles the case where the peer's address changed (NAT rebinding)
     * and our stored peer_addr is stale. */
    struct peer_info *scan = ctx->edge->known_peers;
    while (scan) {
        n2n_sock_t *ps = (scan->sock.family == AF_INET) ? &scan->sock :
                         ((scan->sock6.family == AF_INET6) ? &scan->sock6 : NULL);
        if (ps && sock_equal(ps, sender) == 0 && scan->assigned_ip != 0) {
            bypass_peer_entry_t *pe = bypass_find_peer(ctx, scan->assigned_ip);
            if (pe) {
                /* Update stale peer_addr to current sender */
                pe->peer_addr = *sender;
                return (int)(pe - ctx->peers);
            }
            break;
        }
        scan = scan->next;
    }

    return -1;
}

static int bypass_find_conn_by_id(bypass_context_t *ctx, uint32_t conn_id)
{
    for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
        if (ctx->conns[i].state != BYPASS_CONN_FREE &&
            ctx->conns[i].conn_id == conn_id)
            return i;
    }
    return -1;
}

static int bypass_alloc_conn(bypass_context_t *ctx)
{
    for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
        if (ctx->conns[i].state == BYPASS_CONN_FREE) {
            /* Allocate large buffers dynamically - keeps struct small for cache efficiency */
            struct bypass_conn *c = &ctx->conns[i];
            c->tx_buf = (uint8_t *)calloc(1, BYPASS_TX_BUF_SIZE);
            c->agg_buf = (uint8_t *)calloc(1, BYPASS_MAX_PAYLOAD);
            c->pkt_buf = (uint8_t *)calloc(1, BYPASS_PKT_BUF_SIZE);
            c->kcp_buf = (uint8_t *)calloc(1, BYPASS_PKT_BUF_SIZE);
            if (!c->tx_buf || !c->agg_buf || !c->pkt_buf || !c->kcp_buf) {
                free(c->tx_buf); c->tx_buf = NULL;
                free(c->agg_buf); c->agg_buf = NULL;
                free(c->pkt_buf); c->pkt_buf = NULL;
                free(c->kcp_buf); c->kcp_buf = NULL;
                return -1;
            }
            return i;
        }
    }
    return -1;
}

static void bypass_free_conn(bypass_context_t *ctx, int idx)
{
    struct bypass_conn *c = &ctx->conns[idx];
    if (c->local_sock != -1) {
        shutdown(c->local_sock, SHUT_RDWR);
        closesocket(c->local_sock);
        c->local_sock = -1;
    }
    /* Free KCP and its buffers */
    if (c->kcp) {
        ikcp_release(c->kcp);
        c->kcp = NULL;
    }
    free(c->kcp_buf);  c->kcp_buf = NULL;
    /* Free dynamically allocated buffers */
    free(c->tx_buf);   c->tx_buf = NULL;
    free(c->agg_buf);  c->agg_buf = NULL;
    free(c->pkt_buf);  c->pkt_buf = NULL;
    memset(c, 0, sizeof(*c));
    c->state = BYPASS_CONN_FREE;
    c->local_sock = -1;
}

/* ===== Proxy: accept new connection from iptables redirect ===== */

void bypass_accept_proxy(bypass_context_t *ctx)
{
    struct sockaddr_in client_addr;
    socklen_t alen = sizeof(client_addr);
    SOCKET client_sock = accept(ctx->proxy_sock,
                                (struct sockaddr *)&client_addr, &alen);
    if (client_sock < 0)
        return;

    /* Get original destination (Linux: SO_ORIGINAL_DST, Windows: mapping table) */
    struct sockaddr_in orig_dst;
    memset(&orig_dst, 0, sizeof(orig_dst));
#if defined(__linux__)
    {
        socklen_t dst_len = sizeof(orig_dst);
        if (getsockopt(client_sock, SOL_IP, SO_ORIGINAL_DST,
                       &orig_dst, &dst_len) != 0) {
            closesocket(client_sock);
            return;
        }
    }
#elif defined(_WIN32)
    {
        extern int windivert_lookup_orig_dst(windivert_ctx_t *,
                                              uint32_t, uint16_t,
                                              uint32_t *, uint16_t *);
        windivert_ctx_t *wctx = (windivert_ctx_t *)ctx->windivert_ctx;
        if (!wctx || windivert_lookup_orig_dst(wctx,
                                                client_addr.sin_addr.s_addr,
                                                client_addr.sin_port,
                                                (uint32_t *)&orig_dst.sin_addr.s_addr,
                                                &orig_dst.sin_port) != 0) {
            closesocket(client_sock);
            return;
        }
        orig_dst.sin_family = AF_INET;
    }
#endif

    uint32_t dst_virt_ip = ntohl(orig_dst.sin_addr.s_addr);
    uint16_t dst_port = ntohs(orig_dst.sin_port);

    {
        char client_str[16], orig_str[16];
        struct in_addr ca, oa;
        ca.s_addr = client_addr.sin_addr.s_addr;
        oa.s_addr = orig_dst.sin_addr.s_addr;
        strncpy(client_str, inet_ntoa(ca), sizeof(client_str) - 1);
        strncpy(orig_str, inet_ntoa(oa), sizeof(orig_str) - 1);
        traceEvent(TRACE_INFO, "bypass: proxy accept from %s:%u -> %s:%u",
                   client_str, ntohs(client_addr.sin_port),
                   orig_str, dst_port);
    }

    /* Check if this peer has active bypass */
    if (!bypass_is_peer_active(ctx, dst_virt_ip)) {
        char dst_str[16];
        struct in_addr da;
        da.s_addr = orig_dst.sin_addr.s_addr;
        strncpy(dst_str, inet_ntoa(da), sizeof(dst_str) - 1);
        traceEvent(TRACE_INFO, "bypass: peer %s not active, closing", dst_str);
        closesocket(client_sock);
        return;
    }

    /* Find peer's direct address */
    n2n_sock_t peer_addr;
    if (bypass_find_peer_addr(ctx->edge, dst_virt_ip, &peer_addr) != 0) {
        char dst_str[16];
        struct in_addr da;
        da.s_addr = orig_dst.sin_addr.s_addr;
        strncpy(dst_str, inet_ntoa(da), sizeof(dst_str) - 1);
        traceEvent(TRACE_INFO, "bypass: cannot find peer addr for %s", dst_str);
        closesocket(client_sock);
        return;
    }

    /* New local-initiated connection */
    int idx = bypass_alloc_conn(ctx);
    if (idx < 0) {
        traceEvent(TRACE_INFO, "bypass: no free conn slots");
        closesocket(client_sock);
        return;
    }

    /* Set non-blocking and socket options */
#ifdef _WIN32
    {
        u_long mode = 1;
        ioctlsocket(client_sock, FIONBIO, &mode);
    }
#else
    {
        int fl = fcntl(client_sock, F_GETFL, 0);
        fcntl(client_sock, F_SETFL, fl | O_NONBLOCK);
    }
#endif
    int one = 1;
    setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
    {
        int rcvbuf = 1024 * 1024;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));
    }
    {
        int sndbuf = 1024 * 1024;
        setsockopt(client_sock, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));
    }

    struct bypass_conn *c = &ctx->conns[idx];
    c->local_sock = client_sock;
    c->state = BYPASS_CONN_CONNECTING;
    c->conn_id = ++ctx->conn_id_seq;
    c->remote_virt_ip = dst_virt_ip;
    c->remote_port = dst_port;       /* the service port on remote side */
    c->local_port = 0;               /* not used for initiator */
    c->peer_addr = peer_addr;
    c->peer = bypass_find_peer_info(ctx->edge, dst_virt_ip);
    c->initiator = 1;
    c->last_active = n2n_now();

    /* Send SYN via bypass channel.
     * SYN payload: [0-3]=sender's virtual IP (host order),
     *              [4-5]=dst_port (the service port, e.g. 5201) */
    uint8_t pkt[64];
    bypass_build_header(pkt, ctx->tx_transop_idx, BYPASS_FLAG_SYN, c->conn_id);

    uint32_t our_virt_ip = ntohl(ctx->tap_ip);
    uint8_t payload[8];
    payload[0] = (our_virt_ip >> 24) & 0xFF;
    payload[1] = (our_virt_ip >> 16) & 0xFF;
    payload[2] = (our_virt_ip >> 8) & 0xFF;
    payload[3] = our_virt_ip & 0xFF;
    payload[4] = (dst_port >> 8) & 0xFF;
    payload[5] = dst_port & 0xFF;

    ssize_t enc_len = bypass_encode(ctx, pkt + BYPASS_HEADER_SIZE,
                                     sizeof(pkt) - BYPASS_HEADER_SIZE,
                                     payload, 6, bypass_zero_mac);
    if (enc_len > 0) {
        bypass_sendto(ctx, pkt, BYPASS_HEADER_SIZE + enc_len, &peer_addr);
        /* Init KCP immediately so bypass_handle_local_read can feed
         * TCP data to KCP before SYN-ACK arrives.
         * Use is_lan from peer entry (determined at negotiation time,
         * guaranteed reliable — no race with peer_info population). */
        bypass_peer_entry_t *pe_lan = bypass_find_peer(ctx, dst_virt_ip);
        int is_lan = pe_lan ? pe_lan->is_lan : 0;
        bypass_kcp_init(c, is_lan);
        c->user_data = (void *)ctx;
        traceEvent(TRACE_DEBUG, "bypass: SYN sent conn_id=%u -> %s:%u",
                   (unsigned)c->conn_id,
                   inet_ntoa((struct in_addr){htonl(dst_virt_ip)}),
                   (unsigned)dst_port);
    }
}

/* ===== Proxy: read data from local socket, send via bypass ===== */

/** Write handler: flush pending tx_buf to local socket (called when select
 *  reports the local_sock is writable). Also drain KCP after tx_buf flush
 *  to keep rcv_wnd open. */
void bypass_handle_local_write(bypass_context_t *ctx, int idx)
{
    struct bypass_conn *c = &ctx->conns[idx];
    if (c->state < BYPASS_CONN_ESTABLISHED)
        return;

    if (c->fin_rcvd)
        return;

    /* Flush any pending tx_buf data to local socket */
    if (c->tx_buf_len > 0) {
        ssize_t nf = send(c->local_sock, (const char *)c->tx_buf,
                          c->tx_buf_len, MSG_DONTWAIT);
        if (nf > 0) {
            c->rx_bytes += (size_t)nf;
            ctx->bp_rx_bytes += (size_t)nf;
            if ((size_t)nf < c->tx_buf_len) {
                memmove(c->tx_buf, c->tx_buf + nf, c->tx_buf_len - (size_t)nf);
                c->tx_buf_len -= (size_t)nf;
            } else {
                c->tx_buf_len = 0;
            }
        }
    }

    /* After flushing tx_buf, drain more from KCP and send window update */
    if (c->kcp) {
        if (bypass_kcp_drain(ctx, c) > 0)
            ikcp_update(c->kcp, bypass_kcp_time(c));
    }
}

void bypass_handle_local_read(bypass_context_t *ctx, int idx)
{
    struct bypass_conn *c = &ctx->conns[idx];

    if (c->fin_sent)
        return;

    /* Graduated backpressure: progressively reduce per-cycle read limit
     * as KCP pipeline fills. Thresholds and divisors in bypass.h.
     *   waitsnd < THR_HALF:       full speed
     *   waitsnd THR_HALF-THR_SLOW: max_read_limit / HALF_DIV
     *   waitsnd THR_SLOW-99%:      max_read_limit / SLOW_DIV
     *   waitsnd >= 100%:           stop */
    size_t read_limit = (c->kcp && c->max_read_limit) ? c->max_read_limit : BYPASS_MAX_PAYLOAD;
    if (c->kcp) {
        int ws = ikcp_waitsnd(c->kcp);
        if (ws >= c->snd_wnd)
            return;
        if (ws >= c->snd_wnd * BYPASS_BP_THR_SLOW / 100)
            read_limit = read_limit / BYPASS_BP_SLOW_DIV;
        else if (ws >= c->snd_wnd * BYPASS_BP_THR_HALF / 100)
            read_limit = read_limit / BYPASS_BP_HALF_DIV;
    }
    size_t total = 0;
    int eof = 0;

    for (int _ri = 0; _ri < 64 && total < read_limit; _ri++) {
        size_t space = read_limit - total;
        if (space == 0)
            break;
        ssize_t n = recv(c->local_sock, (char *)c->agg_buf + total,
                         space, MSG_DONTWAIT);
        if (n > 0) {
            total += (size_t)n;
        } else if (n == 0) {
            eof = 1;
            break;
        } else if (BYPASS_ERRNO() == BYPASS_EAGAIN || BYPASS_ERRNO() == BYPASS_EWOULDBLOCK) {
            break;
        } else {
            traceEvent(TRACE_INFO, "bypass: local_sock read error %d conn_id=%u, closing",
                       BYPASS_ERRNO(), (unsigned)c->conn_id);
            bypass_free_conn(ctx, idx);
            return;
        }
    }

    if (total > 0 && c->kcp) {
        /* Feed data into KCP — KCP handles fragmentation, congestion
         * control, and retransmission. The output callback (bypass_kcp_output)
         * encrypts each segment and sends it via UDP with BYPASS_FLAG_KCP. */
        int ret = ikcp_send(c->kcp, (const char *)c->agg_buf, (int)total);
        if (ret < 0) {
            traceEvent(TRACE_DEBUG, "bypass: ikcp_send failed %d conn_id=%u",
                       ret, (unsigned)c->conn_id);
        }
        c->tx_bytes += total;
        ctx->bp_tx_bytes += total;
        c->last_active = n2n_now();
        bypass_conn_update_peer_last_seen(ctx, c);
    }

    if (eof) {
        uint8_t fin_buf[64];
        bypass_build_header(fin_buf, ctx->tx_transop_idx, BYPASS_FLAG_FIN, c->conn_id);
        ssize_t enc_len = bypass_encode(ctx, fin_buf + BYPASS_HEADER_SIZE,
                                         sizeof(fin_buf) - BYPASS_HEADER_SIZE,
                                         (const uint8_t *)"", 0, bypass_zero_mac);
        if (enc_len > 0)
            bypass_sendto_nb(ctx, fin_buf, BYPASS_HEADER_SIZE + enc_len, &c->peer_addr);
        c->fin_sent = 1;
        traceEvent(TRACE_INFO, "bypass: local_sock EOF conn_id=%u (half-close, fin_rcvd=%d)",
                   (unsigned)c->conn_id, c->fin_rcvd);
        if (c->fin_rcvd) {
            bypass_free_conn(ctx, idx);
        }
    }
}

/* ===== Handle received bypass packets ===== */

void bypass_handle_recv(bypass_context_t *ctx, const uint8_t *buf,
                        size_t len, const n2n_sock_t *sender)
{
    uint8_t algo_idx, flags;
    uint32_t conn_id;

    if (bypass_parse_header(buf, len, &algo_idx, &flags, &conn_id) != 0)
        return;

    ++ctx->bp_rx_pkts;

    const uint8_t *enc_payload = buf + BYPASS_HEADER_SIZE;
    size_t enc_len = len - BYPASS_HEADER_SIZE;

    if (flags & BYPASS_FLAG_TEST) {
        /* Respond to test packet and mark peer as ACTIVE */
        int found = bypass_find_peer_by_sender(ctx, sender, 0);
        if (found >= 0) {
            bypass_peer_entry_t *pe = &ctx->peers[found];
            if (pe->state == BYPASS_PEER_CAPABLE ||
                pe->state == BYPASS_PEER_TESTING ||
                pe->state == BYPASS_PEER_PROBING) {
                pe->state = BYPASS_PEER_ACTIVE;
                pe->state_time = n2n_now();
                pe->peer_addr = *sender;
                bypass_add_peer_rule(ctx, pe->virt_ip);
                traceEvent(TRACE_INFO, "bypass: peer %s ACTIVE (passive)",
                           inet_ntoa((struct in_addr){htonl(pe->virt_ip)}));
            }
        }
        uint8_t resp[64];
        bypass_build_header(resp, 0, BYPASS_FLAG_TEST_ACK, 0);
        bypass_sendto(ctx, resp, BYPASS_HEADER_SIZE, sender);
        return;
    }

    if (flags & BYPASS_FLAG_TEST_ACK) {
        /* Test ack received - complete handshake for this peer.
         * Accept TESTING (normal) and ACTIVE (received their TEST already). */
        int found = bypass_find_peer_by_sender(ctx, sender, 0);
        if (found >= 0) {
            bypass_peer_entry_t *pe = &ctx->peers[found];
            if (pe->state == BYPASS_PEER_TESTING ||
                pe->state == BYPASS_PEER_ACTIVE) {
                if (pe->state != BYPASS_PEER_ACTIVE) {
                    bypass_add_peer_rule(ctx, pe->virt_ip);
                }
                pe->state = BYPASS_PEER_ACTIVE;
                pe->state_time = n2n_now();
                pe->peer_addr = *sender;
                traceEvent(TRACE_INFO, "bypass: peer %s ACTIVE",
                           inet_ntoa((struct in_addr){htonl(pe->virt_ip)}));
            }
        }
        return;
    }

    if (flags & BYPASS_FLAG_SYN) {
        /* First, check if this is a SYN-ACK for an existing connection we initiated.
         * Must check BEFORE decoding because SYN-ACK may have empty payload
         * (dec_len=0 after AES decryption), which would be rejected by dec_len < 6. */
        int existing = bypass_find_conn_by_id(ctx, conn_id);
        if (existing >= 0) {
            struct bypass_conn *c = &ctx->conns[existing];
            if (c->state == BYPASS_CONN_CONNECTING) {
                c->state = BYPASS_CONN_ESTABLISHED;
                c->last_active = n2n_now();
                /* KCP was initialized at SYN time; peer entry's is_lan
                 * determined LAN/WAN reliably at negotiation time. */
                c->user_data = (void *)ctx;
                traceEvent(TRACE_DEBUG, "bypass: conn %u ESTABLISHED (SYN-ACK)",
                           (unsigned)conn_id);
            }
            return;
        }

        /* Decode SYN payload to get sender's virtual IP and target port */
        uint8_t dec[64];
        ssize_t dec_len = bypass_decode(ctx, dec, sizeof(dec),
                                         enc_payload, enc_len, algo_idx);
        if (dec_len < 6)
            return;

        /* SYN payload: [0-3]=sender's virtual IP (host order),
         *              [4-5]=dst_port (the service port to connect to on localhost) */
        uint32_t sender_virt_ip = ((uint32_t)dec[0] << 24) | ((uint32_t)dec[1] << 16) |
                                  ((uint32_t)dec[2] << 8) | (uint32_t)dec[3];
        uint16_t dst_port = ((uint16_t)dec[4] << 8) | dec[5];
        if (dst_port == 0)
            return;

        /* Check if we already have a conn with this id (race condition guard) */
        existing = bypass_find_conn_by_id(ctx, conn_id);
        if (existing >= 0) {
            struct bypass_conn *c = &ctx->conns[existing];
            if (c->state == BYPASS_CONN_CONNECTING) {
                c->state = BYPASS_CONN_ESTABLISHED;
                c->last_active = n2n_now();
            }
            return;
        }

        /* Connect to localhost:dst_port (the real service) */
        SOCKET out_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (out_sock < 0)
            return;

        /* Set TCP_NODELAY and buffer sizes before connecting */
        int one = 1;
        setsockopt(out_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
        {
            int rcvbuf = 1024 * 1024;
            setsockopt(out_sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));
        }
        {
            int sndbuf = 1024 * 1024;
            setsockopt(out_sock, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));
        }

        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        local_addr.sin_port = htons(dst_port);

        /* Connect to local service (blocking - localhost connect is fast) */
        if (connect(out_sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
            traceEvent(TRACE_WARNING, "bypass: connect to localhost:%u failed: %s",
                       (unsigned)dst_port, BYPASS_STRERR(BYPASS_ERRNO()));
            closesocket(out_sock);
            return;
        }

        /* Now set non-blocking for subsequent read/write */
#ifdef _WIN32
        {
            u_long mode = 1;
            ioctlsocket(out_sock, FIONBIO, &mode);
        }
#else
        {
            int fl = fcntl(out_sock, F_GETFL, 0);
            fcntl(out_sock, F_SETFL, fl | O_NONBLOCK);
        }
#endif

        /* Allocate conn */
        int idx = bypass_alloc_conn(ctx);
        if (idx < 0) {
            closesocket(out_sock);
            return;
        }

        struct bypass_conn *c = &ctx->conns[idx];
        c->local_sock = out_sock;
        c->state = BYPASS_CONN_ESTABLISHED;
        c->conn_id = conn_id;
        c->remote_virt_ip = sender_virt_ip; /* for bypass_peer_gone cleanup */
        c->remote_port = 0;
        c->local_port = dst_port;
        c->peer_addr = *sender;
        c->peer = bypass_find_peer_info(ctx->edge, sender_virt_ip);
        c->initiator = 0;
        c->last_active = n2n_now();

        /* Init KCP on responder side using pre-determined is_lan
         * (set at peer negotiation — reliable, no race). */
        {
            bypass_peer_entry_t *pe_lan = bypass_find_peer(ctx, sender_virt_ip);
            int is_lan = pe_lan ? pe_lan->is_lan : 0;
            bypass_kcp_init(c, is_lan);
        }
        c->user_data = (void *)ctx;

        /* Reply SYN to confirm connection */
        uint8_t resp[64];
        bypass_build_header(resp, ctx->tx_transop_idx, BYPASS_FLAG_SYN, conn_id);
        ssize_t enc = bypass_encode(ctx, resp + BYPASS_HEADER_SIZE,
                                     sizeof(resp) - BYPASS_HEADER_SIZE,
                                     (const uint8_t *)"", 0, bypass_zero_mac);
        if (enc > 0)
            bypass_sendto(ctx, resp, BYPASS_HEADER_SIZE + enc, sender);

        traceEvent(TRACE_DEBUG, "bypass: SYN-OK conn_id=%u -> localhost:%u",
                   (unsigned)conn_id, (unsigned)dst_port);
        return;
    }

    if (flags & BYPASS_FLAG_KCP) {
        /* KCP segment from peer. Decrypt and feed to KCP.
         * KCP handles ordering, retransmission, and congestion control. */
        int idx = bypass_find_conn_by_id(ctx, conn_id);
        if (idx < 0)
            return;

        struct bypass_conn *c = &ctx->conns[idx];

        ssize_t dec_len = bypass_decode(ctx, c->kcp_buf, BYPASS_PKT_BUF_SIZE,
                                         enc_payload, enc_len, algo_idx);
        if (dec_len <= 0)
            return;

        ikcp_input(c->kcp, (const char *)c->kcp_buf, (long)dec_len);

        /* Drain BEFORE flushing ACKs so ACK carries true rcv_wnd */
        bypass_kcp_drain(ctx, c);

        ikcp_update(c->kcp, bypass_kcp_time(c));

        c->last_active = n2n_now();
        bypass_conn_update_peer_last_seen(ctx, c);
        return;
    }

    if (flags & BYPASS_FLAG_FIN) {
        int idx = bypass_find_conn_by_id(ctx, conn_id);
        if (idx < 0)
            return;

        struct bypass_conn *c = &ctx->conns[idx];

        /* Remote side is done writing. Shutdown our local socket's write
         * side to propagate FIN to local app, but keep reading - local
         * app may still have data to send (TCP half-close). */
        c->fin_rcvd = 1;

        /* Drain any remaining data from KCP's receive buffer */
        if (c->kcp)
            bypass_kcp_drain(ctx, c);

        /* Flush any pending tx_buf before shutting down write side */
        for (int _retry = 0; _retry < 10 && c->tx_buf_len > 0; _retry++) {
            ssize_t nf = send(c->local_sock,
                              (const char *)c->tx_buf,
                              c->tx_buf_len, 0);
            if (nf > 0) {
                c->rx_bytes += (size_t)nf;
                ctx->bp_rx_bytes += (size_t)nf;
                if ((size_t)nf < c->tx_buf_len) {
                    memmove(c->tx_buf, c->tx_buf + nf,
                            c->tx_buf_len - (size_t)nf);
                    c->tx_buf_len -= (size_t)nf;
                } else {
                    c->tx_buf_len = 0;
                }
            } else {
                break;
            }
        }

        /* Shutdown write side only - local app can still read any
         * remaining data we've already delivered, and we can still
         * read from local app to send to remote. */
        shutdown(c->local_sock, SHUT_WR);

        traceEvent(TRACE_INFO, "bypass: conn %u remote FIN (half-close, fin_sent=%d)",
                   (unsigned)conn_id, c->fin_sent);

        if (c->fin_sent) {
            /* Both sides done - safe to close */
            bypass_free_conn(ctx, idx);
        }
        return;
    }

    if (flags & BYPASS_FLAG_RAW) {
        /* Raw IP frame (ICMP etc.) - decode and write to TAP.
         * Use fixed small buffers (ICMP is always < MTU size). */
        uint8_t dec[2048];
        uint8_t eth_frame[14 + 2048];
        ssize_t dec_len = bypass_decode(ctx, dec, sizeof(dec),
                                         enc_payload, enc_len, algo_idx);
        if (dec_len <= 0)
            return;

        /* Reconstruct ethernet frame: dec is an IP packet */
        /* dst MAC = our MAC, src MAC = our MAC (we don't know remote MAC) */
        memcpy(eth_frame, ctx->tap_mac, 6);
        memcpy(eth_frame + 6, ctx->tap_mac, 6);
        eth_frame[12] = 0x08; eth_frame[13] = 0x00;
        memcpy(eth_frame + 14, dec, dec_len);
        tuntap_write(ctx->tap_device, eth_frame, 14 + dec_len);
        ctx->bp_rx_bytes += dec_len;

        /* Update peer's last_seen - extract src IP from IP header */
        if (dec_len >= 20) {
            uint32_t src_ip_n;
            memcpy(&src_ip_n, dec + 12, 4);
            bypass_update_peer_last_seen(ctx->edge, ntohl(src_ip_n));
        }
        return;
    }
}

/* ===== TAP forward: intercept ICMP for bypass-active peers ===== */

int bypass_tap_forward(bypass_context_t *ctx, uint8_t *eth_frame, size_t len)
{
    if (!ctx->enabled)
        return 0;

    if (len < 14)
        return 0;

    uint16_t etype = ((uint16_t)eth_frame[12] << 8) | eth_frame[13];

    /* Only handle IPv4 */
    if (etype != 0x0800)
        return 0;

    if (len < 14 + 20)
        return 0;

    /* Parse IP header */
    uint8_t *ip_hdr = eth_frame + 14;
    uint8_t version_ihl = ip_hdr[0];
    if ((version_ihl >> 4) != 4)
        return 0;

    uint8_t protocol = ip_hdr[9];
    uint32_t dst_ip_n;
    memcpy(&dst_ip_n, ip_hdr + 16, 4);
    uint32_t dst_ip_host = ntohl(dst_ip_n);

    /* Only handle ICMP for now (TCP is handled by iptables redirect) */
    if (protocol != IPPROTO_ICMP)
        return 0;

    /* Check if this peer has active bypass */
    if (!bypass_is_peer_active(ctx, dst_ip_host))
        return 0;

    /* Find peer's direct address */
    n2n_sock_t peer_addr;
    if (bypass_find_peer_addr(ctx->edge, dst_ip_host, &peer_addr) != 0)
        return 0;

    /* Send raw IP frame via bypass channel */
    uint8_t pkt[2048];
    bypass_build_header(pkt, ctx->tx_transop_idx, BYPASS_FLAG_RAW, 0);

    /* Payload is the IP packet (without ethernet header) */
    size_t ip_len = len - 14;
    ssize_t enc_len = bypass_encode(ctx, pkt + BYPASS_HEADER_SIZE,
                                     sizeof(pkt) - BYPASS_HEADER_SIZE,
                                     ip_hdr, ip_len,
                                     bypass_zero_mac);
    if (enc_len > 0) {
        if (bypass_sendto(ctx, pkt, BYPASS_HEADER_SIZE + enc_len, &peer_addr) > 0) {
            ctx->bp_tx_bytes += ip_len;
        }
    }

    /* Update peer's last_seen to prevent keepalive */
    bypass_update_peer_last_seen(ctx->edge, dst_ip_host);

    return 1; /* handled - don't send via normal n2n path */
}

/* ===== Probe frames (carried via n2n old path) ===== */

size_t bypass_build_probe_frame(uint8_t *frame, uint32_t our_ip_n, int is_ack, int wants_bypass)
{
    uint16_t etype = is_ack ? BYPASS_ETYPE_PROBE_ACK : BYPASS_ETYPE_PROBE;

    /* Minimal ethernet frame: dst=broadcast, src=our_mac, type=probe */
    memset(frame, 0, 14 + 4 + 1);
    memset(frame, 0xFF, 6);          /* dst: broadcast */
    /* src MAC will be filled by caller */
    frame[12] = (etype >> 8) & 0xFF;
    frame[13] = etype & 0xFF;

    /* Payload: our virtual IP (4 bytes) + bypass preference flag (1 byte) */
    memcpy(frame + 14, &our_ip_n, 4);
    frame[18] = wants_bypass ? 0x01 : 0x00;

    return 14 + 4 + 1;
}

int bypass_handle_probe_frame(bypass_context_t *ctx, const uint8_t *frame,
                               size_t len, int is_ack, const n2n_sock_t *sender)
{
    if (!ctx->enabled)
        return 0;

    if (len < 14 + 4)
        return 0;

    uint16_t etype = ((uint16_t)frame[12] << 8) | frame[13];
    if (is_ack && etype != BYPASS_ETYPE_PROBE_ACK)
        return 0;
    if (!is_ack && etype != BYPASS_ETYPE_PROBE)
        return 0;

    /* Extract sender's virtual IP */
    uint32_t sender_ip_n;
    memcpy(&sender_ip_n, frame + 14, 4);
    uint32_t sender_ip_host = ntohl(sender_ip_n);

    if (is_ack) {
        /* Mark peer as capable */
        bypass_peer_entry_t *pe = bypass_find_peer(ctx, sender_ip_host);
        if (pe && pe->state == BYPASS_PEER_PROBING) {
            pe->state = BYPASS_PEER_CAPABLE;
            pe->state_time = n2n_now();
            pe->probe_sent = 0;
            pe->probe_retries = 0;
            traceEvent(TRACE_DEBUG, "bypass: peer %s CAPABLE",
                   inet_ntoa((struct in_addr){htonl(sender_ip_host)}));
        }
    } else {
        /* Received PROBE from remote - check initiator's bypass preference */
        uint8_t initiator_wants = 0;
        if (len >= 14 + 4 + 1)
            initiator_wants = frame[18];

        if (!initiator_wants)
            return 0; /* initiator doesn't want bypass, don't respond */

        /* Hard veto: if we have -x, we refuse bypass regardless */
        if (ctx->user_disabled)
            return 0;

        /* Create peer entry if needed */
        bypass_peer_entry_t *pe = bypass_find_peer(ctx, sender_ip_host);
        if (!pe) {
            pe = bypass_alloc_peer(ctx);
            if (!pe)
                return 0; /* no slots */
            pe->virt_ip = sender_ip_host;
            pe->is_lan = bypass_is_lan_peer(ctx, sender_ip_host);
            pe->state_time = n2n_now();
            pe->probe_sent = 0;
            pe->probe_retries = 0;
            ctx->peer_count++;
            if (sender)
                pe->peer_addr = *sender;
            else {
                /* Fallback: look up from peer list */
                n2n_sock_t peer_addr;
                if (bypass_find_peer_addr(ctx->edge, sender_ip_host, &peer_addr) == 0)
                    pe->peer_addr = peer_addr;
            }
            traceEvent(TRACE_INFO, "bypass: received PROBE from %s, CAPABLE",
                       inet_ntoa((struct in_addr){htonl(sender_ip_host)}));
        }
        pe->state = BYPASS_PEER_CAPABLE;

        /* Respond with PROBE_ACK */
        /* Send probe_ack frame via n2n old path - caller handles this */
        return 1; /* signal that we need to send PROBE_ACK */
    }

    return 0;
}

/* ===== Per-peer bypass state management ===== */

bypass_peer_entry_t *bypass_find_peer(bypass_context_t *ctx, uint32_t virt_ip_host)
{
    for (int i = 0; i < BYPASS_MAX_PEERS; i++) {
        if (ctx->peers[i].virt_ip == virt_ip_host)
            return &ctx->peers[i];
    }
    return NULL;
}

static bypass_peer_entry_t *bypass_alloc_peer(bypass_context_t *ctx)
{
    /* Find empty slot or least important (NONE state) */
    for (int i = 0; i < BYPASS_MAX_PEERS; i++) {
        if (ctx->peers[i].virt_ip == 0)
            return &ctx->peers[i];
    }
    return NULL;
}

int bypass_is_peer_active(bypass_context_t *ctx, uint32_t virt_ip_host)
{
    if (!ctx->enabled)
        return 0;
    bypass_peer_entry_t *pe = bypass_find_peer(ctx, virt_ip_host);
    return (pe && pe->state == BYPASS_PEER_ACTIVE);
}

void bypass_start_negotiation(bypass_context_t *ctx, struct peer_info *peer)
{
    if (!ctx->enabled || ctx->user_disabled)
        return;

    if (peer->assigned_ip == 0)
        return;

    bypass_peer_entry_t *pe = bypass_find_peer(ctx, peer->assigned_ip);
    if (pe) {
        if (pe->state == BYPASS_PEER_ACTIVE) {
            /* Already active — nothing to do (bypass_tick keeps is_lan in sync). */
            return;
        }
        if (pe->state == BYPASS_PEER_PROBING ||
            pe->state == BYPASS_PEER_CAPABLE ||
            pe->state == BYPASS_PEER_TESTING) {
            /* Already negotiating, don't restart. */
            return;
        }
        /* NONE or UNAVAILABLE: peer entry exists but not negotiating.
         * Restart negotiation with fresh address.
         * Do NOT increment peer_count — slot already allocated. */
        traceEvent(TRACE_INFO, "bypass: peer %s was %s, restarting negotiation",
                   inet_ntoa((struct in_addr){htonl(peer->assigned_ip)}),
                   pe->state == BYPASS_PEER_UNAVAILABLE ? "UNAVAILABLE" : "NONE");
    } else {
        /* Allocate new peer entry */
        pe = bypass_alloc_peer(ctx);
        if (!pe)
            return;
        ctx->peer_count++;
    }

    /* Get peer's direct address */
    n2n_sock_t peer_addr;
    if (peer->sock.family == AF_INET) {
        peer_addr = peer->sock;
    } else if (peer->sock6.family == AF_INET6) {
        peer_addr = peer->sock6;
    } else {
        return;
    }

    pe->virt_ip = peer->assigned_ip;
    pe->is_lan = bypass_is_lan_peer(ctx, peer->assigned_ip);
    pe->state = BYPASS_PEER_PROBING;
    pe->state_time = n2n_now();
    pe->probe_sent = 0;
    pe->probe_retries = 0;
    pe->peer_addr = peer_addr;
    ctx->peer_count++;

    /* Send PROBE frame via n2n old path.
     * The actual sending is done by the caller in edge.c,
     * which builds the probe frame and sends it as a normal PACKET. */
    traceEvent(TRACE_INFO, "bypass: start negotiation with %s (PROBING)",
               inet_ntoa((struct in_addr){htonl(pe->virt_ip)}));
}

void bypass_peer_gone(bypass_context_t *ctx, uint32_t virt_ip_host)
{
    bypass_peer_entry_t *pe = bypass_find_peer(ctx, virt_ip_host);
    if (!pe)
        return;

    /* Remove iptables rule if active */
    if (pe->state == BYPASS_PEER_ACTIVE)
        bypass_del_peer_rule(ctx, virt_ip_host);

    /* Close all conns for this peer */
    for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
        if (ctx->conns[i].state != BYPASS_CONN_FREE &&
            ctx->conns[i].remote_virt_ip == virt_ip_host)
            bypass_free_conn(ctx, i);
    }

    pe->virt_ip = 0;
    pe->state = BYPASS_PEER_NONE;
    pe->state_time = 0;
    pe->probe_sent = 0;
    pe->probe_retries = 0;
    if (ctx->peer_count > 0)
        ctx->peer_count--;
}

int bypass_get_pending_probes(bypass_context_t *ctx, uint8_t *buf, int max_probes,
                               uint32_t our_ip_n, const uint8_t *our_mac)
{
    int count = 0;
    time_t now = n2n_now();
    size_t frame_size = 14 + 4 + 1; /* bypass_build_probe_frame size */
    int wants_bypass = ctx->user_disabled ? 0 : 1;

    for (int i = 0; i < BYPASS_MAX_PEERS && count < max_probes; i++) {
        bypass_peer_entry_t *pe = &ctx->peers[i];
        if (pe->virt_ip == 0 || pe->state != BYPASS_PEER_PROBING)
            continue;

        /* Already sent and not yet timed out - skip.
         * bypass_tick resets probe_sent to 0 on timeout to allow retry. */
        if (pe->probe_sent > 0)
            continue;

        /* Send probe */
        pe->probe_sent = 1;
        pe->state_time = now;
        uint8_t *frame = buf + count * frame_size;
        size_t flen = bypass_build_probe_frame(frame, our_ip_n, 0, wants_bypass);
        memcpy(frame + 6, our_mac, 6); /* src MAC */

        /* Look up peer's MAC address so the frame goes via P2P (not supernode).
         * Using broadcast MAC triggers send_packet2net to route via supernode,
         * which causes the remote side to see a "Relayed packet" and break P2P. */
        if (ctx->edge) {
            struct peer_info *pi = bypass_find_peer_info(ctx->edge, pe->virt_ip);
            if (pi)
                memcpy(frame, pi->mac_addr, 6);  /* dst MAC = peer's MAC */
        }

        (void)flen;
        traceEvent(TRACE_INFO, "bypass: sending PROBE to peer %s",
                   inet_ntoa((struct in_addr){htonl(pe->virt_ip)}));
        count++;
    }
    return count;
}

/* ===== Tick: handle timeouts and state transitions ===== */

void bypass_tick(bypass_context_t *ctx, time_t now)
{
    if (!ctx->enabled)
        return;

    for (int i = 0; i < BYPASS_MAX_PEERS; i++) {
        bypass_peer_entry_t *pe = &ctx->peers[i];
        if (pe->virt_ip == 0)
            continue;

        switch (pe->state) {
        case BYPASS_PEER_PROBING:
            if (now - pe->state_time > BYPASS_PROBE_TIMEOUT) {
                if (pe->probe_retries < 3) {
                    /* Reset probe_sent to allow bypass_get_pending_probes
                     * to resend on next tick. */
                    pe->probe_sent = 0;
                    pe->probe_retries++;
                    pe->state_time = now;
                    traceEvent(TRACE_INFO, "bypass: peer %s PROBING timeout, retry %d/3",
                               inet_ntoa((struct in_addr){htonl(pe->virt_ip)}),
                               pe->probe_retries);
                } else {
                    /* 3 retries exhausted — mark as UNAVAILABLE instead of
                     * removing, so we don't immediately re-negotiate (which
                     * causes PROBE traffic that may interfere with old path).
                     * Will retry after BYPASS_UNAVAILABLE_RETRY seconds. */
                    pe->state = BYPASS_PEER_UNAVAILABLE;
                    pe->state_time = now;
                    pe->probe_sent = 0;
                    pe->probe_retries = 0;
                    traceEvent(TRACE_INFO, "bypass: peer %s UNAVAILABLE (not bypass-capable)",
                               inet_ntoa((struct in_addr){htonl(pe->virt_ip)}));
                }
            }
            break;

        case BYPASS_PEER_UNAVAILABLE:
            if (now - pe->state_time > BYPASS_UNAVAILABLE_RETRY) {
                pe->state = BYPASS_PEER_NONE;
                pe->virt_ip = 0;
                pe->state_time = 0;
                if (ctx->peer_count > 0)
                    ctx->peer_count--;
            }
            break;

        case BYPASS_PEER_CAPABLE:
            /* Send TEST packet to verify bypass data channel */
            {
                uint8_t pkt[64];
                bypass_build_header(pkt, 0, BYPASS_FLAG_TEST, 0);
                bypass_sendto(ctx, pkt, BYPASS_HEADER_SIZE, &pe->peer_addr);
                pe->state = BYPASS_PEER_TESTING;
                pe->state_time = now;
            }
            break;

        case BYPASS_PEER_TESTING:
            if (now - pe->state_time > BYPASS_TEST_TIMEOUT) {
                /* Test failed, go back to capable to retry */
                pe->state = BYPASS_PEER_CAPABLE;
                pe->state_time = now;
                traceEvent(TRACE_INFO, "bypass: test timeout for %s, retrying",
                           inet_ntoa((struct in_addr){htonl(pe->virt_ip)}));
            }
            break;

        case BYPASS_PEER_ACTIVE:
            /* Keep is_lan in sync with peer_info: sockets[1] may become
             * available after initial negotiation (PEER_INFO arrives late).
             * Once is_lan=1 it stays 1 (LAN never reverts to WAN).
             *
             * Also check peer's last_seen from n2n: if peer went silent
             * (e.g., restarted without DEREGISTER), transition to UNAVAILABLE
             * so bypass can be restarted when peer reconnects. */
            if (!pe->is_lan)
                pe->is_lan = bypass_is_lan_peer(ctx, pe->virt_ip);
            {
                struct peer_info *pi = bypass_find_peer_info(ctx->edge, pe->virt_ip);
                if (pi && (now - pi->last_seen) > 150) {  /* REGISTRATION_TIMEOUT (150s) */
                    /* Peer went silent in n2n layer. Reset to UNAVAILABLE. */
                    bypass_del_peer_rule(ctx, pe->virt_ip);
                    for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
                        if (ctx->conns[i].state != BYPASS_CONN_FREE &&
                            ctx->conns[i].remote_virt_ip == pe->virt_ip)
                            bypass_free_conn(ctx, i);
                    }
                    pe->state = BYPASS_PEER_UNAVAILABLE;
                    pe->state_time = now;
                    traceEvent(TRACE_INFO, "bypass: peer %s went silent, now UNAVAILABLE",
                               inet_ntoa((struct in_addr){htonl(pe->virt_ip)}));
                }
            }
            break;
        }
    }

    /* Timeout stale connections + KCP periodic update */
    for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
        struct bypass_conn *c = &ctx->conns[i];
        if (c->state == BYPASS_CONN_FREE)
            continue;

        /* KCP periodic update — uses high-res clock, not time_t */
        if (c->kcp) {
            /* Flush tx_buf to local socket before drain.
             * When tx_buf fills up, drain stops and rcv_wnd collapses
             * to 0, halting the sender. select-driven write handler
             * may not fire if no new UDP packets arrive (deadlock).
             * Tick-based flush ensures recovery every ~10ms. */
            if (c->tx_buf_len > 0) {
                ssize_t nf = send(c->local_sock, (const char *)c->tx_buf,
                                  c->tx_buf_len, MSG_DONTWAIT);
                if (nf > 0) {
                    c->rx_bytes += (size_t)nf;
                    ctx->bp_rx_bytes += (size_t)nf;
                    if ((size_t)nf < c->tx_buf_len) {
                        memmove(c->tx_buf, c->tx_buf + nf,
                                c->tx_buf_len - (size_t)nf);
                        c->tx_buf_len -= (size_t)nf;
                    } else {
                        c->tx_buf_len = 0;
                    }
                }
            }
            /* Drain before update so ACK carries true window */
            bypass_kcp_drain(ctx, c);
            ikcp_update(c->kcp, bypass_kcp_time(c));
        }

        if (now - c->last_active > BYPASS_CONN_TIMEOUT) {
            traceEvent(TRACE_INFO, "bypass: conn %u timed out", c->conn_id);
            uint8_t pkt[64];
            bypass_build_header(pkt, ctx->tx_transop_idx, BYPASS_FLAG_FIN, c->conn_id);
            ssize_t enc_len = bypass_encode(ctx, pkt + BYPASS_HEADER_SIZE,
                                             sizeof(pkt) - BYPASS_HEADER_SIZE,
                                             (const uint8_t *)"", 0,
                                             bypass_zero_mac);
            if (enc_len > 0)
                bypass_sendto_nb(ctx, pkt, BYPASS_HEADER_SIZE + enc_len, &c->peer_addr);
            bypass_free_conn(ctx, i);
        }
    }

    /* Periodically retry negotiation for known peers that don't have
     * a bypass peer entry (e.g., after probe timeout removed it).
     * Check every ~30 seconds. */
    if (!ctx->user_disabled && ctx->edge) {
        static time_t last_retry = 0;
        if (now - last_retry >= 30) {
            last_retry = now;
            struct peer_info *scan = ctx->edge->known_peers;
            while (scan) {
                if (scan->assigned_ip != 0) {
                    bypass_peer_entry_t *pe = bypass_find_peer(ctx, scan->assigned_ip);
                    if (!pe) {
                        /* No bypass entry for this known peer - start negotiation */
                        bypass_start_negotiation(ctx, scan);
                    }
                }
                scan = scan->next;
            }
        }
    }
}

#ifdef __linux__
/* ===== iptables management ===== */

static int bypass_run_iptables(const char *cmd)
{
    int ret = system(cmd);
    if (ret == -1)
        return -1;
    if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0)
        return 0;
    return -1;
}

void bypass_add_peer_rule(bypass_context_t *ctx, uint32_t virt_ip_host)
{
    char cmd[256];
    char ip_str[16];
    struct in_addr addr;
    addr.s_addr = htonl(virt_ip_host);
    strncpy(ip_str, inet_ntoa(addr), sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';

    /* TCP redirect - only match NEW connections to avoid intercepting
     * reply packets from local services (e.g. iperf3 server replies) */
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -C OUTPUT -d %s/32 -p tcp -m conntrack --ctstate NEW -j REDIRECT --to-port %u 2>/dev/null || "
             "iptables -t nat -A OUTPUT -d %s/32 -p tcp -m conntrack --ctstate NEW -j REDIRECT --to-port %u",
             ip_str, ctx->proxy_port,
             ip_str, ctx->proxy_port);
    int ret = bypass_run_iptables(cmd);
    traceEvent(TRACE_INFO, "bypass: iptables REDIRECT %s -> port %u %s",
               ip_str, ctx->proxy_port, ret == 0 ? "OK" : "FAILED");
}

void bypass_del_peer_rule(bypass_context_t *ctx, uint32_t virt_ip_host)
{
    char cmd[256];
    char ip_str[16];
    struct in_addr addr;
    addr.s_addr = htonl(virt_ip_host);
    strncpy(ip_str, inet_ntoa(addr), sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';

    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -D OUTPUT -d %s/32 -p tcp -m conntrack --ctstate NEW -j REDIRECT --to-port %u 2>/dev/null",
             ip_str, ctx->proxy_port);
    bypass_run_iptables(cmd);
}

void bypass_del_all_rules(bypass_context_t *ctx)
{
    /* Phase 1: remove rules for active peers (from bypass's own state) */
    for (int i = 0; i < BYPASS_MAX_PEERS; i++) {
        if (ctx->peers[i].virt_ip != 0 && ctx->peers[i].state == BYPASS_PEER_ACTIVE)
            bypass_del_peer_rule(ctx, ctx->peers[i].virt_ip);
    }

    /* Phase 2: clean up leftover rules from previous crashed instances.
     * Use popen to read iptables -S output in C, no shell pipeline issues. */
    FILE *fp = popen("iptables -t nat -S OUTPUT 2>/dev/null", "r");
    if (!fp)
        return;

    char port_str[32];
    snprintf(port_str, sizeof(port_str), "to-port %u", ctx->proxy_port);

    char line[512];
    char del_cmd[640];
    while (fgets(line, sizeof(line), fp)) {
        /* Strip trailing newline / carriage return */
        size_t ln = strlen(line);
        while (ln > 0 && (line[ln-1] == '\n' || line[ln-1] == '\r'))
            line[--ln] = '\0';

        if (strstr(line, port_str) && strncmp(line, "-A ", 3) == 0) {
            /* Found a rule matching our port. Replace -A with -D. */
            snprintf(del_cmd, sizeof(del_cmd),
                     "iptables -t nat -D %s 2>/dev/null", line + 3);
            bypass_run_iptables(del_cmd);
        }
    }
    pclose(fp);
}

#endif /* __linux__ */

#ifdef _WIN32
/* Stub implementations for Windows (iptables not available) */
void bypass_add_peer_rule(bypass_context_t *ctx, uint32_t virt_ip_host) { }
void bypass_del_peer_rule(bypass_context_t *ctx, uint32_t virt_ip_host) { }
void bypass_del_all_rules(bypass_context_t *ctx) { }
#endif

/* ===== Init / Deinit ===== */

int bypass_init(bypass_context_t *ctx, struct n2n_edge *edge,
                tuntap_dev *tap, uint32_t dev_ip, uint8_t dev_prefix)
{
    uint16_t saved_proxy_port = edge->bp_proxy_port;
    uint8_t saved_user_disabled = edge->bp_user_disabled;

    memset(ctx, 0, sizeof(*ctx));

    ctx->edge = edge;
    ctx->tap_device = tap;
    ctx->enabled = 1;  /* Linux only - this file is compiled under __linux__ */
    ctx->user_disabled = saved_user_disabled;  /* restore -x flag */
    ctx->tap_ip = dev_ip;
    ctx->tap_prefix = dev_prefix;
    memcpy(ctx->tap_mac, tap->mac_addr, 6);
    ctx->proxy_port = BYPASS_DEFAULT_PORT;
    /* Use port from edge configuration if set */
    if (saved_proxy_port != 0)
        ctx->proxy_port = saved_proxy_port;

    /* Clean up stale iptables rules from previous crashed instance */
    bypass_del_all_rules(ctx);
    ctx->proxy_sock = -1;
    ctx->tx_transop_idx = edge->tx_transop_idx;

    /* Initialize all conns as free */
    for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
        ctx->conns[i].state = BYPASS_CONN_FREE;
        ctx->conns[i].local_sock = -1;
    }

    /* Create proxy listen socket */
    ctx->proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->proxy_sock < 0) {
        traceEvent(TRACE_WARNING, "bypass: failed to create proxy socket: %s",
                   BYPASS_STRERR(BYPASS_ERRNO()));
        ctx->enabled = 0;
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* Try to bind starting from proxy_port, incrementing on conflict.
     * We do NOT set SO_REUSEADDR during probing so that EADDRINUSE
     * reliably tells us the port is taken by another listener. */
    {
        uint16_t try_port = ctx->proxy_port;
        uint16_t max_try = 1000;
        int bind_ok = 0;

        for (uint16_t attempt = 0; attempt < max_try; attempt++) {
            addr.sin_port = htons(try_port);

            if (bind(ctx->proxy_sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                ctx->proxy_port = try_port;
                bind_ok = 1;
                break;
            }

            /* Port is taken, try next */
            if (attempt < max_try - 1) {
                closesocket(ctx->proxy_sock);
                ctx->proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
                if (ctx->proxy_sock < 0) {
                    traceEvent(TRACE_WARNING, "bypass: failed to create proxy socket: %s",
                               BYPASS_STRERR(BYPASS_ERRNO()));
                    ctx->enabled = 0;
                    return -1;
                }
            }

            try_port++;
            if (try_port == 0)
                try_port = 1024; /* wrap around, skip well-known */
        }

        if (!bind_ok) {
            traceEvent(TRACE_WARNING, "bypass: failed to bind proxy port after %u attempts",
                       max_try);
            closesocket(ctx->proxy_sock);
            ctx->proxy_sock = -1;
            ctx->enabled = 0;
            return -1;
        }
    }

    /* Now enable SO_REUSEADDR so listen doesn't fail on TIME_WAIT, etc. */
    {
        int optval = 1;
        setsockopt(ctx->proxy_sock, SOL_SOCKET, SO_REUSEADDR,
                   &optval, sizeof(optval));
    }

    /* Set non-blocking so accept never blocks */
#ifdef _WIN32
    {
        u_long mode = 1;
        ioctlsocket(ctx->proxy_sock, FIONBIO, &mode);
    }
#else
    {
        int fl = fcntl(ctx->proxy_sock, F_GETFL, 0);
        fcntl(ctx->proxy_sock, F_SETFL, fl | O_NONBLOCK);
    }
#endif

    if (listen(ctx->proxy_sock, 32) != 0) {
        traceEvent(TRACE_WARNING, "bypass: failed to listen on proxy port %u: %s",
                   ctx->proxy_port, BYPASS_STRERR(BYPASS_ERRNO()));
        closesocket(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        ctx->enabled = 0;
        return -1;
    }

    traceEvent(TRACE_INFO, "Bypass listening on %u",
               ctx->proxy_port);

#ifdef _WIN32
    /* Initialize WinDivert for transparent TCP redirect */
    if (!ctx->user_disabled) {
        extern int windivert_init(windivert_ctx_t *, uint16_t, uint32_t, uint32_t);
        windivert_ctx_t *wctx = (windivert_ctx_t *)calloc(1, sizeof(windivert_ctx_t));
        if (wctx) {
            uint32_t tap_ip_n = ntohl(dev_ip);
            if (windivert_init(wctx, ctx->proxy_port,
                                tap_ip_n, 0xFFFFFF00) == 0) {
                ctx->windivert_ctx = wctx;
                wctx->bypass_ctx = ctx;  /* set back-pointer for peer state checks */
            } else {
                free(wctx);
                traceEvent(TRACE_WARNING, "WinDivert init failed, bypass will be unavailable");
            }
        }
    }
#endif

    return 0;
}

void bypass_deinit(bypass_context_t *ctx)
{
    if (!ctx->enabled)
        return;

    /* Remove all iptables rules */
    bypass_del_all_rules(ctx);

    /* Close all connections */
    for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
        if (ctx->conns[i].state != BYPASS_CONN_FREE)
            bypass_free_conn(ctx, i);
    }

    /* Close proxy socket */
    if (ctx->proxy_sock >= 0) {
        closesocket(ctx->proxy_sock);
        ctx->proxy_sock = -1;
    }

#ifdef _WIN32
    /* Deinitialize WinDivert */
    if (ctx->windivert_ctx) {
        extern void windivert_deinit(windivert_ctx_t *);
        windivert_deinit((windivert_ctx_t *)ctx->windivert_ctx);
        free(ctx->windivert_ctx);
        ctx->windivert_ctx = NULL;
    }
#endif

    ctx->enabled = 0;
    traceEvent(TRACE_INFO, "bypass: deinitialized");
}

/* ===== Management interface ===== */

/** One-line bypass status (appended to main stat line) */
void bypass_mgmt_oneline(bypass_context_t *ctx, char *buf, size_t bufsize)
{
    if (!ctx || !ctx->enabled || ctx->user_disabled) {
        snprintf(buf, bufsize, "bypass off");
        return;
    }
    snprintf(buf, bufsize, "bypass on %u | tx/rx %zu/%zu bytes",
             ctx->proxy_port, ctx->bp_tx_bytes, ctx->bp_rx_bytes);
}

void bypass_mgmt_status(bypass_context_t *ctx, char *buf, size_t bufsize)
{
    size_t pos = 0;

    if (!ctx) {
        snprintf(buf, bufsize, "Bypass: UNAVAILABLE\n");
        return;
    }

    pos += snprintf(buf + pos, bufsize - pos,
                    "Bypass: %s (port %u)\n",
                    ctx->user_disabled ? "DISABLED" :
                    (ctx->enabled ? "ENABLED" : "UNAVAILABLE"),
                    ctx->proxy_port);

    pos += snprintf(buf + pos, bufsize - pos,
                    "  TX: %zu bytes  RX: %zu bytes\n",
                    ctx->bp_tx_bytes, ctx->bp_rx_bytes);

    pos += snprintf(buf + pos, bufsize - pos, "  Peers:\n");
    for (int i = 0; i < BYPASS_MAX_PEERS; i++) {
        if (ctx->peers[i].virt_ip == 0)
            continue;
        struct in_addr addr;
        addr.s_addr = htonl(ctx->peers[i].virt_ip);
        const char *state_str;
        switch (ctx->peers[i].state) {
        case BYPASS_PEER_PROBING:  state_str = "PROBING"; break;
        case BYPASS_PEER_CAPABLE:  state_str = "CAPABLE"; break;
        case BYPASS_PEER_TESTING:  state_str = "TESTING"; break;
        case BYPASS_PEER_ACTIVE:   state_str = "ACTIVE"; break;
        default:                   state_str = "NONE"; break;
        }
        pos += snprintf(buf + pos, bufsize - pos,
                        "    %-15s  %s\n", inet_ntoa(addr), state_str);
    }

    int active_conns = 0;
    for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
        if (ctx->conns[i].state != BYPASS_CONN_FREE)
            active_conns++;
    }
    pos += snprintf(buf + pos, bufsize - pos,
                    "  Active connections: %d\n", active_conns);
}

void bypass_mgmt_toggle(bypass_context_t *ctx)
{
    if (!ctx->enabled && !ctx->user_disabled) {
        /* Not available on this platform */
        return;
    }

    ctx->user_disabled = !ctx->user_disabled;

    if (ctx->user_disabled) {
        /* Disable: remove all rules, close conns */
        bypass_del_all_rules(ctx);
        for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
            if (ctx->conns[i].state != BYPASS_CONN_FREE)
                bypass_free_conn(ctx, i);
        }
        /* Reset all peers */
        for (int i = 0; i < BYPASS_MAX_PEERS; i++) {
            ctx->peers[i].virt_ip = 0;
            ctx->peers[i].state = BYPASS_PEER_NONE;
        }
        traceEvent(TRACE_INFO, "bypass: off by management");
    } else {
        /* Enable: re-negotiate with all known peers */
        struct peer_info *scan = ctx->edge->known_peers;
        while (scan) {
            if (scan->assigned_ip != 0)
                bypass_start_negotiation(ctx, scan);
            scan = scan->next;
        }
        traceEvent(TRACE_INFO, "bypass: on by management");
    }
}

/* ===== Helper: find peer address by virtual IP ===== */

int bypass_find_peer_addr(struct n2n_edge *eee, uint32_t virt_ip_host,
                           n2n_sock_t *out_addr)
{
    struct peer_info *scan = eee->known_peers;
    while (scan) {
        if (scan->assigned_ip == virt_ip_host) {
            if (scan->sock.family == AF_INET) {
                *out_addr = scan->sock;
                return 0;
            }
            if (scan->sock6.family == AF_INET6) {
                *out_addr = scan->sock6;
                return 0;
            }
        }
        scan = scan->next;
    }
    return -1;
}

static void bypass_update_peer_last_seen(struct n2n_edge *eee, uint32_t virt_ip_host)
{
    struct peer_info *scan = eee->known_peers;
    time_t now = n2n_now();
    while (scan) {
        if (scan->assigned_ip == virt_ip_host) {
            scan->last_seen = now;
            return;
        }
        scan = scan->next;
    }
}

struct peer_info *bypass_find_peer_info(struct n2n_edge *eee, uint32_t virt_ip_host)
{
    struct peer_info *scan = eee->known_peers;
    while (scan) {
        if (scan->assigned_ip == virt_ip_host)
            return scan;
        scan = scan->next;
    }
    return NULL;
}

static void bypass_conn_update_peer_last_seen(bypass_context_t *ctx, struct bypass_conn *c)
{
    /* Cached peer pointer is safe: bypass_peer_gone() calls
     * bypass_free_conn() which clears the conn (including peer).
     * So peer is only non-NULL while the peer is still valid. */
    if (c->peer) {
        c->peer->last_seen = n2n_now();
    } else if (c->remote_virt_ip != 0) {
        bypass_update_peer_last_seen(ctx->edge, c->remote_virt_ip);
    }
}

#else /* !__linux__ */

/* Stub implementations for non-Linux platforms */

int bypass_init(bypass_context_t *ctx, struct n2n_edge *edge,
                tuntap_dev *tap, uint32_t dev_ip, uint8_t dev_prefix)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->enabled = 0;
    ctx->user_disabled = 1;
    return 0;
}

void bypass_deinit(bypass_context_t *ctx) { }

void bypass_tick(bypass_context_t *ctx, time_t now) { }

int bypass_tap_forward(bypass_context_t *ctx, uint8_t *eth_frame, size_t len)
{
    return 0;
}

void bypass_handle_recv(bypass_context_t *ctx, const uint8_t *buf,
                        size_t len, const n2n_sock_t *sender) { }

void bypass_handle_local_read(bypass_context_t *ctx, int idx) { }

void bypass_handle_local_write(bypass_context_t *ctx, int idx) { }

void bypass_accept_proxy(bypass_context_t *ctx) { }

ssize_t bypass_encode(bypass_context_t *ctx, uint8_t *out, size_t out_len,
                      const uint8_t *in, size_t in_len, const n2n_mac_t dst_mac)
{
    return -1;
}

ssize_t bypass_decode(bypass_context_t *ctx, uint8_t *out, size_t out_len,
                      const uint8_t *in, size_t in_len, uint8_t algo_idx)
{
    return -1;
}

void bypass_add_peer_rule(bypass_context_t *ctx, uint32_t virt_ip_host) { }
void bypass_del_peer_rule(bypass_context_t *ctx, uint32_t virt_ip_host) { }
void bypass_del_all_rules(bypass_context_t *ctx) { }

size_t bypass_build_probe_frame(uint8_t *frame, uint32_t our_ip_n, int is_ack, int wants_bypass)
{
    return 0;
}

int bypass_handle_probe_frame(bypass_context_t *ctx, const uint8_t *frame,
                               size_t len, int is_ack, const n2n_sock_t *sender)
{
    return 0;
}

void bypass_start_negotiation(bypass_context_t *ctx, struct peer_info *peer) { }
void bypass_peer_gone(bypass_context_t *ctx, uint32_t virt_ip_host) { }

int bypass_get_pending_probes(bypass_context_t *ctx, uint8_t *buf, int max_probes,
                               uint32_t our_ip_n, const uint8_t *our_mac)
{
    return 0;
}

struct peer_info *bypass_find_peer_info(struct n2n_edge *eee, uint32_t virt_ip_host) { return NULL; }

int bypass_is_peer_active(bypass_context_t *ctx, uint32_t virt_ip_host)
{
    return 0;
}

bypass_peer_entry_t *bypass_find_peer(bypass_context_t *ctx, uint32_t virt_ip_host)
{
    return NULL;
}

void bypass_mgmt_status(bypass_context_t *ctx, char *buf, size_t bufsize)
{
    snprintf(buf, bufsize, "Bypass: not available (non-Linux)\n");
}

void bypass_mgmt_oneline(bypass_context_t *ctx, char *buf, size_t bufsize)
{
    snprintf(buf, bufsize, "bypass off");
}

void bypass_mgmt_toggle(bypass_context_t *ctx) { }

int bypass_find_peer_addr(struct n2n_edge *eee, uint32_t virt_ip_host,
                           n2n_sock_t *out_addr)
{
    return -1;
}

static void bypass_update_peer_last_seen(struct n2n_edge *eee, uint32_t virt_ip_host) { }

#endif /* __linux__ */
