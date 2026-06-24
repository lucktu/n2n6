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

#ifndef BYPASS_H
#define BYPASS_H

#include "ikcp.h"

struct peer_info;  /* forward declaration */

#define BYPASS_MAGIC_0           0xAE
#define BYPASS_MAGIC_1           0xAE
#define BYPASS_MAGIC_2           0xB1
#define BYPASS_HEADER_SIZE       10

#define BYPASS_DEFAULT_PORT      9000
#define BYPASS_MAX_CONNS         64
#define BYPASS_MAX_PAYLOAD       32768  /* Per-cycle aggregate from TCP socket. Split into chunks for encryption. */
#define BYPASS_ENCRYPT_OVERHEAD  64
/* Max plaintext bytes per encryption chunk. Must be large enough for
 * LAN MTU's max segment (8216 + IKCP_OVERHEAD ≈ 8240). PKT_BUF_SIZE
 * must accommodate the largest encrypted output. At runtime, WAN mode
 * limits per-cycle reads to 4096 (small TCP read = small chunk). */
#define BYPASS_MAX_CHUNK         32768
#define BYPASS_MAX_PEERS         32
/* Send buffer for local_sock overflow. 1MB prevents rmt_wnd collapse
 * on high-speed LAN. WAN uses smaller effective burst via read limit. */
#define BYPASS_TX_BUF_SIZE       (1024 * 1024)  /* 1MB */
/* UDP packet buffer: header + encrypted KCP segment (one segment per packet) */
#define BYPASS_PKT_BUF_SIZE      (BYPASS_HEADER_SIZE + BYPASS_MAX_CHUNK + BYPASS_ENCRYPT_OVERHEAD)

/* KCP MTU for LAN vs WAN. LAN uses 16384 — reduces KCP segment count
 * per TCP read cycle by half vs 8216, improving throughput for
 * cache-sensitive ciphers (Twofish, AES) with minimal fragmentation
 * risk on lossless LAN links. WAN uses 1400 to avoid IP fragmentation
 * on lossy links (1500 MTU, 1 fragment per packet). Both are within
 * n2n's 16384-byte transform buffer limit. */
#define KCP_MTU_LAN              8216
#define KCP_MTU_WAN              1400

/* Flags in bypass header byte [5] */
#define BYPASS_FLAG_SYN          0x01
#define BYPASS_FLAG_FIN          0x04
#define BYPASS_FLAG_RAW          0x08   /* raw IP frame (ICMP etc.) */
#define BYPASS_FLAG_TEST         0x10   /* handshake test packet */
#define BYPASS_FLAG_TEST_ACK     0x20   /* handshake test ack */
#define BYPASS_FLAG_KCP          0x40   /* KCP reliable transport segment */

/* Ethernet types for bypass probe frames (carried via n2n old path) */
#define BYPASS_ETYPE_PROBE       0x9001
#define BYPASS_ETYPE_PROBE_ACK   0x9002

/* Connection states */
#define BYPASS_CONN_FREE         0
#define BYPASS_CONN_CONNECTING   1
#define BYPASS_CONN_ESTABLISHED  2

/* Per-peer bypass negotiation states */
#define BYPASS_PEER_NONE         0   /* no bypass for this peer */
#define BYPASS_PEER_PROBING      1   /* sent probe, waiting ack */
#define BYPASS_PEER_CAPABLE      2   /* peer responded to probe */
#define BYPASS_PEER_TESTING      3   /* sent test, waiting ack */
#define BYPASS_PEER_ACTIVE       4   /* bypass active, iptables rule added */
#define BYPASS_PEER_UNAVAILABLE  5   /* probe failed 3 times, wait before retry */

/* Timeouts (seconds) */
#define BYPASS_PROBE_TIMEOUT     10
#define BYPASS_TEST_TIMEOUT      5
#define BYPASS_CONN_TIMEOUT      120
#define BYPASS_UNAVAILABLE_RETRY 300  /* retry unavailable peer after 5 minutes */

/* ===== Data structures ===== */

struct bypass_conn
{
    SOCKET   local_sock;        /* accepted socket from iptables redirect, or connected to localhost */
    time_t   last_active;
    uint8_t  state;             /* BYPASS_CONN_* */
    uint32_t conn_id;           /* connection identifier */
    uint32_t remote_virt_ip;    /* remote peer's virtual IP (host order) */
    uint16_t remote_port;       /* remote peer's port (the service port, e.g. 5201) */
    uint16_t local_port;        /* our port (the service port for remote-initiated) */
    n2n_sock_t peer_addr;       /* peer's direct n2n address for sending */
    struct peer_info *peer;     /* cached peer_info for fast last_seen update */
    uint8_t  initiator;         /* 1=we initiated, 0=remote initiated */
    uint8_t  fin_sent;          /* 1=we sent FIN (local EOF), no more reads */
    uint8_t  fin_rcvd;          /* 1=remote sent FIN, no more writes to local */
    size_t   tx_bytes;
    size_t   rx_bytes;
    /* KCP reliable transport (built-in congestion control) */
    ikcpcb *kcp;                /* NULL until handshake completes */
    uint8_t *kcp_buf;           /* reassembly buffer */
    void    *user_data;         /* back-pointer to bypass_context_t */
    IUINT64  kcp_base;          /* KCP clock base (ms from CLOCK_MONOTONIC at conn init) */
    uint8_t *tx_buf;            /* [BYPASS_TX_BUF_SIZE] pending data to send to local_sock */
    size_t   tx_buf_len;        /* bytes in tx_buf */
    uint8_t *agg_buf;           /* [BYPASS_MAX_PAYLOAD] aggregation buffer for local read */
    uint8_t *pkt_buf;           /* [BYPASS_PKT_BUF_SIZE] encoded packet buffer */
    size_t   max_read_limit;    /* per-cycle TCP read limit: 0=default(BYPASS_MAX_PAYLOAD), 4096=WAN */
};

typedef struct
{
    uint32_t    virt_ip;        /* host order, 0 = empty slot */
    uint8_t     state;          /* BYPASS_PEER_* */
    time_t      state_time;     /* when state was entered */
    uint8_t     probe_sent;     /* PROBING: 1=sent, 0=needs send (or retry) */
    uint8_t     probe_retries;  /* PROBING: total retry count (max 3) */
    uint8_t     is_lan;         /* 1=same LAN (determined at peer negotiation, when peer_info is reliable) */
    n2n_sock_t  peer_addr;      /* peer's direct address for sending bypass packets */
} bypass_peer_entry_t;

typedef struct bypass_context_s
{
    struct n2n_edge  *edge;
    tuntap_dev       *tap_device;
    int               enabled;         /* 1 on Linux, 0 on other OS */
    int               user_disabled;   /* set by -x flag */
    uint8_t           tx_transop_idx;  /* transop index for encoding */
    size_t            bp_tx_bytes;
    size_t            bp_rx_bytes;
    size_t            bp_tx_pkts;      /* packet count for mgmt display */
    size_t            bp_rx_pkts;
    uint32_t          tap_ip;          /* TAP device IP (network order) */
    uint8_t           tap_prefix;
    uint8_t           tap_mac[6];
    SOCKET            proxy_sock;      /* TCP listen socket for iptables redirect */
    uint16_t          proxy_port;      /* proxy listen port */
    uint32_t          conn_id_seq;     /* next conn_id to allocate */
    struct bypass_conn conns[BYPASS_MAX_CONNS];
    bypass_peer_entry_t peers[BYPASS_MAX_PEERS];
    int               peer_count;      /* number of peers in non-NONE state */
} bypass_context_t;

/* Fast check: whether any bypass peer negotiation is in progress or active.
 * Used as a guard in hot paths to skip bypass overhead when not needed. */
static inline int bypass_has_peers(bypass_context_t *ctx) {
    return ctx && ctx->peer_count > 0;
}

/* Fast check: whether any connection has an active KCP session.
 * Used to switch select() timeout from 1s to 10ms for responsive KCP updates. */
static inline int bypass_has_kcp_conns(bypass_context_t *ctx) {
    if (!ctx) return 0;
    for (int i = 0; i < BYPASS_MAX_CONNS; i++) {
        if (ctx->conns[i].state != BYPASS_CONN_FREE && ctx->conns[i].kcp)
            return 1;
    }
    return 0;
}

/* ===== Functions ===== */

/* Init / deinit */
int  bypass_init(bypass_context_t *ctx, struct n2n_edge *edge,
                 tuntap_dev *tap, uint32_t dev_ip, uint8_t dev_prefix);
void bypass_deinit(bypass_context_t *ctx);

/* Main loop hooks */
void bypass_tick(bypass_context_t *ctx, time_t now);
int  bypass_tap_forward(bypass_context_t *ctx, uint8_t *eth_frame, size_t len);
void bypass_handle_recv(bypass_context_t *ctx, const uint8_t *buf,
                        size_t len, const n2n_sock_t *sender);
void bypass_handle_local_read(bypass_context_t *ctx, int idx);
void bypass_handle_local_write(bypass_context_t *ctx, int idx);
void bypass_accept_proxy(bypass_context_t *ctx);

/* Encryption (reuse n2n transop) */
ssize_t bypass_encode(bypass_context_t *ctx, uint8_t *out, size_t out_len,
                      const uint8_t *in, size_t in_len, const n2n_mac_t dst_mac);
ssize_t bypass_decode(bypass_context_t *ctx, uint8_t *out, size_t out_len,
                      const uint8_t *in, size_t in_len, uint8_t algo_idx);

/* iptables management */
void bypass_add_peer_rule(bypass_context_t *ctx, uint32_t virt_ip_host);
void bypass_del_peer_rule(bypass_context_t *ctx, uint32_t virt_ip_host);
void bypass_del_all_rules(bypass_context_t *ctx);

/* Probe frames (carried via n2n old path) */
size_t bypass_build_probe_frame(uint8_t *frame, uint32_t our_ip_n, int is_ack, int wants_bypass);
int  bypass_handle_probe_frame(bypass_context_t *ctx, const uint8_t *frame,
                               size_t len, int is_ack, const n2n_sock_t *sender);

/* Per-peer bypass state management */
void bypass_start_negotiation(bypass_context_t *ctx, struct peer_info *peer);
void bypass_peer_gone(bypass_context_t *ctx, uint32_t virt_ip_host);
int  bypass_is_peer_active(bypass_context_t *ctx, uint32_t virt_ip_host);
bypass_peer_entry_t *bypass_find_peer(bypass_context_t *ctx, uint32_t virt_ip_host);

/* Check if any peer needs a probe frame to be sent (via n2n old path).
 * Returns the number of probe frames built into the provided buffer.
 * Each frame is bypass_build_probe_frame-sized (19 bytes). */
int  bypass_get_pending_probes(bypass_context_t *ctx, uint8_t *buf, int max_probes,
                               uint32_t our_ip_n, const uint8_t *our_mac);

/* Management interface */
void bypass_mgmt_status(bypass_context_t *ctx, char *buf, size_t bufsize);
void bypass_mgmt_oneline(bypass_context_t *ctx, char *buf, size_t bufsize);
void bypass_mgmt_toggle(bypass_context_t *ctx);

/* Helper: find peer's direct n2n address by virtual IP.
 * Returns 0 on success, -1 if not found. */
int bypass_find_peer_addr(struct n2n_edge *eee, uint32_t virt_ip_host,
                          n2n_sock_t *out_addr);

/* Helper: find peer_info by virtual IP (host order). */
struct peer_info *bypass_find_peer_info(struct n2n_edge *eee, uint32_t virt_ip_host);

#endif /* BYPASS_H */
