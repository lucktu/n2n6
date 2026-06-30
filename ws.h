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

#ifndef N2N_WS_H
#define N2N_WS_H

#include <stdint.h>
#include <stddef.h>

/* SOCKET is already defined in n2n.h (non-Windows: #define SOCKET int; Windows: winsock2.h) */
#ifndef SOCKET
typedef int SOCKET;
#endif

/* WS connection state */
typedef enum {
    WS_FREE = 0,    /* Free slot (for sn connection table) */
    WS_CONNECTING,  /* TCP connecting (reserved; currently ws_connect is synchronous) */
    WS_HANDSHAKE,   /* Handshaking (reserved) */
    WS_OPEN,        /* Established, ready to send/receive */
    WS_CLOSED       /* Closed */
} ws_state_t;

/* Receive frame buffer: single n2n packet max N2N_PKT_BUF_SIZE(4096) + WS frame header max 14 bytes;
 * 8192 can hold 1 complete frame plus partial pre-read data of the next frame. */
#define N2N_WS_RX_BUF_SIZE 8192

/* WS single connection context.
 *
 * wss reserved: in the future, add to this struct:
 *     void *tls_ctx;     // Platform TLS context (Windows SChannel / system OpenSSL)
 *     int   use_tls;     // 0=plain ws, 1=wss
 * At that time, only the four functions ws_connect/ws_server_accept/ws_send/ws_recv
 * need TLS branches. */
typedef struct {
    SOCKET              fd;         /* TCP socket, -1 means free/closed */
    ws_state_t          state;
    int                 is_client;  /* 1=edge(client, must mask when sending); 0=sn(server) */
    uint8_t             rx_buf[N2N_WS_RX_BUF_SIZE];
    size_t              rx_len;     /* bytes already received in rx_buf */
    struct sockaddr_storage peer;   /* Peer address (accept/getpeername) */
    time_t              last_seen;  /* Last activity time, used for timeout cleanup (sn side) */
} ws_conn_t;


/* ===================== I/O gateway (wss reserved modification point) ===================== */

/* Initialize an idle ws_conn slot (fd=-1, state=WS_FREE) */
void    ws_init(ws_conn_t *c);

/* Client (edge): establish TCP connection and send WS Upgrade handshake, synchronously read 101 response.
 *   host: hostname or IP string (e.g. "1.2.3.4" or "example.com")
 *   port: port (host byte order)
 * On success state=WS_OPEN, data phase uses blocking socket (read scheduled by select).
 * Connection timeout 5s, handshake timeout 5s. Returns 0 success, <0 failure. */
int     ws_connect(ws_conn_t *c, const char *host, uint16_t port);

/* Server (sn): accept a new connection and complete WS handshake (synchronous).
 *   listen_fd: TCP listening socket that has been set to listen
 * On success state=WS_OPEN. Returns 0 success, <0 failure (caller should discard the connection). */
int     ws_server_accept(ws_conn_t *c, SOCKET listen_fd);

/* Send: wrap payload in a WS binary frame and transmit (client auto-masks).
 *   Returns total bytes sent (including frame header), <0 failure. */
ssize_t ws_send(ws_conn_t *c, const void *payload, size_t len);

/* Send ping control frame (application-level heartbeat, prevent NAT timeout).
 *   Peer's ws_recv will auto-reply with pong upon receiving ping.
 *   Returns: 0=success, -1=connection dead(should close), -2=temporary EAGAIN(should not close connection). */
int     ws_ping(ws_conn_t *c);

/* Receive: read and decode a complete data frame from the connection.
 *   Returns >0 = payload length (filled into out);
 *           0  = no complete frame yet (needs more data, caller should retry after select indicates readable);
 *           <0 = connection closed/error.
 *   Automatically handles ping(reply pong) / pong / close control frames. */
ssize_t ws_recv(ws_conn_t *c, void *out, size_t outlen);

/* Close connection: close fd, set state=WS_CLOSED, fd=-1.
 *   NOTE: does not clear the caller's peer_info.ws pointer (the caller is responsible). */
void    ws_close(ws_conn_t *c);

#endif /* N2N_WS_H */
