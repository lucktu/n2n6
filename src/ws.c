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

#include "n2n.h"      /* Include socket headers + SOCKET definition + ws.h */
#include "ws.h"
#include "random.h"   /* random_bytes (mask key / handshake key) */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#define WS_ERRNO() WSAGetLastError()
#define WS_EAGAIN  WSAEWOULDBLOCK
#define WS_EINTR   WSAEINTR
#define WS_ETIMEOUT WSAETIMEDOUT
#else
#define WS_ERRNO() errno
#define WS_EAGAIN  EAGAIN
#define WS_EINTR   EINTR
#define WS_ETIMEOUT EAGAIN   /* Linux SO_RCVTIMEO timeout returns EAGAIN */
#include <netinet/tcp.h>
#endif


/* ============================ platform helpers ============================ */

static void ws_set_nonblock(SOCKET fd) {
#ifdef _WIN32
    u_long m = 1; ioctlsocket(fd, FIONBIO, &m);
#else
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
#endif
}

static void ws_set_block(SOCKET fd) {
#ifdef _WIN32
    u_long m = 0; ioctlsocket(fd, FIONBIO, &m);
#else
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
#endif
}

static void ws_set_timeo(SOCKET fd, int sec) {
    struct timeval tv; tv.tv_sec = sec; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
}

/* Aggressive TCP keepalive: prevent NAT timeout (idle 10s probe, 5s interval,
 * 3 failures mark dead). Must explicitly set interval — system default is 2 hours,
 * NAT times out in 30-60 seconds. Also set TCP_NODELAY to disable Nagle, preventing
 * WS small frames (ping/pong/register) from being coalesced and delayed. */
static void ws_set_keepalive(SOCKET fd) {
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&on, sizeof(on));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&on, sizeof(on));
#ifdef _WIN32
    {
        struct tcp_keepalive ka;
        ka.onoff = 1;
        ka.keepalivetime = 25000;    /* 25s idle */
        ka.keepaliveinterval = 5000; /* 5s interval */
        DWORD ret;
        WSAIoctl(fd, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &ret, NULL, NULL);
    }
#elif defined(TCP_KEEPIDLE)
    {
        int idle = 25, intvl = 5, cnt = 3;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    }
#endif
}

/* Blocking send of all bytes (loop until done or error). Socket is in blocking mode.
 * Return values:
 *    0  = all sent successfully
 *   -1  = connection dead (send returned 0 peer closed, or EPIPE/ECONNRESET fatal error)
 *   -2  = temporary failure (EAGAIN/EWOULDBLOCK/SO_SNDTIMEO timeout, TCP buffer full)
 *         Caller should not close the connection, just drop the current packet;
 *         can continue on next select readable. */
static int ws_send_all(SOCKET fd, const uint8_t *buf, size_t len) {
    size_t s = 0;
    while (s < len) {
        ssize_t r = send(fd, (const char*)buf + s, len - s, 0);
        if (r > 0) { s += (size_t)r; continue; }
        if (r == 0) return -1;  /* Peer closed: connection dead */
        int err = WS_ERRNO();
        if (err == WS_EINTR) continue;
        if (err == WS_EAGAIN || err == WS_ETIMEOUT)
            return -2;  /* Temporary: TCP buffer full, don't close connection */
        return -1;      /* EPIPE/ECONNRESET etc.: connection dead */
    }
    return 0;
}

/* Blocking read of HTTP header (until "\r\n\r\n"), store in buf (null-terminated).
 * Returns total bytes read (including possible pre-read WS frame data at the end),
 * <0 failure. Socket must be blocking with SO_RCVTIMEO set. */
static int ws_read_http(SOCKET fd, char *buf, size_t bufsz) {
    size_t n = 0;
    while (n < bufsz - 1) {
        ssize_t r = recv(fd, buf + n, bufsz - 1 - n, 0);
        if (r < 0) {
            int err = WS_ERRNO();
            if (err == WS_EINTR) continue;
            return -1;
        }
        if (r == 0) return -1; /* Peer closed */
        n += (size_t)r;
        buf[n] = '\0';
        if (n >= 4 && strstr(buf, "\r\n\r\n")) return (int)n;
    }
    return -1; /* Header too large */
}


/* ============================ SHA-1 (self-contained) ============================ */

typedef struct {
    uint32_t h[5];
    uint8_t  buf[64];
    uint64_t len;
    int      blen;
} sha1_ctx;

static void sha1_init(sha1_ctx *c) {
    c->h[0] = 0x67452301; c->h[1] = 0xEFCDAB89; c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476; c->h[4] = 0xC3D2E1F0;
    c->blen = 0; c->len = 0;
}

static void sha1_block(sha1_ctx *c, const uint8_t *p) {
    uint32_t w[80], a, b, cc, d, e, f, k, t;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | ((uint32_t)p[i*4+3]);
    for (; i < 80; i++) {
        t = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = (t << 1) | (t >> 31);
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & cc) | ((~b) & d);       k = 0x5A827999; }
        else if (i < 40) { f = b ^ cc ^ d;                  k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDC; }
        else             { f = b ^ cc ^ d;                  k = 0xCA62C1D6; }
        t = ((a << 5) | (a >> 27)) + e + k + f + w[i];
        e = d; d = cc; cc = (b << 30) | (b >> 2); b = a; a = t;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}

static void sha1_update(sha1_ctx *c, const uint8_t *d, size_t n) {
    c->len += n;
    while (n) {
        int r = 64 - c->blen;
        int m = ((size_t)r > n) ? (int)n : r;
        memcpy(c->buf + c->blen, d, m);
        c->blen += m; d += m; n -= m;
        if (c->blen == 64) { sha1_block(c, c->buf); c->blen = 0; }
    }
}

static void sha1_final(sha1_ctx *c, uint8_t out[20]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha1_update(c, &pad, 1);
    pad = 0;
    while (c->blen != 56) sha1_update(c, &pad, 1);
    {
        uint8_t lb[8];
        int i;
        for (i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8*i));
        sha1_update(c, lb, 8);
    }
    {
        int i;
        for (i = 0; i < 5; i++) {
            out[i*4]   = (uint8_t)(c->h[i] >> 24);
            out[i*4+1] = (uint8_t)(c->h[i] >> 16);
            out[i*4+2] = (uint8_t)(c->h[i] >> 8);
            out[i*4+3] = (uint8_t)(c->h[i]);
        }
    }
}


/* ============================ base64 (encode only) ============================ */

static const char b64tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64encode(const uint8_t *in, size_t n, char *out) {
    size_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        out[o++] = b64tab[in[i] >> 2];
        out[o++] = b64tab[((in[i] & 3) << 4) | (in[i+1] >> 4)];
        out[o++] = b64tab[((in[i+1] & 15) << 2) | (in[i+2] >> 6)];
        out[o++] = b64tab[in[i+2] & 63];
    }
    if (i < n) {
        out[o++] = b64tab[in[i] >> 2];
        if (i + 1 < n) {
            out[o++] = b64tab[((in[i] & 3) << 4) | (in[i+1] >> 4)];
            out[o++] = b64tab[(in[i+1] & 15) << 2];
            out[o++] = '=';
        } else {
            out[o++] = b64tab[(in[i] & 3) << 4];
            out[o++] = '=';
            out[o++] = '=';
        }
    }
    out[o] = '\0';
    return o;
}


/* ============================ public interface ============================ */

void ws_init(ws_conn_t *c) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->state = WS_FREE;
    c->is_client = 0;
    c->rx_len = 0;
}

void ws_close(ws_conn_t *c) {
    if (c->fd >= 0) {
        /* Best-effort send close frame before closing (ignore failure) */
        uint8_t closefrm[2] = { 0x88, 0x00 };
        if (c->state == WS_OPEN)
            (void)ws_send_all(c->fd, closefrm, 2);
#ifdef _WIN32
        closesocket(c->fd);
#else
        close(c->fd);
#endif
    }
    c->fd = -1;
    c->state = WS_CLOSED;
    c->rx_len = 0;
}


/* ---- Client handshake: compute and send Upgrade, read and verify 101 ---- */
static int ws_client_handshake(SOCKET fd, const char *host, uint16_t port,
                               ws_conn_t *c) {
    uint8_t key[16];
    char keyb64[32];
    char req[512];
    int rl;
    char hbuf[1024];
    int hl;
    char *eoh;

    random_bytes(NULL, key, 16);
    b64encode(key, 16, keyb64);

    rl = snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        host, (unsigned)port, keyb64);

    if (rl <= 0 || (size_t)rl >= sizeof(req)) return -1;
    if (ws_send_all(fd, (const uint8_t*)req, (size_t)rl) < 0) return -1;

    hl = ws_read_http(fd, hbuf, sizeof(hbuf));
    if (hl < 0) return -1;

    /* Verify status line 101 */
    if (strstr(hbuf, " 101 ") == NULL && strncmp(hbuf, "HTTP/1.1 101", 12) != 0
        && strstr(hbuf, "101 Switching") == NULL)
        return -1;

    /* Move pre-read bytes after header (if any) into rx_buf as the first frame of data phase */
    eoh = strstr(hbuf, "\r\n\r\n");
    if (eoh) {
        size_t consumed = (size_t)(eoh - hbuf) + 4;
        size_t left = (size_t)hl - consumed;
        if (left > 0 && left <= sizeof(c->rx_buf)) {
            memcpy(c->rx_buf, hbuf + consumed, left);
            c->rx_len = left;
        }
    }
    return 0;
}


/* ---- Server handshake: read Upgrade, reply 101 ---- */
static int ws_server_handshake(SOCKET fd, ws_conn_t *c) {
    char hbuf[1024];
    int hl;
    char *k, *eol;
    char key[64];
    int ki = 0;
    char accin[256];
    int al;
    uint8_t digest[20];
    char accb64[40];
    char resp[512];
    int rl;
    sha1_ctx sc;
    char *eoh;

    hl = ws_read_http(fd, hbuf, sizeof(hbuf));
    if (hl < 0) return -1;

    /* Extract Sec-WebSocket-Key (case-insensitive) */
    k = strstr(hbuf, "Sec-WebSocket-Key:");
    if (!k) k = strstr(hbuf, "sec-websocket-key:");
    if (!k) return -1;
    k += strlen("Sec-WebSocket-Key:");
    while (*k == ' ' || *k == '\t') k++;
    eol = k;
    while (*eol && *eol != '\r' && *eol != '\n' && ki < 63) {
        key[ki++] = *eol++;
    }
    key[ki] = '\0';
    if (ki == 0) return -1;

    /* accept = base64( sha1( key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ) ) */
    al = snprintf(accin, sizeof(accin), "%s%s",
                  key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    if (al <= 0 || (size_t)al >= sizeof(accin)) return -1;
    sha1_init(&sc);
    sha1_update(&sc, (const uint8_t*)accin, (size_t)al);
    sha1_final(&sc, digest);
    b64encode(digest, 20, accb64);

    rl = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n",
        accb64);
    if (rl <= 0 || (size_t)rl >= sizeof(resp)) return -1;
    if (ws_send_all(fd, (const uint8_t*)resp, (size_t)rl) < 0) return -1;

    /* Move pre-read bytes after header into rx_buf */
    eoh = strstr(hbuf, "\r\n\r\n");
    if (eoh) {
        size_t consumed = (size_t)(eoh - hbuf) + 4;
        size_t left = (size_t)hl - consumed;
        if (left > 0 && left <= sizeof(c->rx_buf)) {
            memcpy(c->rx_buf, hbuf + consumed, left);
            c->rx_len = left;
        }
    }
    return 0;
}


int ws_connect(ws_conn_t *c, const char *host, uint16_t port) {
    struct addrinfo hints, *res = NULL, *rp;
    char ps[16];
    SOCKET fd = -1;
    int connected = 0;

    ws_init(c);
    c->is_client = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(ps, sizeof(ps), "%u", (unsigned)port);

    if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) {
        traceEvent(TRACE_WARNING, "ws_connect: resolve %s:%u failed", host, (unsigned)port);
        return -1;
    }

    for (rp = res; rp && !connected; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        /* Non-blocking connect + 5 second timeout (cross-platform) */
        ws_set_nonblock(fd);
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            memcpy(&c->peer, rp->ai_addr, rp->ai_addrlen);
            connected = 1;
            break;
        }
        {
            int err = WS_ERRNO();
#ifdef _WIN32
            if (err != WSAEWOULDBLOCK) { closesocket(fd); fd = -1; continue; }
#else
            if (err != EINPROGRESS && err != EWOULDBLOCK) {
                closesocket(fd); fd = -1; continue;
            }
#endif
            {
                fd_set wset;
                struct timeval tv;
                int sr;
                int soerr = 0;
                socklen_t sl = sizeof(soerr);
                FD_ZERO(&wset);
                FD_SET(fd, &wset);
                tv.tv_sec = 5; tv.tv_usec = 0;
                sr = select((int)fd + 1, NULL, &wset, NULL, &tv);
                if (sr <= 0) { closesocket(fd); fd = -1; continue; }
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                               (char*)&soerr, &sl) != 0 || soerr != 0) {
                    closesocket(fd); fd = -1; continue;
                }
                memcpy(&c->peer, rp->ai_addr, rp->ai_addrlen);
                connected = 1;
            }
        }
    }
    freeaddrinfo(res);
    if (!connected || fd < 0) {
        traceEvent(TRACE_WARNING, "ws_connect: TCP connect to %s:%u failed (timeout/refused)",
                   host, (unsigned)port);
        return -1;
    }

    c->fd = fd;
    /* Handshake phase: blocking + 5 second timeout */
    ws_set_block(fd);
    ws_set_timeo(fd, 5);

    if (ws_client_handshake(fd, host, port, c) < 0) {
        traceEvent(TRACE_WARNING, "ws_connect: WS handshake to %s:%u failed", host, (unsigned)port);
        ws_close(c);
        return -1;
    }

    /* Data phase: receive timeout 2s, send timeout 50ms (drop packet when buffer full,
     * don't block main loop) */
    {
        struct timeval tv;
        tv.tv_sec = 2; tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        tv.tv_sec = 0; tv.tv_usec = 50000;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    }
    /* TCP keepalive + TCP_NODELAY */
    ws_set_keepalive(fd);

    c->state = WS_OPEN;
    c->last_seen = time(NULL);
    return 0;
}


int ws_server_accept(ws_conn_t *c, SOCKET listen_fd) {
    socklen_t plen;
    SOCKET fd;

    ws_init(c);
    c->is_client = 0;

    plen = (socklen_t)sizeof(c->peer);
    fd = accept(listen_fd, (struct sockaddr*)&c->peer, &plen);
    if (fd < 0) return -1;

    c->fd = fd;
    ws_set_block(fd);
    ws_set_timeo(fd, 5);

    if (ws_server_handshake(fd, c) < 0) {
        ws_close(c);
        return -1;
    }

    /* Data phase: receive timeout 2s, send timeout 50ms (same as ws_connect) + keepalive */
    {
        struct timeval tv;
        tv.tv_sec = 2; tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        tv.tv_sec = 0; tv.tv_usec = 50000;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    }
    ws_set_keepalive(fd);

    c->state = WS_OPEN;
    c->last_seen = time(NULL);
    return 0;
}


/* Send a control frame (pong/close), payload <= 125 */
static int ws_send_control(ws_conn_t *c, uint8_t opcode,
                           const uint8_t *payload, size_t len) {
    uint8_t hdr[6];
    size_t hlen = 2;
    int mask = c->is_client;
    uint8_t mk[4];

    if (len > 125) len = 125;
    hdr[0] = 0x80 | opcode;  /* FIN + opcode */
    if (mask) {
        random_bytes(NULL, mk, 4);
        hdr[1] = (uint8_t)(0x80 | len);
        memcpy(hdr + 2, mk, 4);
        hlen = 6;
    } else {
        hdr[1] = (uint8_t)len;
    }
    {
        int sr = ws_send_all(c->fd, hdr, hlen);
        if (sr < 0) return (sr == -1) ? -1 : -2;  /* -1=dead, -2=EAGAIN pass-through */
    }
    if (len) {
        uint8_t buf[125];
        size_t i;
        int sr;
        memcpy(buf, payload, len);
        if (mask) for (i = 0; i < len; i++) buf[i] ^= mk[i & 3];
        sr = ws_send_all(c->fd, buf, len);
        if (sr < 0) return (sr == -1) ? -1 : -2;
    }
    return 0;
}

/* Send ping control frame (application-level heartbeat, prevent NAT timeout).
 * Returns: 0=success, -1=connection dead, -2=temporary EAGAIN(caller should not close connection). */
int ws_ping(ws_conn_t *c) {
    if (c->state != WS_OPEN || c->fd < 0) return -1;
    return ws_send_control(c, 0x9, NULL, 0);
}


ssize_t ws_send(ws_conn_t *c, const void *payload, size_t len) {
    uint8_t hdr[14];
    size_t hlen = 0;
    int mask = c->is_client;
    uint8_t mk[4];
    uint8_t buf[N2N_PKT_BUF_SIZE];
    size_t outlen;

    if (c->state != WS_OPEN || c->fd < 0) return -1;
    if (len > sizeof(buf)) return -1;  /* n2n packet should not exceed N2N_PKT_BUF_SIZE */

    hdr[0] = 0x82;  /* FIN + binary opcode */
    if (mask) random_bytes(NULL, mk, 4);

    if (len <= 125) {
        hdr[1] = (uint8_t)((mask ? 0x80 : 0) | len);
        hlen = 2;
    } else if (len <= 65535) {
        hdr[1] = (uint8_t)((mask ? 0x80 : 0) | 126);
        hdr[2] = (uint8_t)(len >> 8);
        hdr[3] = (uint8_t)len;
        hlen = 4;
    } else {
        hdr[1] = (uint8_t)((mask ? 0x80 : 0) | 127);
        hdr[2] = hdr[3] = hdr[4] = hdr[5] = 0;
        hdr[6] = (uint8_t)(len >> 24);
        hdr[7] = (uint8_t)(len >> 16);
        hdr[8] = (uint8_t)(len >> 8);
        hdr[9] = (uint8_t)len;
        hlen = 10;
    }
    if (mask) { memcpy(hdr + hlen, mk, 4); hlen += 4; }

    /* Send frame header first.
     * ws_send_all: -1=connection dead(close connection), -2=temporary EAGAIN(don't close,
     * drop this packet) */
    {
        int sr = ws_send_all(c->fd, hdr, hlen);
        if (sr < 0) {
            if (sr == -1) ws_close(c);
            return -1;
        }
    }

    /* Then send payload (client must mask) */
    if (len) {
        size_t i;
        int sr;
        outlen = len;
        memcpy(buf, payload, len);
        if (mask) for (i = 0; i < len; i++) buf[i] ^= mk[i & 3];
        sr = ws_send_all(c->fd, buf, outlen);
        if (sr < 0) {
            if (sr == -1) ws_close(c);
            return -1;
        }
    }

    c->last_seen = time(NULL);
    return (ssize_t)(hlen + len);
}


/* Consume need bytes from rx_buf head, shift remainder forward */
static void ws_consume(ws_conn_t *c, size_t need) {
    if (need >= c->rx_len) {
        c->rx_len = 0;
    } else {
        memmove(c->rx_buf, c->rx_buf + need, c->rx_len - need);
        c->rx_len -= need;
    }
}


ssize_t ws_recv(ws_conn_t *c, void *out, size_t outlen) {
    if (c->state != WS_OPEN || c->fd < 0) return -1;

    for (;;) {
        /* Try to decode a complete frame from rx_buf */
        if (c->rx_len >= 2) {
            uint8_t b0 = c->rx_buf[0];
            uint8_t b1 = c->rx_buf[1];
            int opcode = b0 & 0x0f;
            int masked = (b1 & 0x80) ? 1 : 0;
            size_t plen = b1 & 0x7f;
            size_t extlen = 0;
            size_t payload_len;
            size_t need;
            size_t hdrlen;
            uint8_t *mask_key;
            uint8_t *payload;
            size_t i;

            if (plen == 126) {
                if (c->rx_len < 4) goto needmore;
                payload_len = ((size_t)c->rx_buf[2] << 8) | c->rx_buf[3];
                if (payload_len > N2N_PKT_BUF_SIZE) {
                    ws_close(c);
                    return -1;
                }
                extlen = 2;
            } else if (plen == 127) {
                if (c->rx_len < 10) goto needmore;
                /* Validate: upper 32 bits must be zero (n2n packets fit in 32-bit);
                 * non-zero indicates a malicious/malformed frame. */
                if (c->rx_buf[2] || c->rx_buf[3] || c->rx_buf[4] || c->rx_buf[5]) {
                    ws_close(c);
                    return -1;
                }
                payload_len = ((size_t)c->rx_buf[6] << 24) |
                              ((size_t)c->rx_buf[7] << 16) |
                              ((size_t)c->rx_buf[8] << 8) |
                              ((size_t)c->rx_buf[9]);
                /* Reject oversized payloads (n2n packets are <= N2N_PKT_BUF_SIZE) */
                if (payload_len > N2N_PKT_BUF_SIZE) {
                    ws_close(c);
                    return -1;
                }
                extlen = 8;
            } else {
                payload_len = plen;
            }

            hdrlen = 2 + extlen + (masked ? 4 : 0);
            need = hdrlen + payload_len;
            if (c->rx_len < need) goto needmore;

            mask_key = masked ? (c->rx_buf + 2 + extlen) : NULL;
            payload = c->rx_buf + hdrlen;

            /* Unmask */
            if (masked)
                for (i = 0; i < payload_len; i++) payload[i] ^= mask_key[i & 3];

            /* Handle by opcode */
            if (opcode == 0x8) {
                /* close */
                ws_consume(c, need);
                ws_close(c);
                return -1;
            } else if (opcode == 0x9) {
                /* ping -> pong */
                ws_send_control(c, 0xA, payload, payload_len);
                ws_consume(c, need);
                continue;  /* Continue to decode next frame */
            } else if (opcode == 0xA) {
                /* pong */
                ws_consume(c, need);
                continue;
            } else {
                /* binary(0x2) / text(0x1): treat as data.
                 * Continuation(0x0): protocol error (n2n never fragments).
                 * FIN must be set (n2n never sends fragmented messages). */
                if (opcode == 0x0) {
                    /* Unexpected continuation frame without preceding fragment */
                    ws_close(c);
                    return -1;
                }
                if (!(b0 & 0x80)) {
                    /* Fragmented frame: n2n never fragments, treat as protocol error */
                    ws_close(c);
                    return -1;
                }
                size_t copy = (payload_len < outlen) ? payload_len : outlen;
                memcpy(out, payload, copy);
                ws_consume(c, need);
                c->last_seen = time(NULL);
                return (ssize_t)copy;
            }
        }

needmore:
        /* Non-blocking recv: if data read, continue parsing; if no data, return 0
         * to wait for next select */
        {
            ssize_t r;
            if (c->rx_len >= sizeof(c->rx_buf)) {
                /* Buffer full but still cannot decode frame: protocol anomaly */
                ws_close(c);
                return -1;
            }
#ifdef _WIN32
            {
                u_long nb = 1;
                ioctlsocket(c->fd, FIONBIO, &nb);
                r = recv(c->fd, (char*)c->rx_buf + c->rx_len,
                         sizeof(c->rx_buf) - c->rx_len, 0);
                nb = 0;
                ioctlsocket(c->fd, FIONBIO, &nb);
            }
#else
            r = recv(c->fd, (char*)c->rx_buf + c->rx_len,
                     sizeof(c->rx_buf) - c->rx_len, MSG_DONTWAIT);
#endif
            if (r > 0) {
                c->rx_len += (size_t)r;
                continue;
            }
            if (r == 0) { ws_close(c); return -1; }  /* Peer closed */
            {
                int err = WS_ERRNO();
                if (err == WS_EINTR) continue;
                if (err == WS_EAGAIN || err == WS_ETIMEOUT) return 0;
                ws_close(c);
                return -1;
            }
        }
    }
}
