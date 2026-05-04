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
#include <inttypes.h>
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

/* Per-community MAC -> IP mapping so the same edge always gets the same IP */
struct mac_ip_entry {
    n2n_mac_t        mac;
    uint32_t         ip;   /* host byte order */
    struct mac_ip_entry *next;
};

/* ============================================================
 * Per-community traffic statistics and rate limiting
 * ============================================================ */

#define COMM_STATS_MINUTES   1440   /* 24h in 1-minute buckets */
#define COMM_STATS_DAYS      30     /* 30-day rolling window */
#define COMM_STATS_SECONDS   5      /* instant rate averaging window */
#define RATE_LIMIT_FACTOR    1.05   /* token bucket overshoot factor */

struct community_stats {
    n2n_community_t community_name;

    /* Instant rate (COMM_STATS_SECONDS-second rolling average) */
    uint64_t recent_seconds[COMM_STATS_SECONDS];
    int      recent_idx;
    time_t   last_second;
    uint64_t instant_Bps;   /* bytes/s: rolling average over COMM_STATS_SECONDS */

    /* 24-hour sliding window (1-minute buckets) */
    uint64_t bytes_1440[COMM_STATS_MINUTES];
    int      min_idx;
    time_t   last_minute;
    uint64_t last_24h_bytes;

    /* 30-day rolling window (1-day buckets) */
    uint64_t bytes_30d[COMM_STATS_DAYS];
    int      day_idx;
    time_t   last_day;
    uint64_t total_30d;

    /* Total bytes since stats start */
    uint64_t total_bytes;
    time_t   stats_start_time;
    time_t   last_active;

    /* Rate limiting */
    uint64_t max_24h_bytes;     /* 0 = unlimited */
    uint64_t rate_limit_bps;    /* throttle speed after 24h limit; 0 = block */
    uint64_t tokens;            /* token bucket (bytes) */
    time_t   last_token_refill;

    /* Per-community IP auto-assignment (10.64.0.2 .. 10.64.0.254) */
    uint32_t next_ip;           /* host byte order, 0 = not yet initialised */
    struct mac_ip_entry *mac_ip_map; /* MAC -> IP cache for this community */

    struct community_stats *next;
};

/* Rate limiting rule loaded from config file */
struct rate_limit_rule {
    n2n_community_t community_name; /* "*" matches all */
    uint64_t        max_24h_bytes;
    uint64_t        rate_limit_bps;
    struct rate_limit_rule *next;
};

/* Find or create community stats entry.
 * If newly created and rules != NULL, applies rate limit rules immediately
 * so per-packet apply_rules_to_stats() calls are not needed. */
static struct community_stats * get_community_stats(
        struct community_stats **head,
        const n2n_community_t community,
        time_t now)
{
    struct community_stats *s = *head;
    while (s) {
        if (memcmp(s->community_name, community, sizeof(n2n_community_t)) == 0)
            return s;
        s = s->next;
    }
    s = (struct community_stats*)calloc(1, sizeof(struct community_stats));
    if (!s) return NULL;
    memcpy(s->community_name, community, sizeof(n2n_community_t));
    s->stats_start_time = now;
    s->last_day    = now;
    s->last_minute = now;
    s->last_second = now;
    s->next_ip     = 0x0a400002; /* 10.64.0.2 - per-community start */
    s->mac_ip_map  = NULL;
    s->next = *head;
    *head = s;
    return s;
}

/* Update traffic counters for a community */
static void update_community_traffic(struct community_stats *s, size_t bytes, time_t now)
{
    s->total_bytes += bytes;
    s->last_active  = now;

    /* Instant rate: advance and zero skipped buckets so idle communities decay to 0 */
    if (now != s->last_second) {
        int diff = (int)(now - s->last_second);
        if (diff >= COMM_STATS_SECONDS) {
            memset(s->recent_seconds, 0, sizeof(s->recent_seconds));
            s->recent_idx = 0;
        } else {
            while (diff-- > 0) {
                s->recent_idx = (s->recent_idx + 1) % COMM_STATS_SECONDS;
                s->recent_seconds[s->recent_idx] = 0;
            }
        }
        s->last_second = now;
        uint64_t total = 0;
        for (int k = 0; k < COMM_STATS_SECONDS; k++) total += s->recent_seconds[k];
        s->instant_Bps = total / COMM_STATS_SECONDS;
    }
    s->recent_seconds[s->recent_idx] += bytes;

    /* 24h sliding window - guard against time jumps */
    if (s->last_minute > now || now - s->last_minute > 7200) {
        /* Time jump: recalculate from buckets */
        uint64_t total = 0;
        for (int k = 0; k < COMM_STATS_MINUTES; k++) total += s->bytes_1440[k];
        s->last_24h_bytes = total;
        s->last_minute = now;
    } else if (now - s->last_minute >= 60) {
        int mdiff = (now - s->last_minute) / 60;
        if (mdiff > COMM_STATS_MINUTES) mdiff = COMM_STATS_MINUTES;
        while (mdiff-- > 0) {
            s->min_idx = (s->min_idx + 1) % COMM_STATS_MINUTES;
            s->last_24h_bytes -= s->bytes_1440[s->min_idx];
            s->bytes_1440[s->min_idx] = 0;
        }
        s->last_minute = now;
    }
    s->bytes_1440[s->min_idx] += bytes;
    s->last_24h_bytes += bytes;

    /* 30-day rolling window */
    if (now - s->last_day >= 86400) {
        s->last_day = now;
        s->day_idx  = (s->day_idx + 1) % COMM_STATS_DAYS;
        s->total_30d -= s->bytes_30d[s->day_idx];
        s->bytes_30d[s->day_idx] = 0;
    }
    s->bytes_30d[s->day_idx] += bytes;
    s->total_30d += bytes;
}

/* Check rate limit; returns 1 if packet should be allowed, 0 if blocked/throttled */
static int check_rate_limit(struct community_stats *s, size_t bytes, time_t now)
{
    if (s->max_24h_bytes == 0 && s->rate_limit_bps == 0)
        return 1; /* no limit */

    uint64_t total_24h = s->last_24h_bytes;

    if (s->max_24h_bytes > 0 && total_24h >= s->max_24h_bytes) {
        if (s->rate_limit_bps == 0)
            return 0; /* hard block */
        /* throttle via token bucket */
        if (s->last_token_refill == 0) {
            s->last_token_refill = now;
            s->tokens = (uint64_t)(s->rate_limit_bps * RATE_LIMIT_FACTOR);
        }
        time_t elapsed = now - s->last_token_refill;
        if (elapsed > 0) {
            s->last_token_refill = now;
            s->tokens += (uint64_t)(elapsed * s->rate_limit_bps * RATE_LIMIT_FACTOR);
            uint64_t max_tokens = (uint64_t)(s->rate_limit_bps * 5 * RATE_LIMIT_FACTOR);
            if (s->tokens > max_tokens) s->tokens = max_tokens;
        }
        if (s->tokens < bytes) return 0;
        s->tokens -= bytes;
    }
    return 1;
}

/* Apply rules from config to a community stats entry */
static void apply_rules_to_stats(struct community_stats *s,
                                  struct rate_limit_rule *rules)
{
    s->max_24h_bytes  = 0;
    s->rate_limit_bps = 0;
    struct rate_limit_rule *r = rules;
    while (r) {
        if (strcmp((char*)r->community_name, "*") == 0 ||
            memcmp(r->community_name, s->community_name, sizeof(n2n_community_t)) == 0) {
            s->max_24h_bytes  = r->max_24h_bytes;
            s->rate_limit_bps = r->rate_limit_bps;
            if (strcmp((char*)r->community_name, (char*)s->community_name) == 0)
                break; /* specific rule wins over wildcard */
        }
        r = r->next;
    }
}

/* Free all community stats */
static void free_community_stats(struct community_stats **head)
{
    struct community_stats *s = *head;
    while (s) {
        struct community_stats *next = s->next;
        /* Free per-community MAC->IP map */
        struct mac_ip_entry *e = s->mac_ip_map;
        while (e) {
            struct mac_ip_entry *en = e->next;
            free(e);
            e = en;
        }
        free(s);
        s = next;
    }
    *head = NULL;
}

/* Derive .dat path from config path */
static void stats_dat_path(const char *cfg, char *out, size_t sz)
{
    strncpy(out, cfg, sz - 1);
    out[sz - 1] = '\0';
    char *dot = strrchr(out, '.');
    char *slash = strrchr(out, '/');
#ifdef _WIN32
    char *bslash = strrchr(out, '\\');
    if (!slash || (bslash && bslash > slash)) slash = bslash;
#endif
    if (dot && dot > slash)
        strcpy(dot, ".dat");
    else
        strncat(out, ".dat", sz - strlen(out) - 1);
}

/* Free all rate limit rules */
static void free_rate_limit_rules(struct rate_limit_rule **head)
{
    struct rate_limit_rule *r = *head;
    while (r) {
        struct rate_limit_rule *next = r->next;
        free(r);
        r = next;
    }
    *head = NULL;
}

/* Parse -L config file */
static void parse_rate_limit_config(const char *path,
                                     int *enabled,
                                     struct rate_limit_rule **rules)
{
    free_rate_limit_rules(rules);
    *enabled = 0;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        /* Create default config */
        fp = fopen(path, "w");
        if (fp) {
            fprintf(fp, "# N2N Supernode traffic statistics and rate limiting\n");
            fprintf(fp, "# enabled on|off\n");
            fprintf(fp, "#\n");
            fprintf(fp, "# Rules: <community> <rate_limit_KB/s> <max_24h_GB>\n");
            fprintf(fp, "#   community       : community name, or * for all\n");
            fprintf(fp, "#   rate_limit_KB/s : speed after 24h limit exceeded (0=block)\n");
            fprintf(fp, "#   max_24h_GB      : 24h traffic cap (0=unlimited)\n");
            fprintf(fp, "# Later rules override earlier ones; specific name beats *\n");
            fprintf(fp, "#\n");
            fprintf(fp, "# Examples:\n");
            fprintf(fp, "#*          0    100    # global: block after 100GB/24h\n");
            fprintf(fp, "#n2n       10     50    # n2n: throttle to 10KB/s after 50GB/24h\n");
            fprintf(fp, "#vip        0      0    # vip: unlimited\n");
            fprintf(fp, "\n");
            fprintf(fp, "enabled on\n");
            fclose(fp);
        }
        *enabled = 1;
        return;
    }

    struct rate_limit_rule *tail = NULL;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char kw[64], val[64];
        if (sscanf(line, "%63s %63s", kw, val) == 2 &&
            strcmp(kw, "enabled") == 0) {
            *enabled = (strcmp(val, "on") == 0) ? 1 : 0;
            continue;
        }
        double rate_kbps, max_gb;
        if (sscanf(line, "%63s %lf %lf", kw, &rate_kbps, &max_gb) == 3) {
            struct rate_limit_rule *r = (struct rate_limit_rule*)calloc(1, sizeof(*r));
            if (!r) continue;
            strncpy((char*)r->community_name, kw, sizeof(n2n_community_t) - 1);
            r->rate_limit_bps = (uint64_t)(rate_kbps * 1024);
            r->max_24h_bytes  = (uint64_t)(max_gb * 1024.0 * 1024.0 * 1024.0);
            if (!tail) { *rules = r; tail = r; }
            else { tail->next = r; tail = r; }
        }
    }
    fclose(fp);
}

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
    /* Traffic stats and rate limiting */
    int                    traffic_stats_enabled;
    char                   stats_config_path[256];
    struct community_stats *comm_stats;
    struct rate_limit_rule *rate_rules;
};

typedef struct n2n_sn n2n_sn_t;

/* Save stats to text file (every 5 minutes) */
static void save_community_stats(n2n_sn_t *sss, time_t now)
{
    static time_t last_save = 0;
    if (now - last_save < 300) return;
    last_save = now;

    char path[512];
    stats_dat_path(sss->stats_config_path, path, sizeof(path));
    FILE *fp = fopen(path, "w");
    if (!fp) return;

    struct community_stats *s = sss->comm_stats;
    while (s) {
        fprintf(fp, "%s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                    " %d %" PRId64 " %d %" PRId64 "\n",
                (char*)s->community_name,
                (uint64_t)s->last_active,
                s->total_bytes,
                s->last_24h_bytes,
                s->total_30d,
                s->day_idx, (int64_t)s->last_day,
                s->min_idx, (int64_t)s->last_minute);
        for (int i = 0; i < COMM_STATS_DAYS; i++)
            fprintf(fp, "%" PRIu64 "%c", s->bytes_30d[i], i == COMM_STATS_DAYS-1 ? '\n' : ' ');
        s = s->next;
    }
    fclose(fp);
}

/* Load stats from text file at startup */
static void load_community_stats(n2n_sn_t *sss)
{
    char path[512];
    stats_dat_path(sss->stats_config_path, path, sizeof(path));
    FILE *fp = fopen(path, "r");
    if (!fp) return;

    time_t now = time(NULL);
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char cname[N2N_COMMUNITY_SIZE + 1] = {0};
        uint64_t last_active, total_bytes, last_24h, total_30d;
        int day_idx, min_idx;
        int64_t last_day, last_minute;
        if (sscanf(line, "%16s %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
                         " %d %" SCNd64 " %d %" SCNd64,
                   cname, &last_active, &total_bytes, &last_24h, &total_30d,
                   &day_idx, &last_day, &min_idx, &last_minute) != 9)
            continue;

        char bline[512];
        if (!fgets(bline, sizeof(bline), fp)) break;

        struct community_stats *s = get_community_stats(&sss->comm_stats,
                                        (const uint8_t*)cname, now);
        if (!s) continue;

        s->last_active    = (time_t)last_active;
        s->total_bytes    = total_bytes;
        s->last_24h_bytes = last_24h;
        s->total_30d      = total_30d;
        s->day_idx        = day_idx;
        s->last_day       = (time_t)last_day;
        s->min_idx        = min_idx;
        s->last_minute    = (time_t)last_minute;

        char *p = bline;
        for (int i = 0; i < COMM_STATS_DAYS; i++) {
            uint64_t v = 0;
            sscanf(p, "%" SCNu64, &v);
            s->bytes_30d[i] = v;
            p = strchr(p, ' ');
            if (!p) break;
            p++;
        }

        /* Advance expired 30d buckets */
        if (s->last_day > 0 && now - s->last_day >= 86400) {
            int ddiff = (now - s->last_day) / 86400;
            if (ddiff > COMM_STATS_DAYS) ddiff = COMM_STATS_DAYS;
            while (ddiff-- > 0) {
                s->day_idx = (s->day_idx + 1) % COMM_STATS_DAYS;
                if (s->total_30d >= s->bytes_30d[s->day_idx])
                    s->total_30d -= s->bytes_30d[s->day_idx];
                else
                    s->total_30d = 0;
                s->bytes_30d[s->day_idx] = 0;
            }
            s->last_day = now;
        }
    }
    fclose(fp);
    traceEvent(TRACE_NORMAL, "Traffic stats loaded from %s", path);
}

#define PURGE_STATS_FREQUENCY  30   /* seconds between community stats purge runs */

/* Purge community stats: remove entries idle >= 30d; advance expired 30d buckets for others */
static void purge_expired_community_stats(n2n_sn_t *sss, time_t *p_last_purge, time_t now)
{
    if (now - *p_last_purge < PURGE_STATS_FREQUENCY) return;
    *p_last_purge = now;

    struct community_stats **pp = &sss->comm_stats;
    while (*pp) {
        struct community_stats *s = *pp;
        time_t idle = now - s->last_active;

        if (idle >= 30 * 86400) {
            /* Remove entirely */
            *pp = s->next;
            struct mac_ip_entry *e = s->mac_ip_map;
            while (e) { struct mac_ip_entry *en = e->next; free(e); e = en; }
            free(s);
            continue;
        }

        /* Advance expired 30d buckets */
        if (s->last_day > 0 && now - s->last_day >= 86400) {
            int ddiff = (now - s->last_day) / 86400;
            if (ddiff > COMM_STATS_DAYS) ddiff = COMM_STATS_DAYS;
            while (ddiff-- > 0) {
                s->day_idx = (s->day_idx + 1) % COMM_STATS_DAYS;
                if (s->total_30d >= s->bytes_30d[s->day_idx])
                    s->total_30d -= s->bytes_30d[s->day_idx];
                else
                    s->total_30d = 0;
                s->bytes_30d[s->day_idx] = 0;
            }
            s->last_day = now;
            /* If 30d traffic is now zero, remove */
            if (s->total_30d == 0) {
                *pp = s->next;
                struct mac_ip_entry *e = s->mac_ip_map;
                while (e) { struct mac_ip_entry *en = e->next; free(e); e = en; }
                free(s);
                continue;
            }
        }

        pp = &s->next;
    }
}

static int update_edge( n2n_sn_t * sss,
                        const n2n_mac_t edgeMac,
                        const n2n_community_t community,
                        const n2n_sock_t * sender_sock,
                        const n2n_sock_t * local_sock,
                        uint8_t local_sock_ena,
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


/* Test connectivity by attempting a non-blocking connect to a well-known address */
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
                        const n2n_sock_t * local_sock,
                        uint8_t local_sock_ena,
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
                traceEvent(TRACE_DEBUG, "Edge %s using static IP %u.%u.%u.%u",
                           macaddr_str(mac_buf, edgeMac),
                           (assigned_ip>>24)&0xFF, (assigned_ip>>16)&0xFF,
                           (assigned_ip>>8)&0xFF, assigned_ip&0xFF);
            } else {
                /* Per-community IP assignment: get or create community stats entry */
                struct community_stats *cs = get_community_stats(&sss->comm_stats, community, now);
                uint32_t cached_ip = 0;
                if (cs) {
                    /* Look up MAC in this community's map */
                    struct mac_ip_entry *e = cs->mac_ip_map;
                    while (e) {
                        if (memcmp(e->mac, edgeMac, sizeof(n2n_mac_t)) == 0) {
                            cached_ip = e->ip;
                            break;
                        }
                        e = e->next;
                    }
                }
                if (cached_ip != 0) {
                    assigned_ip = cached_ip;
                    traceEvent(TRACE_INFO, "Reusing IP %u.%u.%u.%u for edge %s (community %s)",
                               (assigned_ip>>24)&0xFF, (assigned_ip>>16)&0xFF,
                               (assigned_ip>>8)&0xFF, assigned_ip&0xFF,
                               macaddr_str(mac_buf, edgeMac), (char*)community);
                } else {
                    if (cs) {
                        assigned_ip = cs->next_ip++;
                        /* Wrap when last octet exceeds 254 (x.x.x.255 is broadcast) */
                        if ((cs->next_ip & 0xFF) > 254)
                            cs->next_ip = (cs->next_ip & 0xFFFFFF00) + 2; /* skip .0 and .1 */
                        /* Wrap entire block back to 10.64.0.2 after 10.64.255.254 */
                        if (cs->next_ip > 0x0a40FFFE)
                            cs->next_ip = 0x0a400002;
                        /* Store in community's MAC->IP map */
                        struct mac_ip_entry *ne = calloc(1, sizeof(struct mac_ip_entry));
                        if (ne) {
                            memcpy(ne->mac, edgeMac, sizeof(n2n_mac_t));
                            ne->ip = assigned_ip;
                            ne->next = cs->mac_ip_map;
                            cs->mac_ip_map = ne;
                        }
                    } else {
                        /* Fallback: should not happen, but be safe */
                        assigned_ip = 0x0a400002;
                    }
                    traceEvent(TRACE_INFO, "Auto-assigning IP %u.%u.%u.%u to edge %s (community %s)",
                               (assigned_ip>>24)&0xFF, (assigned_ip>>16)&0xFF,
                               (assigned_ip>>8)&0xFF, assigned_ip&0xFF,
                               macaddr_str(mac_buf, edgeMac), (char*)community);
                }
            }
            scan->assigned_ip = assigned_ip;
        }

        memcpy(scan->community_name, community, sizeof(n2n_community_t) );
        memcpy(&(scan->mac_addr), edgeMac, sizeof(n2n_mac_t));
        memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
        /* Also record in the appropriate typed slot */
        if (sender_sock->family == AF_INET6)
            memcpy(&(scan->sock6), sender_sock, sizeof(n2n_sock_t));
        else
            memset(&(scan->sock6), 0, sizeof(n2n_sock_t));

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
        scan->next = sss->edges;
        sss->edges = scan;

        scan->sock     = *sender_sock;  /* IPv4 public (or IPv6 if that's what came in) */
        if (local_sock_ena && local_sock)
            scan->sock_lan = *local_sock;

        {
            struct in_addr vip_addr;
            vip_addr.s_addr = htonl(scan->assigned_ip);
            traceEvent( TRACE_NORMAL, "update_edge created   %s vip=%s ==> %s%s",
                        macaddr_str( mac_buf, edgeMac ),
                        inet_ntoa(vip_addr),
                        sock_to_cstr( sockbuf, &scan->sock ),
                        (scan->sock_lan.family != 0) ? " (LAN)" : "" );
        }

        scan->last_seen = now;
        return 1;  /* new edge */
    }
    else
    {
        /* Known */
        if ( (0 != memcmp(community, scan->community_name, sizeof(n2n_community_t))) ||
             (0 != sock_equal(sender_sock, &(scan->sock) )) )
        {
            /* Alt-family registration: only update the other-family address, don't overwrite primary */
            if (scan->sock.family != 0 && sender_sock->family != scan->sock.family) {
                if (sender_sock->family == AF_INET6) {
                    int had_sock6 = (scan->sock6.family == AF_INET6);
                    memcpy(&scan->sock6, sender_sock, sizeof(n2n_sock_t));
                    scan->last_seen = now;
                    /* If sock6 was newly learned, return 1 so peers get a fresh PEER_INFO
                     * that includes the IPv6 address. */
                    return had_sock6 ? 0 : 1;
                }
                /* IPv4 alt: primary sock already has IPv4 from main registration */
                scan->last_seen = now;
                return 0;
            }

            memcpy(scan->community_name, community, sizeof(n2n_community_t) );
            memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
            if (sender_sock->family == AF_INET6)
                memcpy(&(scan->sock6), sender_sock, sizeof(n2n_sock_t));
            else if (scan->sock6.family == 0)
                memset(&(scan->sock6), 0, sizeof(n2n_sock_t));

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

            if (local_sock_ena && local_sock) {
                scan->sock_lan = *local_sock;
            } else {
                memset(&scan->sock_lan, 0, sizeof(n2n_sock_t));
            }

            scan->last_seen = now;
            return 1;  /* address changed - treat as new for peer push */
        }
        else
        {
            traceEvent( TRACE_DEBUG, "update_edge unchanged %s ==> %s",
                        macaddr_str( mac_buf, edgeMac ),
                        sock_to_cstr( sockbuf, sender_sock ) );
        }

    }

    scan->last_seen = now;
    return 0;  /* unchanged, no push needed */
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
    time_t              now = time(NULL);

    /* Rate limiting check */
    if (sss->traffic_stats_enabled) {
        struct community_stats *cs = get_community_stats(&sss->comm_stats,
                                                          cmn->community, now);
        if (cs) {
            /* Apply rules on first use (new entry has zeroed limits) */
            if (cs->rate_limit_bps == 0 && cs->max_24h_bytes == 0)
                apply_rules_to_stats(cs, sss->rate_rules);
            if (!check_rate_limit(cs, pktsize, now)) {
                traceEvent(TRACE_DEBUG, "rate limit drop for community %s", cmn->community);
                return 0;
            }
            update_community_traffic(cs, pktsize, now);
        }
    }

    scan = find_peer_by_mac( sss->edges, dstMac );

    if ( NULL != scan )
    {
        ssize_t data_sent_len;
        scan->last_seen = now;
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
#define MAX_COMMUNITIES 256
    n2n_community_t communities[MAX_COMMUNITIES];
    struct peer_info *community_edges[MAX_COMMUNITIES];
    int num_communities = 0;
    uint32_t num_edges = 0;

    traceEvent( TRACE_DEBUG, "process_mgmt" );

    /* Send header */
    ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                      "  id  mac                virt_ip          wan_ip               <KB/s     GB/24h   GB/30d>  ver      os\n");
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                       "---v2.3----------------------------------------------------------------------------------------------------\n");

    r = sendto(sss->mgmt_sock, resbuf, ressize, 0,
               sender_sock, sender_sock_len);
    if (r <= 0) return -1;

    /* First pass: collect unique community names (no malloc, pointer only) */
    list = sss->edges;
    while (list) {
        int found = 0;
        for (int i = 0; i < num_communities; i++) {
            if (memcmp(communities[i], list->community_name, sizeof(n2n_community_t)) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && num_communities < MAX_COMMUNITIES) {
            memcpy(communities[num_communities], list->community_name, sizeof(n2n_community_t));
            community_edges[num_communities] = NULL; /* unused now */
            num_communities++;
        } else if (!found) {
            traceEvent(TRACE_WARNING,
                       "process_mgmt: community limit (%d) reached, some communities not displayed",
                       MAX_COMMUNITIES);
        }
        num_edges++;
        list = list->next;
    }

    /* Second pass: for each community, scan edges list directly - no malloc needed */
    uint32_t displayed_edges = 0;
    for (int i = 0; i < num_communities; i++) {
        /* Community name line with traffic stats on same line */
        if (sss->traffic_stats_enabled) {
            struct community_stats *cs = sss->comm_stats;
            while (cs && memcmp(cs->community_name, communities[i], sizeof(n2n_community_t)) != 0)
                cs = cs->next;
            if (cs && cs->total_30d > 0) {
                double kbps   = cs->instant_Bps / 1024.0;
                double gb_24h = cs->last_24h_bytes / (1024.0*1024.0*1024.0);
                double gb_30d = cs->total_30d / (1024.0*1024.0*1024.0);
                const char *arrow = (cs->instant_Bps > 0) ? "--->" : "    ";
                ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                                   "%-57s  %s %-7.1f  %-7.1f  %-10.1f\n",
                                   communities[i], arrow, kbps, gb_24h, gb_30d);
            } else {
                ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE, "%s\n", communities[i]);
            }
        } else {
            ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE, "%s\n", communities[i]);
        }
        r = sendto(sss->mgmt_sock, resbuf, ressize, 0, sender_sock, sender_sock_len);
        if (r <= 0) return -1;

        /* Output all edges belonging to this community directly from the original list */
        struct peer_info *edge = sss->edges;
        int id = 1;
        while (edge) {
            if (memcmp(edge->community_name, communities[i], sizeof(n2n_community_t)) != 0) {
                edge = edge->next;
                continue;
            }

            macstr_t mac_buf;
            n2n_sock_str_t sock_buf;
            const char *version = (edge->version[0] != '\0') ? edge->version : "unknown";
            const char *os_name = (edge->os_name[0] != '\0') ? edge->os_name : "unknown";

            uint8_t *mac = edge->mac_addr;
            int is_valid_mac = 1;
            if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
                mac[3] == 0 && mac[4] == 0 && mac[5] == 0)
                is_valid_mac = 0;
            if (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
                mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF)
                is_valid_mac = 0;
            if (mac[0] == 0x00 && mac[1] == 0x01 && mac[2] == 0x00)
                is_valid_mac = 0;

            if (!is_valid_mac) {
                edge = edge->next;
                continue;
            }

            displayed_edges++;

            struct in_addr a;
            a.s_addr = htonl(edge->assigned_ip);
            char virt_ip[20] = "-";
            if (edge->assigned_ip != 0)
                snprintf(virt_ip, sizeof(virt_ip), "%s", inet_ntoa(a));

            ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                               "  %2u  %-17s  %-15s  %-47s  %-7s  %s\n",
                               id++,
                               macaddr_str(mac_buf, edge->mac_addr),
                               virt_ip,
                               sock_to_cstr(sock_buf, &edge->sock),
                               version,
                               os_name);

            r = sendto(sss->mgmt_sock, resbuf, ressize, 0, sender_sock, sender_sock_len);
            if (r <= 0) return -1;

            edge = edge->next;
        }
    }

    num_edges = displayed_edges;

    /* Offline communities: in comm_stats but no current edges */
    if (sss->traffic_stats_enabled) {
        double off_kbps = 0.0, off_24h = 0.0, off_30d = 0.0;
        struct community_stats *cs = sss->comm_stats;
        while (cs) {
            int online = 0;
            for (int i = 0; i < num_communities; i++) {
                if (memcmp(communities[i], cs->community_name, sizeof(n2n_community_t)) == 0) {
                    online = 1;
                    break;
                }
            }
            if (!online) {
                time_t idle = now - cs->last_active;
                if (idle < 86400) {
                    /* Offline < 24h: show individually */
                    if (cs->total_30d > 0) {
                        double kbps  = cs->instant_Bps / 1024.0;
                        double gb24h = cs->last_24h_bytes / (1024.0*1024.0*1024.0);
                        double gb30d = cs->total_30d / (1024.0*1024.0*1024.0);
                        const char *arrow = (cs->instant_Bps > 0) ? "--->" : "    ";
                        ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                                           "%-57s  %s %-7.1f  %-7.1f  %-10.1f\n",
                                           cs->community_name, arrow, kbps, gb24h, gb30d);
                    } else {
                        ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE, "%s\n",
                                           cs->community_name);
                    }
                    r = sendto(sss->mgmt_sock, resbuf, ressize, 0, sender_sock, sender_sock_len);
                    if (r <= 0) return -1;
                } else {
                    /* Offline >= 24h: fold into summary */
                    off_kbps += cs->instant_Bps / 1024.0;
                    off_24h  += cs->last_24h_bytes / (1024.0*1024.0*1024.0);
                    off_30d  += cs->total_30d / (1024.0*1024.0*1024.0);
                }
            }
            cs = cs->next;
        }
        if (off_30d > 0) {
            ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                               "%-57s       %-7.1f  %-7.1f  %-10.1f\n",
                               "offline_community/24h", off_kbps, off_24h, off_30d);
            sendto(sss->mgmt_sock, resbuf, ressize, 0, sender_sock, sender_sock_len);
        }
    }

    /* Traffic Total line - before the footer separator */
    if (sss->traffic_stats_enabled) {
        double total_kbps = 0.0, total_24h = 0.0, total_30d = 0.0;
        struct community_stats *cs = sss->comm_stats;
        while (cs) {
            total_kbps += cs->instant_Bps / 1024.0;
            total_24h  += cs->last_24h_bytes / (1024.0*1024.0*1024.0);
            total_30d  += cs->total_30d / (1024.0*1024.0*1024.0);
            cs = cs->next;
        }
        if (total_30d > 0 || total_24h > 0 || total_kbps > 0) {
            const char *tarrow = (total_kbps > 0.0) ? "--->" : "    ";
            ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                               "-------------\n"
                               "Total traffic                                              %s %-7.1f  %-7.1f  %-10.1f\n",
                               tarrow, total_kbps, total_24h, total_30d);
            sendto(sss->mgmt_sock, resbuf, ressize, 0, sender_sock, sender_sock_len);
        }
    }

    /* Send footer and statistics */
    ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                      "----------------------------------------------------------------------------------------------------v2.3---\n");

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
    time_t              now = time(NULL);

    traceEvent( TRACE_DEBUG, "try_broadcast" );

    /* Rate limiting check for broadcast */
    if (sss->traffic_stats_enabled) {
        struct community_stats *cs = get_community_stats(&sss->comm_stats,
                                                          cmn->community, now);
        if (cs) {
            if (cs->rate_limit_bps == 0 && cs->max_24h_bytes == 0)
                apply_rules_to_stats(cs, sss->rate_rules);
            if (!check_rate_limit(cs, pktsize, now)) {
                traceEvent(TRACE_DEBUG, "rate limit drop broadcast for community %s",
                           cmn->community);
                return 0;
            }
            update_community_traffic(cs, pktsize, now);
        }
    }

    scan = sss->edges;
    while(scan != NULL)
    {
        if( 0 == (memcmp(scan->community_name, cmn->community, sizeof(n2n_community_t)) )
            && (0 != memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) ) )
        {
            ssize_t data_sent_len;

            scan->last_seen = now;
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

        /* Update version/os_name in peer record from REGISTER packet */
        {
            struct peer_info *p = find_peer_by_mac(sss->edges, reg.srcMac);
            if (p) {
                if (reg.version[0] != '\0')
                    strncpy(p->version, reg.version, sizeof(p->version) - 1);
                if (reg.os_name[0] != '\0')
                    strncpy(p->os_name, reg.os_name, sizeof(p->os_name) - 1);
            }
        }

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
    else if ( msg_type == n2n_deregister )
    {
        n2n_DEREGISTER_t dereg;
        decode_DEREGISTER( &dereg, &cmn, udp_buf, &rem, &idx );

        traceEvent( TRACE_INFO, "Rx DEREGISTER from %s", macaddr_str(mac_buf, dereg.srcMac) );

        struct peer_info *prev = NULL, *scan = sss->edges;
        while (scan) {
            if (memcmp(scan->mac_addr, dereg.srcMac, N2N_MAC_SIZE) == 0) {
                if (prev) prev->next = scan->next;
                else sss->edges = scan->next;
                free(scan);
                break;
            }
            prev = scan;
            scan = scan->next;
        }
    }
    else if ( msg_type == n2n_probe_ack )
    {
        /* Edge sends PROBE_ACK via supernode to deliver observed addr to the probe sender.
         * Decode dstMac and forward the raw packet to that edge. */
        n2n_PROBE_ACK_t ack;
        decode_PROBE_ACK(&ack, &cmn, udp_buf, &rem, &idx);

        traceEvent(TRACE_DEBUG, "Rx PROBE_ACK: forward to %s", macaddr_str(mac_buf, ack.srcMac));
        try_forward(sss, &cmn, ack.srcMac, udp_buf, udp_size);
    }
    else if ( msg_type == n2n_query_peer )
    {
        n2n_QUERY_PEER_t  query;
        n2n_PEER_INFO_t   pi;
        n2n_common_t      cmn2;
        uint8_t           encbuf[N2N_SN_PKTBUF_SIZE];
        size_t            encx = 0;

        decode_QUERY_PEER( &query, &cmn, udp_buf, &rem, &idx );

        struct peer_info *target = find_peer_by_mac( sss->edges, query.targetMac );
        if ( target )
        {
            memset( &cmn2, 0, sizeof(cmn2) );
            cmn2.ttl   = N2N_DEFAULT_TTL;
            cmn2.pc    = n2n_peer_info;
            cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy( cmn2.community, cmn.community, sizeof(n2n_community_t) );

            memcpy( pi.mac, query.targetMac, N2N_MAC_SIZE );
            pi.aflags = (target->sock_lan.family != 0 &&
                         target->sock_lan.port != 0) ? N2N_AFLAGS_LOCAL_SOCKET : 0;
            pi.sockets[0] = target->sock;
            if (pi.aflags & N2N_AFLAGS_LOCAL_SOCKET)
                pi.sockets[1] = target->sock_lan;
            if (target->sock6.family == AF_INET6) {
                pi.aflags |= N2N_AFLAGS_IPV6_SOCKET;
                pi.sock6 = target->sock6;
            }

            encode_PEER_INFO( encbuf, &encx, &cmn2, &pi );
            {
                SOCKET send_sock = (sender_sock->sa_family == AF_INET6) ? sss->sock6 : sss->sock;
                socklen_t slen = (sender_sock->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                sendto( send_sock, encbuf, encx, 0, sender_sock, slen );
            }

            /* Simultaneous open: also push A's address to B so B punches back */
            struct peer_info *requester = find_peer_by_mac( sss->edges, query.srcMac );
            if ( requester )
            {
                n2n_PEER_INFO_t pi2;
                n2n_common_t    cmn3;
                uint8_t         encbuf2[N2N_SN_PKTBUF_SIZE];
                size_t          encx2 = 0;
                struct sockaddr_storage b_addr;
                socklen_t b_len = sizeof(b_addr);

                memset( &cmn3, 0, sizeof(cmn3) );
                cmn3.ttl   = N2N_DEFAULT_TTL;
                cmn3.pc    = n2n_peer_info;
                cmn3.flags = N2N_FLAGS_FROM_SUPERNODE;
                memcpy( cmn3.community, cmn.community, sizeof(n2n_community_t) );

                memcpy( pi2.mac, query.srcMac, N2N_MAC_SIZE );
                pi2.aflags = (requester->sock_lan.family != 0 &&
                              requester->sock_lan.port != 0) ? N2N_AFLAGS_LOCAL_SOCKET : 0;
                pi2.sockets[0] = requester->sock;
                if (pi2.aflags & N2N_AFLAGS_LOCAL_SOCKET)
                    pi2.sockets[1] = requester->sock_lan;

                encode_PEER_INFO( encbuf2, &encx2, &cmn3, &pi2 );
                /* Send to B via appropriate socket */
                if ( fill_sockaddr((struct sockaddr*)&b_addr, b_len, &target->sock) == 0 ) {
                    SOCKET send_sock2 = (target->sock.family == AF_INET6) ? sss->sock6 : sss->sock;
                    socklen_t slen2 = (target->sock.family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                    sendto( send_sock2, encbuf2, encx2, 0, (struct sockaddr*)&b_addr, slen2 );
                    traceEvent(TRACE_DEBUG, "Simultaneous open: pushed A's addr to B for %s",
                               macaddr_str(mac_buf, query.targetMac));
                }
            }
        }
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
        size_t reg_start_idx = idx;
        decode_REGISTER_SUPER( &reg, &cmn, udp_buf, &rem, &idx );

        /* Extract dev_addr (net_addr + net_bitlen) from ntop's n2n_v2 */
        uint32_t extra_requested_ip = 0;
        size_t dev_idx = reg_start_idx + N2N_COOKIE_SIZE + N2N_MAC_SIZE;
        size_t dev_rem = udp_size - dev_idx;
        size_t dev_pos = dev_idx;
        if (dev_rem >= 5) {
            decode_uint32(&extra_requested_ip, udp_buf, &dev_rem, &dev_pos);
            extra_requested_ip = ntohl(extra_requested_ip);
        }

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

        /* Fill sn_caps so edge knows this supernode's IP stack capabilities */
        ack.sn_caps = 0;
        if (sss->ipv4_available) ack.sn_caps |= N2N_SN_CAPS_IPV4;
        if (sss->ipv6_available) ack.sn_caps |= N2N_SN_CAPS_IPV6;

        traceEvent( TRACE_DEBUG, "Rx REGISTER_SUPER for %s %s",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ) );

        uint32_t use_requested_ip = reg.dev_addr.net_addr;
        if (extra_requested_ip != 0) {
            use_requested_ip = extra_requested_ip;
        }
        uint8_t use_request_ip = 1; /* always assign IP (auto-assign if net_addr==0) */

        const n2n_sock_t *local_sock_ptr = (reg.aflags & N2N_AFLAGS_LOCAL_SOCKET) ? &reg.local_sock : NULL;
        uint8_t local_sock_ena = (reg.aflags & N2N_AFLAGS_LOCAL_SOCKET) ? 1 : 0;

        int is_new_edge = update_edge( sss, reg.edgeMac, cmn.community, &(ack.sock),
                     local_sock_ptr, local_sock_ena,
                     now, NULL, NULL, use_request_ip, use_requested_ip );

        /* Set assigned IP in ACK */
        if (use_request_ip) {
            struct peer_info *edge_peer = find_peer_by_mac(sss->edges, reg.edgeMac);
            if (edge_peer && edge_peer->assigned_ip) {
                ack.dev_addr.net_addr = htonl(edge_peer->assigned_ip);
                ack.dev_addr.net_bitlen = 24;
            }
        }

        encode_REGISTER_SUPER_ACK( ackbuf, &encx, &cmn2, &ack );

        /* Select the correct socket based on the address family */
        SOCKET send_sock = (sender_sock->sa_family == AF_INET6) ? sss->sock6 : sss->sock;
        socklen_t sock_len = (sender_sock->sa_family == AF_INET6) ?
                             sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

        sendto( send_sock, ackbuf, encx, 0,
                (struct sockaddr *)sender_sock, sock_len );

        traceEvent( TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s %s",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ) );

        /* Push all existing peers to the new edge only.
         * Do NOT push the new edge to existing peers - they discover
         * it on demand via QUERY_PEER / REGISTER when needed. */
        if ( is_new_edge )
        {
            n2n_common_t    pi_cmn;
            n2n_PEER_INFO_t pi;
            uint8_t         pibuf[N2N_SN_PKTBUF_SIZE];
            size_t          pix;
            struct peer_info *p = sss->edges;

            memset(&pi_cmn, 0, sizeof(pi_cmn));
            pi_cmn.ttl   = N2N_DEFAULT_TTL;
            pi_cmn.pc    = n2n_peer_info;
            pi_cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(pi_cmn.community, cmn.community, sizeof(n2n_community_t));

            while (p) {
                if (memcmp(p->community_name, cmn.community, sizeof(n2n_community_t)) == 0 &&
                    memcmp(p->mac_addr, reg.edgeMac, N2N_MAC_SIZE) != 0)
                {
                    memcpy(pi.mac, p->mac_addr, N2N_MAC_SIZE);
                    pi.sockets[0] = p->sock;
                    if (p->sock_lan.family != 0 && p->sock_lan.port != 0)
                    {
                        pi.aflags = N2N_AFLAGS_LOCAL_SOCKET;
                        pi.sockets[1] = p->sock_lan;
                    } else {
                        pi.aflags = 0;
                    }
                    if (p->sock6.family == AF_INET6) {
                        pi.aflags |= N2N_AFLAGS_IPV6_SOCKET;
                        pi.sock6 = p->sock6;
                    } else {
                        memset(&pi.sock6, 0, sizeof(n2n_sock_t));
                    }
                    strncpy(pi.version, p->version, sizeof(pi.version) - 1);
                    strncpy(pi.os_name, p->os_name, sizeof(pi.os_name) - 1);
                    pix = 0;
                    encode_PEER_INFO(pibuf, &pix, &pi_cmn, &pi);
                    sendto(send_sock, pibuf, pix, 0,
                           (struct sockaddr *)sender_sock, sock_len);
                    traceEvent(TRACE_DEBUG, "pushed PEER_INFO %s to new edge %s",
                               macaddr_str(mac_buf, p->mac_addr),
                               macaddr_str(mac_buf2, reg.edgeMac));
                }
                p = p->next;
            }
        }
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
    fprintf( stderr, "-L <file> \tEnable traffic stats and rate limiting (config file)\n" );
    fprintf( stderr, "-4|-6     \tIP mode: -4 (IPv4 only), -6 (IPv6 only), both/none (dual-stack)\n" );
 #ifndef _WIN32
    fprintf( stderr, "-t <port>\tSet management UDP port to <port> (default: 5646)\n" );
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

        while((opt = getopt_long(argc, argv, "ft:l:L:46vh", long_options, NULL)) != -1)
        {
            switch (opt)
            {
            case 'l': /* local-port */
                sss.lport = atoi(optarg);
																lport_specified = 1;
                break;
            case 'L': /* traffic stats and rate limiting config */
                strncpy(sss.stats_config_path, optarg, sizeof(sss.stats_config_path) - 1);
                parse_rate_limit_config(sss.stats_config_path,
                                        &sss.traffic_stats_enabled,
                                        &sss.rate_rules);
                if (sss.traffic_stats_enabled)
                    load_community_stats(&sss);
                traceEvent(TRACE_NORMAL, "Traffic stats %s, config: %s",
                           sss.traffic_stats_enabled ? "enabled" : "disabled",
                           sss.stats_config_path);
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
                ipv6 = false;
                break;
            case '6':
                ipv4 = false;
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
            /* Socket bound OK, but only mark IPv6 available if the system
             * has at least one non-link-local, non-loopback global IPv6 address.
             * A server with only fe80:: addresses cannot accept external IPv6 connections. */
#ifndef _WIN32
            struct ifaddrs *ifap = NULL;
            if (getifaddrs(&ifap) == 0) {
                struct ifaddrs *ifa;
                for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6) continue;
                    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                    if (!IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr) &&
                        !IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) {
                        ipv6_available = 1;
                        break;
                    }
                }
                freeifaddrs(ifap);
            }
#else
            /* Windows: check via GetAdaptersAddresses */
            ULONG buflen = 15000;
            IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES*)malloc(buflen);
            if (addrs && GetAdaptersAddresses(AF_INET6, 0, NULL, addrs, &buflen) == NO_ERROR) {
                IP_ADAPTER_ADDRESSES *a;
                for (a = addrs; a && !ipv6_available; a = a->Next) {
                    IP_ADAPTER_UNICAST_ADDRESS *ua;
                    for (ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                        struct sockaddr_in6 *s6 = (struct sockaddr_in6*)ua->Address.lpSockaddr;
                        if (s6->sin6_family == AF_INET6 &&
                            !IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr) &&
                            !IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) {
                            ipv6_available = 1;
                            break;
                        }
                    }
                }
            }
            if (addrs) free(addrs);
#endif
            if (!ipv6_available) {
                traceEvent(TRACE_WARNING, "IPv6 socket bound but no global IPv6 address found - IPv6 disabled");
                closesocket(sss.sock6);
                sss.sock6 = -1;
            }
        } else {
            traceEvent( TRACE_WARNING, "IPv6 socket failed, continuing without IPv6" );
            sss.sock6 = -1;
        }
    }

    /* Socket bind success is sufficient to confirm availability */
    if (ipv4_available) {
        traceEvent( TRACE_NORMAL, "IPv4 socket ready" );
    }

    if (ipv6_available) {
        traceEvent( TRACE_NORMAL, "IPv6 socket ready" );
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

    sss.mgmt_sock = open_socket(sss.mgmt_port, 0 /* bind LOOPBACK */ );
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
    traceEvent( TRACE_NORMAL, "supernode is listening on UDP %u (management)", sss.mgmt_port );
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
        if (sss->traffic_stats_enabled) {
            static time_t last_stats_purge = 0;
            purge_expired_community_stats(sss, &last_stats_purge, now);
            save_community_stats(sss, now);
        }
    }

    deinit_sn( sss );
    free_community_stats( &sss->comm_stats );
    free_rate_limit_rules( &sss->rate_rules );
    return 0;
}
