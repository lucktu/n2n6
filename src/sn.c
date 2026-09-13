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

/* forward declarations - needed by run_loop before their definitions */
struct n2n_sn;
static int resolve_brother_addr(const char *text, n2n_sock_t *out);
static void send_brother_reg(struct n2n_sn *sss, time_t now);
static size_t brother_list_format(struct n2n_sn *sss, time_t now, char *buf, size_t bufsz);

/* Build an n2n_sock_t from a recvfrom() sockaddr (family 0 if unsupported). */
static int sock_from_sender( n2n_sock_t *out, const struct sockaddr *sa )
{
    memset( out, 0, sizeof(n2n_sock_t) );
    if ( sa->sa_family == AF_INET )
    {
        const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
        out->family = AF_INET;
        out->port = ntohs( a->sin_port );
        memcpy( out->addr.v4, &a->sin_addr, IPV4_SIZE );
    }
    else if ( sa->sa_family == AF_INET6 )
    {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
        out->family = AF_INET6;
        out->port = ntohs( a->sin6_port );
        memcpy( out->addr.v6, &a->sin6_addr, IPV6_SIZE );
    }
    return out->family;
}

/* sn_get_device_mac: read the MAC of the first non-loopback, up NIC.
 * On success returns 1 and fills out_mac. On failure returns 0 and leaves
 * out_mac zeroed. Implementation depends on platform headers that are
 * only available after the include block below, so the body is placed
 * further down. */
static int sn_get_device_mac(n2n_mac_t out_mac);
#include <signal.h>
#include <inttypes.h>
#include <limits.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define SOCKET_INVALID INVALID_SOCKET
#define CLOSE_SOCKET(s) closesocket(s)
#else
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ifaddrs.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
#include <net/if_dl.h>  /* AF_LINK MAC lookup on macOS/BSD */
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
/* <net/if.h> intentionally not included: n2n.h already pulls in
 * <linux/if.h> on Linux and redefinition of IFF_* / struct ifreq
 * would break compilation. SIOCGIFHWADDR, struct ifreq and IFNAMSIZ
 * are therefore already available via n2n.h. */
#define SOCKET_INVALID -1
#define CLOSE_SOCKET(s) close(s)
#endif

/* sn_get_device_mac implementation: depends on platform headers above. */
static int sn_get_device_mac(n2n_mac_t out_mac)
{
    memset(out_mac, 0, sizeof(n2n_mac_t));
#ifndef _WIN32
#if defined(__linux__)
    /* Walk getifaddrs, pick the first interface with any address entry
     * that is not the loopback interface. The kernel name "lo" (Linux)
     * is treated as loopback regardless of sa_family — necessary for
     * musl/uClibc where sa_family may be reported as AF_PACKET or
     * AF_UNSPEC and IFF_* macros clash between libc <net/if.h> and
     * kernel <linux/if.h>. */
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0) return 0;
    char picked_name[IFNAMSIZ + 1] = {0};
    struct ifaddrs *ifa;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        snprintf(picked_name, sizeof(picked_name), "%s", ifa->ifa_name);
        break;
    }
    freeifaddrs(ifap);
    if (picked_name[0] == '\0') return 0;

    int probe_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe_sock < 0) return 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", picked_name);
    if (ioctl(probe_sock, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(out_mac, ifr.ifr_hwaddr.sa_data, sizeof(n2n_mac_t));
        close(probe_sock);
        return 1;
    }
    close(probe_sock);
    return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
    /* macOS/BSD: no SIOCGIFHWADDR; take the first AF_LINK entry carrying a
     * 6-byte hardware address, skipping loopback (lo*). */
    struct ifaddrs *ifap = NULL;
    struct ifaddrs *ifa;
    if (getifaddrs(&ifap) != 0) return 0;
    int ok = 0;
    for (ifa = ifap; ifa && !ok; ifa = ifa->ifa_next) {
        struct sockaddr_dl *sdl;
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        if (strncmp(ifa->ifa_name, "lo", 2) == 0) continue;
        sdl = (struct sockaddr_dl *)ifa->ifa_addr;
        if (sdl->sdl_alen != sizeof(n2n_mac_t)) continue;
        memcpy(out_mac, LLADDR(sdl), sizeof(n2n_mac_t));
        ok = 1;
    }
    freeifaddrs(ifap);
    return ok;
#else
    return 0; /* other platforms: zero MAC; caller logs a warning */
#endif
#else
    ULONG buflen = 15000;
    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
    if (!addrs) return 0;
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addrs, &buflen);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        free(addrs);
        buflen = 15000;
        addrs = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
        if (!addrs) return 0;
        rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addrs, &buflen);
    }
    if (rc != NO_ERROR) { free(addrs); return 0; }
    IP_ADAPTER_ADDRESSES *a;
    int ok = 0;
    for (a = addrs; a && !ok; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->PhysicalAddressLength == sizeof(n2n_mac_t)) {
            memcpy(out_mac, a->PhysicalAddress, sizeof(n2n_mac_t));
            ok = 1;
        }
    }
    free(addrs);
    return ok;
#endif
}

#define N2N_SN_LPORT_DEFAULT SUPERNODE_PORT
#define N2N_SN_MGMT_PORT     5646

/* Transform indices - defined in n2n.h */

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
#define RATE_LIMIT_FACTOR    1.0    /* actual rate = limit x this factor */
#define RATE_DEBT_SECONDS    10     /* overdraft allowance before queueing */
#define SHAPER_SLOTS         8      /* queued packets per community (~16KB) */

/* One packet parked in the shaper queue, waiting for tokens */
struct shaper_slot {
    uint16_t  len;
    n2n_mac_t mac;      /* destination MAC, re-looked up at drain time */
    uint8_t   buf[N2N_SN_PKTBUF_SIZE];
};

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
    time_t   last_active;

    /* Rate limiting */
    uint64_t max_24h_bytes;     /* 0 = unlimited */
    uint64_t rate_limit_bps;    /* throttle speed after 24h limit; 0 = block */
    int64_t  tokens;            /* token bucket (bytes); negative = overdraft */
    int64_t  last_token_refill_ms; /* monotonic ms clock for smooth refill */
    int      bc_gate;           /* broadcast member cap while throttled
                                 * (INT_MAX = everyone) */

    /* Shaper queue: packets parked instead of dropped while throttled */
    struct shaper_slot *q;      /* lazily allocated ring of SHAPER_SLOTS */
    int      q_r;               /* read index */
    int      q_n;               /* queued count */

    /* Per-community IP auto-assignment (10.64.0.2 .. 10.64.0.254) */
    uint32_t next_ip;           /* host byte order, 0 = not yet initialised */
    struct mac_ip_entry *mac_ip_map; /* MAC -> IP cache for this community */

    /* Cache for compact broadcast optimization: all_compact == 1 means every edge in this
     * community is compact_capable, so SN can skip broadcast conversion check.
     * false means there's at least one legacy edge, need check or force conversion. */
    int             all_compact;

    struct community_stats *next;
};

/* Rate limiting rule loaded from config file */
struct rate_limit_rule {
    n2n_community_t community_name; /* "*" matches all */
    uint64_t        max_24h_bytes;
    uint64_t        rate_limit_bps;
    int             bc_gate;    /* broadcast member cap while throttled */
    int             deny;       /* 1 = deny registration (black/white list) */
    struct rate_limit_rule *next;
};

/* Find or create community stats entry.
 * Rate limit rules are applied lazily on first use (see try_forward /
 * try_broadcast) so per-packet rule lookups are avoided for the steady state. */
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
    s->last_day    = now;
    s->last_minute = now;
    s->last_second = now;
    s->next_ip     = 0x0a400002; /* 10.64.0.2 - per-community start */
    s->mac_ip_map  = NULL;
    s->all_compact = 1;          /* assume all new edges are compact until proven otherwise */
    s->bc_gate     = INT_MAX;    /* default: broadcast to everyone */
    s->next = *head;
    *head = s;
    return s;
}

/* Advance expired 30-day buckets: roll the day window forward to now,
 * evicting any whole days that have elapsed since last_day. */
static void advance_30d_buckets(struct community_stats *s, time_t now)
{
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

/* Advance expired 24-hour minute buckets: roll the sliding window forward to
 * now so last_24h_bytes decays even while a community is idle or throttled.
 * This is what prevents the rate limit from dead-locking a community that has
 * exhausted its 24h quota: without traffic there is no update_community_traffic
 * call, so only periodic advancement (purge/load) can shrink last_24h_bytes. */
static void advance_24h_buckets(struct community_stats *s, time_t now)
{
    if (s->last_minute > now) {
        /* Clock went backwards: rebuild from buckets */
        uint64_t total = 0;
        for (int k = 0; k < COMM_STATS_MINUTES; k++) total += s->bytes_1440[k];
        s->last_24h_bytes = total;
        s->last_minute = now;
        return;
    }
    if (now - s->last_minute < 60)
        return;

    int mdiff = (int)((now - s->last_minute) / 60);
    if (mdiff > COMM_STATS_MINUTES) mdiff = COMM_STATS_MINUTES;
    while (mdiff-- > 0) {
        s->min_idx = (s->min_idx + 1) % COMM_STATS_MINUTES;
        if (s->last_24h_bytes >= s->bytes_1440[s->min_idx])
            s->last_24h_bytes -= s->bytes_1440[s->min_idx];
        else
            s->last_24h_bytes = 0;
        s->bytes_1440[s->min_idx] = 0;
    }
    s->last_minute = now;
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
    }
    s->recent_seconds[s->recent_idx] += bytes;

    /* Recompute on every call so the current second is always included
     * (computing only on second-tick loses 1/5 of the window) */
    {
        uint64_t total = 0;
        for (int k = 0; k < COMM_STATS_SECONDS; k++) total += s->recent_seconds[k];
        s->instant_Bps = total / COMM_STATS_SECONDS;
    }

    /* 24h sliding window */
    advance_24h_buckets(s, now);
    s->bytes_1440[s->min_idx] += bytes;
    s->last_24h_bytes += bytes;

    /* 30-day rolling window */
    advance_30d_buckets(s, now);
    s->bytes_30d[s->day_idx] += bytes;
    s->total_30d += bytes;
}

/* Monotonic milliseconds (token refill clock, sub-second precision) */
static int64_t sn_monotonic_ms(void)
{
#ifdef _WIN32
    return (int64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
#endif
}

/* Token bucket cap: 1 second worth of tokens. Bursts up to this pass without
 * queueing; larger caps only enlarge the instant passthrough after idle. */
static uint64_t token_bucket_max(struct community_stats *s)
{
    uint64_t max_tokens = (uint64_t)(s->rate_limit_bps * RATE_LIMIT_FACTOR);
    uint64_t min_bucket = 4096; /* accommodate one typical MAX-sized n2n packet */
    if (max_tokens < min_bucket) max_tokens = min_bucket;
    return max_tokens;
}

/* Refill the token bucket from the monotonic ms clock so queued packets are
 * released smoothly instead of in whole-second bursts. */
static void token_refill(struct community_stats *s, uint64_t max_tokens)
{
    int64_t now = sn_monotonic_ms();
    if (s->last_token_refill_ms == 0) {
        s->last_token_refill_ms = now;
        s->tokens = (int64_t)max_tokens; /* start full so a single packet can pass */
        return;
    }
    int64_t elapsed = now - s->last_token_refill_ms;
    if (elapsed <= 0) return;
    s->last_token_refill_ms = now;
    s->tokens += (int64_t)((double)elapsed * s->rate_limit_bps * RATE_LIMIT_FACTOR / 1000.0);
    if (s->tokens > (int64_t)max_tokens) s->tokens = (int64_t)max_tokens;
}

/* Refill tokens and try to admit `bytes`; charges the bucket when admitted.
 * Shared by the direct path (try_forward) and the shaper drain, keeping a
 * single accounting path. Returns 1 if allowed, 0 if it must wait or block. */
static int rate_admit(struct community_stats *s, size_t bytes)
{
    if (s->max_24h_bytes == 0 && s->rate_limit_bps == 0)
        return 1; /* no limit */

    if (s->max_24h_bytes > 0 && s->last_24h_bytes >= s->max_24h_bytes) {
        if (s->rate_limit_bps == 0)
            return 0; /* hard block */
        /* Throttle via token bucket with overdraft (credit): the bucket may
         * go negative down to RATE_DEBT_SECONDS worth of tokens. Short bursts
         * borrow from future tokens instead of delaying packets; once the
         * credit is exhausted try_forward parks packets in the shaper queue
         * instead of dropping them, so TCP sees no loss and keeps its
         * congestion window. */
        uint64_t max_tokens = token_bucket_max(s);
        int64_t debt_max = (int64_t)(s->rate_limit_bps * RATE_DEBT_SECONDS);
        if (debt_max < 16384) debt_max = 16384;
        uint64_t charge = bytes;
        if (charge > max_tokens) charge = max_tokens; /* cap single-packet charge */
        token_refill(s, max_tokens);
        if (s->tokens - (int64_t)charge < -debt_max)
            return 0; /* credit exhausted */
        s->tokens -= (int64_t)charge;
    }
    return 1;
}

/* Apply rules from config to a community stats entry */
static void apply_rules_to_stats(struct community_stats *s,
                                  struct rate_limit_rule *rules)
{
    s->max_24h_bytes  = 0;
    s->rate_limit_bps = 0;
    s->bc_gate        = INT_MAX;
    struct rate_limit_rule *r = rules;
    while (r) {
        if (strcmp((char*)r->community_name, "*") == 0 ||
            memcmp(r->community_name, s->community_name, sizeof(n2n_community_t)) == 0) {
            s->max_24h_bytes  = r->max_24h_bytes;
            s->rate_limit_bps = r->rate_limit_bps;
            s->bc_gate        = r->bc_gate;
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
        free(s->q);
        free(s);
        s = next;
    }
    *head = NULL;
}

/* Derive .dat path from config path */
/** Derive stats file path: replace .cfg suffix with .dat */
static void stats_dat_path(const char *cfgpath, char *out, size_t sz)
{
    strncpy(out, cfgpath, sz - 1);
    out[sz - 1] = '\0';
    char *dot = strrchr(out, '.');
    char *slash = strrchr(out, '/');
#ifdef _WIN32
    char *bslash = strrchr(out, '\\');
    if (!slash || (bslash && bslash > slash)) slash = bslash;
#endif
    if (dot && dot > slash)
        strcpy(dot, ".dat");
    else {
        size_t remaining = sz - strlen(out) - 1;
        if (remaining > 0)
            strncat(out, ".dat", remaining);
    }
}

/** Derive cfg file path: replace .dat suffix with .cfg */
static void stats_cfg_path(const char *datpath, char *out, size_t sz)
{
    strncpy(out, datpath, sz - 1);
    out[sz - 1] = '\0';
    char *dot = strrchr(out, '.');
    char *slash = strrchr(out, '/');
#ifdef _WIN32
    char *bslash = strrchr(out, '\\');
    if (!slash || (bslash && bslash > slash)) slash = bslash;
#endif
    if (dot && dot > slash)
        strcpy(dot, ".cfg");
    else
        strncat(out, ".cfg", sz - strlen(out) - 1);
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

/* Black/white list lookup: is this community denied registration?
 * Rule precedence: exact name beats "*"; at the same level x (deny) beats
 * y (allow). No matching rule => allow (blacklist default). Checked only
 * at REGISTER_SUPER; online edges fall off at their next re-registration. */
static int community_denied(const struct rate_limit_rule *rules,
                            const n2n_community_t comm)
{
    int level = 0, denied = 0; /* level: 0 none, 1 wildcard, 2 exact */
    const struct rate_limit_rule *r = rules;
    while (r) {
        int exact = (strncmp((char *)r->community_name, (char *)comm,
                             sizeof(n2n_community_t)) == 0);
        int wild  = !exact && (strcmp((char *)r->community_name, "*") == 0);
        if (exact || wild) {
            int lvl = exact ? 2 : 1;
            if (lvl > level) { level = lvl; denied = 0; }
            if (r->deny) denied = 1; /* x beats y at the same level */
        }
        r = r->next;
    }
    return denied;
}

/* Access action column token: "x" (deny) or "y" (allow) */
static int is_access_action(const char *s)
{
    return s[1] == '\0' &&
           (s[0] == 'x' || s[0] == 'X' || s[0] == 'y' || s[0] == 'Y');
}

/* Parse -c config file: rate limiting + community access list */
static void parse_rate_limit_config(const char *datpath,
                                     int *enabled,
                                     struct rate_limit_rule **rules)
{
    char cfgpath[512];
    stats_cfg_path(datpath, cfgpath, sizeof(cfgpath));
    free_rate_limit_rules(rules);
    *enabled = 0;

    FILE *fp = fopen(cfgpath, "r");
    if (!fp) {
        /* Create default config */
        fp = fopen(cfgpath, "w");
        if (fp) {
            fprintf(fp, "# N2N Supernode traffic statistics, rate limiting and community access list\n");
            fprintf(fp, "# enabled on|off\n");
            fprintf(fp, "#\n");
            fprintf(fp, "# Rules: <community> <max_24h_GB> <rate_limit_KB/s> <broadcast_members> <Allow_and_block_lists>\n");
            fprintf(fp, "#   community            : community name, or * for all\n");
            fprintf(fp, "#   max_24h_GB           : 24h traffic cap in GB (0=unlimited)\n");
            fprintf(fp, "#   rate_limit_KB/s      : speed in KB/s once the cap is reached (0=block all)\n");
            fprintf(fp, "#   broadcast_members    : how many members receive broadcast while throttled\n");
            fprintf(fp, "#                      0 : everyone; N : at most N members (default 64)\n");
            fprintf(fp, "#   Allow_and_block_lists: x = deny registration, y = allow; optional, default y\n");
            fprintf(fp, "#                          (may also replace broadcast_members as the last column)\n");
            fprintf(fp, "# A community name alone means allow with no limits.\n");
            fprintf(fp, "# Precedence: exact name beats *; x beats y on the same level.\n");
            fprintf(fp, "# Blacklist (default allow): add x lines to deny. Whitelist: end with\n");
            fprintf(fp, "# \"* 0 0 x\" so only y communities may register. Denial = silent drop.\n");
            fprintf(fp, "# Later rules override earlier ones; specific name beats *\n");
            fprintf(fp, "#\n");
            fprintf(fp, "# Examples:\n");
            fprintf(fp, "#<community> <max_24h_GB> <rate_limit_KB/s> <broadcast_members> <Allow_and_block_lists>\n");
            fprintf(fp, "#*            10            116                                                          # global: 116KB/s after 10GB/24h\n");
            fprintf(fp, "#n2n          50            580               64                                         # n2n: 580KB/s after 50GB/24h, broadcast to max 64\n");
            fprintf(fp, "#vip           0            0                                                            # vip: unlimited\n");
            fprintf(fp, "#badnet        0            0                                     x                      # deny registration\n");
            fprintf(fp, "#good                                                                                    # allow, no limits\n");
            fprintf(fp, "#*             0            0                                     x                      # whitelist: deny all others\n");
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
        char *tok[5];
        int ntok = 0;
        char *t = strtok(line, " \t\r\n");
        while (t && ntok < 5) {         /* stop at '#' or after 5 columns */
            if (t[0] == '#') break;
            tok[ntok++] = t;
            t = strtok(NULL, " \t\r\n");
        }
        if (ntok == 0) continue;
        if (ntok >= 2 && strcmp(tok[0], "enabled") == 0) {
            *enabled = (strcmp(tok[1], "on") == 0) ? 1 : 0;
            continue;
        }
        /* Trailing access action: x = deny, y = allow (default) */
        const char *act = NULL;
        if (ntok >= 2 && is_access_action(tok[ntok - 1])) { act = tok[ntok - 1]; ntok--; }
        double max_gb = 0, rate_kbps = 0;
        int bc = 64;
        if (ntok == 4) {
            bc = atoi(tok[3]);
            max_gb = atof(tok[1]); rate_kbps = atof(tok[2]);
        } else if (ntok == 3) {
            max_gb = atof(tok[1]); rate_kbps = atof(tok[2]);
        } else if (ntok >= 2) {
            continue; /* unsupported column count, ignore like before */
        }
        /* ntok == 1: community-only line = allow, no limits (compatible
         * with official community.list) */
        struct rate_limit_rule *r = (struct rate_limit_rule*)calloc(1, sizeof(*r));
        if (!r) continue;
        strncpy((char*)r->community_name, tok[0], sizeof(n2n_community_t) - 1);
        r->max_24h_bytes  = (uint64_t)(max_gb * 1024.0 * 1024.0 * 1024.0);
        r->rate_limit_bps = (uint64_t)(rate_kbps * 1024);
        r->bc_gate = bc;
        if (r->bc_gate <= 0)
            r->bc_gate = INT_MAX; /* 0 = everyone */
        r->deny = act ? (tolower((unsigned char)act[0]) == 'x') : 0;
        if (!tail) { *rules = r; tail = r; }
        else { tail->next = r; tail = r; }
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

/* Promoted-peer list: edges that proved their sn1 affiliation by sending an
 * ask_backup/QUERY_ONLY probe whose desired_sn1_mac matches a brother-table
 * entry. Recorded so their later real registration after the failover switch
 * (which carries no sn1 hint and no sn2 token) is admitted when -E is set. */
#define PROMOTED_LIST_MAX  32
#define PROMOTED_TTL       180   /* refreshed by probes and registrations */

struct promoted_peer {
    n2n_mac_t       mac;
    n2n_community_t community;
    time_t          seen;    /* last probe/registration time (0 = free slot) */
};

struct n2n_sn
{
    time_t              start_time;     /* Used to measure uptime. */
    sn_stats_t          stats;
    int                 daemon;         /* If non-zero then daemonise. */
    uint16_t            lport;          /* Local UDP port to bind to. */
    uint16_t            mgmt_port;      /* Managing UDP ports */
    SOCKET              sock;           /* Main socket for UDP traffic with edges. */
    SOCKET              sock6;
    n2n_sock_t          my_ipv6;        /* first non-link-local IPv6 GUA on this host (used for brother_reg.own_ipv6) */
    /* brothers[] - active brother SNs discovered via brother_reg.
     * Indexed by MAC so multiple sn1 peers can register against this sn2
     * and each slot holds its own v4/v6 socket + last-seen timestamp. */
    n2n_brother_entry_t    brothers[MAX_BROTHER_SNS];
    SOCKET              mgmt_sock;      /* management socket. */
    SOCKET              bounce_sock;    /* NAT bounce-test helper socket (random
                                         * source port, outbound-only; replies
                                         * "N2NB" to edges requesting a bounce). */
    SOCKET              ws_listen_sock; /* TCP listen socket for WebSocket (same as lport). */
#define N2N_SN_MAX_WS 64
    ws_conn_t           ws_conns[N2N_SN_MAX_WS]; /* WS connection table (edge connected via WS). */
    struct peer_info *  edges;          /* Link list of registered edges. */
    n2n_trans_op_t      transop[N2N_MAX_TRANSFORMS];
    int                 ipv4_available; /* 0=unavailable, 1=available */
    int                 ipv6_available; /* 0=unavailable, 1=available */
    int                 relay_advert_enabled; /* 1=advertise the community relay peer (default), 0=off */
    /* Traffic stats and rate limiting */
    int                    traffic_stats_enabled;
    char                   stats_config_path[256];
    struct community_stats *comm_stats;
    struct rate_limit_rule *rate_rules;
    n2n_auth_t             peer_token;     /* token required from edge peers (-E) */
    int                    peer_token_set;
    n2n_auth_t             backup_token;   /* token required from brother SNs (-B) */
    int                    backup_token_set;
    struct promoted_peer   promoted[PROMOTED_LIST_MAX]; /* ask-backup-verified sn1 edges */
    char                   backup_addr_text[256]; /* sn2 address (sn1 given via -b) */
    time_t                 last_brother_seen;
    n2n_mac_t              device_mac;       /* local NIC MAC used as SN identity in brother_reg */
    /* Deferred full-cone probes: N2NF #1 fires on FCP arrival, #2/#3 are
     * staggered so a re-mapped edge has already re-armed its stranger
     * window (its own ACK wins the race against probe #1). */
#define FC_PROBE_MAX 16
#define FC_PROBE_SPREAD 2   /* seconds between the 3 sends */
    struct { n2n_sock_t target; time_t due; uint8_t left; } fc_probes[FC_PROBE_MAX];
};

typedef struct n2n_sn n2n_sn_t;

/* Fixed identity MAC used when a NIC MAC cannot be read. This is the single
 * source of truth shared by both the edge-facing Advertise and the brother
 * registration, so a SN is uniquely identified by one MAC value everywhere. */
static const n2n_mac_t sn_fallback_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

/* SN identity MAC: the detected NIC MAC, falling back to the fixed local
 * identity when no NIC MAC could be read. brother_reg and the ACK
 * self-advertisement both use this so every path reports the same unique
 * SN identity. */
static const uint8_t * sn_identity_mac( const n2n_sn_t * sss )
{
    return ( sss->device_mac[0] || sss->device_mac[1] || sss->device_mac[2] ||
             sss->device_mac[3] || sss->device_mac[4] || sss->device_mac[5] )
           ? sss->device_mac : sn_fallback_mac;
}

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
        /* 24h minute buckets: 6 rows x 240 values each.
         * Must be persisted, otherwise the sliding window cannot decay
         * across restarts and the 24h rate limit would hit permanently. */
        for (int i = 0, c = 0; i < COMM_STATS_MINUTES; i++) {
            fprintf(fp, "%" PRIu64 "%c", s->bytes_1440[i], c == 239 ? '\n' : ' ');
            if (++c == 240) c = 0;
        }
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

        char bline[2048];
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

        /* 24h minute buckets: 6 rows x 240 values each */
        int got = 0;
        char mline[6144];
        while (got < COMM_STATS_MINUTES) {
            if (!fgets(mline, sizeof(mline), fp)) break;
            p = mline;
            while (got < COMM_STATS_MINUTES) {
                uint64_t v = 0;
                if (sscanf(p, "%" SCNu64, &v) != 1) break;
                s->bytes_1440[got++] = v;
                p = strchr(p, ' ');
                if (!p) break;
                p++;
            }
        }

        /* After restore, roll 24h/30d windows forward to current time so
         * quotas decay correctly after a downtime or long throttle. */
        advance_24h_buckets(s, now);
        advance_30d_buckets(s, now);
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
            free(s->q);
            free(s);
            continue;
        }

        /* Refresh rate limit rules and advance expired 24h/30d buckets so
         * quotas decay while idle/throttled. Periodic refresh makes config
         * changes take effect for communities that never go idle long enough
         * to hit the lazy first-use path. */
        apply_rules_to_stats(s, sss->rate_rules);
        advance_24h_buckets(s, now);
        advance_30d_buckets(s, now);

        /* If 30d traffic is now zero, remove */
        if (s->total_30d == 0) {
            *pp = s->next;
            struct mac_ip_entry *e = s->mac_ip_map;
            while (e) { struct mac_ip_entry *en = e->next; free(e); e = en; }
            free(s->q);
            free(s);
            continue;
        }

        pp = &s->next;
    }
}

static int is_private_ipv4(const uint8_t addr[IPV4_SIZE])
{
    if (addr[0] == 10) return 1;
    if (addr[0] == 172 && (addr[1] & 0xF0) == 16) return 1;
    if (addr[0] == 192 && addr[1] == 168) return 1;
    if (addr[0] == 127) return 1;
    return 0;
}

/* Find a live promoted entry (mac + community, not expired).
 * Expired slots are lazily cleared on the way. */
static struct promoted_peer * find_promoted( n2n_sn_t *sss,
                                             const n2n_mac_t mac,
                                             const n2n_community_t community,
                                             time_t now )
{
    for (int i = 0; i < PROMOTED_LIST_MAX; i++)
    {
        struct promoted_peer *p = &sss->promoted[i];
        if (p->seen == 0) continue;
        if (now - p->seen > PROMOTED_TTL) { p->seen = 0; continue; }
        if (memcmp(p->mac, mac, N2N_MAC_SIZE) == 0 &&
            memcmp(p->community, community, sizeof(n2n_community_t)) == 0)
            return p;
    }
    return NULL;
}

/* Record or refresh a promoted entry (probe verified this edge belongs to sn1). */
static void record_promoted( n2n_sn_t *sss,
                             const n2n_mac_t mac,
                             const n2n_community_t community,
                             time_t now )
{
    struct promoted_peer *free_slot = NULL, *oldest = NULL;
    time_t oldest_t = (time_t)(~(time_t)0);

    for (int i = 0; i < PROMOTED_LIST_MAX; i++)
    {
        struct promoted_peer *p = &sss->promoted[i];
        if (p->seen == 0) { if (!free_slot) free_slot = p; continue; }
        if (memcmp(p->mac, mac, N2N_MAC_SIZE) == 0 &&
            memcmp(p->community, community, sizeof(n2n_community_t)) == 0)
        {
            p->seen = now; /* refresh */
            return;
        }
        if (p->seen < oldest_t) { oldest_t = p->seen; oldest = p; }
    }
    if (!free_slot) free_slot = oldest; /* replace oldest when full */
    if (!free_slot) return;
    memcpy(free_slot->mac, mac, N2N_MAC_SIZE);
    memcpy(free_slot->community, community, sizeof(n2n_community_t));
    free_slot->seen = now;
}

static int update_edge( n2n_sn_t * sss,
                        const n2n_mac_t edgeMac,
                        const n2n_community_t community,
                        const n2n_sock_t * sender_sock,
                        const n2n_sock_t * local_sock,
                        uint8_t local_sock_ena,
                        const n2n_sock_t * report_ipv6, /* edge-reported GUA or NULL */
                        time_t now,
                        const char * version,
                        const char * os_name,
                        uint8_t nat_type,
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
    sss->bounce_sock = -1;
    sss->ws_listen_sock = -1;
    {
        int wi;
        for (wi = 0; wi < N2N_SN_MAX_WS; wi++)
            ws_init(&sss->ws_conns[wi]);
    }
    sss->edges = NULL;
    sss->relay_advert_enabled = 1; /* community relay advertisement ON by default */
    /* Initialize transforms - required to decode encrypted packets */
    transop_null_init(    &(sss->transop[N2N_TRANSOP_NULL_IDX]) );
    transop_twofish_init( &(sss->transop[N2N_TRANSOP_TF_IDX])  );
    transop_aes_init( &(sss->transop[N2N_TRANSOP_AESCBC_IDX])  );
    transop_cc20_init(   &(sss->transop[N2N_TRANSOP_CC20_IDX]) );
    transop_speck_init( &(sss->transop[N2N_TRANSOP_SPECK_IDX]) );

    /* Capture local NIC MAC as the SN's brother_reg identity. Falls back
     * to all-zero if no NIC can be read; brother_list_store already
     * rejects entries with a zero MAC so the partner SN will ignore such
     * registrations. */
    if (!sn_get_device_mac(sss->device_mac)) {
        traceEvent(TRACE_WARNING, "Could not detect a NIC MAC; brother_reg will carry a zero MAC.");
    } else {
        macstr_t mac_buf;
        traceEvent(TRACE_NORMAL, "Detected NIC MAC %s",
                   macaddr_str(mac_buf, sss->device_mac));
    }

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

    if ( sss->bounce_sock >= 0 )
    {
        closesocket(sss->bounce_sock);
    }
    sss->bounce_sock = -1;

    if ( sss->ws_listen_sock >= 0 )
    {
        closesocket(sss->ws_listen_sock);
    }
    sss->ws_listen_sock = -1;
    {
        int wi;
        for (wi = 0; wi < N2N_SN_MAX_WS; wi++)
            ws_close(&sss->ws_conns[wi]);
    }

    purge_peer_list( &(sss->edges), 0xffffffff );

#ifdef _WIN32
    WSACleanup();
#endif
}


/* brother_list bookkeeping and the helpers that drive it. */

/* Mgmt table header, shared by the brother and edges tables so the column
 * positions (e.g. the trailing "os" column) stay in sync. */
static const char mgmt_header[] =
    "  id  mac                n2n_ip           wan_ip               <KB/s     GB/24h   GB/30d>  ver      os       nat\n";

/* brother_list display helper: format brother SN status lines (for -Q / trace). */
static size_t brother_list_format(n2n_sn_t *sss, time_t now, char *buf, size_t bufsz)
{
    size_t written = 0;
    int shown = 0;
    int counter = 0;

    /* Live brother SN: one slot per brother, show v4/v6 on one line. */
    for (int j = 0; j < MAX_BROTHER_SNS; j++)
    {
        n2n_brother_entry_t *b = &sss->brothers[j];
        uint8_t zero[6] = {0,0,0,0,0,0};
        if (memcmp(b->mac, zero, 6) == 0) continue;
        int have_v4 = (b->sock.family != 0 && b->seen != 0);
        int have_v6 = (b->sock6.family != 0 && b->seen6 != 0);
        if (!have_v4 && !have_v6) continue;

        if (shown == 0)
            written += snprintf(buf + written, bufsz - written, "[brother]\n");
        counter++;
        const uint8_t *mac = b->mac;
        char v4_part[64] = "-";
        if (have_v4)
            sock_to_cstr(v4_part, &b->sock);
        char v6_part[64] = "-";
        if (have_v6)
        {
            char v6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, b->sock6.addr.v6, v6_str, sizeof(v6_str));
            snprintf(v6_part, sizeof(v6_part), "[%s]:%u", v6_str, b->sock6.port);
        }
        /* Heartbeat age: v4 first, v6 fallback; left-aligned to the "os"
         * column of the header. (have_v4 || have_v6 is guaranteed above,
         * so the slot always has a last-seen timestamp.) */
        time_t last = b->seen ? b->seen : b->seen6;
        size_t line_start = written;
        written += snprintf(buf + written, bufsz - written,
                            "%4d  %02X:%02X:%02X:%02X:%02X:%02X  %s/%s",
                            counter,
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                            v4_part, v6_part);
        int pad = (int)sizeof(mgmt_header) - 4 - (int)(written - line_start);
        if (pad < 1) pad = 1;
        written += snprintf(buf + written, bufsz - written,
                            "%*s%lds\n", pad, "", (long)(now - last));
        shown++;
    }
    return written;
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
                        const n2n_sock_t * report_ipv6, /* edge-reported GUA or NULL */
                        time_t now,
                        const char * version,
                        const char * os_name,
                        uint8_t nat_type,
                        uint8_t request_ip,
                        uint32_t requested_ip )
{
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;
    struct peer_info *  scan;
    uint8_t             nat_changed = 0; /* reported NAT type differs from stored */

    traceEvent( TRACE_DEBUG, "update_edge for %s %s",
                macaddr_str( mac_buf, edgeMac ),
                sock_to_cstr( sockbuf, sender_sock ) );

    scan = find_peer_by_mac( sss->edges, edgeMac );

    if ( NULL == scan )
    {
        /* Not known */

        scan = (struct peer_info*)calloc(1, sizeof(struct peer_info)); /* deallocated in purge_expired_registrations */
        if (!scan) {
            traceEvent(TRACE_ERROR, "update_edge: out of memory for new edge");
            return 0;
        }

        if (request_ip) {
            uint32_t assigned_ip;
            if (requested_ip != 0) {
                assigned_ip = requested_ip;
                {
                    struct peer_info *check = sss->edges;
                    int ip_conflict = 0;
                    while (check) {
                        if (memcmp(check->community_name, community, sizeof(n2n_community_t)) == 0 &&
                            memcmp(check->mac_addr, edgeMac, sizeof(n2n_mac_t)) != 0 &&
                            check->assigned_ip == assigned_ip) {
                            ip_conflict = 1;
                            break;
                        }
                        check = check->next;
                    }
                    if (ip_conflict) {
                        traceEvent(TRACE_WARNING, "Edge %s static IP %u.%u.%u.%u conflicts with existing edge in community %s",
                                   macaddr_str(mac_buf, edgeMac),
                                   (assigned_ip>>24)&0xFF, (assigned_ip>>16)&0xFF,
                                   (assigned_ip>>8)&0xFF, assigned_ip&0xFF,
                                   (char*)community);
                        assigned_ip = 0;
                    } else {
                        traceEvent(TRACE_DEBUG, "Edge %s using static IP %u.%u.%u.%u",
                                   macaddr_str(mac_buf, edgeMac),
                                   (assigned_ip>>24)&0xFF, (assigned_ip>>16)&0xFF,
                                   (assigned_ip>>8)&0xFF, assigned_ip&0xFF);
                    }
                }
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
                        struct peer_info *check;
                        int conflict;
                        int safety = 0;
                        do {
                            assigned_ip = cs->next_ip++;
                            /* Wrap when last octet exceeds 254 (x.x.x.255 is broadcast) */
                            if ((cs->next_ip & 0xFF) > 254)
                                cs->next_ip = (cs->next_ip & 0xFFFFFF00) + 2; /* skip .0 and .1 */
                            /* Wrap entire block back to 10.64.0.2 after 10.64.255.254 */
                            if (cs->next_ip > 0x0a40FFFE)
                                cs->next_ip = 0x0a400002;

                            /* Verify no other edge in this community already has this IP.
                             * Can happen if community_stats was purged while edges remained registered. */
                            conflict = 0;
                            check = sss->edges;
                            while (check) {
                                if (memcmp(check->community_name, community, sizeof(n2n_community_t)) == 0 &&
                                    memcmp(check->mac_addr, edgeMac, sizeof(n2n_mac_t)) != 0 &&
                                    check->assigned_ip == assigned_ip) {
                                    conflict = 1;
                                    break;
                                }
                                check = check->next;
                            }
                            if (++safety > 65534) {
                                traceEvent(TRACE_WARNING, "IP collision loop safety at %s for %s",
                                           macaddr_str(mac_buf, edgeMac), (char*)community);
                                break;
                            }
                        } while (conflict);

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

        scan->connect_family = sender_sock->family;

        memcpy(scan->community_name, community, sizeof(n2n_community_t) );
        memcpy(&(scan->mac_addr), edgeMac, sizeof(n2n_mac_t));
        
        /* Store address in the correct slot based on family */
        if (sender_sock->family == AF_INET6) {
            memcpy(&(scan->sock6), sender_sock, sizeof(n2n_sock_t));
            /* sock remains 0 from calloc */
        } else {
            memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
            /* sock6 remains 0 from calloc */
        }

        /* Edge-reported global IPv6 (GUA). An IPv4-only supernode cannot
         * observe our IPv6, so it uses this address to hand to peers for
         * IPv6 hole-punching. A dual-stack supernode observes sock6 itself
         * (more authoritative, it is the NAT egress), so only fall back to
         * the reported address when no IPv6 was observed. */
        if (scan->sock6.family != AF_INET6 && report_ipv6 && report_ipv6->family == AF_INET6)
            memcpy(&(scan->sock6), report_ipv6, sizeof(n2n_sock_t));

        /* Check if edge is in same LAN as supernode:
         * local_sock IP == sender_sock IP and both are private */
        if (local_sock_ena && local_sock &&
            sender_sock->family == AF_INET && local_sock->family == AF_INET &&
            memcmp(sender_sock->addr.v4, local_sock->addr.v4, IPV4_SIZE) == 0 &&
            is_private_ipv4(sender_sock->addr.v4))
        {
            scan->same_lan_as_sn = 1;
        }

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
        scan->nat_type = nat_type;

        /* insert this guy at the head of the edges list */
        scan->next = sss->edges;
        sss->edges = scan;

        /* Build sockets array for hole-punching.
        * sockets[0] = primary (connect_family), sock6 = IPv6 (if available) */
        scan->num_sockets = 0;
        if (scan->connect_family == AF_INET6 && scan->sock6.family == AF_INET6) {
            scan->sockets[scan->num_sockets++] = scan->sock6;
        } else if (scan->sock.family == AF_INET) {
            scan->sockets[scan->num_sockets++] = scan->sock;
        } else if (scan->sock6.family == AF_INET6) {
            scan->sockets[scan->num_sockets++] = scan->sock6;
        }
        if (local_sock_ena && local_sock) {
            scan->sockets[scan->num_sockets++] = *local_sock;
        }

        {
            struct in_addr vip_addr;
            vip_addr.s_addr = htonl(scan->assigned_ip);
            char addr_buf[64];
            if (scan->sock.family == AF_INET)
                sock_to_cstr(addr_buf, &scan->sock);
            else if (scan->sock6.family == AF_INET6)
                sock_to_cstr(addr_buf, &scan->sock6);
            else
                strcpy(addr_buf, "-");
            traceEvent( TRACE_NORMAL, "update_edge created %s ==> %s",
                        inet_ntoa(vip_addr),
                        addr_buf );
        }

        scan->last_seen = now;
        return 1;  /* new edge */
    }
    else
    {
        /* Known */

        /* Refresh identity/metadata on every registration regardless of
         * address changes. Repeat registrations carry a stable IP:port
         * (the edge socket does not move), so the addr_changed guard below
         * would otherwise skip this block and a NAT type learned later
         * (after the first, NAT-less registration) would never land on
         * this edge. */
        if (version) {
            strncpy(scan->version, version, sizeof(scan->version) - 1);
            scan->version[sizeof(scan->version) - 1] = '\0';
        }
        if (os_name) {
            strncpy(scan->os_name, os_name, sizeof(scan->os_name) - 1);
            scan->os_name[sizeof(scan->os_name) - 1] = '\0';
        }
        if (nat_type) {
            if (nat_type != scan->nat_type ||
                (now - scan->last_nat_push) >= 300) { /* re-push same value every 5 min: heals a lost PEER_INFO */
                nat_changed = 1;
                scan->last_nat_push = now;
            }
            scan->nat_type = nat_type;
        }

        /* Update assigned IP if edge requests a different valid IP */
        if (request_ip && requested_ip != 0) {
            uint32_t new_ip = requested_ip;
            if (scan->assigned_ip != new_ip) {
                struct peer_info *check = sss->edges;
                int ip_conflict = 0;
                while (check) {
                    if (memcmp(check->community_name, community, sizeof(n2n_community_t)) == 0 &&
                        memcmp(check->mac_addr, edgeMac, sizeof(n2n_mac_t)) != 0 &&
                        check->assigned_ip == new_ip) {
                        ip_conflict = 1;
                        break;
                    }
                    check = check->next;
                }
                if (!ip_conflict) {
                    scan->assigned_ip = new_ip;
                    traceEvent(TRACE_INFO, "update_edge reassigned IP for %s to %u.%u.%u.%u",
                               macaddr_str(mac_buf, edgeMac),
                               (new_ip >> 24) & 0xFF, (new_ip >> 16) & 0xFF,
                               (new_ip >> 8) & 0xFF, new_ip & 0xFF);
                }
            }
        }

        /* Check if this is an update (community or address changed) */
        int addr_changed = 0;
        if (sender_sock->family == AF_INET6) {
            addr_changed = (0 != sock_equal(sender_sock, &(scan->sock6)));
        } else {
            addr_changed = (0 != sock_equal(sender_sock, &(scan->sock)));
        }
        
        if ( (0 != memcmp(community, scan->community_name, sizeof(n2n_community_t))) || addr_changed )
        {
            /* Determine existing primary family (backward compat: old data may not have connect_family) */
            int existing_family = scan->connect_family;
            if (existing_family == 0) {
                if (scan->sock.family != 0)
                    existing_family = AF_INET;
                else if (scan->sock6.family != 0)
                    existing_family = AF_INET6;
            }

            /* Alt-family registration: update address.
             * Keep connect_family as primary registration's family.
             * sn_send_to_peer dual-sends to both IPv4 and IPv6, so
             * connect_family no longer needs switching. */
            if (existing_family != 0 && sender_sock->family != existing_family) {
                if (sender_sock->family == AF_INET6) {
                    int had_sock6 = (scan->sock6.family == AF_INET6);
                    memcpy(&scan->sock6, sender_sock, sizeof(n2n_sock_t));
                    scan->num_sockets = 0;
                    if (scan->sock.family == AF_INET) {
                        scan->sockets[scan->num_sockets++] = scan->sock;
                    }
                    if (scan->sock6.family == AF_INET6) {
                        scan->sockets[scan->num_sockets++] = scan->sock6;
                    }
                    if (local_sock_ena && local_sock) {
                        scan->sockets[scan->num_sockets++] = *local_sock;
                    }
                    scan->last_seen = now;
                    return had_sock6 ? 0 : 1;
                }
                /* IPv4 alt: primary was IPv6 */
                memcpy(&scan->sock, sender_sock, sizeof(n2n_sock_t));
                scan->num_sockets = 0;
                if (scan->sock.family == AF_INET) {
                    scan->sockets[scan->num_sockets++] = scan->sock;
                }
                if (scan->sock6.family == AF_INET6) {
                    scan->sockets[scan->num_sockets++] = scan->sock6;
                }
                if (local_sock_ena && local_sock) {
                    scan->sockets[scan->num_sockets++] = *local_sock;
                }
                scan->last_seen = now;
                return 1;
            }

            memcpy(scan->community_name, community, sizeof(n2n_community_t) );
            scan->connect_family = sender_sock->family;
            
            /* Store address in the correct slot based on family */
            if (sender_sock->family == AF_INET6) {
                memcpy(&(scan->sock6), sender_sock, sizeof(n2n_sock_t));
                /* Don't clear sock - it may have IPv4 from earlier registration */
            } else {
                memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
                /* Don't clear sock6 - it may have IPv6 from earlier registration */
                /* IPv4-only registration: use edge-reported GUA as sock6
                 * when we still have no observed IPv6 (see note at top). */
                if (scan->sock6.family != AF_INET6 && report_ipv6 && report_ipv6->family == AF_INET6)
                    memcpy(&(scan->sock6), report_ipv6, sizeof(n2n_sock_t));
            }

            /* Check if edge is in same LAN as supernode */
            if (local_sock_ena && local_sock &&
                sender_sock->family == AF_INET && local_sock->family == AF_INET &&
                memcmp(sender_sock->addr.v4, local_sock->addr.v4, IPV4_SIZE) == 0 &&
                is_private_ipv4(sender_sock->addr.v4))
            {
                scan->same_lan_as_sn = 1;
            }

            traceEvent( TRACE_INFO, "update_edge updated   %s ==> %s",
                        macaddr_str( mac_buf, edgeMac ),
                        sock_to_cstr( sockbuf, sender_sock ) );

            /* Build sockets array for hole-punching.
            * sockets[0] = primary (connect_family), sock6 = IPv6 (if available) */
            scan->num_sockets = 0;
            if (scan->connect_family == AF_INET6 && scan->sock6.family == AF_INET6) {
                scan->sockets[scan->num_sockets++] = scan->sock6;
            } else if (scan->sock.family == AF_INET) {
                scan->sockets[scan->num_sockets++] = scan->sock;
            } else if (scan->sock6.family == AF_INET6) {
                scan->sockets[scan->num_sockets++] = scan->sock6;
            }
            if (local_sock_ena && local_sock) {
                scan->sockets[scan->num_sockets++] = *local_sock;
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
    return nat_changed ? 2 : 0;  /* 2 = unchanged address but NAT type changed:
                                     peers need a fresh PEER_INFO push */
}


/* ============================ WebSocket support ============================ */

/* Create TCP listen socket (same port as UDP), to accept WS edge connections.
 * Returns fd on success, -1 on failure. */
static SOCKET open_ws_listen_socket(uint16_t local_port) {
    SOCKET fd;
    struct sockaddr_in addr;
    int reuse = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        traceEvent(TRACE_WARNING, "WS listen bind failed (port %u): %s",
                   (unsigned)local_port, strerror(errno));
        closesocket(fd);
        return -1;
    }
    if (listen(fd, 16) == -1) {
        traceEvent(TRACE_WARNING, "WS listen() failed: %s", strerror(errno));
        closesocket(fd);
        return -1;
    }
    return fd;
}

/* Find a free slot in ws_conns[], return index or -1 */
static int sn_ws_find_free_slot(n2n_sn_t * sss) {
    int i;
    for (i = 0; i < N2N_SN_MAX_WS; i++)
        if (sss->ws_conns[i].state == WS_FREE || sss->ws_conns[i].state == WS_CLOSED)
            return i;
    return -1;
}

/* Close the specified ws_conn slot and clear all peer_info ws pointers pointing to it.
 * slot is the index into ws_conns. */
static void sn_ws_drop_conn(n2n_sn_t * sss, int slot) {
    ws_conn_t *wc;
    struct peer_info *scan;
    if (slot < 0 || slot >= N2N_SN_MAX_WS) return;
    wc = &sss->ws_conns[slot];
    if (wc->fd < 0 && wc->state == WS_FREE) return;

    /* Clear peer->ws references to this connection */
    scan = sss->edges;
    while (scan) {
        if (scan->ws == wc) scan->ws = NULL;
        scan = scan->next;
    }
    ws_close(wc);
    ws_init(wc);  /* recycle as free slot */
}

/* Send data to a registered edge: if the edge is on WS use ws_send, otherwise UDP.
 * Returns bytes sent, <0 on failure. */
static ssize_t sendto_sock(n2n_sn_t * sss,
                           const n2n_sock_t * sock,
                           const uint8_t * pktbuf,
                           size_t pktsize);
static ssize_t sn_send_to_peer(n2n_sn_t * sss,
                               struct peer_info * peer,
                               const uint8_t * pktbuf,
                               size_t pktsize) {
    if (peer->ws && peer->ws->state == WS_OPEN) {
        /* ws_send failure drops only this packet, does not mark CLOSED — connection
         * liveness is determined by ws_recv, to avoid TCP buffer full (EAGAIN)
         * incorrectly closing the connection and leaving peer->ws dangling. */
        return ws_send(peer->ws, pktbuf, pktsize);
    }
    /* UDP routing: dual-send to both IPv4 and IPv6 if available.
     * UDP sendto always succeeds (packet accepted by kernel) even when the
     * peer's NAT mapping is stale, so primary/fallback based on sendto return
     * value never triggers. Send to both paths so the peer receives data on
     * whichever path is actually reachable. */
    {
        ssize_t r = -1;
        if (peer->sock.family != 0)
            r = sendto_sock(sss, &peer->sock, pktbuf, pktsize);
        if (peer->sock6.family != 0) {
            ssize_t r6 = sendto_sock(sss, &peer->sock6, pktbuf, pktsize);
            if (r6 == (ssize_t)pktsize) r = r6;
        }
        return r;
    }
}

/* Purge timed out / closed WS connections. Close if idle for WS_KEEPALIVE_TIMEOUT seconds. */
#define WS_KEEPALIVE_TIMEOUT 60
static void sn_ws_purge(n2n_sn_t * sss, time_t now) {
    int i;
    for (i = 0; i < N2N_SN_MAX_WS; i++) {
        ws_conn_t *wc = &sss->ws_conns[i];
        if (wc->state == WS_OPEN) {
            if (now - wc->last_seen > WS_KEEPALIVE_TIMEOUT) {
                traceEvent(TRACE_DEBUG, "WS conn[%d] idle timeout, closing", i);
                sn_ws_drop_conn(sss, i);
            }
        } else if (wc->state == WS_CLOSED) {
            sn_ws_drop_conn(sss, i);
        }
    }
}

/* ===================================================================== */


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
    ssize_t             sent;

    if ( AF_INET == sock->family )
    {
        struct sockaddr_in udpsock;

        udpsock.sin_family = AF_INET;
        udpsock.sin_port = htons( sock->port );
        memcpy( &(udpsock.sin_addr), &(sock->addr.v4), IPV4_SIZE );

        sent = sendto( sss->sock, pktbuf, pktsize, 0,
                       (const struct sockaddr *)&udpsock, sizeof(struct sockaddr_in) );
    }
    else if ( AF_INET6 == sock->family )
    {
        struct sockaddr_in6 udpsock = { 0 };

        udpsock.sin6_family = AF_INET6;
        udpsock.sin6_port = htons( sock->port );
        memcpy( &(udpsock.sin6_addr), &(sock->addr.v6), IPV6_SIZE );

        sent = sendto( sss->sock6, pktbuf, pktsize, 0,
                       (const struct sockaddr *)&udpsock, sizeof(struct sockaddr_in6) );
    }
    else
    {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if ( sent < 0 )
    {
#ifdef _WIN32
        int error = WSAGetLastError();
        /* WSAECONNRESET is expected on UDP (ICMP port unreachable) - silently ignore.
         * Also silence WSAEFAULT (10014), WSAEAFNOSUPPORT (10047), WSAEWOULDBLOCK (10035). */
        if ( error != 10014 && error != 10047 && error != 10035 &&
             error != WSAECONNRESET ) {
            traceEvent( TRACE_ERROR, "sendto_sock failed: code=%d to %s",
                        error, sock_to_cstr( sockbuf, sock ) );
        }
#else
        traceEvent( TRACE_DEBUG, "sendto_sock failed (%d) %s to %s",
                    errno, strerror(errno), sock_to_cstr( sockbuf, sock ) );
#endif
    }
    else
    {
        traceEvent( TRACE_DEBUG, "sendto_sock sent=%d to %s",
                    (int)sent, sock_to_cstr( sockbuf, sock ) );
    }

    return sent;
}

/* ===== Compromise shaper: small FIFO queue instead of drops =====
 * While throttled, packets that exceed the token credit are parked here
 * (SHAPER_SLOTS x ~2KB ~ 16KB, ~140ms at 115KB/s) and released FIFO as the
 * bucket refills. TCP sees no loss, avoiding retransmission storms; the cost
 * is added queueing latency. One queue per community, lazily allocated. */
static int shaper_enqueue(struct community_stats *s,
                          const n2n_mac_t mac,
                          const uint8_t *pktbuf, size_t pktsize)
{
    if (pktsize > N2N_SN_PKTBUF_SIZE) return 0;
    if (!s->q) {
        s->q = (struct shaper_slot*)calloc(SHAPER_SLOTS, sizeof(struct shaper_slot));
        if (!s->q) return 0;
    }
    if (s->q_n >= SHAPER_SLOTS) return 0; /* queue full: tail drop */
    struct shaper_slot *sl = &s->q[(s->q_r + s->q_n) % SHAPER_SLOTS];
    memcpy(sl->mac, mac, sizeof(n2n_mac_t));
    sl->len = (uint16_t)pktsize;
    memcpy(sl->buf, pktbuf, pktsize);
    s->q_n++;
    return 1;
}

/* Release queued packets in FIFO order as the token bucket refills. */
static void shaper_drain(n2n_sn_t *sss, struct community_stats *s)
{
    if (!s->q || s->q_n == 0) return;
    time_t now = time(NULL);
    while (s->q_n > 0) {
        struct shaper_slot *sl = &s->q[s->q_r];
        struct peer_info *peer = find_peer_by_mac(sss->edges, sl->mac);
        if (!peer) {
            /* destination vanished while queued: drop this slot */
            s->q_r = (s->q_r + 1) % SHAPER_SLOTS;
            s->q_n--;
            continue;
        }
        if (!rate_admit(s, sl->len)) break; /* out of credit: wait for refill */
        if (sn_send_to_peer(sss, peer, sl->buf, sl->len) == (ssize_t)sl->len) {
            ++(sss->stats.fwd);
            sss->stats.last_fwd = now;
            update_community_traffic(s, sl->len, now);
        }
        s->q_r = (s->q_r + 1) % SHAPER_SLOTS;
        s->q_n--;
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
    struct community_stats *cs = NULL;
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;
    time_t              now = time(NULL);

    scan = find_peer_by_mac( sss->edges, dstMac );

    /* Check the destination exists first: packets to unknown MACs are dropped
     * without touching traffic stats / rate limit, so flooding a random MAC
     * cannot consume a community's quota. */
    if ( NULL == scan )
    {
        traceEvent( TRACE_DEBUG, "try_forward unknown MAC" );
        return 0;
    }

    /* Rate limiting check (after destination lookup) */
    if (sss->traffic_stats_enabled) {
        cs = get_community_stats(&sss->comm_stats,
                                                      cmn->community, now);
        if (cs) {
            /* Apply rules on first use (new entry has zeroed limits) */
            if (cs->rate_limit_bps == 0 && cs->max_24h_bytes == 0)
                apply_rules_to_stats(cs, sss->rate_rules);
            shaper_drain(sss, cs);
            if (!rate_admit(cs, pktsize)) {
                if (cs->rate_limit_bps > 0 &&
                    shaper_enqueue(cs, scan->mac_addr, pktbuf, pktsize)) {
                    traceEvent(TRACE_DEBUG, "shaper queued %lu for community %s",
                               (unsigned long)pktsize, cmn->community);
                } else {
                    traceEvent(TRACE_DEBUG, "rate limit drop for community %s", cmn->community);
                }
                return 0;
            }
        }
    }

    ssize_t data_sent_len;
    n2n_sock_t *primary = (scan->connect_family == AF_INET6 && scan->sock6.family == AF_INET6)
                          ? &scan->sock6 : &scan->sock;

    /* WS edge goes via ws_send, otherwise UDP primary/fallback address families */
    data_sent_len = sn_send_to_peer( sss, scan, pktbuf, pktsize );

    if ( data_sent_len == pktsize )
    {
        ++(sss->stats.fwd);
        sss->stats.last_fwd = now;
        if (cs) update_community_traffic(cs, pktsize, now);
        traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s%s",
                   pktsize,
                   sock_to_cstr( sockbuf, primary ),
                   macaddr_str(mac_buf, scan->mac_addr),
                   scan->ws ? " (ws)" : "");
    }
    else
    {
        int err = errno;
        ++(sss->stats.errors);
        /* EAGAIN is expected transient packet loss (TCP buffer full), do not spam */
        if (err == EAGAIN || err == EWOULDBLOCK) {
            traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s%s EAGAIN (drop)",
                       pktsize,
                       sock_to_cstr( sockbuf, primary ),
                       macaddr_str(mac_buf, scan->mac_addr),
                       scan->ws ? " (ws)" : "");
        } else {
            traceEvent(TRACE_WARNING, "unicast %lu to [%s] %s%s FAILED (%d: %s)",
                       pktsize,
                       sock_to_cstr( sockbuf, primary ),
                       macaddr_str(mac_buf, scan->mac_addr),
                       scan->ws ? " (ws)" : "",
                       err, strerror(err));
        }
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
    n2n_sock_str_t sockbuf;
#define MAX_COMMUNITIES 256
    n2n_community_t communities[MAX_COMMUNITIES];
    int num_communities = 0;
    uint32_t num_edges = 0;

    traceEvent( TRACE_DEBUG, "process_mgmt" );

    /* Only allow localhost connections for security */
    int is_localhost = 0;
    if (sender_sock->sa_family == AF_INET) {
        uint32_t addr = ((struct sockaddr_in*)sender_sock)->sin_addr.s_addr;
        is_localhost = (addr == htonl(INADDR_LOOPBACK)) || (addr == 0);
    } else if (sender_sock->sa_family == AF_INET6) {
        struct in6_addr *a6 = &((struct sockaddr_in6*)sender_sock)->sin6_addr;
        is_localhost = (memcmp(a6, &in6addr_loopback, sizeof(*a6)) == 0);
    }
    if (!is_localhost) {
        char tmp[INET6_ADDRSTRLEN] = "unknown";
        if (sender_sock->sa_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in*)sender_sock)->sin_addr, tmp, sizeof(tmp));
        else if (sender_sock->sa_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)sender_sock)->sin6_addr, tmp, sizeof(tmp));
        traceEvent(TRACE_WARNING, "mgmt request from non-localhost %s rejected", tmp);
        return -1;
    }

    /* Drain any stale data from mgmt_sock before sending response */
    {
        uint8_t discard[256];
        while (recvfrom(sss->mgmt_sock, (char*)discard, sizeof(discard), 0, NULL, NULL) > 0) {}
    }

    /* Send header */
    ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE, "%s", mgmt_header);
	if (ressize < N2N_SN_PKTBUF_SIZE)
        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                           "---v2.3----------------------------------------------------------------------------------------------------------------\n");
    /* brother table sits between the two v2.3 separator lines */
    ressize += brother_list_format(sss, time(NULL), resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize);

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
        /* Mark communities that hold promoted edges (registered via a
         * brother supernode's identity, not directly on this SN): the
         * community name gets a "* " prepended ("*n2n"). */
        int is_prom = 0;
        for (int p = 0; p < PROMOTED_LIST_MAX && !is_prom; p++)
            if (sss->promoted[p].seen != 0 &&
                now - sss->promoted[p].seen <= PROMOTED_TTL &&
                memcmp(sss->promoted[p].community, communities[i],
                       sizeof(n2n_community_t)) == 0)
                is_prom = 1;
        char cname[N2N_COMMUNITY_SIZE + 3];
        int cnamelen = 0;
        while (cnamelen < N2N_COMMUNITY_SIZE && communities[i][cnamelen])
            cnamelen++;
        int off = 0;
        if (is_prom) cname[off++] = '*';
        memcpy(cname + off, communities[i], cnamelen);
        off += cnamelen;
        cname[off] = 0;
        /* Community name line with traffic stats on same line */
        if (sss->traffic_stats_enabled) {
            struct community_stats *cs = sss->comm_stats;
            while (cs && memcmp(cs->community_name, communities[i], sizeof(n2n_community_t)) != 0)
                cs = cs->next;
            if (cs) {
                double kbps   = cs->instant_Bps / 1024.0;
                double gb_24h = cs->last_24h_bytes / (1024.0*1024.0*1024.0);
                double gb_30d = cs->total_30d / (1024.0*1024.0*1024.0);
                /* Zero out KB/s if no traffic in last COMM_STATS_SECONDS */
                if (now - cs->last_second >= COMM_STATS_SECONDS)
                    kbps = 0.0;
                /* Online community: show the traffic line whenever there is
                 * current throughput or a visible 30-day total (>= 0.1 GB).
                 * An online group with history must always display its
                 * numbers so the total traffic still adds up, even when it
                 * is idle right now (0 KB/s, 0 24h). */
                if (kbps > 0.0 || gb_30d >= 0.1) {
                    const char *arrow = (kbps >= 0.1) ? "--->" : "    ";
                    ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                                       "%s%*s  %s %-7.1f  %-7.1f  %-10.1f\n",
                                       cname, (int)(57 - off), "", arrow,
                                       kbps, gb_24h, gb_30d);
                } else {
                    ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE, "%s\n", cname);
                }
            } else {
                ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE, "%s\n", cname);
            }
        } else {
            ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE, "%s\n", cname);
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

            {
                n2n_sock_str_t sbuf, sbuf6;
                char wan[64];
                if (edge->sock.family != 0) {
                    snprintf(wan, sizeof(wan), "%s", sock_to_cstr(sbuf, &edge->sock));
                } else if (edge->sock6.family != 0) {
                    snprintf(wan, sizeof(wan), "%s", sock_to_cstr(sbuf6, &edge->sock6));
                } else {
                    wan[0] = '\0';
                }
                /* Also append secondary IPv6 when both families available */
                if (edge->sock6.family != 0 && edge->sock.family != 0) {
                    const char *v6 = sock_to_cstr(sbuf6, &edge->sock6);
                    size_t cur = strlen(wan);
                    int budget = 47 - (int)cur - 1; /* column width - primary - '/' */
                    if (budget >= 6) {
                        wan[cur++] = '/';
                        if ((int)strlen(v6) <= budget) {
                            strcpy(wan + cur, v6);
                        } else {
                            const char *port = strrchr(v6, ':');
                            int port_len = port ? (int)strlen(port) : 0;
                            int addr_max = budget - port_len;
                            if (addr_max < 3) addr_max = 3;
                            int w = 0;
                            while (w < addr_max - 2 && v6[w]) { wan[cur + w] = v6[w]; w++; }
                            wan[cur + w++] = '*';
                            wan[cur + w++] = ']';
                            if (port && w + port_len <= budget)
                                memcpy(wan + cur + w, port, port_len + 1);
                            else
                                wan[cur + w] = '\0';
                        }
                    }
                }
                ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                                   "  %2u  %-17s  %-15s  %-47s  %-7s  %-7s  %s\n",
                                   id++, macaddr_str(mac_buf, edge->mac_addr), virt_ip,
                                   wan, version, os_name,
                                   N2N_NAT_NAME(edge->nat_type));
            }

            r = sendto(sss->mgmt_sock, resbuf, ressize, 0, sender_sock, sender_sock_len);
            if (r <= 0) return -1;

            edge = edge->next;
        }
    }

    num_edges = displayed_edges;

    /* Offline communities: in comm_stats but no current edges */
    /* Show individually if has recent 24h traffic, else aggregate into Older Offline */
    double older_30d = 0.0;
    if (sss->traffic_stats_enabled) {
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
                double kbps  = cs->instant_Bps / 1024.0;
                double gb24h = cs->last_24h_bytes / (1024.0*1024.0*1024.0);
                double gb30d = cs->total_30d / (1024.0*1024.0*1024.0);
                if (now - cs->last_second >= COMM_STATS_SECONDS)
                    kbps = 0.0;

                /* Show individually only when there is current throughput or
                  * recent 24h traffic. Otherwise (24h idle) aggregate into
                  * Offline_over_24h. */
                if (kbps > 0.0 || gb24h >= 0.01) {
                    ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                                       "%-57.16s       %-7.1f  %-7.1f  %-10.1f\n",
                                       cs->community_name, kbps, gb24h, gb30d);
                    r = sendto(sss->mgmt_sock, resbuf, ressize, 0, sender_sock, sender_sock_len);
                    if (r <= 0) return -1;
                } else if (gb30d > 0.0) {
                     /* No recent traffic: aggregate into Older Offline */
                     older_30d  += gb30d;
                 }
            } else {
                /* Online community: if it didn't show a traffic line, contribute to Older */
                if ((now - cs->last_active) >= 86400 && cs->total_30d > 0) {
                    older_30d  += cs->total_30d / (1024.0*1024.0*1024.0);
                }
            }
            cs = cs->next;
        }
    }

    /* Older Offline: aggregated stats for offline groups with no 24h traffic */
    if (sss->traffic_stats_enabled && older_30d > 0.001) {
        ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                                   "%-57.16s       %-7.1f  %-7.1f  %-10.1f\n",
                                   "Offline_over_24h", 0.0, 0.0, older_30d);
        r = sendto(sss->mgmt_sock, resbuf, ressize, 0, sender_sock, sender_sock_len);
        if (r <= 0) return -1;
    }

    /* Traffic Total line - before the footer separator */
    if (sss->traffic_stats_enabled) {
        double total_kbps = 0.0, total_24h = 0.0, total_30d = 0.0;
        struct community_stats *cs = sss->comm_stats;
        while (cs) {
            total_kbps += (now - cs->last_second >= COMM_STATS_SECONDS)
                          ? 0.0 : (cs->instant_Bps / 1024.0);
            if ((now - cs->last_active) < 86400)
                total_24h  += cs->last_24h_bytes / (1024.0*1024.0*1024.0);
            total_30d  += cs->total_30d / (1024.0*1024.0*1024.0);
            cs = cs->next;
        }
        if (total_kbps > 0 || total_30d >= 0.1) {
            const char *tarrow = (total_kbps >= 0.1) ? "--->" : "    ";
            ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                               "----------------\n"
                               "Total_traffic                                              %s %-7.1f  %-7.1f  %-10.1f\n",
                               tarrow, total_kbps, total_24h, total_30d);
            sendto(sss->mgmt_sock, resbuf, ressize, 0, sender_sock, sender_sock_len);
        }
    }

    /* Send footer and statistics */
    ressize = snprintf(resbuf, N2N_SN_PKTBUF_SIZE,
                      "----------------------------------------------------------------------------------------------------------------v2.3---\n");

    time_t uptime = now - sss->start_time;
    int days = uptime / 86400;
    int hours = (uptime % 86400) / 3600;
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    int mins = (uptime % 3600) / 60;

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                       "%s up %dd_%dh_%dm | cmnts %u | edges %u | reg_nak %u | errs %u | last_reg/fwd %lus/%lus ago\n",
                       time_buf, days, hours, mins,
                       num_communities,
                       num_edges,
                       (unsigned int)sss->stats.reg_super_nak,
                       (unsigned int)sss->stats.errors,
                       (long unsigned int)(sss->stats.last_reg_super ? now - sss->stats.last_reg_super : 0),
                       (long unsigned int)(sss->stats.last_fwd ? now - sss->stats.last_fwd : 0));

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

    if (ressize < N2N_SN_PKTBUF_SIZE)
        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                           "broadcast %u | reg_sup %u | fwd %u | ip_support: %s | %s\n",
                           (unsigned int) sss->stats.broadcast,
                           (unsigned int)sss->stats.reg_super,
                           (unsigned int) sss->stats.fwd,
                           ip_support,
                           n2n_sw_version_full);

    /* brother_list_format output is sent earlier, between the two v2.3
     * separator lines. */

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
    struct community_stats *cs = NULL;
    int bc_count = 0;
    int bc_limit = INT_MAX; /* broadcast member cap while throttled */
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;
    time_t              now = time(NULL);

    traceEvent( TRACE_DEBUG, "try_broadcast" );

    /* Broadcast throttle policy (B1 simple gate): broadcasts never enter the
     * token bucket (a per-member charge would dead-lock them), instead their
     * fan-out is capped by bc_gate while the community is over its 24h cap.
     * Accounting still records what is actually sent, so broadcast traffic
     * keeps counting towards the 24h quota. */
    if (sss->traffic_stats_enabled) {
        cs = get_community_stats(&sss->comm_stats,
                                                      cmn->community, now);
        if (cs) {
            if (cs->rate_limit_bps == 0 && cs->max_24h_bytes == 0)
                apply_rules_to_stats(cs, sss->rate_rules);
            if (cs->max_24h_bytes > 0 && cs->last_24h_bytes >= cs->max_24h_bytes) {
                if (cs->rate_limit_bps == 0) {
                    /* hard block: no broadcast at all */
                    traceEvent(TRACE_DEBUG, "rate limit drop broadcast for community %s",
                               cmn->community);
                    return 0;
                }
                bc_limit = cs->bc_gate;
            }
        }
    }

    scan = sss->edges;
    while(scan != NULL)
    {
        if( 0 == (memcmp(scan->community_name, cmn->community, sizeof(n2n_community_t)) )
            && (0 != memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) ) )
        {
            if (bc_count >= bc_limit)
                break; /* gate reached: stop forwarding to further members */
            ssize_t data_sent_len;
            n2n_sock_t *primary = (scan->connect_family == AF_INET6 &&
                                   scan->sock6.family == AF_INET6)
                                  ? &scan->sock6 : &scan->sock;

            /* WS edge goes via ws_send, otherwise UDP */
            data_sent_len = sn_send_to_peer(sss, scan, pktbuf, pktsize);
            if(data_sent_len != (ssize_t)pktsize)
            {
                ++(sss->stats.errors);
            }
            else
            {
                ++(sss->stats.broadcast);
                ++bc_count;
                sss->stats.last_fwd = now;
                traceEvent(TRACE_DEBUG, "multicast %lu to %s %s%s",
                           pktsize,
                           sock_to_cstr( sockbuf, primary ),
                           macaddr_str( mac_buf, scan->mac_addr),
                           scan->ws ? " (ws)" : "");
            }
        }

        scan = scan->next;
    }

    if (bc_count > 0 && cs)
        update_community_traffic(cs, pktsize * bc_count, now);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Full-cone probe (plan C): the edge's NAT filter whitelist is per
 * mapping and starts empty. A source the edge has NEVER contacted can
 * therefore only get through a full-cone NAT. When a brother SN forwards
 * a brand-new edge mapping ("N2NF" + mac + IPv4 + port, 16 raw bytes),
 * we fire 3 tiny "N2NF" datagrams at it from our main socket — by
 * construction a never-contacted source. The edge accepts the probe only
 * from its sn2 query channel IP and only before its first packet there. */

/* Fire the probe at a forwarded edge mapping. Sender must match a live
 * brother entry (IP level) so only the paired SN can trigger it. */
static void handle_fc_probe_request( n2n_sn_t *sss,
                                     const struct sockaddr *sender_sock,
                                     const uint8_t *udp_buf,
                                     time_t now )
{
    n2n_sock_str_t sockbuf;
    n2n_sock_t sender_n2n;
    n2n_sock_t target;
    int from_brother = 0;
    static const uint8_t msg[4] = { 'N', '2', 'N', 'F' };

    if ( sss->last_brother_seen == 0 || now - sss->last_brother_seen > 180 )
        return;

    sock_from_sender( &sender_n2n, sender_sock );
    if ( sender_n2n.family != AF_INET )
        return;

    {
        uint8_t zero[6] = {0,0,0,0,0,0};
        for ( int j = 0; j < MAX_BROTHER_SNS && !from_brother; j++ )
        {
            n2n_brother_entry_t *b = &sss->brothers[j];
            if ( memcmp( b->mac, zero, 6 ) == 0 ) continue;
            if ( b->sock.family == AF_INET &&
                 memcmp( b->sock.addr.v4, sender_n2n.addr.v4, IPV4_SIZE ) == 0 )
                from_brother = 1;
        }
    }
    if ( !from_brother ) return;

    memset( &target, 0, sizeof(target) );
    target.family = AF_INET;
    memcpy( target.addr.v4, udp_buf + 10, IPV4_SIZE );
    target.port = ( (uint16_t)udp_buf[14] << 8 ) | udp_buf[15];
    if ( is_private_ipv4( target.addr.v4 ) )
        return; /* probes only cross a NAT; never send to private addresses */

    /* #1 now; #2/#3 staggered (fc_probes, ticked by the main loop). On a
     * re-mapped edge the ACK that re-arms its stranger window beats probe
     * #1 — the later probes are the ones that land in the open window. */
    sendto_sock( sss, &target, msg, sizeof(msg) );
    for ( int i = 0; i < FC_PROBE_MAX; i++ )
    {
        if ( sss->fc_probes[i].left > 0 ) continue;
        sss->fc_probes[i].target = target;
        sss->fc_probes[i].due    = now + FC_PROBE_SPREAD;
        sss->fc_probes[i].left   = 2;
        break;
    }

    traceEvent( TRACE_INFO, "FC probe: N2NF x3 -> %s",
                sock_to_cstr( sockbuf, &target ) );
}

/* Fire the staggered N2NF probes (#2/#3). The main loop wakes every 100ms,
 * far finer than FC_PROBE_SPREAD. */
static void fc_probes_tick( n2n_sn_t * sss, time_t now )
{
    static const uint8_t msg[4] = { 'N', '2', 'N', 'F' };

    for ( int i = 0; i < FC_PROBE_MAX; i++ )
    {
        if ( sss->fc_probes[i].left == 0 || now < sss->fc_probes[i].due )
            continue;
        sendto_sock( sss, &sss->fc_probes[i].target, msg, sizeof(msg) );
        sss->fc_probes[i].left--;
        sss->fc_probes[i].due = now + FC_PROBE_SPREAD;
    }
}

/* Forward a brand-new edge mapping to the brother SN(s) so THEY can act
 * as the never-contacted source. Targets: live brothers[] entries first,
 * fallback to the resolved -b address (asymmetric -b configs). */
static void send_fc_probe_request( n2n_sn_t *sss,
                                   const n2n_mac_t edgeMac,
                                   const n2n_sock_t *edge_sock,
                                   time_t now )
{
    uint8_t pkt[16];
    int sent = 0;

    if ( edge_sock->family != AF_INET ) return; /* NAT test is IPv4-only */

    memcpy( pkt, "N2NF", 4 );
    memcpy( pkt + 4, edgeMac, N2N_MAC_SIZE );
    memcpy( pkt + 10, edge_sock->addr.v4, IPV4_SIZE );
    pkt[14] = ( edge_sock->port >> 8 ) & 0xFF;
    pkt[15] = edge_sock->port & 0xFF;

    for ( int j = 0; j < MAX_BROTHER_SNS; j++ )
    {
        n2n_brother_entry_t *b = &sss->brothers[j];
        time_t seen = b->seen > b->seen6 ? b->seen : b->seen6;
        if ( b->sock.family == AF_INET && seen != 0 && now - seen <= 180 )
        {
            sendto_sock( sss, &b->sock, pkt, sizeof(pkt) );
            sent = 1;
        }
    }
    if ( !sent && sss->backup_addr_text[0] != '\0' )
    {
        n2n_sock_t bs;
        if ( resolve_brother_addr( sss->backup_addr_text, &bs ) == 0 &&
             bs.family == AF_INET )
        {
            sendto_sock( sss, &bs, pkt, sizeof(pkt) );
            sent = 1;
        }
    }
    if ( sent )
    {
        macstr_t mac_buf;
        traceEvent( TRACE_DEBUG, "FC probe request forwarded for %s",
                    macaddr_str( mac_buf, edgeMac ) );
    }
}

/* push_nat_to_community: an edge's reported NAT type changed (update_edge
 * returned 2) while its address stayed the same — nobody else would learn
 * it (PEER_INFO pushes otherwise fire only on new/addr-changed edges).
 * Send one PEER_INFO about the changed edge to every other community
 * member so their mgmt "nat" column stays fresh. */
static void push_nat_to_community( n2n_sn_t *sss,
                                   struct peer_info *changed,
                                   const n2n_community_t community )
{
    n2n_common_t    pi_cmn;
    n2n_PEER_INFO_t pi;
    uint8_t         pibuf[N2N_SN_PKTBUF_SIZE];
    size_t          pix;
    macstr_t        mac_buf;
    struct peer_info *p;

    if ( !changed ) return;

    memset(&pi_cmn, 0, sizeof(pi_cmn));
    memset(&pi, 0, sizeof(pi));
    pi_cmn.ttl   = N2N_DEFAULT_TTL;
    pi_cmn.pc    = n2n_peer_info;
    pi_cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
    memcpy(pi_cmn.community, community, sizeof(n2n_community_t));

    memcpy(pi.mac, changed->mac_addr, N2N_MAC_SIZE);
    /* Always put IPv4 in sockets[0] if available */
    if (changed->sock.family == AF_INET)
        pi.sockets[0] = changed->sock;
    else if (changed->sock6.family == AF_INET6)
        pi.sockets[0] = changed->sock6;
    if (changed->num_sockets > 1 &&
        changed->sockets[1].family != 0 &&
        changed->sockets[1].port != 0)
    {
        pi.aflags = N2N_AFLAGS_LOCAL_SOCKET;
        pi.sockets[1] = changed->sockets[1];
    } else {
        pi.aflags = 0;
    }
    /* Include IPv6 address if available */
    if (changed->sock6.family == AF_INET6) {
        pi.aflags |= N2N_AFLAGS_IPV6_SOCKET;
        pi.sock6 = changed->sock6;
    } else {
        memset(&pi.sock6, 0, sizeof(n2n_sock_t));
    }
    if (changed->same_lan_as_sn) {
        pi.aflags |= N2N_AFLAGS_SAME_LAN_AS_SN;
    }
    strncpy(pi.version, changed->version, sizeof(pi.version) - 1);
    strncpy(pi.os_name, changed->os_name, sizeof(pi.os_name) - 1);
    pi.assigned_ip = changed->assigned_ip;
    pi.aflags |= N2N_NAT_AFLAGS(changed->nat_type);
    pix = 0;
    encode_PEER_INFO(pibuf, &pix, &pi_cmn, &pi);

    for ( p = sss->edges; p; p = p->next )
    {
        if ( p == changed ) continue;
        if ( memcmp(p->community_name, community, sizeof(n2n_community_t)) != 0 ) continue;
        sn_send_to_peer( sss, p, pibuf, pix );
    }
    traceEvent(TRACE_DEBUG, "pushed NAT change of %s to community",
               macaddr_str(mac_buf, changed->mac_addr));
}

/* ---- community relay helpers (mini-SN) -----------------------------------
 *
 * The relay is a community peer picked to forward traffic for members that
 * cannot P2P directly. It must be a "good" peer: measured cone NAT (NAT1) and
 * holding a usable public IPv4 socket, so the members can reach it without
 * punching. Address rewriting / NAT2 relays are intentionally left as the
 * "else -> back to SN" path.
 * ------------------------------------------------------------------------ */

/* A peer is relay-capable only if its extern addr is a public IPv4 and its
 * NAT type is relay-eligible (N2N_NAT_RELAY_CAPABLE). Private addrs would
 * make A/B unreachable. */
static int is_relay_capable( const struct peer_info * peer )
{
    if (!peer) return 0;
    if (!N2N_NAT_RELAY_CAPABLE(peer->nat_type)) return 0;
    if (peer->sock.family != AF_INET) return 0;
    return !is_private_ipv4(peer->sock.addr.v4);
}

/* Pick the community's relay among the registered edges. Excludes a given MAC
 * (e.g. the registering party) so the relay never relays for itself. A -Z 3
 * (force) member is always used as-is and never filtered by NAT/public state
 * -- if it cannot relay, the edge's 5s relay_proven fallback routes back
 * through the SN. When several forcing members exist, exactly one is chosen at
 * random and given a single chance (no rotation) -- this is an edge case and
 * is intentionally rough. Only when nobody forces does the normal priority
 * apply: willing (2) over default (1); a refusing peer (-Z 0) is never picked,
 * and when relay is globally off (force_only) nobody forces means no relay at
 * all. Newest peer first (edges list is latest-first). Returns NULL if none
 * eligible. */
static struct peer_info * find_community_relay( n2n_sn_t *sss,
                                                const n2n_community_t community,
                                                const n2n_mac_t exclude_mac,
                                                int force_only )
{
    struct peer_info * scan;
    struct peer_info * forcers[32];
    int n = 0;

    for ( scan = sss->edges; scan; scan = scan->next )
    {
        if ( memcmp(scan->mac_addr, exclude_mac, N2N_MAC_SIZE) == 0 ) continue;
        if ( memcmp(scan->community_name, community, sizeof(n2n_community_t)) != 0 ) continue;
        if ( scan->relay_willing == 3 )
        {
            if ( n < 32 ) forcers[n++] = scan; /* never state-checked */
        }
    }
    if ( n > 0 )
    {
        /* Random single pick among the forcing members -- one chance. */
        unsigned long seed = (unsigned long)time(NULL) ^ (unsigned long)&forcers[0];
        seed = seed * 2654435761u;
        seed += (unsigned long)&scan; /* vary with layout across calls */
        return forcers[ seed % n ];
    }

    {
        struct peer_info * best_willing = NULL;  /* willing==2 */
        struct peer_info * best_default = NULL;  /* willing==1 */
        for ( scan = sss->edges; scan; scan = scan->next )
        {
            if ( memcmp(scan->mac_addr, exclude_mac, N2N_MAC_SIZE) == 0 ) continue;
            if ( memcmp(scan->community_name, community, sizeof(n2n_community_t)) != 0 ) continue;
            if ( !is_relay_capable(scan) ) continue;
            if ( scan->relay_willing == 0 ) continue;      /* refusing: never pick */
            if ( force_only ) continue;                    /* globally off, nobody forces: no relay */
            if ( scan->relay_willing == 2 ) { if (!best_willing) best_willing = scan; }
            else if ( !best_default ) best_default = scan;
        }
        if ( best_willing ) return best_willing;
        return best_default;
    }
}

/* Send one PEER_INFO telling <dest> that <relay> is the community's relay
 * peer. The RELAY flag makes the receiving edge register to it and fall back
 * to it when direct punching fails. */
static void advertise_relay_to( n2n_sn_t *sss,
                                const n2n_common_t * cmn,
                                struct peer_info * dest,
                                struct peer_info * relay )
{
    n2n_common_t    pi_cmn;
    n2n_PEER_INFO_t pi;
    uint8_t         pibuf[N2N_SN_PKTBUF_SIZE];
    size_t          pix = 0;

    if ( !dest || !relay ) return;

    memset(&pi_cmn, 0, sizeof(pi_cmn));
    memset(&pi, 0, sizeof(pi));
    pi_cmn.ttl   = N2N_DEFAULT_TTL;
    pi_cmn.pc    = n2n_peer_info;
    pi_cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
    memcpy(pi_cmn.community, cmn->community, sizeof(n2n_community_t));

    memcpy(pi.mac, relay->mac_addr, N2N_MAC_SIZE);
    pi.aflags = N2N_AFLAGS_RELAY; /* this peer is the relay, not a punch target */
    if (relay->sock.family == AF_INET)
        pi.sockets[0] = relay->sock;
    else if (relay->sock6.family == AF_INET6)
        pi.sockets[0] = relay->sock6;
    if (relay->sock6.family == AF_INET6) {
        pi.aflags |= N2N_AFLAGS_IPV6_SOCKET;
        pi.sock6 = relay->sock6;
    }
    strncpy(pi.version, relay->version, sizeof(pi.version) - 1);
    strncpy(pi.os_name, relay->os_name, sizeof(pi.os_name) - 1);
    pi.aflags |= N2N_NAT_AFLAGS(relay->nat_type);

    encode_PEER_INFO( pibuf, &pix, &pi_cmn, &pi );
    sn_send_to_peer( sss, dest, pibuf, pix );
}

/* When the supernode actually relays unicast traffic between <req_mac> and
 * <tgt_mac> ("communication attempt / failed direct"), advertise the community
 * relay peer to both so they start registering to it and route through it.
 * Throttled to ~once per 15s per requester so heavy flows don't flood PEER_INFO. */
static void advertise_relay_on_pair( n2n_sn_t *sss,
                                     const n2n_common_t * cmn,
                                     const n2n_mac_t req_mac,
                                     const n2n_mac_t tgt_mac )
{
    int force_only;
    /* Whole-relay feature switch: when the admin disabled community relay
     * advertisement (sn -Z 0), stay on plain SN relay UNLESS a member forces
     * (edge -Z 3) -- a forcing member turns the group relay back on and is then
     * used as-is (SN never checks its NAT/public state); if it cannot relay,
     * the edge's 5s relay_proven fallback routes back through the SN. */
    force_only = !sss->relay_advert_enabled;

    struct peer_info * req = find_peer_by_mac( sss->edges, req_mac );
    if ( !req ) return;

    time_t now = time(NULL);
    if ( (now - req->relay_adv_time) < 15 ) return; /* throttled */

    /* R must be a proper third peer: neither the sender nor the target. */
    struct peer_info * relay = find_community_relay( sss, cmn->community, req_mac, force_only );
    if ( !relay || (memcmp(relay->mac_addr, tgt_mac, N2N_MAC_SIZE) == 0) )
        return; /* no good peer (incl. globally-off with no forcing member) -> plain SN */
    req->relay_adv_time = now;

    struct peer_info * tgt = find_peer_by_mac( sss->edges, tgt_mac );
    advertise_relay_to( sss, cmn, req, relay );
    if ( tgt ) advertise_relay_to( sss, cmn, tgt, relay );
    /* Notify the relay itself (PEER_INFO RELAY naming its own MAC) so it
     * switches on forwarding without self-judging eligibility. Idempotent. */
    advertise_relay_to( sss, cmn, relay, relay );
}

/** Examine a datagram and determine what to do with it.
 *
 */
static int process_udp( n2n_sn_t * sss,
                        const struct sockaddr * sender_sock,
												socklen_t sender_sock_len,
                        const uint8_t * udp_buf,
                        size_t udp_size,
                        time_t now,
                        ws_conn_t * ws_sender)
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

    /* Full-cone probe request from a brother SN: 16 raw bytes, not n2n. */
    if ( udp_size == 16 && memcmp( udp_buf, "N2NF", 4 ) == 0 )
    {
        handle_fc_probe_request( sss, sender_sock, udp_buf, now );
        return 0;
    }

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

    /* Check for compact format (leading tag N2N_PKT_VERSION_COMPACT) */
    if ( udp_size > 0 && udp_buf[0] == N2N_PKT_VERSION_COMPACT )
    {
        n2n_mac_t compact_dstMac;
        n2n_sock_t compact_sock;
        n2n_common_t cmn2;
        uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
        size_t encx = 0;
        int unicast;
        const uint8_t *rec_buf;
        struct peer_info *sender_peer = NULL;

        memset( &compact_sock, 0, sizeof(compact_sock) );

        if ( decode_compact_header( &cmn, compact_dstMac, &compact_sock, udp_buf, &rem, &idx ) < 0 )
        {
            traceEvent( TRACE_DEBUG, "Failed to decode compact header" );
            return -1;
        }

        msg_type = cmn.pc;
        from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;

        if ( cmn.ttl < 1 )
        {
            traceEvent( TRACE_WARNING, "Expired TTL in compact packet" );
            return 0;
        }

        --(cmn.ttl);

        if ( msg_type != MSG_TYPE_PACKET )
            return 0;

        /* Find the sender edge: for WS scan peer->ws pointer, for UDP scan socket */
        if ( ws_sender )
        {
            struct peer_info *scan = sss->edges;
            while ( scan )
            {
                if ( scan->ws == ws_sender )
                {
                    sender_peer = scan;
                    break;
                }
                scan = scan->next;
            }
        }
        else
        {
            sender_peer = find_peer_by_sock( sss->edges, sender_sock );
        }

        if ( !sender_peer )
        {
            traceEvent( TRACE_DEBUG, "compact: unknown sender, dropping" );
            return 0;
        }

        /* Fill community from sender's registration */
        memcpy( cmn.community, sender_peer->community_name, N2N_COMMUNITY_SIZE );
        sender_peer->compact_capable = 1;

        unicast = (0 == is_multi_broadcast( compact_dstMac ));

        traceEvent( TRACE_DEBUG, "Rx compact PACKET (%s) %s -> %s %s",
                    (unicast?"unicast":"multicast"),
                    macaddr_str( mac_buf, sender_peer->mac_addr ),
                    macaddr_str( mac_buf2, compact_dstMac ),
                    (from_supernode?"from sn":"local") );

        if ( !from_supernode )
        {
            /* Edge → SN: re-encode as compact with FROM_SUPERNODE + SOCKET */
            memcpy( &cmn2, &cmn, sizeof( n2n_common_t ) );
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            /* Fill sock from the original sender's physical address */
            if ( sender_sock->sa_family == AF_INET )
            {
                const struct sockaddr_in *sin = (const struct sockaddr_in *)sender_sock;
                compact_sock.family = AF_INET;
                compact_sock.port = ntohs( sin->sin_port );
                memcpy( compact_sock.addr.v4, &sin->sin_addr, 4 );
            }
            else if ( sender_sock->sa_family == AF_INET6 )
            {
                const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sender_sock;
                compact_sock.family = AF_INET6;
                compact_sock.port = ntohs( sin6->sin6_port );
                memcpy( compact_sock.addr.v6, &sin6->sin6_addr, 16 );
            }

            rec_buf = encbuf;
            encx = 0;
            encode_compact_header( encbuf, &encx, &cmn2, compact_dstMac, &compact_sock );
            /* Copy the encrypted payload unchanged */
            encode_buf( encbuf, &encx, (udp_buf + idx), (udp_size - idx) );

            /* Update sender's edge address in the edge table */
            {
                if ( sender_sock->sa_family == AF_INET && sender_peer->sock.family == AF_INET )
                {
                    const struct sockaddr_in *sin = (const struct sockaddr_in *)sender_sock;
                    if ( sender_peer->sock.port != ntohs(sin->sin_port) ||
                         memcmp( sender_peer->sock.addr.v4, &sin->sin_addr, 4 ) != 0 )
                    {
                        sender_peer->sock.port = ntohs(sin->sin_port);
                        memcpy( sender_peer->sock.addr.v4, &sin->sin_addr, 4 );
                        sender_peer->last_seen = now;
                        traceEvent( TRACE_DEBUG, "Edge %s addr updated from compact PACKET",
                                    macaddr_str( mac_buf, sender_peer->mac_addr ) );
                    }
                }
                else if ( sender_sock->sa_family == AF_INET6 && sender_peer->sock6.family == AF_INET6 )
                {
                    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sender_sock;
                    if ( sender_peer->sock6.port != ntohs(sin6->sin6_port) ||
                         memcmp( sender_peer->sock6.addr.v6, &sin6->sin6_addr, 16 ) != 0 )
                    {
                        sender_peer->sock6.port = ntohs(sin6->sin6_port);
                        memcpy( sender_peer->sock6.addr.v6, &sin6->sin6_addr, 16 );
                        sender_peer->last_seen = now;
                        traceEvent( TRACE_DEBUG, "Edge %s addr updated from compact PACKET",
                                    macaddr_str( mac_buf, sender_peer->mac_addr ) );
                    }
                }
            }
        }
        else
        {
            /* Already from a supernode. Nothing to modify, just pass to destination. */
            traceEvent( TRACE_DEBUG, "Rx compact PACKET fwd unmodified" );
            rec_buf = udp_buf;
            encx = udp_size;
        }

        /* Common section to forward the final product.
         * Before forwarding, check if any receiver is legacy (doesn't support compact).
         * If so, convert compact→legacy so old edges can still receive the packet.
         * For unicast, we also keep dest around so the conversion block can use
         * dest->transform_id as a fallback if sender_peer->transform_id is 0.
         *
         * Broadcast uses a community-level cache (all_compact) to avoid scanning
         * all peers on every packet: once a legacy PACKET is seen in the community,
         * all_compact is set to 0 and all subsequent broadcasts are converted
         * conservatively. This eliminates O(N) scanning per broadcast packet. */
        {
            int all_receivers_compact = 0;
            struct peer_info *dest = NULL; /* used by unicast path + conversion fallback */
            if ( unicast )
            {
                dest = find_peer_by_mac( sss->edges, compact_dstMac );
                if ( !dest )
                {
                    /* Unknown destination — skip conversion (try_forward will drop) */
                    all_receivers_compact = 1;
                }
                else if ( dest->compact_capable )
                {
                    all_receivers_compact = 1;
                }
            }
            else
            {
                /* Broadcast: use community-level cache instead of scanning all peers.
                 * all_compact=1 means ALL peers are compact-capable → no conversion.
                 * all_compact=0 means at least one legacy peer exists → convert conservatively. */
                struct community_stats *cs = get_community_stats(&sss->comm_stats, cmn.community, now);
                if ( cs && cs->all_compact )
                    all_receivers_compact = 1;
                /* else: all_receivers_compact stays 0, conversion path follows */
            }

            if ( !all_receivers_compact )
            {
                /* Convert to legacy format for old edges */
                uint8_t legacy_buf[N2N_SN_PKTBUF_SIZE];
                size_t legacy_x = 0;
                n2n_common_t legacy_cmn;
                n2n_PACKET_t legacy_pkt;

                memcpy( &legacy_cmn, &cmn, sizeof( n2n_common_t ) );
                legacy_cmn.flags |= N2N_FLAGS_FROM_SUPERNODE;
                /* Add SOCKET so the legacy PACKET includes the sender's physical address */
                if ( !(legacy_cmn.flags & N2N_FLAGS_SOCKET) )
                    legacy_cmn.flags |= N2N_FLAGS_SOCKET;

                memset( &legacy_pkt, 0, sizeof( legacy_pkt ) );
                memcpy( legacy_pkt.srcMac, sender_peer->mac_addr, N2N_MAC_SIZE );
                memcpy( legacy_pkt.dstMac, compact_dstMac, N2N_MAC_SIZE );
                legacy_pkt.transform = sender_peer->transform_id;

                /* Fallback: if sender's transform_id is unknown (compact-only sender),
                 * try the destination's transform_id (all edges in a community share
                 * the same transform). */
                if ( legacy_pkt.transform == 0 && dest && dest->transform_id != 0 )
                    legacy_pkt.transform = dest->transform_id;

                /* Use the sender's physical sock (from the compact-header sock if present,
                 * otherwise from the recvfrom socket) */
                if ( compact_sock.family != 0 )
                    legacy_pkt.sock = compact_sock;
                else if ( sender_sock->sa_family == AF_INET )
                {
                    const struct sockaddr_in *sin = (const struct sockaddr_in *)sender_sock;
                    legacy_pkt.sock.family = AF_INET;
                    legacy_pkt.sock.port = ntohs( sin->sin_port );
                    memcpy( legacy_pkt.sock.addr.v4, &sin->sin_addr, 4 );
                }
                else if ( sender_sock->sa_family == AF_INET6 )
                {
                    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sender_sock;
                    legacy_pkt.sock.family = AF_INET6;
                    legacy_pkt.sock.port = ntohs( sin6->sin6_port );
                    memcpy( legacy_pkt.sock.addr.v6, &sin6->sin6_addr, 16 );
                }

                encode_common( legacy_buf, &legacy_x, &legacy_cmn );
                encode_PACKET( legacy_buf, &legacy_x, &legacy_cmn, &legacy_pkt );
                encode_buf( legacy_buf, &legacy_x, (udp_buf + idx), (udp_size - idx) );

                rec_buf = legacy_buf;
                encx = legacy_x;

                traceEvent( TRACE_DEBUG, "compact→legacy conversion for %s %s",
                            (unicast?"unicast":"broadcast"),
                            macaddr_str( mac_buf, compact_dstMac ) );
            }
        }

        if ( unicast )
        {
            /* Relay: the supernode relaying the first member-to-member data
             * frame is the signal to start registering to the relay peer
             * (concurrent with the on-going punch). */
            if ( sender_peer )
                advertise_relay_on_pair( sss, &cmn, sender_peer->mac_addr, compact_dstMac );
            try_forward( sss, &cmn, compact_dstMac, rec_buf, encx );
        }
        else
        {
            try_broadcast( sss, &cmn, sender_peer->mac_addr, rec_buf, encx );
        }

        return 0;
    }

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


        decode_PACKET( &pkt, &cmn, udp_buf, &rem, &idx );

        /* A legacy PACKET means at least one edge in this community is legacy.
         * Invalidate the all_compact cache so SN does proper broadcast conversion. */
        {
            struct community_stats *cs = get_community_stats(&sss->comm_stats, cmn.community, now);
            if (cs) cs->all_compact = 0;
        }

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

            /* Update sender's edge address in the edge table so the
             * supernode can forward replies to the correct address.
             * Without this, after a WiFi switch (NAT address change),
             * the supernode would forward replies to the old address
             * until the next REGISTER_SUPER (up to 30s + 3×12s retries).
             * Only update if the family matches the existing registration. */
            {
                struct peer_info *sender_edge = find_peer_by_mac(sss->edges, pkt.srcMac);
                if (sender_edge) {
                    sender_edge->transform_id = pkt.transform;
                    if (sender_sock->sa_family == AF_INET && sender_edge->sock.family == AF_INET) {
                        struct sockaddr_in *si = (struct sockaddr_in *)sender_sock;
                        if (sender_edge->sock.port != ntohs(si->sin_port) ||
                            memcmp(sender_edge->sock.addr.v4, &si->sin_addr, IPV4_SIZE) != 0) {
                            sender_edge->sock.port = ntohs(si->sin_port);
                            memcpy(sender_edge->sock.addr.v4, &si->sin_addr, IPV4_SIZE);
                            sender_edge->last_seen = now;
                            traceEvent(TRACE_DEBUG, "Edge %s addr updated from PACKET",
                                       macaddr_str(mac_buf, pkt.srcMac));
                        }
                    } else if (sender_sock->sa_family == AF_INET6 && sender_edge->sock6.family == AF_INET6) {
                        struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)sender_sock;
                        if (sender_edge->sock6.port != ntohs(si6->sin6_port) ||
                            memcmp(sender_edge->sock6.addr.v6, &si6->sin6_addr, IPV6_SIZE) != 0) {
                            sender_edge->sock6.port = ntohs(si6->sin6_port);
                            memcpy(sender_edge->sock6.addr.v6, &si6->sin6_addr, IPV6_SIZE);
                            sender_edge->last_seen = now;
                            traceEvent(TRACE_DEBUG, "Edge %s addr updated from PACKET",
                                       macaddr_str(mac_buf, pkt.srcMac));
                        }
                    }
                }
            }
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
            /* Relay: the supernode relaying member-to-member data is a clear
             * sign direct failed; push the community relay peer so the members
             * can switch to it. */
            advertise_relay_on_pair( sss, &cmn, pkt.srcMac, pkt.dstMac );
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
        /* Relay: one member wants another -> tell both about the community
         * relay peer so they can register to it and use it once direct
         * punching fails. */
        advertise_relay_on_pair( sss, &cmn, reg.srcMac, reg.dstMac );

        traceEvent( TRACE_DEBUG, "Rx REGISTER %s -> %s %s",
                    macaddr_str( mac_buf, reg.srcMac ),
                    macaddr_str( mac_buf2, reg.dstMac ),
                    ((cmn.flags & N2N_FLAGS_FROM_SUPERNODE)?"from sn":"local") );

        if ( 0 != (cmn.flags & N2N_FLAGS_FROM_SUPERNODE) )
        {
            memcpy( &cmn2, &cmn, sizeof( n2n_common_t ) );

            /* We are going to add socket even if it was not there before */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            sock_from_sender( &(reg.sock), sender_sock );

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
            memcpy( &cmn2, &cmn, sizeof( n2n_common_t ) );

            rec_buf = udp_buf;
            encx = udp_size;
        }

        try_forward( sss, &cmn2, reg.dstMac, rec_buf, encx ); /* unicast only */
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
            pi.aflags = N2N_AFLAGS_PUNCH_REQUEST;
            if (target->num_sockets > 1 &&
                target->sockets[1].family != 0 &&
                target->sockets[1].port != 0)
                pi.aflags |= N2N_AFLAGS_LOCAL_SOCKET;
            /* Always put IPv4 in sockets[0] if available, so both addresses are carried */
            if (target->sock.family == AF_INET)
                pi.sockets[0] = target->sock;
            else if (target->sock6.family == AF_INET6)
                pi.sockets[0] = target->sock6;
            if (pi.aflags & N2N_AFLAGS_LOCAL_SOCKET)
                pi.sockets[1] = target->sockets[1];
            if (target->sock6.family == AF_INET6) {
                pi.aflags |= N2N_AFLAGS_IPV6_SOCKET;
                pi.sock6 = target->sock6;
            }
            if (target->same_lan_as_sn) {
                pi.aflags |= N2N_AFLAGS_SAME_LAN_AS_SN;
            }
            /* Include version and os_name so edge can display them */
            if (target->version[0] != '\0') {
                strncpy(pi.version, target->version, sizeof(pi.version) - 1);
                pi.version[sizeof(pi.version) - 1] = '\0';
            }
            if (target->os_name[0] != '\0') {
                strncpy(pi.os_name, target->os_name, sizeof(pi.os_name) - 1);
                pi.os_name[sizeof(pi.os_name) - 1] = '\0';
            }
            pi.assigned_ip = target->assigned_ip;
            /* Carry the peer's NAT type so edge mgmt can display it */
            pi.aflags |= N2N_NAT_AFLAGS(target->nat_type);

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
                pi2.aflags = N2N_AFLAGS_PUNCH_REQUEST;
                if (requester->num_sockets > 1 &&
                    requester->sockets[1].family != 0 &&
                    requester->sockets[1].port != 0)
                    pi2.aflags |= N2N_AFLAGS_LOCAL_SOCKET;
                /* Always put IPv4 in sockets[0] if available */
                if (requester->sock.family == AF_INET)
                    pi2.sockets[0] = requester->sock;
                else if (requester->sock6.family == AF_INET6)
                    pi2.sockets[0] = requester->sock6;
                if (pi2.aflags & N2N_AFLAGS_LOCAL_SOCKET)
                    pi2.sockets[1] = requester->sockets[1];
                if (requester->sock6.family == AF_INET6) {
                    pi2.aflags |= N2N_AFLAGS_IPV6_SOCKET;
                    pi2.sock6 = requester->sock6;
                }
                if (requester->same_lan_as_sn) {
                    pi2.aflags |= N2N_AFLAGS_SAME_LAN_AS_SN;
                }
                /* Include version and os_name so edge can display them */
                if (requester->version[0] != '\0') {
                    strncpy(pi2.version, requester->version, sizeof(pi2.version) - 1);
                    pi2.version[sizeof(pi2.version) - 1] = '\0';
                }
                if (requester->os_name[0] != '\0') {
                    strncpy(pi2.os_name, requester->os_name, sizeof(pi2.os_name) - 1);
                    pi2.os_name[sizeof(pi2.os_name) - 1] = '\0';
                }
                pi2.assigned_ip = requester->assigned_ip;
                pi2.aflags |= N2N_NAT_AFLAGS(requester->nat_type);

                encode_PEER_INFO( encbuf2, &encx2, &cmn3, &pi2 );
                /* Send to B via appropriate socket */
                if ( fill_sockaddr((struct sockaddr*)&b_addr, b_len, &target->sockets[0]) == 0 ) {
                    SOCKET send_sock2 = (target->sockets[0].family == AF_INET6) ? sss->sock6 : sss->sock;
                    socklen_t slen2 = (target->sockets[0].family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
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

        memset(&ack, 0, sizeof(ack));

        /* Edge requesting registration with us.  */

        decode_REGISTER_SUPER( &reg, &cmn, udp_buf, &rem, &idx );

        /* NAT bounce test: the edge asks us to reply from the helper socket
         * (different source port) so it can tell restricted (IP-gated, any
         * port allowed) from port-restricted NATs. Purely outbound, 4-byte
         * magic, no state; sender's IP is re-checked by the edge. */
        if ( (reg.aflags & N2N_AFLAGS_NAT_BOUNCE) &&
             sender_sock->sa_family == AF_INET &&
             sss->bounce_sock >= 0 )
        {
            static const uint8_t bmsg[4] = { 'N', '2', 'N', 'B' };
            sendto( sss->bounce_sock, bmsg, sizeof(bmsg), 0,
                    sender_sock, sender_sock_len );
        }

        /* Brother SN detection: sn1 -> sn2 periodic registration, carries sn1's current address. */
        int is_brother_reg = (memcmp(cmn.community, "brother_reg", 11) == 0);
        if (is_brother_reg)
        {
            /* Validate backup_token when configured; no -B accepts any
             * brother SN (auto-pairing via -b alone). */
            if (sss->backup_token_set &&
                memcmp(reg.auth.token, sss->backup_token.token, sss->backup_token.toksize) != 0)
            {
                traceEvent(TRACE_WARNING, "Brother reg rejected: bad backup token");
                return 0;
            }

            /* Find slot by MAC; if not found, fill first empty slot;
             * if all full, replace the slot whose seen is the oldest. */
            uint8_t zero[6] = {0,0,0,0,0,0};
            int slot = -1, oldest_slot = -1;
            time_t oldest_seen = (time_t)(~(time_t)0);
            for (int j = 0; j < MAX_BROTHER_SNS; j++) {
                n2n_brother_entry_t *bb = &sss->brothers[j];
                int mac_zero = (memcmp(bb->mac, zero, 6) == 0);
                int mac_match = !mac_zero && (memcmp(bb->mac, reg.edgeMac, 6) == 0);
                if (mac_match) { slot = j; break; }
                if (mac_zero && slot < 0) slot = j;
                time_t bb_seen = bb->seen > bb->seen6 ? bb->seen : bb->seen6;
                if (bb_seen < oldest_seen) {
                    oldest_seen = bb_seen;
                    oldest_slot = j;
                }
            }
            if (slot < 0) slot = (oldest_slot >= 0) ? oldest_slot : 0;

            n2n_brother_entry_t *be = &sss->brothers[slot];
            memcpy(be->mac, reg.edgeMac, sizeof(n2n_mac_t));

            /* Build n2n_sock_t from sender and assign to matching slot family. */
            n2n_sock_t sender_n2n;
            sock_from_sender( &sender_n2n, sender_sock );
            if ( sender_n2n.family == AF_INET )
            {
                be->sock = sender_n2n;
                be->seen = now;
            }
            else if ( sender_n2n.family == AF_INET6 )
            {
                be->sock6 = sender_n2n;
                be->seen6 = now;
            }
            sss->last_brother_seen = now;

            /* Refresh IPv6 entry from reg.own_ipv6 whenever sn1 provides one.
             * The own_ipv6 GUA is what sn1 currently uses for incoming IPv6
             * traffic, so its port follows sn1's -l value. Update every
             * brother_reg so a port change on sn1 is reflected here. */
            if ((reg.aflags & N2N_AFLAGS_IPV6_SOCKET) &&
                reg.own_ipv6.family == AF_INET6)
            {
                be->sock6 = reg.own_ipv6;
                be->seen6 = now;
            }
            traceEvent(TRACE_INFO, "Brother SN registered from %s",
                       sock_to_cstr(sockbuf, &sender_n2n));
            return 0; /* brother registration does not need an ACK */
        }

        /* Count only real edge registrations; brother heartbeats above
         * return before this point so they never pollute last_reg/reg_sup. */
        sss->stats.last_reg_super=now;
        ++(sss->stats.reg_super);

        /* Black/white list: silently drop registration for denied
         * communities (no reply, so the SN stays hidden). brother_reg
         * above is exempt from this check. */
        if (community_denied(sss->rate_rules, cmn.community))
            return 0;

        /* Edge registration: validate peer_token (if configured).
         * Brother-trusted source: if the edge arrives from a registered
         * brother sn1 (recently seen, sender matches its sock), the peer is
         * admitted without token verification. The edge carries no sn2
         * token because the user only configured sn1's -T.
         * Ask-backup probes carry desired_sn1_mac; a match against the
         * brother table proves the edge belongs to sn1 — record it in the
         * promoted list and admit the probe (the probe itself is not
         * registered). After the failover switch the real registration
         * carries neither hint nor token and is admitted via the list. */
        if (sss->peer_token_set)
        {
            int brother_alive = (sss->last_brother_seen != 0) &&
                                ((now - sss->last_brother_seen) <= 180);
            int from_brother = 0;
            if (brother_alive)
            {
                n2n_sock_t sender_n2n;
                uint8_t zero[6] = {0,0,0,0,0,0};
                sock_from_sender( &sender_n2n, sender_sock );
                for (int j = 0; j < MAX_BROTHER_SNS && !from_brother; j++) {
                    n2n_brother_entry_t *b = &sss->brothers[j];
                    if (memcmp(b->mac, zero, 6) == 0) continue;
                    if ((b->sock.family != 0 &&
                         sock_equal(&sender_n2n, &b->sock) == 0) ||
                        (b->sock6.family == AF_INET6 &&
                         sock_equal(&sender_n2n, &b->sock6) == 0))
                        from_brother = 1;
                }
            }

            int sn1_hint_ok = 0;
            {
                uint8_t hint_zero[6] = {0,0,0,0,0,0};
                if (memcmp(reg.desired_sn1_mac, hint_zero, 6) != 0)
                    for (int j = 0; j < MAX_BROTHER_SNS && !sn1_hint_ok; j++)
                        if (memcmp(sss->brothers[j].mac, reg.desired_sn1_mac,
                                   N2N_MAC_SIZE) == 0)
                            sn1_hint_ok = 1;
            }
            if (sn1_hint_ok)
                record_promoted( sss, reg.edgeMac, cmn.community, now );

            struct promoted_peer *pe =
                find_promoted( sss, reg.edgeMac, cmn.community, now );

            if (!from_brother && !pe &&
                memcmp(reg.auth.token, sss->peer_token.token, sss->peer_token.toksize) != 0)
            {
                traceEvent(TRACE_WARNING, "Peer reg rejected: bad peer token");
                return 0;
            }
            if (pe)
                pe->seen = now; /* registration keeps the entry alive */
        }

        cmn2.ttl = N2N_DEFAULT_TTL;
        cmn2.pc = n2n_register_super_ack;
        cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
        memcpy( cmn2.community, cmn.community, sizeof(n2n_community_t) );

        memcpy( &(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t) );
        memcpy( ack.edgeMac, reg.edgeMac, sizeof(n2n_mac_t) );
        ack.lifetime = reg_lifetime( sss );

        sock_from_sender( &(ack.sock), sender_sock );

        /* Advertise sn2 to it inside the ACK when we know a configured -b string
         * or have a live brother within 180s. The edge uses sn_bak_str (the
         * verbatim DNS-style string from sn1's -b argument) so it stays
         * stable across DNS changes. sn_bak / sn_bak_v6 are kept zero and
         * ignored on the edge. */
        if (sss->backup_addr_text[0] != 0)
        {
            size_t slen = strlen(sss->backup_addr_text);
            if (slen >= N2N_SOCKBUF_SIZE) slen = N2N_SOCKBUF_SIZE - 1;
            ack.num_sn = 1;
            ack.sn_bak_str_len = (uint16_t)slen;
            memcpy(ack.sn_bak_str, sss->backup_addr_text, slen);
            ack.sn_bak_str[slen] = '\0';
        }

        /* ask_backup lookup: if the registering edge supplied desired_sn1_sock
         * and we have a brother SN whose IP matches (port-agnostic since
         * the very point of this lookup is sn1 changed its port), return
         * that brother's current resolved IP and MAC so the edge can
         * reconnect to sn1 at its new address and track sn1 identity. */
        uint8_t ask_zero[6] = {0,0,0,0,0,0};

        /* Not an ask_backup probe: a normal edge is registering with us.
         * Advertise our own SN identity (MAC + global IPv6) — the same
         * identity brother_reg carries to the brother SN — so a newly
         * started edge learns sn1's MAC/IPv6 right from its first ACK.
         * Hint presence is tested by port: a zero-encoded sock decodes as
         * AF_INET with port 0, so family cannot distinguish "no hint". */
        if (reg.desired_sn1_sock.port == 0 &&
            memcmp(reg.desired_sn1_mac, ask_zero, 6) == 0)
        {
            const uint8_t *id_mac = sn_identity_mac( sss );
            memcpy(ack.sn1_mac, id_mac, N2N_MAC_SIZE);
            /* Report our own global IPv6 so the edge can show a dual-stack
             * address for this SN (stays family 0 when we have none). */
            if (sss->my_ipv6.family == AF_INET6)
                ack.sn_bak_v6 = sss->my_ipv6;
        }

        /* Match by sn1 MAC first (exact identity, immune to shared/shifted
         * IP); fall back to IP when the edge has no sn1 MAC yet. */
        int want_mac = (memcmp(reg.desired_sn1_mac, ask_zero, 6) != 0);
        /* Hint presence is detected by port (a real sn1 sock always has a
         * port); a zero-encoded sock decodes as AF_INET with port 0, so
         * checking family here would fire on every normal registration. */
        if ((reg.desired_sn1_sock.port != 0 || want_mac) &&
            sss->last_brother_seen != 0 &&
            (now - sss->last_brother_seen <= 180))
        {
            n2n_sock_t *ds = &reg.desired_sn1_sock;
            for (int j = 0; j < MAX_BROTHER_SNS; j++) {
                n2n_brother_entry_t *bb = &sss->brothers[j];
                if (memcmp(bb->mac, ask_zero, 6) == 0) continue;

                int match = 0;
                if (want_mac) {
                    if (memcmp(bb->mac, reg.desired_sn1_mac, N2N_MAC_SIZE) == 0)
                        match = 1;
                } else {
                    if (ds->family == AF_INET && bb->sock.family == AF_INET &&
                        memcmp(ds->addr.v4, bb->sock.addr.v4, IPV4_SIZE) == 0)
                        match = 1;
                    else if (ds->family == AF_INET6 && bb->sock6.family == AF_INET6 &&
                        memcmp(ds->addr.v6, bb->sock6.addr.v6, IPV6_SIZE) == 0)
                        match = 1;
                }
                if (!match) continue;

                if (bb->sock.family != 0)
                {
                    ack.sn_bak = bb->sock;
                    /* num_sn gates the on-wire encoding of sn_bak in
                     * REGISTER_SUPER_ACK. Without setting it here the
                     * matched brother address is filled in memory but
                     * never sent, and the edge sees an empty answer. */
                    ack.num_sn = 1;
                }
                if (bb->sock6.family == AF_INET6) ack.sn_bak_v6 = bb->sock6;
                memcpy(ack.sn1_mac, bb->mac, N2N_MAC_SIZE);
                traceEvent(TRACE_INFO, "ask_backup: sn1 %s MAC %s",
                           sock_to_cstr(sockbuf, &ack.sn_bak),
                           macaddr_str(mac_buf, bb->mac));
                break;
            }
        }

        /* Fill sn_caps so edge knows this supernode's IP stack capabilities */
        ack.sn_caps = 0;
        if (sss->ipv4_available) ack.sn_caps |= N2N_SN_CAPS_IPV4;
        if (sss->ipv6_available) ack.sn_caps |= N2N_SN_CAPS_IPV6;

        /* sn1's identity reaches the edge from two sources, both derived
         * from the same device_mac: the self-advertisement above (normal
         * registrations) and the ask_backup lookup above reporting the
         * brother record's MAC. The edge adopts them only from genuine sn1
         * sources (its own ACK while on sn1, or sn_bak-carrying replies), so
         * a failover target's own identity never overwrites sn1's. */

        traceEvent( TRACE_DEBUG, "Rx REGISTER_SUPER for %s %s",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ) );

        uint32_t use_requested_ip = reg.dev_addr.net_addr;
        uint8_t use_request_ip = 1; /* always assign IP (auto-assign if net_addr==0) */

        /* QUERY_ONLY: edge is asking us (as the brother/query channel) for
         * sn1's current address via a one-shot probe. Answer with the ACK
         * (including the sn1 brother lookup) but do NOT register/persist
         * this edge as a peer, so it never shows up in / clogs our table.
         * Registrations carrying an sn1 hint (ask_backup probe: sock or
         * MAC) count as queries too — the probing edge still belongs to
         * sn1 and is only promoted into the table when it really
         * registers here after the failover switch. */
        int query_only = (reg.aflags & N2N_AFLAGS_QUERY_ONLY) ? 1 : 0;
        if (!query_only &&
            (reg.desired_sn1_sock.port != 0 ||
             memcmp(reg.desired_sn1_mac, ask_zero, 6) != 0))
            query_only = 1;

        const n2n_sock_t *local_sock_ptr = (reg.aflags & N2N_AFLAGS_LOCAL_SOCKET) ? &reg.local_sock : NULL;
        uint8_t local_sock_ena = (reg.aflags & N2N_AFLAGS_LOCAL_SOCKET) ? 1 : 0;
        uint8_t force_peer_info = (reg.aflags & N2N_AFLAGS_FORCE_PEER_INFO) ? 1 : 0;

        /* Check IP conflict: different MAC, same IP in same community */
        if (!query_only && use_request_ip && use_requested_ip != 0) {
            struct peer_info *ck = sss->edges;
            while (ck) {
                if (ck->assigned_ip == use_requested_ip &&
                    memcmp(ck->community_name, cmn.community, sizeof(n2n_community_t)) == 0 &&
                    memcmp(ck->mac_addr, reg.edgeMac, sizeof(n2n_mac_t)) != 0) {
                    n2n_common_t nak_cmn;
                    n2n_REGISTER_SUPER_NAK_t nak;

                    memset(&nak_cmn, 0, sizeof(nak_cmn));
                    nak_cmn.ttl = N2N_DEFAULT_TTL;
                    nak_cmn.pc = n2n_register_super_nak;
                    nak_cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
                    memcpy(nak_cmn.community, cmn.community, sizeof(n2n_community_t));
                    memcpy(&nak.cookie, &reg.cookie, sizeof(n2n_cookie_t));

                    encx = 0;
                    encode_REGISTER_SUPER_NAK(ackbuf, &encx, &nak_cmn, &nak);

                    if (ws_sender) {
                        ws_send(ws_sender, ackbuf, encx);
                    } else {
                        SOCKET send_sock = (sender_sock->sa_family == AF_INET6) ? sss->sock6 : sss->sock;
                        sendto(send_sock, ackbuf, encx, 0, (struct sockaddr *)sender_sock,
                               (sender_sock->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                    }
                    ++(sss->stats.reg_super_nak);
                    traceEvent(TRACE_WARNING, "IP %u.%u.%u.%u already used by another edge, sending NAK",
                               (use_requested_ip>>24)&0xFF, (use_requested_ip>>16)&0xFF,
                               (use_requested_ip>>8)&0xFF, use_requested_ip&0xFF);
                    return 0;
                }
                ck = ck->next;
            }
        }

        int is_new_edge = query_only ? 0 : update_edge( sss, reg.edgeMac, cmn.community, &(ack.sock),
                     local_sock_ptr, local_sock_ena,
                     ((reg.aflags & N2N_AFLAGS_IPV6_SOCKET) && reg.own_ipv6.family == AF_INET6)
                         ? &reg.own_ipv6 : NULL,
                     now, NULL, NULL,
                     N2N_NAT_FROM_AFLAGS(reg.aflags),
                     use_request_ip, use_requested_ip );

        /* NAT type changed with unchanged address (update_edge == 2):
         * other edges would never learn it — push the fresh value. */
        if ( is_new_edge == 2 )
            push_nat_to_community( sss,
                                   find_peer_by_mac(sss->edges, reg.edgeMac),
                                   cmn.community );

        /* Brand-new (or re-mapped) edge — or an edge that explicitly asked for a
         * manual NAT re-probe (mgmt "n", N2N_AFLAGS_NAT_REPROBE): one-shot
         * chance for the brother SN to full-cone-probe it as a
         * never-contacted source. */
        if ( is_new_edge || (reg.aflags & N2N_AFLAGS_NAT_REPROBE) )
            send_fc_probe_request( sss, reg.edgeMac, &(ack.sock), now );

        /* Remember the edge's relay stance so find_community_relay can prefer
         * willing/force / skip refusing candidates. Default (neither bit)=1;
         * force (3) is the relay even if relay is globally off. */
        if (!query_only)
        {
            struct peer_info *w_edge = find_peer_by_mac( sss->edges, reg.edgeMac );
            if ( w_edge )
            {
                if ( reg.aflags & N2N_AFLAGS_RELAY_WILLING_FORCE )
                    w_edge->relay_willing = 3;
                else if ( reg.aflags & N2N_AFLAGS_RELAY_WILLING_NO )
                    w_edge->relay_willing = 0;
                else if ( reg.aflags & N2N_AFLAGS_RELAY_WILLING_YES )
                    w_edge->relay_willing = 2;
                else
                    w_edge->relay_willing = 1;
            }
        }

        /* Set assigned IP in ACK */
        if (!query_only && use_request_ip) {
            struct peer_info *edge_peer = find_peer_by_mac(sss->edges, reg.edgeMac);
            if (edge_peer && edge_peer->assigned_ip) {
                ack.dev_addr.net_addr = htonl(edge_peer->assigned_ip);
                ack.dev_addr.net_bitlen = 24;
            }
        }

        /* If this REGISTER_SUPER arrived via WS, mark the edge as WS-connected (forwarding uses ws_send) */
        if (!query_only && ws_sender) {
            struct peer_info *edge_peer = find_peer_by_mac(sss->edges, reg.edgeMac);
            if (edge_peer) edge_peer->ws = ws_sender;
        }

        /* Fill sn_version so edge can display supernode version */
        strncpy(ack.sn_version, n2n_sw_version_full, sizeof(ack.sn_version) - 1);

        encode_REGISTER_SUPER_ACK( ackbuf, &encx, &cmn2, &ack );


        /* Reply ACK: WS via ws_send, UDP via the matching v4/v6 socket */
        if (ws_sender) {
            ws_send(ws_sender, ackbuf, encx);
        } else {
            sendto_sock( sss, &ack.sock, ackbuf, encx );
        }

        traceEvent( TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s %s%s",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ),
                    ws_sender ? " (ws)" : "" );

        /* Push all existing peers when this is a NEW edge registration or FORCE_PEER_INFO flag is set */
        if ( is_new_edge || force_peer_info )
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
                    /* Always put IPv4 in sockets[0] if available */
                    if (p->sock.family == AF_INET)
                        pi.sockets[0] = p->sock;
                    else if (p->sock6.family == AF_INET6)
                        pi.sockets[0] = p->sock6;
                    if (p->num_sockets > 1 &&
                        p->sockets[1].family != 0 &&
                        p->sockets[1].port != 0)
                    {
                        pi.aflags = N2N_AFLAGS_LOCAL_SOCKET;
                        pi.sockets[1] = p->sockets[1];
                    } else {
                        pi.aflags = 0;
                    }
                    /* Include IPv6 address if available */
                    if (p->sock6.family == AF_INET6) {
                        pi.aflags |= N2N_AFLAGS_IPV6_SOCKET;
                        pi.sock6 = p->sock6;
                    } else {
                        memset(&pi.sock6, 0, sizeof(n2n_sock_t));
                    }
                    if (p->same_lan_as_sn) {
                        pi.aflags |= N2N_AFLAGS_SAME_LAN_AS_SN;
                    }
                    /* Include version and os_name so edge can display them */
                    strncpy(pi.version, p->version, sizeof(pi.version) - 1);
                    strncpy(pi.os_name, p->os_name, sizeof(pi.os_name) - 1);
                    pi.assigned_ip = p->assigned_ip;
                    pi.aflags |= N2N_NAT_AFLAGS(p->nat_type);
                    pix = 0;
                    encode_PEER_INFO(pibuf, &pix, &pi_cmn, &pi);
                    if (ws_sender) {
                        ws_send(ws_sender, pibuf, pix);
                    } else {
                        SOCKET send_sock2 = (sender_sock->sa_family == AF_INET6) ? sss->sock6 : sss->sock;
                        socklen_t sock_len2 = (sender_sock->sa_family == AF_INET6) ?
                                     sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                        sendto(send_sock2, pibuf, pix, 0,
                               sender_sock, sock_len2);
                    }
                    traceEvent(TRACE_DEBUG, "pushed PEER_INFO %s to new edge %s%s",
                               macaddr_str(mac_buf, p->mac_addr),
                               macaddr_str(mac_buf2, reg.edgeMac),
                               ws_sender ? " (ws)" : "");
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

    fprintf( stderr, "-l <lport>\tSet UDP main listen port to <lport>.\n" );
    fprintf( stderr, "-4|-6     \tIP mode: -4 (IPv4 only), -6 (IPv6 only), both/none (dual-stack).\n" );
    fprintf( stderr, "-b <host:port>\tBrother supernode address.\n" );
    fprintf( stderr, "-B <token>\tToken required from brother SNs (no -B = accept any brother).\n" );
    fprintf( stderr, "-c <file> \tCommunity access list, traffic stats and limiting (config auto-derived as .cfg)\n" );
    fprintf( stderr, "          \tConfigure traffic stats file: -c abc.dat, modify abc.cfg after startup.\n" );
    fprintf( stderr, "-E <token>\tToken required from edges.\n" );
#if defined(N2N_HAVE_DAEMON)
    fprintf( stderr, "-f        \tRun in foreground.\n" );
#endif /* #if defined(N2N_HAVE_DAEMON) */
    fprintf( stderr, "-Q <port> \tQuery management port (for standalone use). (default: %d).\n", N2N_SN_MGMT_PORT );
#ifndef _WIN32
    fprintf( stderr, "-t <port>\tSet management UDP port to <port> (default: 5646).\n" );
#endif
    fprintf( stderr, "-v        \tIncrease verbosity. Can be used multiple times.\n" );
    fprintf( stderr, "-Z <mode> \tRelay support: 0 = disable, 1 = enable (default).\n" );
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
  { "relay",           required_argument, NULL, 'Z' },  /* 0=disable community relay advertisement, else support */
  { NULL,              0,                 NULL,  0  }
};

/** Main program entry point from kernel. */
int main( int argc, char * const argv[] )
{
    int lport_specified = 0;

    n2n_sn_t sss;
    bool ipv4 = true, ipv6 = true;

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);  /* Prevent SIGPIPE killing process when writing to a closed WS socket */
#endif

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

    /* Handle -Q before any initialization: optional port argument */
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-Q") == 0) {
#ifdef WIN32
                initWin32();
#endif
                uint16_t qport = N2N_SN_MGMT_PORT;
                if (i + 1 < argc && argv[i+1][0] != '-') {
                    int p = atoi(argv[i+1]);
                    if (p > 0 && p <= 65535) qport = (uint16_t)p;
                }
                return query_mgmt(qport);
            }
        }
    }

    init_sn( &sss );

    {
        int opt;

        while((opt = getopt_long(argc, argv, "ft:l:c:46vhE:B:b:Z:", long_options, NULL)) != -1)
        {
            switch (opt)
            {
            case 'l': /* local-port */
                sss.lport = atoi(optarg);
																lport_specified = 1;
                break;
            case 'c': /* traffic stats, rate limiting and community access list config */
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
            case 'E': /* peer-token (token required from edge peers) */
                sss.peer_token.scheme = 0; /* scheme=0: plaintext memcmp */
                sss.peer_token.toksize = (uint16_t)strlen(optarg);
                if (sss.peer_token.toksize > N2N_AUTH_TOKEN_SIZE)
                    sss.peer_token.toksize = N2N_AUTH_TOKEN_SIZE;
                memcpy(sss.peer_token.token, optarg, sss.peer_token.toksize);
                sss.peer_token_set = 1;
                break;
            case 'B': /* backup-token (token required from brother SNs) */
                sss.backup_token.scheme = 0;
                sss.backup_token.toksize = (uint16_t)strlen(optarg);
                if (sss.backup_token.toksize > N2N_AUTH_TOKEN_SIZE)
                    sss.backup_token.toksize = N2N_AUTH_TOKEN_SIZE;
                memcpy(sss.backup_token.token, optarg, sss.backup_token.toksize);
                sss.backup_token_set = 1;
                break;
            case 'b': /* peer (brother) supernode address (sn1 -> sn2 brother_reg) */
                strncpy(sss.backup_addr_text, optarg, sizeof(sss.backup_addr_text)-1);
                sss.backup_addr_text[sizeof(sss.backup_addr_text)-1] = '\0';
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
            case 'Z': /* 0=disable community relay advertisement, 1=support (default) */
                sss.relay_advert_enabled = ( (!optarg) || atoi(optarg) != 0 ) ? 1 : 0;
                if ( !sss.relay_advert_enabled )
                    traceEvent(TRACE_NORMAL, "Community relay advertisement disabled (-Z 0)" );
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
            /* supernode uses a small SNDBUF (256KB) instead of edge's 2MB:
             * the kernel auto-doubles the requested size, so this still leaves
             * plenty of headroom for forwarding bursts to many peers without
             * holding large per-socket memory pools. */
            { int snd = 256 * 1024;
              setsockopt(sss.sock, SOL_SOCKET, SO_SNDBUF, (const char*)&snd, sizeof(snd)); }
            /* NAT bounce-test helper socket: random source port, no firewall
             * inbound needed (the edge never connects to it; the sn only
             * sends "N2NB" out and replies ride the conntrack entry). */
            sss.bounce_sock = open_socket(0 /* any port */, 1 /*bind ANY*/ );
            if (sss.bounce_sock == -1) {
                traceEvent( TRACE_WARNING, "NAT bounce socket failed; bounce tests disabled" );
            }
        } else {
            traceEvent( TRACE_WARNING, "IPv4 socket failed, continuing without IPv4" );
            sss.sock = -1;
        }
    }

    if (ipv6) {
        sss.sock6 = open_socket6(sss.lport, 1 /*bind ANY*/ );
        if (sss.sock6 != -1) {
            /* supernode: see SNDBUF note in IPv4 socket block above. */
            { int snd = 256 * 1024;
              setsockopt(sss.sock6, SOL_SOCKET, SO_SNDBUF, (const char*)&snd, sizeof(snd)); }
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
                        sss.my_ipv6.family = AF_INET6;
                        sss.my_ipv6.port = sss.lport;
                        memcpy(sss.my_ipv6.addr.v6, &s6->sin6_addr, IPV6_SIZE);
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
                            sss.my_ipv6.family = AF_INET6;
                            sss.my_ipv6.port = sss.lport;
                            memcpy(sss.my_ipv6.addr.v6, &s6->sin6_addr, IPV6_SIZE);
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

    /* Create WebSocket TCP listener (same port as UDP, optional - failure is non-fatal) */
    sss.ws_listen_sock = open_ws_listen_socket(sss.lport);
    if (sss.ws_listen_sock >= 0) {
        traceEvent(TRACE_NORMAL, "WebSocket listener ready on port %u (TCP)",
                   (unsigned)sss.lport);
    } else {
        traceEvent(TRACE_WARNING, "WebSocket listener disabled (UDP-only mode)");
    }

    /* Display actual running mode */
    if (ipv4_available && ipv6_available) {
        traceEvent( TRACE_NORMAL, "Supernode running in dual-stack mode (IPv4+IPv6)" );
    } else if (ipv4_available) {
        traceEvent( TRACE_NORMAL, "Supernode running in IPv4 only mode" );
    } else if (ipv6_available) {
        traceEvent( TRACE_NORMAL, "Supernode running in IPv6 only mode" );
    }

    sss.mgmt_sock = open_socket(sss.mgmt_port, 0 /* bind LOOPBACK */ );
    if ( -1 != sss.mgmt_sock )
    {
        /* supernode: see SNDBUF note in IPv4 socket block above. */
        int snd = 256 * 1024;
        setsockopt(sss.mgmt_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&snd, sizeof(snd));
    }
    if ( -1 == sss.mgmt_sock )
    {
        /* Resolve error string outside the traceEvent() macro — MSVC rejects
         * preprocessor directives inside macro arguments (C99 6.10.3p11). */
#ifdef _WIN32
        const char *mgmt_err = "socket error";
#else
        const char *mgmt_err = strerror(errno);
#endif
        traceEvent( TRACE_ERROR, "Failed to open management socket. %s",
                    mgmt_err );
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

        if (sss->mgmt_sock != -1) {
            FD_SET(sss->mgmt_sock, &socket_mask);
            max_sock = max(max_sock, sss->mgmt_sock);
        }

        /* WebSocket: listen socket + all established ws_conns */
        if (sss->ws_listen_sock >= 0) {
            FD_SET(sss->ws_listen_sock, &socket_mask);
            max_sock = max(max_sock, sss->ws_listen_sock);
        }
        {
            int wi;
            for (wi = 0; wi < N2N_SN_MAX_WS; wi++) {
                ws_conn_t *wc = &sss->ws_conns[wi];
                if (wc->state == WS_OPEN && wc->fd >= 0) {
                    FD_SET(wc->fd, &socket_mask);
                    max_sock = max(max_sock, wc->fd);
                }
            }
        }

        wait_time.tv_sec = 0;   /* wake at least every 100ms to drain shaper queues */
        wait_time.tv_usec = 100 * 1000;

        rc = select(max_sock+1, &socket_mask, NULL, NULL, &wait_time);

        now = time(NULL);

        /* Shaper: release queued packets as tokens refill (all communities) */
        if (sss->traffic_stats_enabled) {
            struct community_stats *s;
            for (s = sss->comm_stats; s; s = s->next)
                shaper_drain(sss, s);
        }

        if(rc > 0)
        {
            if (sss->sock != -1 && FD_ISSET(sss->sock, &socket_mask)) {
                struct sockaddr_storage udp_sender_sock;
                socklen_t udp_sender_len = sizeof(udp_sender_sock);

                bread = recvfrom(sss->sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0,
                               (struct sockaddr *)&udp_sender_sock, &udp_sender_len);

                if (bread > 0) {
                    process_udp( sss, (struct sockaddr*) &udp_sender_sock, udp_sender_len,
                                pktbuf, bread, now, NULL );
                }
            }

            if (sss->sock6 != -1 && FD_ISSET(sss->sock6, &socket_mask)) {
                struct sockaddr_storage udp6_sender_sock;
                socklen_t udp6_sender_len = sizeof(udp6_sender_sock);

                bread = recvfrom(sss->sock6, pktbuf, N2N_SN_PKTBUF_SIZE, 0,
                               (struct sockaddr *)&udp6_sender_sock, &udp6_sender_len);

                if (bread > 0) {
                    process_udp( sss, (struct sockaddr*) &udp6_sender_sock, udp6_sender_len,
                                pktbuf, bread, now, NULL );
                }
            }

            /* WebSocket: accept new connections */
            if (sss->ws_listen_sock >= 0 &&
                FD_ISSET(sss->ws_listen_sock, &socket_mask)) {
                int slot = sn_ws_find_free_slot(sss);
                if (slot >= 0) {
                    ws_conn_t *wc = &sss->ws_conns[slot];
                    if (ws_server_accept(wc, sss->ws_listen_sock) == 0) {
                        wc->last_seen = now;
                        traceEvent(TRACE_NORMAL, "WS edge connected, slot=%d fd=%d",
                                   slot, (int)wc->fd);
                    } else {
                        traceEvent(TRACE_WARNING, "WS handshake failed, slot=%d", slot);
                        ws_close(wc);
                        ws_init(wc);
                    }
                } else {
                    /* Table full: accept then immediately close to avoid listen queue buildup */
                    SOCKET tmp = accept(sss->ws_listen_sock, NULL, NULL);
                    if (tmp >= 0) closesocket(tmp);
                    traceEvent(TRACE_WARNING, "WS conn table full, rejecting");
                }
            }

            /* WebSocket: process data from connected edges.
             *
             * KNOWN LIMITATION (fairness under many concurrent WS conns):
             * ws_send uses a BLOCKING send bounded by 3s (SO_SNDTIMEO, see
             * ws_send_all in ws.c). If one WS peer stops reading (its TCP
             * window stays 0), forwarding to it can block this
             * single-threaded main loop for up to 3s, briefly stalling the
             * other 63 WS connections. This is acceptable for the common
             * 1-edge-per-SN deployment (a stalled peer is purged after 60s
             * by sn_ws_purge), but if a future deployment runs dozens of WS
             * edges with poor downlinks, revisit: switch to a truly
             * non-blocking send (per-conn TX queue + select writable event
             * drive, no blocking send at all) so one slow peer cannot delay
             * the others. */
            {
                int wi;
                for (wi = 0; wi < N2N_SN_MAX_WS; wi++) {
                    ws_conn_t *wc = &sss->ws_conns[wi];
                    if (wc->state != WS_OPEN || wc->fd < 0) continue;
                    if (!FD_ISSET(wc->fd, &socket_mask)) continue;

                    /* Drain the WS connection like the UDP path does
                     * (128-frame cap): ws_recv decodes ONE complete n2n
                     * frame per call, so without a loop every select tick
                     * (~10 ms) forwards just one frame per connection —
                     * capping WS relay throughput at ~1 Mbps regardless of
                     * link speed. */
                    for (int _wi = 0; _wi < 128; _wi++) {
                        uint8_t wbuf[N2N_SN_PKTBUF_SIZE];
                        ssize_t n = ws_recv(wc, wbuf, sizeof(wbuf));
                        if (n > 0) {
                            wc->last_seen = now;
                            process_udp(sss,
                                        (struct sockaddr*)&wc->peer,
                                        (socklen_t)sizeof(wc->peer),
                                        wbuf, (size_t)n, now, wc);
                        } else if (n < 0) {
                            traceEvent(TRACE_DEBUG, "WS conn[%d] closed by peer", wi);
                            sn_ws_drop_conn(sss, wi);
                            break;
                        } else {
                            /* n == 0: no complete frame yet, wait for next select */
                            break;
                        }
                    }
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
        sn_ws_purge(sss, now);
        if (sss->traffic_stats_enabled) {
            static time_t last_stats_purge = 0;
            purge_expired_community_stats(sss, &last_stats_purge, now);
            save_community_stats(sss, now);
        }

        /* Re-read the rate limit and access config every 5 minutes so edits
         * apply without a restart. Kept outside the traffic_stats_enabled
         * gate so "enabled on|off" can be toggled from the file itself. */
        if (sss->stats_config_path[0])
        {
            static time_t last_cfg_reload = 0;
            if (last_cfg_reload == 0)
                last_cfg_reload = now;
            else if (now - last_cfg_reload >= 300)
            {
                last_cfg_reload = now;
                parse_rate_limit_config(sss->stats_config_path,
                                        &sss->traffic_stats_enabled,
                                        &sss->rate_rules);
                /* Re-apply rules to all known communities so changed,
                 * added and removed limits take effect immediately. */
                for (struct community_stats *s = sss->comm_stats; s; s = s->next)
                    apply_rules_to_stats(s, sss->rate_rules);
                traceEvent(TRACE_DEBUG, "Rate limit config reloaded");
            }
        }

        /* Deferred full-cone N2NF probes (#2/#3, staggered). */
        fc_probes_tick( sss, now );

        /* sn1 -> sn2 brother_reg, every 31s. */
        if (sss->backup_addr_text[0])
        {
            static time_t last_brother_reg = 0;
            if (now - last_brother_reg >= 31)
            {
                last_brother_reg = now;
                send_brother_reg(sss, now);
            }
        }

        /* Keep brother entries while any sn1 peer may still need them:
         * the promoted list (edges registered through sn1's identity) is
         * refreshed by every probe/registration, so its newest "seen" is
         * the liveness signal. Once no sn1 peer has been active for an
         * hour the entries are no longer needed and are dropped. The
         * ask_backup lookup itself only trusts the address while
         * brother_alive (180s) so stale entries stay harmless. */
        {
            static time_t last_brother_purge = 0;
            if (now - last_brother_purge >= 30)
            {
                last_brother_purge = now;
                time_t last_promoted = 0;
                for (int i = 0; i < PROMOTED_LIST_MAX; i++)
                    if (sss->promoted[i].seen > last_promoted)
                        last_promoted = sss->promoted[i].seen;
                int peers_idle = (last_promoted == 0) ||
                                 ((now - last_promoted) > 3600);
                uint8_t zero[6] = {0,0,0,0,0,0};
                for (int j = 0; j < MAX_BROTHER_SNS; j++) {
                    n2n_brother_entry_t *bb = &sss->brothers[j];
                    if (memcmp(bb->mac, zero, 6) == 0) continue;
                    time_t last = bb->seen > bb->seen6 ? bb->seen : bb->seen6;
                    if (peers_idle && last != 0 && (now - last) > 3600) {
                        traceEvent(TRACE_NORMAL, "Brother purge: %02X:%02X:%02X:%02X:%02X:%02X idle %lus",
                                   bb->mac[0], bb->mac[1], bb->mac[2],
                                   bb->mac[3], bb->mac[4], bb->mac[5],
                                   (unsigned long)(now - last));
                        memset(bb, 0, sizeof(n2n_brother_entry_t));
                    }
                }
            }
        }
    }

    deinit_sn( sss );
    free_community_stats( &sss->comm_stats );
    free_rate_limit_rules( &sss->rate_rules );
    return 0;
}

/* send_brother_reg: sn1 -> sn2 brother registration, sent every 60s.
 * Uses the local NIC MAC as the SN identifier (matches what edge sees when
 * the SN forwards traffic) and the community string "brother_reg" (11
 * bytes, no trailing NUL) so sn2 can detect that the packet is a brother
 * update rather than a normal edge register. */
static void send_brother_reg(n2n_sn_t *sss, time_t now)
{
    n2n_sock_t              backup_sock;
    n2n_common_t            cmn;
    n2n_REGISTER_SUPER_t    reg;
    uint8_t                 pktbuf[N2N_SN_PKTBUF_SIZE];
    size_t                  idx = 0;
    n2n_sock_str_t          sockbuf;

    if (sss->backup_addr_text[0] == '\0') return;

    /* Resolve and cache the sn2 address inside this process. */
    static n2n_sock_t  cached_sock = {0};
    static int        cached_resolved = 0;
    static time_t     cached_time = 0;

    if (!cached_resolved || (now - cached_time > 300)) {
        cached_resolved = 0;
        memset(&cached_sock, 0, sizeof(cached_sock));
        if (resolve_brother_addr(sss->backup_addr_text, &cached_sock) == 0) {
            cached_resolved = 1;
            cached_time = now;
        }
    }
    if (!cached_resolved) return;
    backup_sock = cached_sock;

    /* Prefer the live NIC MAC. Skip registration entirely if neither NIC
     * MAC nor fallback is available so the partner SN never sees a
     * zero-MAC entry. */
    const uint8_t *id_mac = sn_identity_mac( sss );

    memset(&cmn, 0, sizeof(cmn));
    memset(&reg, 0, sizeof(reg));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_register_super;
    cmn.flags = N2N_FLAGS_SOCKET;
    memcpy(cmn.community, "brother_reg", 11); /* brother-only community tag */

    /* Cookie = id_mac; edgeMac = id_mac. */
    memcpy(reg.cookie, id_mac, N2N_COOKIE_SIZE);
    memcpy(reg.edgeMac, id_mac, sizeof(reg.edgeMac));
    /* Carry our IPv6 GUA (if any) so a v4-only sn2 still learns how to reach us on IPv6. */
    if (sss->my_ipv6.family == AF_INET6) {
        reg.aflags |= N2N_AFLAGS_IPV6_SOCKET;
        reg.own_ipv6 = sss->my_ipv6;
    }
    /* Carry backup_token when configured. */
    if (sss->backup_token_set) {
        memcpy(reg.auth.token, sss->backup_token.token, sss->backup_token.toksize);
        reg.auth.toksize = sss->backup_token.toksize;
    }

    encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

    /* Send to sn2 over the address family the resolver returned. */
    sendto_sock( sss, &backup_sock, pktbuf, idx );

    traceEvent(TRACE_DEBUG, "Sent brother_reg to %s as %02x:%02x:%02x:%02x:%02x:%02x",
               sock_to_cstr(sockbuf, &backup_sock),
               id_mac[0], id_mac[1], id_mac[2], id_mac[3], id_mac[4], id_mac[5]);
}

/* resolve_brother_addr: parse "host:port" into an n2n_sock_t.
 * getaddrinfo handles IPv4/IPv6 literals and DNS names; prefer IPv4. */
static int resolve_brother_addr(const char *text, n2n_sock_t *out)
{
    char host[256];
    const char *colon;
    uint16_t port;
    struct addrinfo hints, *res = NULL, *p = NULL;

    if (!text || !out) return -1;
    colon = strrchr(text, ':');
    if (!colon) return -1;
    size_t hlen = colon - text;
    if (hlen >= sizeof(host)) return -1;
    memcpy(host, text, hlen);
    host[hlen] = '\0';
    port = (uint16_t)atoi(colon + 1);
    if (port == 0) return -1;

    /* Strip optional IPv6 brackets. */
    if (host[0] == '[' && host[hlen-1] == ']')
    {
        host[hlen-1] = '\0';
        memmove(host, host + 1, hlen - 1);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;

    for (p = res; p; p = p->ai_next) if (p->ai_family == AF_INET) break;
    if (!p) for (p = res; p; p = p->ai_next) if (p->ai_family == AF_INET6) break;
    if (!p) { freeaddrinfo(res); return -1; }

    if (p->ai_family == AF_INET)
    {
        out->family = AF_INET;
        memcpy(out->addr.v4, &((struct sockaddr_in*)p->ai_addr)->sin_addr, IPV4_SIZE);
    }
    else
    {
        out->family = AF_INET6;
        memcpy(out->addr.v6, &((struct sockaddr_in6*)p->ai_addr)->sin6_addr, IPV6_SIZE);
    }
    out->port = port;
    freeaddrinfo(res);
    return 0;
}
