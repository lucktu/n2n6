/**
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
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 * Code contributions courtesy of:
 * Don Bindner <don.bindner@gmail.com>
 * Sylwester Sosnowski <syso-n2n@no-route.org>
 * Wilfried "Wonka" Klaebe
 * Lukasz Taczuk
 *
 */

#include "n2n.h"
#include "n2n_transforms.h"
#include "speck.h"
#include "pearson.h"
#include "assert.h"
#include "minilzo.h"
#include "random.h"
#include "string.h"
#include "upnp.h"

#ifdef _WIN32
#include <iphlpapi.h>
#endif

/* reallocarray compatibility for older glibc versions */
#ifndef HAVE_REALLOCARRAY
#define reallocarray(p, n, s) realloc((p), (n) * (s))
#endif

#define SOCKET_TIMEOUT_INTERVAL_SECS    1    /* sec */
#define REGISTER_SUPER_INTERVAL_DFL     60   /* sec */
#define REGISTER_SUPER_INTERVAL_MIN     30   /* sec */
#define REGISTER_SUPER_INTERVAL_MAX     120  /* sec */
#define IFACE_UPDATE_INTERVAL           (30) /* sec. How long it usually takes to get an IP lease. */
#define TRANSOP_TICK_INTERVAL           (10) /* sec */
#define PUNCH_TIMEOUT                   60   /* sec: give up hole-punch after this */

/** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH       4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH        1024

#define N2N_PATHNAME_MAXLEN             256
#define N2N_MAX_TRANSFORMS              16
#define N2N_EDGE_MGMT_PORT              5664

/** Positions in the transop array where various transforms are stored.
 *
 *  Used by transop_enum_to_index(). See also the transform enumerations in
 *  n2n_transforms.h */
#define N2N_TRANSOP_NULL_IDX    0
#define N2N_TRANSOP_TF_IDX      1
#define N2N_TRANSOP_AESCBC_IDX  2
#define N2N_TRANSOP_CC20_IDX    3
#define N2N_TRANSOP_SPECK_IDX   4



/* ******************************************************* */

#define N2N_EDGE_SN_HOST_SIZE   48

typedef char n2n_sn_name_t[N2N_EDGE_SN_HOST_SIZE];

#define N2N_EDGE_NUM_SUPERNODES 3
#define N2N_EDGE_SUP_ATTEMPTS   3       /* Number of failed attmpts before moving on to next supernode. */

/* Portable temporary buffer macros - avoids C99 compound literals which
 * cause issues on older ARM compilers (GCC 4.x / ARMv5). */
#define MACSTR_TMP(var)      macstr_t var; memset(var, 0, sizeof(var))
#define SOCKSTR_TMP(var)     n2n_sock_str_t var; memset(var, 0, sizeof(var))

static int default_ip_assignment = 0;
static int initial_connection_complete = 0;

/* Global flag set by signal handler to request graceful shutdown */
static volatile int g_edge_running = 1;

#ifndef _WIN32
#include <signal.h>
static void edge_signal_handler(int sig) {
    (void)sig;
    g_edge_running = 0;
}
#endif

/** Main structure type for edge. */
struct n2n_edge
{
    int                 daemon;                 /**< Non-zero if edge should detach and run in the background. */
    uint8_t             re_resolve_supernode_ip;

    n2n_sock_t          supernode;
    n2n_sock_t          supernode_alt;          /**< Alternate address family for supernode (family=0 if unavailable) */

    size_t              sn_idx;                 /**< Currently active supernode. */
    size_t              sn_num;                 /**< Number of supernode addresses defined. */
    n2n_sn_name_t       sn_ip_array[N2N_EDGE_NUM_SUPERNODES];
    int                 sn_af;
    int                 sn_wait;                /**< Whether we are waiting for a supernode response. */

    n2n_community_t     community_name;         /**< The community. 16 full octets. */
    char                keyschedule[N2N_PATHNAME_MAXLEN];
    int                 null_transop;           /**< Only allowed if no key sources defined. */
    char                supernode_version[16];

    SOCKET              udp_sock;                /**< IPv4 UDP socket */
    SOCKET              udp_sock6;               /**< IPv6 UDP socket (-1 if unavailable) */
    SOCKET              mgmt_sock;               /**< socket for status info. */

    tuntap_dev          device;                 /**< All about the TUNTAP device */
    int                 dyn_ip_mode;            /**< Interface IP address is dynamically allocated, eg. DHCP. */
    int                 allow_routing;          /**< Accept packet no to interface address. */
    int                 drop_multicast;         /**< Multicast ethernet addresses. */

    n2n_trans_op_t      transop[N2N_MAX_TRANSFORMS]; /* one for each transform at fixed positions */
    size_t              tx_transop_idx;         /**< The transop to use when encoding. */

    struct peer_info *  known_peers;            /**< Edges we are connected to. */
    struct peer_info *  pending_peers;          /**< Edges we have tried to register with. */
#ifdef _WIN32
    CRITICAL_SECTION    peers_lock;             /**< Protect known_peers/pending_peers from tunReadThread vs main thread */
#endif
    time_t              last_register_req;      /**< Check if time to re-register with super*/
    size_t              register_lifetime;      /**< Time distance after last_register_req at which to re-register. */
    time_t              last_p2p;               /**< Last time p2p traffic was received. */
    time_t              last_sup;               /**< Last time a packet arrived from supernode. */
    size_t              sup_attempts;           /**< Number of remaining attempts to this supernode. */
    n2n_cookie_t        last_cookie;            /**< Cookie sent in last REGISTER_SUPER. */
    uint8_t             sn_ack_count;           /**< Number of REGISTER_SUPER_ACKs received for current cookie (dual-stack sends 2) */
    uint8_t             sn_ipv4_support;        /**< Supernode IPv4 support capability */
    uint8_t             sn_ipv6_support;        /**< Supernode IPv6 support capability */

    time_t              start_time;             /**< For calculating uptime */

    n2n_sock_t          my_public_sock;         /**< Our own public IP:port as seen by supernode */

    n2n_sock_t          local_sock;             /**< LAN address for same-NAT direct connect */
    int                 local_sock_ena;         /**< 1 if local_sock is valid */

    /* UPnP/NAT-PMP */
    uint16_t            upnp_mapped_port;       /**< External port mapped via UPnP/NAT-PMP, 0 if none */

    /* Statistics */
    size_t              tx_p2p;
    size_t              rx_p2p;
    size_t              tx_sup;
    size_t              rx_sup;
#ifdef _WIN32
    volatile int        keep_running;           /**< Set to 0 to stop tunReadThread */
#endif
};

#ifdef _WIN32
#define PEERS_LOCK(eee)   EnterCriticalSection(&(eee)->peers_lock)
#define PEERS_UNLOCK(eee) LeaveCriticalSection(&(eee)->peers_lock)
#else
#define PEERS_LOCK(eee)   /* no-op on Linux: single-threaded TAP */
#define PEERS_UNLOCK(eee) /* no-op on Linux: single-threaded TAP */
#endif

/** Return the IP address of the current supernode in the ring. */
static const char * supernode_ip( const n2n_edge_t * eee )
{
    return (eee->sn_ip_array)[eee->sn_idx];
}


static int supernode2addr(n2n_sock_t * sn, int af, const n2n_sn_name_t addr);

static void send_packet2net(n2n_edge_t * eee,
                uint8_t *decrypted_msg, size_t len);

/* ************************************** */

static int readConfFile(const char * filename, char * const linebuffer) {
    FILE* fd;
    char* buffer;

    buffer = (char*) malloc(MAX_CONFFILE_LINE_LENGTH);
    if (!buffer) {
        traceEvent( TRACE_ERROR, "Unable to allocate memory");
        return -1;
    }

    if (access(filename, R_OK)) {
        if (errno == ENOENT)
            traceEvent(TRACE_ERROR, "parameter file %s not found/unable to access\n", filename);
        else
            traceEvent(TRACE_ERROR, "cannot stat file %s, %s\n",filename, strerror(errno));
        free(buffer);
        return -1;
    }

				fd = fopen(filename, "rb");
    if (!fd) {
        traceEvent(TRACE_ERROR, "Unable to open parameter file '%s': %s\n", filename, strerror(errno));
        free(buffer);
        return -1;
    }
    while(fgets(buffer, MAX_CONFFILE_LINE_LENGTH,fd)) {
        char* p;

        /* strip out comments */
        p = strchr(buffer, '#');
        if (p) *p ='\0';

        /* remove \n */
        p = strchr(buffer, '\n');
        if (p) *p ='\0';

        /* Verify buffer validity */
        if (!buffer || strlen(buffer) == 0) {
            continue;
        }

        /* strip out heading spaces */
        p = buffer;
        while (*p == ' ') ++p;
        if (p != buffer) {
            size_t len = strlen(p);
            if (len < MAX_CONFFILE_LINE_LENGTH) {
                memmove(buffer, p, len + 1);
            } else {
                traceEvent(TRACE_ERROR, "line too long");
                continue;
            }
        }

        /* strip out trailing spaces */
        size_t buf_len = strlen(buffer);
        while(buf_len > 0 && buffer[buf_len-1] == ' ') {
            buffer[buf_len-1] = '\0';
            buf_len--;
        }

        /* check for nested @file option */
        if (strchr(buffer, '@')) {
            traceEvent(TRACE_ERROR, "@file in file nesting is not supported\n");
            free(buffer);
            fclose(fd);
            return -1;
        }
        /* Calculate the current length and remaining space */
        size_t line_len = strlen(linebuffer);

        /* Check if there is enough space */
        if (line_len + buf_len + 2 <= MAX_CMDLINE_BUFFER_LENGTH) {
            linebuffer[line_len] = ' ';
            memcpy(linebuffer + line_len + 1, buffer, buf_len + 1);
        } else {
            traceEvent(TRACE_ERROR, "too many arguments");
            free(buffer);
           fclose(fd);
            return -1;
        }
    }

    free(buffer);
    fclose(fd);

    return 0;
}

static int edge_init_speck( n2n_edge_t * eee, uint8_t *encrypt_pwd, uint64_t encrypt_pwd_len )
{
    n2n_cipherspec_t spec;
    int retval;

    /* Create a cipherspec for single-key Speck operation */
    spec.t = N2N_TRANSFORM_ID_SPECK;
    spec.valid_from = 0;
    spec.valid_until = 0xFFFFFFFF;

    /* Format: "0_hexkey" where 0 is SA ID */
    snprintf((char*)spec.opaque, sizeof(spec.opaque), "0_");

    /* Try hex first, if fails use ASCII directly */
    int pstat = n2n_parse_hex(spec.opaque + 2, sizeof(spec.opaque) - 2,
                             (char*)encrypt_pwd, encrypt_pwd_len);

    if (pstat <= 0) {
        /* Hex parsing failed, use ASCII directly */
        memcpy(spec.opaque + 2, encrypt_pwd, encrypt_pwd_len);
        spec.opaque[2 + encrypt_pwd_len] = '\0';
        pstat = encrypt_pwd_len;
    }

    /* Add the spec to the Speck transform */
    retval = (eee->transop[N2N_TRANSOP_SPECK_IDX].addspec)(
                &(eee->transop[N2N_TRANSOP_SPECK_IDX]), &spec );

    if (retval == 0) {
        eee->tx_transop_idx = N2N_TRANSOP_SPECK_IDX;
    }

    return retval;
}

/* Create the argv vector */
static char ** buildargv(int * effectiveargc, char * const linebuffer) {
    const int  INITIAL_MAXARGC = 16;	/* Number of args + NULL in initial argv */
    int     maxargc;
    int     argc=0;
    char ** argv;
    char *  buffer, * buff;

    if (!linebuffer) {
        return NULL;
    }

    *effectiveargc = 0;
    buffer = (char *)calloc(1, strlen(linebuffer)+2);
    if (!buffer) {
        traceEvent( TRACE_ERROR, "Unable to allocate memory");
        return NULL;
    }

    memcpy(buffer, linebuffer, strlen(linebuffer) + 1);

    maxargc = INITIAL_MAXARGC;
    argv = (char **)malloc(maxargc * sizeof(char*));
    if (argv == NULL) {
        traceEvent( TRACE_ERROR, "Unable to allocate memory");
        free(buffer);
        return NULL;
    }
    buff = buffer;
    while(buff) {
        char * p = strchr(buff,' ');
        if (p) {
            *p='\0';
            argv[argc++] = strdup(buff);
            while(*++p == ' ');
            buff=p;
            if (argc >= maxargc) {
                maxargc *= 2;
                char** new_argv = (char **)realloc(argv, maxargc * sizeof(char*));
                if (new_argv == NULL) {
                    traceEvent(TRACE_ERROR, "Unable to re-allocate memory");
                    for (int i = 0; i < argc; i++) {
                        free(argv[i]);
                    }
                    free(argv);
                    free(buffer);
                    return NULL;
                } else {
                    argv = new_argv;
                }
            }
        } else {
            argv[argc++] = strdup(buff);
            break;
        }
    }
    free(buffer);
    *effectiveargc = argc;
    return argv;
}

/* ************************************** */


/** Initialise an edge to defaults.
 *
 *  This also initialises the NULL transform operation opstruct.
 */
static int edge_init(n2n_edge_t * eee)
{
#ifdef _WIN32
    initWin32();
#endif
    memset(eee, 0, sizeof(n2n_edge_t));
    eee->start_time = n2n_now();

    transop_null_init(    &(eee->transop[N2N_TRANSOP_NULL_IDX]) );
    transop_twofish_init( &(eee->transop[N2N_TRANSOP_TF_IDX]  ) );
    transop_aes_init(     &(eee->transop[N2N_TRANSOP_AESCBC_IDX]) );
    transop_cc20_init(    &(eee->transop[N2N_TRANSOP_CC20_IDX]) );
    transop_speck_init(   &(eee->transop[N2N_TRANSOP_SPECK_IDX]) );

    eee->tx_transop_idx = N2N_TRANSOP_NULL_IDX; /* No guarantee the others have been setup */

    eee->daemon = 1;    /* By default run in daemon mode. */
    eee->re_resolve_supernode_ip = 0;
    /* keyschedule set to NULLs by memset */
    /* community_name set to NULLs by memset */
    eee->null_transop   = 0;
    eee->udp_sock       = -1;
    eee->udp_sock6      = -1;
    eee->mgmt_sock      = -1;
    eee->dyn_ip_mode    = 0;
    eee->allow_routing  = 0;
    eee->drop_multicast = 1;
    eee->known_peers    = NULL;
    eee->pending_peers  = NULL;
    eee->upnp_mapped_port = 0;
#ifdef _WIN32
    InitializeCriticalSection(&eee->peers_lock);
    eee->keep_running   = 1;
#endif
    eee->last_register_req = 0;
    eee->register_lifetime = 120;
    eee->last_p2p = 0;
    eee->last_sup = 0;
    eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
    eee->sn_af = AF_UNSPEC;
    memset(&eee->my_public_sock, 0, sizeof(n2n_sock_t));

    if(lzo_init() != LZO_E_OK)
    {
        traceEvent(TRACE_ERROR, "LZO compression error");
        return(-1);
    }

    pearson_hash_init();

    return(0);
}

/** Called in main() after options are parsed. */
static int edge_init_twofish( n2n_edge_t * eee, uint8_t *encrypt_pwd, uint64_t encrypt_pwd_len )
{
    int retval;

    retval = transop_twofish_setup( &(eee->transop[N2N_TRANSOP_TF_IDX]), 0, encrypt_pwd, encrypt_pwd_len );

    if (retval == 0) {
        eee->tx_transop_idx = N2N_TRANSOP_TF_IDX;
    }

    return retval;
}

#ifdef N2N_HAVE_AES
static int edge_init_aes( n2n_edge_t * eee, uint8_t *encrypt_pwd, uint64_t encrypt_pwd_len )
{
    int retval = edge_init_aes_from_key(&eee->transop[N2N_TRANSOP_AESCBC_IDX],
                                        encrypt_pwd, (size_t)encrypt_pwd_len);
    if (retval == 0)
        eee->tx_transop_idx = N2N_TRANSOP_AESCBC_IDX;
    return retval;
}
#endif

#ifdef N2N_HAVE_CC20
static int edge_init_cc20( n2n_edge_t * eee, uint8_t *encrypt_pwd, uint64_t encrypt_pwd_len )
{
    int retval = edge_init_cc20_from_key(&eee->transop[N2N_TRANSOP_CC20_IDX],
                                         encrypt_pwd, (size_t)encrypt_pwd_len);
    if (retval == 0)
        eee->tx_transop_idx = N2N_TRANSOP_CC20_IDX;
    return retval;
}
#endif

static int transop_enum_to_index( n2n_transform_t id )
{
    switch (id) {
    case N2N_TRANSFORM_ID_TWOFISH:  return N2N_TRANSOP_TF_IDX;
    case N2N_TRANSFORM_ID_NULL:     return N2N_TRANSOP_NULL_IDX;
    case N2N_TRANSFORM_ID_AESCBC:   return N2N_TRANSOP_AESCBC_IDX;
    case N2N_TRANSFORM_ID_CHACHA20: return N2N_TRANSOP_CC20_IDX;
    case N2N_TRANSFORM_ID_SPECK:    return N2N_TRANSOP_SPECK_IDX;
    default:                        return -1;
    }
}

static int n2n_tick_transop( n2n_edge_t * eee, time_t now )
{
    /* Tick all transops for maintenance only.
     * tx_transop_idx is set by -B option and must not be overridden here. */
    (eee->transop[N2N_TRANSOP_NULL_IDX].tick)( &(eee->transop[N2N_TRANSOP_NULL_IDX]), now );
    (eee->transop[N2N_TRANSOP_TF_IDX].tick)( &(eee->transop[N2N_TRANSOP_TF_IDX]), now );
    (eee->transop[N2N_TRANSOP_AESCBC_IDX].tick)( &(eee->transop[N2N_TRANSOP_AESCBC_IDX]), now );
    (eee->transop[N2N_TRANSOP_CC20_IDX].tick)( &(eee->transop[N2N_TRANSOP_CC20_IDX]), now );
    (eee->transop[N2N_TRANSOP_SPECK_IDX].tick)( &(eee->transop[N2N_TRANSOP_SPECK_IDX]), now );
    return 0;
}

/** Deinitialise the edge and deallocate any owned memory. */
static void edge_deinit(n2n_edge_t * eee)
{
    if ( eee->udp_sock != -1 )
        closesocket( eee->udp_sock );

    if ( eee->udp_sock6 != -1 )
        closesocket( eee->udp_sock6 );

    if ( eee->mgmt_sock != -1 )
        closesocket(eee->mgmt_sock);

    /* Remove UPnP/NAT-PMP port mapping on exit */
    if (eee->upnp_mapped_port != 0) {
        traceEvent(TRACE_NORMAL, "Removing UPnP/NAT-PMP port mapping for port %u",
                   (unsigned)eee->upnp_mapped_port);
        upnp_unmap_port(eee->upnp_mapped_port);
        eee->upnp_mapped_port = 0;
    }

    clear_peer_list( &(eee->pending_peers) );
    clear_peer_list( &(eee->known_peers) );

    (eee->transop[N2N_TRANSOP_TF_IDX].deinit)(&eee->transop[N2N_TRANSOP_TF_IDX]);
    (eee->transop[N2N_TRANSOP_NULL_IDX].deinit)(&eee->transop[N2N_TRANSOP_NULL_IDX]);
    (eee->transop[N2N_TRANSOP_AESCBC_IDX].deinit)(&eee->transop[N2N_TRANSOP_AESCBC_IDX]);
    (eee->transop[N2N_TRANSOP_CC20_IDX].deinit)(&eee->transop[N2N_TRANSOP_CC20_IDX]);
    (eee->transop[N2N_TRANSOP_SPECK_IDX].deinit)(&eee->transop[N2N_TRANSOP_SPECK_IDX]);

#ifdef _WIN32
    WSACleanup();
#endif
}

static void readFromIPSocket( n2n_edge_t * eee, SOCKET fd );

static void readFromMgmtSocket( n2n_edge_t * eee, int * keep_running );

static void help() {
    print_n2n_version();
    printf("\n");

    printf("Usage: edge [config_file] <options>\n");
    printf("or: edge -a <tun IP address> -c <community> -k <encrypt key> -B <mode> -l <supernode host:port>\n");
    printf("or: edge -c <community> (default: -d n2nx -a 10.64.0.x -l ouno.eu.org:10084; no password, not secure, not recommended)\n");
    printf("\n");

#if N2N_CAN_NAME_IFACE && !defined(_WIN32)
    printf("-d <tun device>          | tun device name\n");
#elif N2N_CAN_NAME_IFACE && defined(_WIN32)
    printf("-d <tun device>          | tun device name (optional)\n");
#endif
    printf("-a <mode:IPv4/prefixlen> | Set interface IPv4 address. For DHCP use '-r -a dhcp:0.0.0.0/0'\n");
    printf("                         : If not specified, auto-assigns 10.64.0.x from supernode\n");
    printf("-A <IPv6>/<prefixlen>    | Set interface IPv6 address, only supported if IPv4 set to 'static'\n");
    printf("-c <community>           | n2n community name the edge belongs to.\n");
    printf("-B <mode>                | Encryption:");
    printf(" B1 = disable, B2 = twofish(-k)");
    #ifdef N2N_HAVE_AES
    printf(", B3 = AES-CBC(-k)");
    #endif
    #ifdef N2N_HAVE_CC20
    printf(", B4 = ChaCha20(-k)");
    #endif
    printf("\n");
    printf("                         : B5 = Speck(-k). '-B1' can also be used as '-B 1' (default: twofish)\n");
    printf("-k <encrypt key>         | Encryption key (ASCII, max 32) - also N2N_KEY=<encrypt key>.\n");
    printf("-l <supernode host:port> | Supernode IP:port (default: ouno.eu.org:10084)\n");
    printf("-4/-6                    | Resolve supernode DNS name as IPv4 or IPv6 (default: auto)\n");
    printf("-p <local port>          | Fixed local UDP port.\n");
#ifndef _WIN32
    printf("-u <UID>                 | User ID (numeric) to use when privileges are dropped.\n");
    printf("-g <GID>                 | Group ID (numeric) to use when privileges are dropped.\n");
#endif /* ifndef _WIN32 */
#ifdef N2N_HAVE_DAEMON
    printf("-f                       | Do not fork and run as a daemon; rather run in foreground.\n");
#endif /* #ifdef N2N_HAVE_DAEMON */
#ifndef _WIN32
    printf("-m <MAC address>         | Fix MAC address for the TAP interface (otherwise it may be random)\n"
           "                         : eg. -m 01:02:03:04:05:06\n");
    printf("-M <mtu>                 | Specify n2n MTU of edge interface (default: %d).\n", DEFAULT_MTU);
#endif
    printf("-r                       | Enable packet forwarding through n2n community.\n");
    printf("-R <dest>/<length>,<gw>  | Enable packet forwarding and add a route, IPv4/6 is autodetected\n");
    printf("-E                       | Accept multicast MAC addresses (default: drop).\n");
    printf("-v                       | Make more verbose. Repeat as required.\n");
    printf("-t <port|path>           | Management Socket (UDP Port or absolute path). (default: %d)\n", N2N_EDGE_MGMT_PORT);
    printf("-h                       | Show this help message\n");

    printf("\nEnvironment variables:\n");
    printf("  N2N_KEY                | Encryption key (ASCII). Not with -K or -k.\n" );
    printf("\n");
}


/** Send a datagram to a socket defined by a n2n_sock_t */
static ssize_t sendto_sock( SOCKET fd, const void * buf, size_t len, const n2n_sock_t * dest )
{
    struct sockaddr_in6 peer_addr;
    ssize_t sent;
    socklen_t addr_len;

    fill_sockaddr( (struct sockaddr*) &peer_addr, sizeof(peer_addr), dest );
    addr_len = (dest->family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

    sent = sendto( fd, buf, len, 0/*flags*/,
                   (struct sockaddr*) &peer_addr, addr_len );
    if ( sent < 0 )
    {
#ifdef _WIN32
        int error = WSAGetLastError();
        /* 10014 = WSAEFAULT: IPv6 socket sending to IPv4 address - silent */
        /* 10047 = WSAEAFNOSUPPORT: IPv4 socket sending to IPv6 address - silent */
        if ( error != 10014 && error != 10047 ) {
            W32_ERROR(error, c)
            traceEvent( TRACE_ERROR, "sendto failed (%d) %ls", error, c );
            W32_ERROR_FREE(c)
        }
#else
        char * c = strerror(errno);
        traceEvent( TRACE_DEBUG, "sendto failed (%d) %s", errno, c );
#endif
    }
    else
    {
        traceEvent( TRACE_DEBUG, "sendto sent=%d to", (signed int) sent );
    }

    return sent;
}

/** Select the correct UDP socket based on destination address family */
static inline SOCKET sock_for_dest( const n2n_edge_t * eee, const n2n_sock_t * dest )
{
    if ( dest->family == AF_INET6 && eee->udp_sock6 != -1 )
        return eee->udp_sock6;
    return eee->udp_sock;
}


/** Send a REGISTER packet to another edge. */
static void send_register( n2n_edge_t * eee,
    const n2n_sock_t * remote_peer)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_REGISTER_t reg;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn) );
    memset(&reg, 0, sizeof(reg) );
    cmn.ttl=N2N_DEFAULT_TTL;
    cmn.pc = n2n_register;
    cmn.flags = 0;
    memcpy( cmn.community, eee->community_name, N2N_COMMUNITY_SIZE );

    strncpy(reg.version, n2n_sw_version, sizeof(reg.version) - 1);
    strncpy(reg.os_name, n2n_sw_osName, sizeof(reg.os_name) - 1);

    idx=0;
    encode_uint32( reg.cookie, &idx, 123456789 );
    idx=0;
    encode_mac( reg.srcMac, &idx, eee->device.mac_addr );

    /* Attach our LAN address so the peer can try direct LAN connect */
    if ( eee->local_sock_ena ) {
        reg.sock = eee->local_sock;
        cmn.flags |= N2N_FLAGS_SOCKET;
    }

    idx=0;
    encode_REGISTER( pktbuf, &idx, &cmn, &reg );

    traceEvent( TRACE_INFO, "send REGISTER %s",
        sock_to_cstr( sockbuf, remote_peer ) );

    sendto_sock( sock_for_dest(eee, remote_peer), pktbuf, idx, remote_peer );
}


/** Automatically detect LAN IP address for same-NAT direct connect.
 *  Uses connect()+getsockname() to find the exit IP towards supernode.
 *  Only uses the result if it's a private IP address. */
static void set_localip( n2n_edge_t * eee )
{
    n2n_sock_str_t sockbuf;
    eee->local_sock_ena = 0;

    struct sockaddr_in sa2;
    socklen_t sa2_len = sizeof(sa2);
    if (getsockname(eee->udp_sock, (struct sockaddr*)&sa2, &sa2_len) < 0) return;
    uint16_t local_port = ntohs(sa2.sin_port);

    struct sockaddr_in sa, sa_sn;
    socklen_t sa_len = sizeof(sa);
#ifdef _WIN32
    SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == INVALID_SOCKET) return;
#else
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
#endif
    fill_sockaddr((struct sockaddr*)&sa_sn, sizeof(sa_sn), &eee->supernode);
    if (connect(fd, (struct sockaddr*)&sa_sn, sizeof(sa_sn)) == 0 &&
        getsockname(fd, (struct sockaddr*)&sa, &sa_len) == 0 &&
        sa.sin_family == AF_INET && sa.sin_addr.s_addr != 0)
    {
        uint32_t ip = ntohl(sa.sin_addr.s_addr);
        /* Only use private IP addresses */
        int is_private = ((ip >> 24) == 10) ||
                         ((ip & 0xFFF00000) == 0xAC100000) ||
                         ((ip >> 16) == (192 << 8 | 168));
        if (is_private && ip != ntohl(eee->device.ip_addr)) {
            eee->local_sock.family = AF_INET;
            eee->local_sock.port   = local_port;
            memcpy(eee->local_sock.addr.v4, &sa.sin_addr.s_addr, IPV4_SIZE);
            eee->local_sock_ena = 1;
        }
    }
    closesocket(fd);

    if (eee->local_sock_ena)
        traceEvent(TRACE_NORMAL, "Local LAN socket: %s",
                   sock_to_cstr(sockbuf, &eee->local_sock));
    else
        traceEvent(TRACE_WARNING, "set_localip: no private LAN address found");
}

/** Send a QUERY_PEER packet to supernode asking for target's address. */
static void send_query_peer( n2n_edge_t * eee, const n2n_mac_t targetMac )
{
    uint8_t          pktbuf[N2N_PKT_BUF_SIZE];
    size_t           idx = 0;
    n2n_common_t     cmn;
    n2n_QUERY_PEER_t query;

    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc  = n2n_query_peer;
    cmn.flags = 0;
    memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

    memcpy(query.srcMac,    eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy(query.targetMac, targetMac,            N2N_MAC_SIZE);

    encode_QUERY_PEER(pktbuf, &idx, &cmn, &query);
    sendto_sock(sock_for_dest(eee, &eee->supernode), pktbuf, idx, &(eee->supernode));
}

/** Send a REGISTER_SUPER packet to the current supernode. */
static void send_register_super( n2n_edge_t * eee,
                                const n2n_sock_t * supernode)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_REGISTER_SUPER_t reg;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn) );
    memset(&reg, 0, sizeof(reg) );
    cmn.ttl=N2N_DEFAULT_TTL;
    cmn.pc = n2n_register_super;
    cmn.flags = 0;
    memcpy( cmn.community, eee->community_name, N2N_COMMUNITY_SIZE );

    /* Generate cookie once; both primary and alt address use the same cookie
     * so both ACKs pass the cookie check and neither triggers a spurious warning. */
    random_bytes(NULL, eee->last_cookie, N2N_COOKIE_SIZE);
    eee->sn_ack_count = 0; /* reset duplicate-ACK counter */

    memcpy( reg.cookie, eee->last_cookie, N2N_COOKIE_SIZE );
    reg.auth.scheme=0; /* No auth yet */

    idx=0;
    encode_mac( reg.edgeMac, &idx, eee->device.mac_addr );

    /* Fill dev_addr: net_addr=0 means request auto-assign from supernode */
    reg.dev_addr.net_addr = default_ip_assignment ? 0 : ntohl(eee->device.ip_addr);
    reg.dev_addr.net_bitlen = eee->device.ip_prefixlen;

    /* Attach LAN address for same-NAT direct connect */
    if (eee->local_sock_ena) {
        reg.aflags    |= N2N_AFLAGS_LOCAL_SOCKET;
        reg.local_sock = eee->local_sock;
    }

    idx=0;
    encode_REGISTER_SUPER( pktbuf, &idx, &cmn, &reg );

    traceEvent( TRACE_INFO, "send REGISTER_SUPER to %s",
        sock_to_cstr( sockbuf, supernode ) );

    sendto_sock( sock_for_dest(eee, supernode), pktbuf, idx, supernode );

    /* Also register via alternate address family so supernode knows both our addresses */
    if (eee->supernode_alt.family != 0) {
        SOCKET alt_sock = (eee->supernode_alt.family == AF_INET6) ? eee->udp_sock6 : eee->udp_sock;
        if (alt_sock != -1) {
            traceEvent(TRACE_INFO, "send REGISTER_SUPER (alt) to %s",
                       sock_to_cstr(sockbuf, &eee->supernode_alt));
            sendto_sock(alt_sock, pktbuf, idx, &eee->supernode_alt);
        }
    }
}

/** Send a REGISTER_ACK packet to a peer edge. */
static void send_register_ack( n2n_edge_t * eee,
                               const n2n_sock_t * remote_peer,
                               const n2n_REGISTER_t * reg )
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_REGISTER_ACK_t ack;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn) );
    memset(&ack, 0, sizeof(ack) );
    cmn.ttl=N2N_DEFAULT_TTL;
    cmn.pc = n2n_register_ack;
    cmn.flags = 0;
    memcpy( cmn.community, eee->community_name, N2N_COMMUNITY_SIZE );

    memset( &ack, 0, sizeof(ack) );
    memcpy( ack.cookie, reg->cookie, N2N_COOKIE_SIZE );
    memcpy( ack.srcMac, eee->device.mac_addr, N2N_MAC_SIZE );
    memcpy( ack.dstMac, reg->srcMac, N2N_MAC_SIZE );

    idx=0;
    encode_REGISTER_ACK( pktbuf, &idx, &cmn, &ack );

    traceEvent( TRACE_INFO, "send REGISTER_ACK %s",
        sock_to_cstr( sockbuf, remote_peer ) );


    sendto_sock( sock_for_dest(eee, remote_peer), pktbuf, idx, remote_peer );
}


/** Send a DEREGISTER packet to supernode and all known peers to notify going offline. */
static void send_deregister(n2n_edge_t * eee,
    n2n_sock_t * remote_peer)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_DEREGISTER_t reg;

    memset(&cmn, 0, sizeof(cmn));
    memset(&reg, 0, sizeof(reg));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc  = n2n_deregister;
    cmn.flags = 0;
    memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);
    memcpy(reg.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);

    idx = 0;
    encode_DEREGISTER(pktbuf, &idx, &cmn, &reg);
    sendto_sock(sock_for_dest(eee, remote_peer), pktbuf, idx, remote_peer);
}

/** Check if two sockets are on the same public IP (same LAN behind same NAT) */
static int same_public_ip( const n2n_sock_t * a, const n2n_sock_t * b )
{
    if ( a->family != b->family ) return 0;
    if ( a->family == AF_INET )
        return (memcmp(a->addr.v4, b->addr.v4, IPV4_SIZE) == 0);
    if ( a->family == AF_INET6 )
        return (memcmp(a->addr.v6, b->addr.v6, IPV6_SIZE) == 0);
    return 0;
}

/** Send a PROBE packet directly to a peer to open NAT mapping */
static void send_probe( n2n_edge_t * eee, const n2n_sock_t * peer_sock, const n2n_mac_t dstMac )
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    n2n_common_t cmn;
    n2n_PROBE_t probe;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_probe;
    cmn.flags = 0;
    memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

    memcpy(probe.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy(probe.dstMac, dstMac, N2N_MAC_SIZE);

    encode_PROBE(pktbuf, &idx, &cmn, &probe);

    traceEvent(TRACE_INFO, "send PROBE to %s", sock_to_cstr(sockbuf, peer_sock));
    sendto_sock(sock_for_dest(eee, peer_sock), pktbuf, idx, peer_sock);
}

/** Send PROBE_ACK via supernode: tell srcMac what addr we observed from their PROBE */
static void send_probe_ack( n2n_edge_t * eee,
                            const n2n_mac_t srcMac,
                            const n2n_sock_t * observed_addr )
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    n2n_common_t cmn;
    n2n_PROBE_ACK_t ack;

    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_probe_ack;
    cmn.flags = N2N_FLAGS_FROM_SUPERNODE; /* route via supernode */
    memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

    memcpy(ack.srcMac, srcMac, N2N_MAC_SIZE);          /* who sent the probe */
    memcpy(ack.dstMac, eee->device.mac_addr, N2N_MAC_SIZE); /* us, the observer */
    ack.observed_addr = *observed_addr;

    encode_PROBE_ACK(pktbuf, &idx, &cmn, &ack);

    {
        MACSTR_TMP(mac_tmp);
        traceEvent(TRACE_INFO, "send PROBE_ACK via supernode for %s",
                   macaddr_str(mac_tmp, srcMac));
    }
    sendto_sock(sock_for_dest(eee, &eee->supernode), pktbuf, idx, &eee->supernode);
}

static int is_empty_ip_address( const n2n_sock_t * sock );

/** Start hole-punch for a peer: send PROBE directly, record punch start time */
static void start_punch( n2n_edge_t * eee, struct peer_info * peer )
{
    MACSTR_TMP(mac_tmp);

    if ( peer->punch_failed ) return;           /* already gave up */
    if ( peer->punch_start_time != 0 ) return;  /* already in progress */

    /* Don't punch if same public IP (same LAN) - handled separately.
     * Only skip if my_public_sock is actually known (non-zero). */
    if ( !is_empty_ip_address(&eee->my_public_sock) &&
         same_public_ip(&eee->my_public_sock, &peer->sock) ) return;

    /* Skip punch if we don't have the right socket for this peer's address family */
    if ( peer->sock.family == AF_INET6 && eee->udp_sock6 == -1 ) return;

    peer->punch_start_time = n2n_now();
    peer->last_punch_probe = peer->punch_start_time;
    send_probe(eee, &peer->sock, peer->mac_addr);
    traceEvent(TRACE_INFO, "hole-punch started for %s",
               macaddr_str(mac_tmp, peer->mac_addr));
}

/** Check punch timeouts in pending_peers: give up after PUNCH_TIMEOUT seconds,
 *  but reset and retry every 5 minutes in case NAT conditions change. */
static void check_punch_timeouts( n2n_edge_t * eee, time_t now )
{
    struct peer_info * scan = eee->pending_peers;
    struct peer_info * prev = NULL;
    MACSTR_TMP(mac_tmp);
    while ( scan ) {
        /* LAN punch: if no ACK within 15 seconds, fall back to WAN punch */
        if ( scan->num_sockets == 2 && !scan->lan_punch_done &&
             scan->lan_punch_start != 0 &&
             (now - scan->lan_punch_start) >= 15 )
        {
            scan->lan_punch_done = 1;
            traceEvent(TRACE_INFO, "LAN punch timeout for %s - trying WAN",
                       macaddr_str(mac_tmp, scan->mac_addr));
            send_register(eee, &scan->sockets[0]);
            send_register(eee, &(eee->supernode));
            start_punch(eee, scan);
        }

        if ( scan->punch_start_time != 0 &&
             !scan->punch_failed &&
             (now - scan->punch_start_time) > PUNCH_TIMEOUT )
        {
            scan->punch_failed = 1;
            scan->punch_reset_time = now;
            traceEvent(TRACE_NORMAL, "PsP (supernode relay) for %s - P2P punch timeout",
                       macaddr_str(mac_tmp, scan->mac_addr));
        } else if ( scan->punch_start_time != 0 &&
                    !scan->punch_failed &&
                    (now - scan->punch_start_time) <= 5 &&
                    (now - scan->last_punch_probe) >= 1 )
        {
            /* Retransmit PROBE every 1s for first 5s - skip if no socket for this family */
            if ( scan->sock.family == AF_INET6 && eee->udp_sock6 == -1 ) {
                /* no IPv6 socket, can't punch */
            } else {
                send_probe(eee, &scan->sock, scan->mac_addr);
                scan->last_punch_probe = now;
            }
        } else if ( scan->punch_start_time == 0 && !scan->punch_failed &&
                    scan->last_seen != 0 &&
                    (now - scan->last_seen) > 1800 )
        {
            traceEvent(TRACE_NORMAL, "Removing stuck pending peer %s (no punch possible, idle %lus)",
                       macaddr_str(mac_tmp, scan->mac_addr),
                       (unsigned long)(now - scan->last_seen));
            struct peer_info *tmp = scan;
            if ( prev ) prev->next = scan->next;
            else eee->pending_peers = scan->next;
            scan = scan->next;
            free(tmp);
            continue;
        } else if ( scan->punch_failed &&
                    (now - scan->punch_reset_time) > 300 )
        {
            scan->punch_retry_count++;
            if ( scan->punch_retry_count > 3 ) {
                traceEvent(TRACE_NORMAL, "Giving up on %s after %u punch retries, removing",
                           macaddr_str(mac_tmp, scan->mac_addr),
                           scan->punch_retry_count);
                struct peer_info *tmp = scan;
                if ( prev ) prev->next = scan->next;
                else eee->pending_peers = scan->next;
                scan = scan->next;
                free(tmp);
                continue;
            }
            scan->punch_failed = 0;
            scan->punch_start_time = 0;
            scan->lan_punch_done = 0;
            scan->lan_punch_start = 0;
            traceEvent(TRACE_INFO, "Retrying P2P punch for %s (attempt %u/3)",
                       macaddr_str(mac_tmp, scan->mac_addr),
                       scan->punch_retry_count);
            start_punch(eee, scan);
        }
        prev = scan;
        scan = scan->next;
    }
}

#define KEEPALIVE_IDLE_SECONDS   20   /* send probe after this many seconds of silence */
#define KEEPALIVE_TIMEOUT_SECONDS 25  /* remove peer if no reply within this many seconds after probe */
#define KEEPALIVE_MAX_FAILS       3   /* remove peer after this many consecutive failures */

static void update_peer_address(n2n_edge_t * eee,
                                uint8_t from_supernode,
                                const n2n_mac_t mac,
                                const n2n_sock_t * peer,
                                time_t when);

/** Send keepalive PROBEs to known_peers that have been silent too long,
 *  and remove peers that have failed KEEPALIVE_MAX_FAILS times. */
static void check_keepalive( n2n_edge_t * eee, time_t now )
{
    struct peer_info *scan = eee->known_peers;
    struct peer_info *prev = NULL;
    MACSTR_TMP(mac_tmp);

    while ( scan ) {
        struct peer_info *next = scan->next;
        time_t idle = now - scan->last_seen;

        /* Skip keepalive for IPv4-only peers if we have no IPv4 socket (shouldn't happen) */
        if ( scan->sock.family == AF_INET && eee->udp_sock == -1 ) {
            prev = scan;
            scan = next;
            continue;
        }
        /* Skip keepalive for IPv6-only peers if we have no IPv6 socket */
        if ( scan->sock.family == AF_INET6 && eee->udp_sock6 == -1 ) {
            prev = scan;
            scan = next;
            continue;
        }

        if ( scan->last_probe_sent == 0 ) {
            /* No probe sent yet: send one if idle too long */
            if ( idle >= KEEPALIVE_IDLE_SECONDS ) {
                n2n_common_t cmn;
                n2n_PROBE_t probe;
                uint8_t pktbuf[N2N_PKT_BUF_SIZE];
                size_t idx = 0;

                memset(&cmn, 0, sizeof(cmn));
                cmn.ttl = N2N_DEFAULT_TTL;
                cmn.pc  = n2n_probe;
                cmn.flags = 0;
                memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);
                memcpy(probe.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
                memcpy(probe.dstMac, scan->mac_addr, N2N_MAC_SIZE);

                encode_PROBE(pktbuf, &idx, &cmn, &probe);
                sendto_sock(sock_for_dest(eee, &scan->sock), pktbuf, idx, &scan->sock);

                scan->last_probe_sent = now;
                traceEvent(TRACE_INFO, "Keepalive PROBE sent to %s (idle %lds)",
                           macaddr_str(mac_tmp, scan->mac_addr), (long)idle);
            }
        } else {
            /* Probe already sent: check if reply came back */
            if ( scan->last_seen >= scan->last_probe_sent ) {
                /* Got a reply: reset */
                scan->last_probe_sent = 0;
                scan->keepalive_fails = 0;
            } else if ( (now - scan->last_probe_sent) >= (KEEPALIVE_TIMEOUT_SECONDS - KEEPALIVE_IDLE_SECONDS) ) {
                /* No reply within timeout */
                scan->keepalive_fails++;
                scan->last_probe_sent = 0;

                traceEvent(TRACE_NORMAL, "Keepalive PROBE no reply from %s (fail %u/%u)",
                           macaddr_str(mac_tmp, scan->mac_addr),
                           scan->keepalive_fails, KEEPALIVE_MAX_FAILS);

                if ( scan->keepalive_fails >= KEEPALIVE_MAX_FAILS ) {
                    traceEvent(TRACE_NORMAL, "Keepalive: peer %s unreachable, moving to pending for re-punch",
                               macaddr_str(mac_tmp, scan->mac_addr));
                    /* Remove from known_peers */
                    if ( prev ) prev->next = next;
                    else eee->known_peers = next;
                    /* Move to pending_peers and re-punch instead of freeing,
                     * so supernode PEER_INFO can trigger reconnect even if
                     * the peer's address hasn't changed. */
                    scan->next             = eee->pending_peers;
                    eee->pending_peers     = scan;
                    scan->punch_start_time = 0;
                    scan->punch_failed     = 0;
                    scan->keepalive_fails  = 0;
                    scan->last_probe_sent  = 0;
                    scan->lan_punch_start  = 0;
                    scan->lan_punch_done   = 0;
                    send_query_peer(eee, scan->mac_addr);
                    start_punch(eee, scan);
                    scan = next;
                    continue;
                }
            }
        }

        prev = scan;
        scan = next;
    }
}

/** Update the last_seen time for this peer, or get registered. */
void check_peer( n2n_edge_t * eee,
                 uint8_t from_supernode,
                 const n2n_mac_t mac,
                 const n2n_sock_t * peer,
                 const char * version,
                 const char * os_name );
void try_send_register( n2n_edge_t * eee,
                        uint8_t from_supernode,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer );
void try_send_register_lan( n2n_edge_t * eee,
                        uint8_t from_supernode,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer,
                        const n2n_sock_t * local_sock );
void set_peer_operational( n2n_edge_t * eee,
                           const n2n_mac_t mac,
                           const n2n_sock_t * peer );



/** Start the registration process.
 *
 *  If the peer is already in pending_peers, ignore the request.
 *  If not in pending_peers, add it and send a REGISTER.
 *
 *  If hdr is for a direct peer-to-peer packet, try to register back to sender
 *  even if the MAC is in pending_peers. This is because an incident direct
 *  packet indicates that peer-to-peer exchange should work so more aggressive
 *  registration can be permitted (once per incoming packet) as this should only
 *  last for a small number of packets..
 *
 *  Called from the main loop when Rx a packet for our device mac.
 */
void try_send_register( n2n_edge_t * eee,
                        uint8_t from_supernode,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer )
{
    struct peer_info * scan = find_peer_by_mac( eee->pending_peers, mac );

    if ( NULL == scan ) {
        macstr_t mac_buf;
        n2n_sock_str_t sockbuf;

        scan = (struct peer_info*) calloc( 1, sizeof( struct peer_info ) );
        if (!scan) {
            traceEvent( TRACE_ERROR, "Unable to allocate memory for peer_info");
            return;
        }

        memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
        scan->sock = *peer;
        scan->last_seen = n2n_now();
        scan->punch_start_time = 0;
        scan->punch_failed = 0;

        strncpy(scan->version, n2n_sw_version, sizeof(scan->version) - 1);
        strncpy(scan->os_name, n2n_sw_osName, sizeof(scan->os_name) - 1);

        peer_list_add( &(eee->pending_peers), scan );

        /* Send REGISTER directly to peer (punch hole) and also via supernode */
        if ( from_supernode ) {
            send_register(eee, &(scan->sock) );
            send_register(eee, &(eee->supernode) );
        } else {
            send_register(eee, &(scan->sock) );
        }

        /* Start parallel hole-punch if different public IP */
        start_punch(eee, scan);

    } else {
        /* Already pending: update address if changed, reset and re-punch */
        if ( sock_equal(&scan->sock, peer) != 0 ) {
            scan->sock = *peer;
            scan->num_sockets = 1;
            scan->sockets[0] = *peer;
            scan->punch_start_time = 0;
            scan->punch_failed = 0;
            scan->lan_punch_start = 0;
            scan->lan_punch_done = 0;
            send_register(eee, peer);
            send_register(eee, &(eee->supernode));
            start_punch(eee, scan);
        } else if ( scan->punch_start_time == 0 && !scan->punch_failed ) {
            start_punch(eee, scan);
        }
    }
}

/** Like try_send_register but tries LAN address first; WAN punch deferred
 *  until LAN times out (handled in check_punch_timeouts). */
void try_send_register_lan( n2n_edge_t * eee,
                        uint8_t from_supernode,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer,
                        const n2n_sock_t * local_sock )
{
    struct peer_info * scan = find_peer_by_mac( eee->pending_peers, mac );

    if ( NULL == scan ) {
        scan = (struct peer_info*) calloc( 1, sizeof( struct peer_info ) );
        if (!scan) return;

        memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
        scan->sock         = *peer;
        scan->num_sockets  = 2;
        scan->sockets[0]   = *peer;
        scan->sockets[1]   = *local_sock;
        scan->last_seen    = n2n_now();
        scan->lan_punch_start = n2n_now();
        scan->lan_punch_done  = 0;

        peer_list_add( &(eee->pending_peers), scan );
    } else {
        scan->sock        = *peer;
        scan->num_sockets = 2;
        scan->sockets[0]  = *peer;
        scan->sockets[1]  = *local_sock;
        scan->lan_punch_start = n2n_now();
        scan->lan_punch_done  = 0;
        scan->punch_start_time = 0;
        scan->punch_failed = 0;
    }

    /* Send REGISTER only to LAN address first */
    send_register(eee, local_sock);
    {
        MACSTR_TMP(mac_tmp);
        traceEvent(TRACE_INFO, "LAN punch started for %s", macaddr_str(mac_tmp, mac));
    }
}

/** Update the last_seen time for this peer, or get registered. */
void check_peer( n2n_edge_t * eee,
                 uint8_t from_supernode,
                 const n2n_mac_t mac,
                 const n2n_sock_t * peer,
                 const char * version,
                 const char * os_name )
{
    struct peer_info * scan = find_peer_by_mac( eee->known_peers, mac );

    if ( NULL == scan ) {
        /* Create new peer entry with version/OS info */
        scan = (struct peer_info*) calloc( 1, sizeof( struct peer_info ) );
        if ( NULL == scan ) {
            traceEvent( TRACE_ERROR, "check_peer calloc failed" );
            return;
        }
        memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
        scan->sock = *peer;
        scan->assigned_ip = 0;
        strncpy(scan->version, version ? version : "unknown", sizeof(scan->version) - 1);
        strncpy(scan->os_name, os_name ? os_name : "unknown", sizeof(scan->os_name) - 1);
        peer_list_add( &(eee->known_peers), scan );
    } else {
        /* Update existing peer */
        update_peer_address( eee, from_supernode, mac, peer, n2n_now() );
    }
}


/* Move the peer from the pending_peers list to the known_peers lists.
 *
 * peer must be a pointer to an element of the pending_peers list.
 *
 * Called by main loop when Rx a REGISTER_ACK.
 */
void set_peer_operational( n2n_edge_t * eee,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer )
{
    struct peer_info * prev = NULL;
    struct peer_info * scan;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    traceEvent( TRACE_INFO, "set_peer_operational: %s -> %s",
                macaddr_str( mac_buf, mac),
                sock_to_cstr( sockbuf, peer ) );

    scan=eee->pending_peers;

    while ( NULL != scan ) {
        if ( 0 == memcmp( scan->mac_addr, mac, N2N_MAC_SIZE ) ) {
            break; /* found. */
        }

        prev = scan;
        scan = scan->next;
    }

    if ( scan ) {
        /* Remove scan from pending_peers. */
        if ( prev ) {
            prev->next = scan->next;
        } else {
            eee->pending_peers = scan->next;
        }

        /* Add scan to known_peers. */
        scan->next = eee->known_peers;
        eee->known_peers = scan;

        scan->sock = *peer;
        /* If peer connected via IPv6, record it in sock6.
         * If IPv4, sock6 may already be set from PEER_INFO (stored in try_send_register). */
        if (peer->family == AF_INET6)
            scan->sock6 = *peer;
        scan->last_seen = n2n_now();
        scan->punch_start_time = 0;  /* stop punch activity */
        scan->punch_failed = 0;

        traceEvent( TRACE_NORMAL, "P2P established with %s at %s",
                    macaddr_str( mac_buf, scan->mac_addr),
                    sock_to_cstr( sockbuf, &(scan->sock) ) );

        /* Send REGISTER back to confirm our new address to the peer */
        send_register( eee, &(scan->sock) );

        /* Send unicast gratuitous ARP to the newly established peer so it
         * updates its ARP table with our MAC, allowing ping immediately. */
        {
            uint8_t arp[42];
            memset(arp, 0, sizeof(arp));
            memcpy(arp,   scan->mac_addr, 6);              /* dst: peer's MAC */
            memcpy(arp+6, eee->device.mac_addr, 6);        /* src: our MAC */
            arp[12] = 0x08; arp[13] = 0x06;               /* ARP */
            arp[14] = 0x00; arp[15] = 0x01;               /* Ethernet */
            arp[16] = 0x08; arp[17] = 0x00;               /* IPv4 */
            arp[18] = 6;    arp[19] = 4;
            arp[20] = 0x00; arp[21] = 0x01;               /* Request */
            memcpy(arp+22, eee->device.mac_addr, 6);       /* sender MAC */
            memcpy(arp+28, &eee->device.ip_addr, 4);       /* sender IP */
            memcpy(arp+32, scan->mac_addr, 6);             /* target MAC: peer */
            memcpy(arp+38, &eee->device.ip_addr, 4);       /* target IP = our IP */
            tuntap_write(&eee->device, arp, sizeof(arp));
        }

        traceEvent( TRACE_INFO, "Pending peers list size=%u",
                    (unsigned int)peer_list_size( eee->pending_peers ) );

        traceEvent( TRACE_INFO, "Operational peers list size=%u",
                    (unsigned int)peer_list_size( eee->known_peers ) );

    } else {
        traceEvent( TRACE_DEBUG, "Failed to find sender in pending_peers." );
    }
}

n2n_mac_t broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static int is_empty_ip_address( const n2n_sock_t * sock )
{
    const uint8_t * ptr=NULL;
    size_t len=0;
    size_t i;

    if ( AF_INET6 == sock->family )
    {
        ptr = sock->addr.v6;
        len = 16;
    }
    else
    {
        ptr = sock->addr.v4;
        len = 4;
    }

    for (i=0; i<len; ++i)
    {
        if ( 0 != ptr[i] )
        {
            /* found a non-zero byte in address */
            return 0;
        }
    }

    return 1;
}

/** Keep the known_peers list straight.
 *
 *  Ignore broadcast L2 packets, and packets with invalid public_ip.
 *  If the dst_mac is in known_peers make sure the entry is correct:
 *  - if the public_ip socket has changed, erase the entry
 *  - if the same, update its last_seen = when
 */
static void update_peer_address(n2n_edge_t * eee,
                                uint8_t from_supernode,
                                const n2n_mac_t mac,
                                const n2n_sock_t * peer,
                                time_t when)
{
    struct peer_info *scan = eee->known_peers;
    struct peer_info *prev = NULL; /* use to remove bad registrations. */
    n2n_sock_str_t sockbuf1;
    n2n_sock_str_t sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t mac_buf;

    if ( is_empty_ip_address( peer ) )
    {
        /* Not to be registered. */
        return;
    }

    if ( 0 == memcmp( mac, broadcast_mac, N2N_MAC_SIZE ) )
    {
        /* Not to be registered. */
        return;
    }


    while(scan != NULL)
    {
        if(memcmp(mac, scan->mac_addr, N2N_MAC_SIZE) == 0)
        {
            break;
        }

        prev = scan;
        scan = scan->next;
    }

    if ( NULL == scan )
    {
        /* Not in known_peers. */
        return;
    }

    if (scan->version[0] == '\0') {
        strncpy(scan->version, "unknown", sizeof(scan->version) - 1);
    }
    if (scan->os_name[0] == '\0') {
        strncpy(scan->os_name, "unknown", sizeof(scan->os_name) - 1);
    }

    if ( 0 != sock_equal( &(scan->sock), peer))
    {
        if ( 0 == from_supernode )
        {
            /* Peer address changed but P2P is established: update in-place, no re-punch. */
            traceEvent( TRACE_INFO, "Peer addr updated %s: %s -> %s",
                        macaddr_str( mac_buf, scan->mac_addr ),
                        sock_to_cstr(sockbuf1, &(scan->sock)),
                        sock_to_cstr(sockbuf2, peer) );
            scan->sock = *peer;
            scan->last_seen = when;
        }
        else
        {
            /* Don't worry about what the supernode reports, it could be seeing a different socket. */
        }
    }
    else
    {
        /* Found and unchanged. */
        scan->last_seen = when;
    }
}

/** @brief Check to see if we should re-register with the supernode.
 *
 *  This is frequently called by the main loop.
 */
static void update_supernode_reg( n2n_edge_t * eee, time_t nowTime )
{
    if ( nowTime > (time_t) (eee->last_register_req + 30) )
    {
        eee->sn_wait = 0;
        eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
        send_register_super( eee, &(eee->supernode) );
        eee->sn_wait = 1;
        eee->last_register_req = nowTime;
        return;
    }

    if ( eee->sn_wait && ( nowTime > (time_t) (eee->last_register_req + (eee->register_lifetime/10) ) ) )
    {
        /* fall through - fast retry */
    }
    else if ( nowTime < (time_t) (eee->last_register_req + eee->register_lifetime))
    {
        return; /* Too early */
    }

    if ( 0 == eee->sup_attempts )
    {
        ++(eee->sn_idx);
        if (eee->sn_idx >= eee->sn_num) eee->sn_idx=0;
        traceEvent(TRACE_WARNING, "Supernode not responding - moving to %u of %u",
                   (unsigned int)eee->sn_idx, (unsigned int)eee->sn_num);
        eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
    }
    else
    {
        --(eee->sup_attempts);
    }

    if(eee->re_resolve_supernode_ip)
    {
        supernode2addr(&(eee->supernode), eee->sn_af, eee->sn_ip_array[eee->sn_idx]);
        memset(&eee->supernode_alt, 0, sizeof(n2n_sock_t));
        {
            int alt_af = (eee->supernode.family == AF_INET6) ? AF_INET : AF_INET6;
            if (supernode2addr(&eee->supernode_alt, alt_af, eee->sn_ip_array[eee->sn_idx]) != 0)
                memset(&eee->supernode_alt, 0, sizeof(n2n_sock_t));
        }
    }

    send_register_super( eee, &(eee->supernode) );
    eee->sn_wait=1;
    eee->last_register_req = nowTime;
}

/* @return 1 if destination is a peer, 0 if destination is supernode */
static int find_peer_destination(n2n_edge_t * eee,
                                 n2n_mac_t mac_address,
                                 n2n_sock_t * destination)
{
    const struct peer_info *scan = eee->known_peers;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    time_t now = n2n_now();
    int retval=0;

    traceEvent(TRACE_DEBUG, "Searching destination peer for MAC %02X:%02X:%02X:%02X:%02X:%02X",
               mac_address[0] & 0xFF, mac_address[1] & 0xFF, mac_address[2] & 0xFF,
               mac_address[3] & 0xFF, mac_address[4] & 0xFF, mac_address[5] & 0xFF);

    while(scan != NULL) {
        traceEvent(TRACE_DEBUG, "Evaluating peer [MAC=%02X:%02X:%02X:%02X:%02X:%02X]",
                   scan->mac_addr[0] & 0xFF, scan->mac_addr[1] & 0xFF, scan->mac_addr[2] & 0xFF,
                   scan->mac_addr[3] & 0xFF, scan->mac_addr[4] & 0xFF, scan->mac_addr[5] & 0xFF
            );

        if((scan->last_seen > 0) &&
           !scan->punch_failed &&
           (memcmp(mac_address, scan->mac_addr, N2N_MAC_SIZE) == 0))
        {
            /* If keepalive probe is pending but peer was recently active, still use direct */
            if (scan->last_probe_sent > 0 && (now - scan->last_seen) > KEEPALIVE_TIMEOUT_SECONDS) {
                break; /* retval stays 0, use supernode as fallback */
            }
            /* Prefer IPv6 direct if peer has IPv6 and we have IPv6 socket */
            if (scan->sock6.family == AF_INET6 && eee->udp_sock6 != -1)
                memcpy(destination, &scan->sock6, sizeof(n2n_sock_t));
            else
                memcpy(destination, &scan->sock, sizeof(n2n_sock_t));
            retval=1;
            break;
        }
        scan = scan->next;
    }

    if ( 0 == retval )
    {
        memcpy(destination, &(eee->supernode), sizeof(n2n_sock_t));
    }

    traceEvent(TRACE_DEBUG, "find_peer_address (%s) -> %s",
               macaddr_str( mac_buf, mac_address ),
               sock_to_cstr( sockbuf, destination ) );

    return retval;
}

/* *********************************************** */

static const struct option long_options[] = {
  { "community",       required_argument, NULL, 'c' },
  { "supernode-list",  required_argument, NULL, 'l' },
  { "tun-device",      required_argument, NULL, 'd' },
  { "euid",            required_argument, NULL, 'u' },
  { "egid",            required_argument, NULL, 'g' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { NULL,              0,                 NULL,  0  }
};

/* ***************************************************** */

/** Send an ecapsulated ethernet PACKET to a destination edge or broadcast MAC
 *  address. */
static int send_PACKET( n2n_edge_t * eee,
                        n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktlen )
{
    int dest;
    n2n_sock_str_t sockbuf;
    n2n_sock_t destination;

    /* hexdump( pktbuf, pktlen ); */

    PEERS_LOCK(eee);
    dest = find_peer_destination(eee, dstMac, &destination);
    if ( dest )
        ++(eee->tx_p2p);
    else
        ++(eee->tx_sup);
    PEERS_UNLOCK(eee);

    traceEvent( TRACE_INFO, "send_PACKET to %s", sock_to_cstr( sockbuf, &destination ) );

    sendto_sock( sock_for_dest(eee, &destination), pktbuf, pktlen, &destination );

    /* If routing via supernode for a unicast peer, re-register with supernode
     * and query peer's latest address - triggers full reconnect like a restart. */
    if ( !dest && !is_multi_broadcast(dstMac) )
    {
        time_t now = n2n_now();
        PEERS_LOCK(eee);
        struct peer_info *p = find_peer_by_mac(eee->pending_peers, dstMac);
        if ( !p ) p = find_peer_by_mac(eee->known_peers, dstMac);
        int do_query = (!p || (now - p->last_query_sent) >= 5);
        if (p) p->last_query_sent = now;
        PEERS_UNLOCK(eee);

        if (do_query) {
            update_supernode_reg(eee, now);
            send_query_peer(eee, dstMac);
        }
    }

    return 0;
}

/* Choose the transop for Tx. This should be based on the newest valid
 * cipherspec in the key schedule.
 *
 * Never fall back to NULL tranform unless no key sources were specified. It is
 * better to render edge inoperative than to expose user data in the clear. In
 * the case where all SAs are expired an arbitrary transform will be chosen for
 * Tx. It will fail having no valid SAs but one must be selected.
 */
static size_t edge_choose_tx_transop( const n2n_edge_t * eee )
{
    if ( eee->null_transop) {
        return N2N_TRANSOP_NULL_IDX;
    }

    if (eee->tx_transop_idx == N2N_TRANSOP_SPECK_IDX) {
        return N2N_TRANSOP_SPECK_IDX;
    }

    return eee->tx_transop_idx;
}

/** A layer-2 packet was received at the tunnel and needs to be sent via UDP. */
static void send_packet2net(n2n_edge_t * eee,
                            uint8_t *tap_pkt, size_t len)
{
    ipstr_t ip_buf;
    n2n_mac_t destMac;

    n2n_common_t cmn;
    n2n_PACKET_t pkt;

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx=0;
    size_t tx_transop_idx=0;

    ether_hdr_t eh;

    /* tap_pkt is not aligned so we have to copy to aligned memory */
    memcpy( &eh, tap_pkt, sizeof(ether_hdr_t) );

    /* Discard IP packets that are not originated by this hosts */
    if(!(eee->allow_routing)) {
        if(htons(0x0800) == eh.type) {
            /* This is an IP packet from the local source address - not forwarded. */
#define ETH_FRAMESIZE 14
#define IP4_SRCOFFSET 12
            uint32_t *dst = (uint32_t*)&tap_pkt[ETH_FRAMESIZE + IP4_SRCOFFSET];

            /* Note: all elements of the_ip are in network order */
            if( *dst != eee->device.ip_addr) {
                /* This is a packet that needs to be routed */
                traceEvent(TRACE_INFO, "Discarding routed packet [%s]",
                           inet_ntop(AF_INET, dst, ip_buf, sizeof(ip_buf)));
                return;
            } else {
                /* This packet is originated by us */
                /* traceEvent(TRACE_INFO, "Sending non-routed packet"); */
            }
        } else if(htons(0x86dd) == eh.type) {
            /* IPv6 package */
#define IP6_SRCOFFSET 8
            struct in6_addr* dst = (struct in6_addr *)&tap_pkt[ETH_FRAMESIZE + IP6_SRCOFFSET];
            if( memcmp(dst, &eee->device.ip6_addr, IPV6_SIZE ) != 0 ) {
                traceEvent(TRACE_INFO, "Discarding routed packet [%s]",
                           inet_ntop(AF_INET6, dst, ip_buf, sizeof(ip_buf)));
                return;
            } else {

            }
        }
    }

    /* Optionally compress then apply transforms, eg encryption. */

    /* Once processed, send to destination in PACKET */

    memcpy( destMac, tap_pkt, N2N_MAC_SIZE ); /* dest MAC is first in ethernet header */

    memset( &cmn, 0, sizeof(cmn) );
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_packet;
    cmn.flags=0; /* no options, not from supernode, no socket */
    memcpy( cmn.community, eee->community_name, N2N_COMMUNITY_SIZE );

    memset( &pkt, 0, sizeof(pkt) );
    memcpy( pkt.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy( pkt.dstMac, destMac, N2N_MAC_SIZE);

    tx_transop_idx = edge_choose_tx_transop( eee );

    pkt.sock.family=0; /* do not encode sock */
    pkt.transform = eee->transop[tx_transop_idx].transform_id;

    idx=0;
    encode_PACKET( pktbuf, &idx, &cmn, &pkt );
    traceEvent( TRACE_DEBUG, "encoded PACKET header of size=%u transform %u (idx=%u)",
                (unsigned int)idx, (unsigned int)pkt.transform, (unsigned int)tx_transop_idx );

    idx += eee->transop[tx_transop_idx].fwd( &(eee->transop[tx_transop_idx]),
                                             pktbuf+idx, N2N_PKT_BUF_SIZE-idx,
                                             tap_pkt, len, destMac );
    ++(eee->transop[tx_transop_idx].tx_cnt); /* stats */

    send_PACKET( eee, destMac, pktbuf, idx ); /* to peer or supernode */
}

/** Destination MAC 33:33:0:00:00:00 - 33:33:FF:FF:FF:FF is reserved for IPv6
 *  neighbour discovery.
 */
static int is_ip6_discovery( const void * buf, size_t bufsize )
{
    int retval = 0;

    if ( bufsize >= sizeof(ether_hdr_t) )
    {
        /* copy to aligned memory */
        ether_hdr_t eh;
        memcpy( &eh, buf, sizeof(ether_hdr_t) );

        if ( (0x33 == eh.dhost[0]) &&
             (0x33 == eh.dhost[1]) )
        {
            retval = 1; /* This is an IPv6 multicast packet [RFC2464]. */
        }
    }
    return retval;
}

/** Destination 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF is multicast ethernet.
 */
static int is_ethMulticast( const void * buf, size_t bufsize )
{
    int retval = 0;

    /* Match 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF */
    if ( bufsize >= sizeof(ether_hdr_t) )
    {
        /* copy to aligned memory */
        ether_hdr_t eh;
        memcpy( &eh, buf, sizeof(ether_hdr_t) );

        if ( (0x01 == eh.dhost[0]) &&
             (0x00 == eh.dhost[1]) &&
             (0x5E == eh.dhost[2]) &&
             (0 == (0x80 & eh.dhost[3])) )
        {
            retval = 1; /* This is an ethernet multicast packet [RFC1112]. */
        }
    }
    return retval;
}

/** Read a single packet from the TAP interface, process it and write out the
 *  corresponding packet to the cooked socket.
 */
static void readFromTAPSocket( n2n_edge_t * eee )
{
    /* tun -> remote */
    uint8_t             eth_pkt[N2N_PKT_BUF_SIZE];
    macstr_t            mac_buf;
    ssize_t             len;
retry:
    len = tuntap_read( &(eee->device), eth_pkt, N2N_PKT_BUF_SIZE );

    if( (len <= 0) || (len > N2N_PKT_BUF_SIZE) )
    {
#ifdef _WIN32
        DWORD err = GetLastError();
        W32_ERROR(err, error);
        traceEvent(TRACE_WARNING, "read()=%d [%d/%ls]", (signed int)len, err, error);
        W32_ERROR_FREE(error);
        if (ERROR_OPERATION_ABORTED == err) {
retry2:
            traceEvent(TRACE_NORMAL, "Restart TAP device");
            if (tuntap_restart( &eee->device ) < 0) {
                Sleep(2000);
                goto retry2;
            }
            goto retry;
        }
#else
        traceEvent(TRACE_WARNING, "read()=%d [%d/%s]", (signed int)len, errno, strerror(errno));
#endif
    }
    else
    {
        const uint8_t * mac = eth_pkt;
        traceEvent(TRACE_INFO, "### Rx TAP packet (%4d) for %s",
                   (signed int)len, macaddr_str(mac_buf, mac) );

        /* don't filter ip6_discovery this is needed for ip6 connectivity */
        if ( eee->drop_multicast && (
             is_ethMulticast( eth_pkt, len) /* || is_ip6_discovery( eth_pkt, len ) */
            ) )
        {
            traceEvent(TRACE_DEBUG, "Dropping multicast");
        }
        else
        {
            send_packet2net(eee, eth_pkt, len);
        }
    }
}

/** A PACKET has arrived containing an encapsulated ethernet datagram - usually
 *  encrypted. */
static int handle_PACKET( n2n_edge_t * eee,
                          const n2n_common_t * cmn,
                          const n2n_PACKET_t * pkt,
                          const n2n_sock_t * orig_sender,
                          uint8_t * payload,
                          size_t psize )
{
    ssize_t             data_sent_len;
    uint8_t             from_supernode;
    uint8_t *           eth_payload=NULL;
    int                 retval = -1;
    time_t              now;

    now = n2n_now();

    traceEvent( TRACE_DEBUG, "handle_PACKET size %u transform %u",
                (unsigned int)psize, (unsigned int)pkt->transform );
    /* hexdump( payload, psize ); */

    from_supernode= cmn->flags & N2N_FLAGS_FROM_SUPERNODE;

    if ( from_supernode )
    {
        ++(eee->rx_sup);
        eee->last_sup=now;
    }
    else
    {
        ++(eee->rx_p2p);
        eee->last_p2p=now;
    }

    /* Update the sender in peer table entry */
    PEERS_LOCK(eee);
    struct peer_info *scan = find_peer_by_mac(eee->known_peers, pkt->srcMac);
    if (NULL == scan) {
        try_send_register(eee, from_supernode, pkt->srcMac, orig_sender);
    } else if (!from_supernode) {
        /* P2P packet from known peer: only update address if it changed */
        if (0 != sock_equal(&scan->sock, orig_sender)) {
            update_peer_address(eee, from_supernode, pkt->srcMac, orig_sender, now);
        } else {
            scan->last_seen = now;
        }
    } else {
        update_peer_address(eee, from_supernode, pkt->srcMac, orig_sender, now);
    }
    PEERS_UNLOCK(eee);

    /* Handle transform. */
    {
        uint8_t decodebuf[N2N_PKT_BUF_SIZE];
        size_t eth_size;
        int rx_transop_idx=0;

        rx_transop_idx = transop_enum_to_index(pkt->transform);

        if ( rx_transop_idx >= 0 )
        {
            eth_payload = decodebuf;
            eth_size = eee->transop[rx_transop_idx].rev( &(eee->transop[rx_transop_idx]),
                                                         eth_payload, N2N_PKT_BUF_SIZE,
                                                         payload, psize, pkt->srcMac );
            ++(eee->transop[rx_transop_idx].rx_cnt); /* stats */

            /* Write ethernet packet to tap device. */
            traceEvent( TRACE_INFO, "sending to TAP %u", (unsigned int)eth_size );

            /* Extract sender's virtual IP from first packet if not yet known */
            if ( eth_size >= 34 ) {
                uint16_t ethertype = (eth_payload[12] << 8) | eth_payload[13];
                uint32_t src_ip = 0;
                struct peer_info *sp;
                if ( ethertype == 0x0800 && eth_size >= 34 ) {
                    memcpy(&src_ip, eth_payload + 26, 4);
                } else if ( ethertype == 0x0806 && eth_size >= 42 ) {
                    memcpy(&src_ip, eth_payload + 28, 4);
                }
                if ( src_ip != 0 ) {
                    PEERS_LOCK(eee);
                    sp = find_peer_by_mac(eee->known_peers, pkt->srcMac);
                    if ( !sp ) sp = find_peer_by_mac(eee->pending_peers, pkt->srcMac);
                    if ( sp && sp->assigned_ip == 0 )
                        sp->assigned_ip = ntohl(src_ip);
                    PEERS_UNLOCK(eee);
                }
            }

            data_sent_len = tuntap_write(&(eee->device), eth_payload, eth_size);

            if (data_sent_len == eth_size)
            {
                retval = 0;
            }
        }
        else
        {
            traceEvent( TRACE_ERROR, "handle_PACKET dropped unknown transform enum %u",
                        (unsigned int)pkt->transform );
        }
    }

    return retval;
}

/** Read a datagram from the management UDP socket and take appropriate
 *  action. */
static void readFromMgmtSocket(n2n_edge_t *eee, int *keep_running) {
    uint8_t udp_buf[N2N_PKT_BUF_SIZE];      /* Complete UDP packet */
    ssize_t recvlen;
    _unused_ ssize_t sendlen;
#ifdef _WIN32
    struct sockaddr_storage sender_sock;
#else
    struct sockaddr_un sender_sock;
#endif
    socklen_t i;
    size_t msg_len;
    time_t now;

    now = n2n_now();
    i = sizeof(sender_sock);
    recvlen = recvfrom(eee->mgmt_sock, udp_buf, N2N_PKT_BUF_SIZE, 0/*flags*/,
                      (struct sockaddr*) &sender_sock, &i);
    if (i > 0) {
#ifndef _WIN32
        if (((struct sockaddr*) &sender_sock)->sa_family == AF_UNIX) {
            traceEvent( TRACE_INFO, "mgmt pkg from %s", ((struct sockaddr_un*) &sender_sock)->sun_path );
        } else {
#endif
            {
                char tmp[INET6_ADDRSTRLEN] = "unknown";
                if (((struct sockaddr*)&sender_sock)->sa_family == AF_INET)
                    inet_ntop(AF_INET, &((struct sockaddr_in*)&sender_sock)->sin_addr, tmp, sizeof(tmp));
                else if (((struct sockaddr*)&sender_sock)->sa_family == AF_INET6)
                    inet_ntop(AF_INET6, &((struct sockaddr_in6*)&sender_sock)->sin6_addr, tmp, sizeof(tmp));
                traceEvent( TRACE_INFO, "mgmt pkg from %s", tmp);
            }
#ifndef _WIN32
        }
#endif
    }
    if (recvlen < 0) {
#ifdef _WIN32
        W32_ERROR(WSAGetLastError(), c)
        traceEvent( TRACE_ERROR, "mgmt recvfrom failed with %ls", c );
        W32_ERROR_FREE(c)
#else
        traceEvent(TRACE_ERROR, "mgmt recvfrom failed with %s", strerror(errno));
#endif
        return; /* failed to receive data from UDP */
    }

    /* Handle commands */
    if (recvlen >= 4) {
        if (0 == memcmp(udp_buf, "stop", 4)) {
            traceEvent(TRACE_ERROR, "stop command received.");
            *keep_running = 0;
            return;
        }

        if (0 == memcmp(udp_buf, "help", 4)) {
            msg_len = 0;
            msg_len += snprintf((char*)(udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "Help for edge management console:\n"
                                "  stop    Gracefully exit edge\n"
                                "  help    This help message\n"
                                "  +verb   Increase verbosity of logging\n"
                                "  -verb   Decrease verbosity of logging\n"
                                "  <enter> Display statistics\n\n");
            sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
                   (struct sockaddr*) &sender_sock, i);
            return;
        }
    }

    if (recvlen >= 5) {
        if (0 == memcmp(udp_buf, "+verb", 5)) {
            msg_len = 0;
            ++traceLevel;
            traceEvent(TRACE_ERROR, "+verb traceLevel=%d", traceLevel);
            msg_len += snprintf((char*) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "> +OK traceLevel=%d\n", traceLevel);
            sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
                   (struct sockaddr*) &sender_sock, i);
            return;
        }

        if (0 == memcmp(udp_buf, "-verb", 5)) {
            msg_len = 0;
            if (traceLevel > 0) {
                --traceLevel;
                msg_len += snprintf((char*) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "> -OK traceLevel=%d\n", traceLevel);
            } else {
                msg_len += snprintf((char*) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "> -NOK traceLevel=%d\n", traceLevel);
            }
            traceEvent(TRACE_ERROR, "-verb traceLevel=%d", traceLevel);
            sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
                   (struct sockaddr*) &sender_sock, i);
            return;
        }
    }

    traceEvent(TRACE_DEBUG, "mgmt status rq");

    /* Send community info */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       "community: %s\n", eee->community_name);
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    /* Send header */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       " id  mac                virt_ip          wan_ip                                            ver      os\n");
    msg_len += snprintf((char*) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "---n2n6----------------------------------------------------------------------------------------------------\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    /* Send PsP_with section */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE, "PsP_with:\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    macstr_t mac;
    n2n_sock_str_t sockaddr;
    struct peer_info* peer = eee->pending_peers;
    int id = 1;
    while(peer) {
        /* Skip if same virtual IP as local edge */
        if (peer->assigned_ip == ntohl(eee->device.ip_addr)) {
            peer = peer->next;
            continue;
        }
        sock_to_cstr(sockaddr, &peer->sock);
        const char *version = (peer->version[0] != '\0') ? peer->version : "unknown";
        const char *os_name = (peer->os_name[0] != '\0') ? peer->os_name : "unknown";

        /* Format virtual IP */
        char virt_ip[16] = "-";
        if (peer->assigned_ip != 0) {
            struct in_addr addr;
            addr.s_addr = htonl(peer->assigned_ip);
            inet_ntop(AF_INET, &addr, virt_ip, sizeof(virt_ip));
        }

        msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                           " %2u  %-17s  %-15s  %-48s  %-7s  %s\n",
                           id++,
                           macaddr_str(mac, peer->mac_addr),
                           virt_ip,
                           sock_to_cstr(sockaddr, &peer->sock),
                           version,
                           os_name);
        sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
               (struct sockaddr*) &sender_sock, i);
        peer = peer->next;
    }

    /* Send P2P_with section */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE, "P2P_with:\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    peer = eee->known_peers;
    id = 1;
    while(peer) {
        /* Skip if same virtual IP as local edge */
        if (peer->assigned_ip == ntohl(eee->device.ip_addr)) {
            peer = peer->next;
            continue;
        }
        sock_to_cstr(sockaddr, &peer->sock);
        const char *version = (peer->version[0] != '\0') ? peer->version : "unknown";
        const char *os_name = (peer->os_name[0] != '\0') ? peer->os_name : "unknown";

        /* Format virtual IP */
        char virt_ip[16] = "-";
        if (peer->assigned_ip != 0) {
            struct in_addr addr;
            addr.s_addr = htonl(peer->assigned_ip);
            inet_ntop(AF_INET, &addr, virt_ip, sizeof(virt_ip));
        }

        msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                           " %2u  %-17s  %-15s  %-48s  %-7s  %s\n",
                           id++,
                           macaddr_str(mac, peer->mac_addr),
                           virt_ip,
                           sock_to_cstr(sockaddr, &peer->sock),
                           version,
                           os_name);
        sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
               (struct sockaddr*) &sender_sock, i);
        peer = peer->next;
    }

    /* Send supernode info */
    const char *sn_support = (eee->supernode.family == AF_INET6) ? "IPv6" : "IPv4";

    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE, "Supernodes\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       "  l* |  %s | v%s | %s\n",
                       eee->sn_ip_array[eee->sn_idx],
                       eee->supernode_version,
                       sn_support);
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    /* Send statistics */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       "----------------------------------------------------------------------------------------------------n2n6---\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    time_t uptime = now - eee->start_time;
    int days = uptime / 86400;
    int hours = (uptime % 86400) / 3600;
    {
        char sup_str[32], p2p_str[32];
        if (eee->last_sup) snprintf(sup_str, sizeof(sup_str), "%lus ago", (unsigned long)(now - eee->last_sup));
        else strcpy(sup_str, "never");
        if (eee->last_p2p) snprintf(p2p_str, sizeof(p2p_str), "%lus ago", (unsigned long)(now - eee->last_p2p));
        else strcpy(p2p_str, "never");
        msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                           "uptime %d_%dh | pend/known_peers %u/%u | last_super/p2p %s/%s\n",
                           days, hours,
                           (unsigned int)peer_list_size(eee->pending_peers),
                           (unsigned int)peer_list_size(eee->known_peers),
                           sup_str, p2p_str);
    }
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       "transop %u,%u | super %u,%u | p2p %u,%u\n",
                       (unsigned int)eee->transop[N2N_TRANSOP_NULL_IDX].tx_cnt,
                       (unsigned int)eee->transop[N2N_TRANSOP_NULL_IDX].rx_cnt,
                       (unsigned int)eee->tx_sup,
                       (unsigned int)eee->rx_sup,
                       (unsigned int)eee->tx_p2p,
                       (unsigned int)eee->rx_p2p);
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       "\nType \"help\" to see more commands.\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);
}

/** Read a datagram from the main UDP socket to the internet. */
static void readFromIPSocket( n2n_edge_t * eee, SOCKET fd )
{
    n2n_common_t        cmn; /* common fields in the packet header */
    static int          first_ok_message_shown = 0;

    n2n_sock_str_t      sockbuf1;
    n2n_sock_str_t      sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t            mac_buf1;
    macstr_t            mac_buf2;

    uint8_t             udp_buf[N2N_PKT_BUF_SIZE];      /* Compete UDP packet */
    ssize_t             recvlen;
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    uint8_t             from_supernode;
    struct sockaddr_in6 sender_sock;
    n2n_sock_t          sender;
    n2n_sock_t *        orig_sender = NULL;
    time_t              now = 0;

    size_t              i;

    i = sizeof(sender_sock);
    recvlen = recvfrom(fd, udp_buf, N2N_PKT_BUF_SIZE, 0/*flags*/,
                      (struct sockaddr*) &sender_sock, (socklen_t*) &i);

    if ( recvlen < 0 )
    {
#ifdef _WIN32
        W32_ERROR(WSAGetLastError(), c)
        traceEvent( TRACE_ERROR, "recvfrom failed with %ls", c );
        W32_ERROR_FREE(c)
#else
        traceEvent(TRACE_ERROR, "recvfrom failed with %s", strerror(errno) );
#endif

        return; /* failed to receive data from UDP */
    }

    /* Determine sender address from socket family */
    sender.family = (uint8_t) sender_sock.sin6_family;
    if (AF_INET == sender.family) {
        struct sockaddr_in* sock = (struct sockaddr_in*) &sender_sock;
        sender.port = ntohs(sock->sin_port);
        memcpy( &(sender.addr.v4), &(sock->sin_addr), IPV4_SIZE );
    } else if (AF_INET6 == sender.family) {
        sender.port = ntohs(sender_sock.sin6_port);
        memcpy( &(sender.addr.v6), &(sender_sock.sin6_addr), IPV6_SIZE );
    }

    /* The packet may not have an orig_sender socket spec. So default to last
     * hop as sender. */
    orig_sender=&sender;

    traceEvent(TRACE_INFO, "### Rx N2N UDP (%d) from %s",
               (signed int) recvlen, sock_to_cstr(sockbuf1, &sender) );

    /* hexdump( udp_buf, recvlen ); */

    rem = recvlen; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */
    if ( decode_common(&cmn, udp_buf, &rem, &idx) < 0 )
    {
        traceEvent( TRACE_ERROR, "Failed to decode common section in N2N_UDP" );
        return; /* failed to decode packet */
    }

    now = n2n_now();

    msg_type = cmn.pc;
    from_supernode= cmn.flags & N2N_FLAGS_FROM_SUPERNODE;

    if( 0 == memcmp(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE) )
    {
        if( msg_type == MSG_TYPE_PACKET)
        {
            /* process PACKET - most frequent so first in list. */
            n2n_PACKET_t pkt;

            decode_PACKET( &pkt, &cmn, udp_buf, &rem, &idx );

            if ( pkt.sock.family )
            {
                orig_sender = &(pkt.sock);
            }

            traceEvent(TRACE_INFO, "Rx PACKET from %s (%s)",
                       sock_to_cstr(sockbuf1, &sender),
                       sock_to_cstr(sockbuf2, orig_sender) );

            handle_PACKET( eee, &cmn, &pkt, orig_sender, udp_buf + idx, recvlen - idx );
        }
        else if(msg_type == MSG_TYPE_REGISTER)
        {
            /* Another edge is registering with us */
            n2n_REGISTER_t reg;

            decode_REGISTER( &reg, &cmn, udp_buf, &rem, &idx );

            if ( reg.sock.family &&
                 eee->my_public_sock.family == AF_INET &&
                 sender.family == AF_INET &&
                 memcmp(eee->my_public_sock.addr.v4, sender.addr.v4, IPV4_SIZE) == 0 )
            {
                orig_sender = &(reg.sock);
            }

            traceEvent(TRACE_INFO, "Rx REGISTER src=%s dst=%s from peer %s (%s)",
                       macaddr_str( mac_buf1, reg.srcMac ),
                       macaddr_str( mac_buf2, reg.dstMac ),
                       sock_to_cstr(sockbuf1, &sender),
                       sock_to_cstr(sockbuf2, orig_sender) );

            if ( 0 == memcmp(reg.dstMac, (eee->device.mac_addr), 6) ||
                 0 == memcmp(reg.dstMac, "\x00\x00\x00\x00\x00\x00", 6) )
            {
                PEERS_LOCK(eee);
                struct peer_info *scan = find_peer_by_mac(eee->known_peers, reg.srcMac);
                if (NULL == scan) {
                    /* If reg.sock carries a LAN address and public IP matches, try LAN */
                    if ( reg.sock.family != 0 && reg.sock.port != 0 &&
                         eee->local_sock_ena &&
                         eee->my_public_sock.family == AF_INET &&
                         sender.family == AF_INET &&
                         memcmp(eee->my_public_sock.addr.v4, sender.addr.v4, IPV4_SIZE) == 0 )
                    {
                        /* Use sender's public port for LAN address */
                        n2n_sock_t lan_sock = reg.sock;
                        lan_sock.port = orig_sender->port;
                        traceEvent(TRACE_INFO, "Rx REGISTER with LAN addr %s - trying LAN direct",
                                   sock_to_cstr(sockbuf1, &lan_sock));
                        try_send_register_lan(eee, from_supernode, reg.srcMac, orig_sender, &lan_sock);
                    } else {
                        try_send_register(eee, from_supernode, reg.srcMac, orig_sender);
                    }
                } else {
                    /* A already in known_peers - check if address changed */
                    if ( 0 != sock_equal( &scan->sock, orig_sender ) ) {
                        /* Address changed: update and send REGISTER back so A can update us */
                        traceEvent(TRACE_INFO, "Peer %s addr changed, sending REGISTER back",
                                   macaddr_str(mac_buf1, reg.srcMac));
                        update_peer_address(eee, from_supernode, reg.srcMac, orig_sender, n2n_now());
                        /* Clear keepalive state so traffic flows directly to new address */
                        scan->last_probe_sent = 0;
                        scan->keepalive_fails = 0;
                        send_register(eee, orig_sender);

                        /* *** Move peer back to pending_peers for re-punch *** */
                        struct peer_info *prev = NULL, *curr = eee->known_peers;
                        while (curr && memcmp(curr->mac_addr, reg.srcMac, N2N_MAC_SIZE) != 0) {
                            prev = curr;
                            curr = curr->next;
                        }
                        if (curr) {
                            /* Remove from known_peers */
                            if (prev) prev->next = curr->next;
                            else eee->known_peers = curr->next;

                            /* Reset punch state */
                            curr->punch_start_time = 0;
                            curr->punch_failed = 0;
                            curr->lan_punch_start = 0;
                            curr->lan_punch_done = 0;

                            /* Add to pending_peers */
                            curr->next = eee->pending_peers;
                            eee->pending_peers = curr;

                            /* Start hole punching */
                            start_punch(eee, curr);

                            traceEvent(TRACE_INFO, "Moved peer %s back to pending for re-punch",
                                       macaddr_str(mac_buf1, reg.srcMac));
                        }
                    } else {
                        update_peer_address(eee, from_supernode, reg.srcMac, orig_sender, n2n_now());
                    }
                }
                PEERS_UNLOCK(eee);
            }

            send_register_ack(eee, orig_sender, &reg);
        }
        else if(msg_type == MSG_TYPE_REGISTER_ACK)
        {
            /* Peer edge is acknowledging our register request */
            n2n_REGISTER_ACK_t ra;

            decode_REGISTER_ACK( &ra, &cmn, udp_buf, &rem, &idx );

            if ( ra.sock.family )
            {
                orig_sender = &(ra.sock);
            }

            traceEvent(TRACE_INFO, "Rx REGISTER_ACK src=%s dst=%s from peer %s (%s)",
                       macaddr_str( mac_buf1, ra.srcMac ),
                       macaddr_str( mac_buf2, ra.dstMac ),
                       sock_to_cstr(sockbuf1, &sender),
                       sock_to_cstr(sockbuf2, orig_sender) );

            /* Move from pending_peers to known_peers; ignore if not in pending. */
            PEERS_LOCK(eee);
            if ( from_supernode ) {
                /* REGISTER_ACK relayed via supernode: direct path NOT verified.
                 * Do NOT move to known_peers. Keep in pending_peers so traffic uses
                 * supernode relay. Only promote to known_peers on a direct REGISTER_ACK. */
                struct peer_info *pscan = find_peer_by_mac(eee->pending_peers, ra.srcMac);
                if ( pscan )
                    pscan->last_seen = n2n_now(); /* keep alive in pending_peers */
                    traceEvent(TRACE_INFO, "REGISTER_ACK via supernode for %s - direct unverified, staying in pending",
                               macaddr_str(mac_buf1, ra.srcMac));
            } else {
                /* Direct REGISTER_ACK: sender is the real peer address. Direct path confirmed. */
                set_peer_operational( eee, ra.srcMac, &sender );
            }
            PEERS_UNLOCK(eee);
        }
        else if(msg_type == n2n_probe)
        {
            /* Another edge sent us a direct PROBE to open NAT mapping.
             * 1. Send PROBE_ACK via supernode so sender learns their public addr.
             * 2. Start reverse punch only if not already in progress/done. */
            n2n_PROBE_t probe;
            decode_PROBE(&probe, &cmn, udp_buf, &rem, &idx);

            traceEvent(TRACE_INFO, "Rx PROBE from %s at %s - sending PROBE_ACK",
                       macaddr_str(mac_buf1, probe.srcMac), sock_to_cstr(sockbuf1, &sender));

            /* Send PROBE_ACK via supernode: tell sender what addr we observed */
            send_probe_ack(eee, probe.srcMac, &sender);

            /* sender is the peer's real public address (direct UDP packet).
             * Update pending_peers sock so subsequent REGISTERs go directly. */
            PEERS_LOCK(eee);
            if ( NULL == find_peer_by_mac(eee->known_peers, probe.srcMac) ) {
                struct peer_info *pscan = find_peer_by_mac(eee->pending_peers, probe.srcMac);
                if ( NULL == pscan ) {
                    try_send_register(eee, 0, probe.srcMac, &sender);
                } else {
                    /* Update to real observed address and send REGISTER directly */
                    pscan->sock = sender;
                    send_register(eee, &sender);
                }
            }
            PEERS_UNLOCK(eee);
        }
        else if(msg_type == n2n_probe_ack)
        {
            /* Supernode forwarded a PROBE_ACK: we now know our real public addr
             * as observed by the remote peer. Update that peer's sock and retry REGISTER. */
            n2n_PROBE_ACK_t ack;
            decode_PROBE_ACK(&ack, &cmn, udp_buf, &rem, &idx);

            traceEvent(TRACE_INFO, "Rx PROBE_ACK from %s: my observed addr = %s",
                       macaddr_str(mac_buf1, ack.dstMac), sock_to_cstr(sockbuf1, &ack.observed_addr));

            /* The peer that sent PROBE_ACK is ack.dstMac; their sock is 'sender' (via SN).
             * More importantly, we now know our own public addr. Update and retry REGISTER. */
            PEERS_LOCK(eee);
            /* Update last_seen in known_peers so keepalive knows peer is alive */
            struct peer_info *kp = find_peer_by_mac(eee->known_peers, ack.dstMac);
            if (kp) {
                kp->last_seen = now;
                kp->last_probe_sent = 0;
                kp->keepalive_fails = 0;
            }
            struct peer_info * scan = find_peer_by_mac(eee->pending_peers, ack.dstMac);
            if ( scan && !scan->punch_failed ) {
                /* Send REGISTER directly to peer and also via supernode */
                send_register(eee, &scan->sock);
                send_register(eee, &(eee->supernode));
                traceEvent(TRACE_INFO, "PROBE_ACK: retrying REGISTER to %s",
                           macaddr_str(mac_buf1, ack.dstMac));
            }
            PEERS_UNLOCK(eee);
        }
        else if(msg_type == n2n_peer_info)
        {
            /* Supernode pushed a peer's address to us - start hole-punch immediately. */
            n2n_PEER_INFO_t pi;
            decode_PEER_INFO(&pi, &cmn, udp_buf, &rem, &idx);

            traceEvent(TRACE_INFO, "Rx PEER_INFO for %s at %s - starting punch",
                       macaddr_str(mac_buf1, pi.mac),
                       sock_to_cstr(sockbuf1, &pi.sockets[0]));

            PEERS_LOCK(eee);
            struct peer_info *known = find_peer_by_mac(eee->known_peers, pi.mac);
            if (!known) {
                /* New peer: IPv6 preferred if we have IPv6 socket and peer has IPv6 */
                if ((pi.aflags & N2N_AFLAGS_IPV6_SOCKET) &&
                    pi.sock6.family == AF_INET6 &&
                    eee->udp_sock6 != -1)
                {
                    traceEvent(TRACE_NORMAL, "IPv6 direct: trying %s",
                               sock_to_cstr(sockbuf1, &pi.sock6));
                    try_send_register(eee, 1, pi.mac, &pi.sock6);
                }
                else if ((pi.aflags & N2N_AFLAGS_LOCAL_SOCKET) &&
                    pi.sockets[1].family != 0 && pi.sockets[1].port != 0 &&
                    eee->my_public_sock.family == AF_INET &&
                    pi.sockets[0].family == AF_INET &&
                    memcmp(eee->my_public_sock.addr.v4, pi.sockets[0].addr.v4, IPV4_SIZE) == 0)
                {
                    n2n_sock_t lan_sock = pi.sockets[1];
                    lan_sock.port = pi.sockets[0].port;
                    traceEvent(TRACE_NORMAL, "Same public IP - trying LAN direct: %s",
                               sock_to_cstr(sockbuf1, &lan_sock));
                    try_send_register_lan(eee, 1, pi.mac, &pi.sockets[0], &lan_sock);
                }
                else if (pi.sockets[0].family == AF_INET6 && eee->udp_sock6 == -1)
                {
                    /* Peer is IPv6-only but we have no IPv6 socket - relay only */
                    traceEvent(TRACE_DEBUG, "Peer %s is IPv6-only but no local IPv6 socket, relay only",
                               macaddr_str(mac_buf1, pi.mac));
                }
                else
                {
                    try_send_register(eee, 1, pi.mac, &pi.sockets[0]);
                }
                /* After registering, store sock6 in pending_peer so set_peer_operational
                 * can inherit it when the peer becomes known. */
                if ((pi.aflags & N2N_AFLAGS_IPV6_SOCKET) && pi.sock6.family == AF_INET6) {
                    struct peer_info *pp = find_peer_by_mac(eee->pending_peers, pi.mac);
                    if (pp) pp->sock6 = pi.sock6;
                }
            } else if (sock_equal(&known->sock, &pi.sockets[0]) != 0) {
                /* Check if known->sock is the LAN address matching pi.sockets[1] */
                int lan_match = (pi.aflags & N2N_AFLAGS_LOCAL_SOCKET) &&
                                sock_equal(&known->sock, &pi.sockets[1]) == 0;
                if (!lan_match) {
                /* Peer address changed: move back to pending and re-punch */
                traceEvent(TRACE_NORMAL, "Peer %s addr changed, re-punching",
                           macaddr_str(mac_buf1, pi.mac));
                /* Remove from known_peers */
                struct peer_info *prev = NULL, *scan = eee->known_peers;
                while (scan && memcmp(scan->mac_addr, pi.mac, N2N_MAC_SIZE) != 0) {
                    prev = scan; scan = scan->next;
                }
                if (scan) {
                    if (prev) prev->next = scan->next;
                    else eee->known_peers = scan->next;
                    free(scan);
                }
                /* Re-punch with new address */
                if ((pi.aflags & N2N_AFLAGS_IPV6_SOCKET) &&
                    pi.sock6.family == AF_INET6 &&
                    eee->udp_sock6 != -1)
                {
                    traceEvent(TRACE_NORMAL, "IPv6 direct re-punch: %s",
                               sock_to_cstr(sockbuf1, &pi.sock6));
                    try_send_register(eee, 1, pi.mac, &pi.sock6);
                }
                else if ((pi.aflags & N2N_AFLAGS_LOCAL_SOCKET) &&
                    pi.sockets[1].family != 0 && pi.sockets[1].port != 0 &&
                    eee->my_public_sock.family == AF_INET &&
                    pi.sockets[0].family == AF_INET &&
                    memcmp(eee->my_public_sock.addr.v4, pi.sockets[0].addr.v4, IPV4_SIZE) == 0)
                {
                    n2n_sock_t lan_sock = pi.sockets[1];
                    lan_sock.port = pi.sockets[0].port;
                    try_send_register_lan(eee, 1, pi.mac, &pi.sockets[0], &lan_sock);
                }
                else if (pi.sockets[0].family == AF_INET6 && eee->udp_sock6 == -1)
                {
                    traceEvent(TRACE_DEBUG, "Peer %s re-punch: IPv6-only but no local IPv6 socket, relay only",
                               macaddr_str(mac_buf1, pi.mac));
                }
                else
                {
                    try_send_register(eee, 1, pi.mac, &pi.sockets[0]);
                }
                /* Store sock6 in pending_peer for re-punch case too */
                if ((pi.aflags & N2N_AFLAGS_IPV6_SOCKET) && pi.sock6.family == AF_INET6) {
                    struct peer_info *pp = find_peer_by_mac(eee->pending_peers, pi.mac);
                    if (pp) pp->sock6 = pi.sock6;
                }
                } /* end if (!lan_match) */
            }
            PEERS_UNLOCK(eee);
        }
        else if(msg_type == MSG_TYPE_REGISTER_SUPER_ACK)
        {
            n2n_REGISTER_SUPER_ACK_t ra;

            if ( eee->sn_wait || eee->sn_ack_count > 0 )
            {
                decode_REGISTER_SUPER_ACK( &ra, &cmn, udp_buf, &rem, &idx );

                if ( ra.sock.family )
                {
                    orig_sender = &(ra.sock);
                }

                if ( 0 == memcmp( ra.cookie, eee->last_cookie, N2N_COOKIE_SIZE ) )
                {
                    eee->sn_ack_count++;

                    if ( ra.num_sn > 0 )
                    {
                        traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_ACK backup supernode at %s",
                                   sock_to_cstr(sockbuf1, &(ra.sn_bak) ) );
                    }

                    /* Only do full processing on the first ACK; subsequent ACKs
                     * (from alt address family) just refresh last_sup silently. */
                    if ( eee->sn_ack_count == 1 ) {
					eee->last_sup = now;
					eee->sn_wait=0;
					eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS; /* refresh because we got a response */

					if (default_ip_assignment && ra.dev_addr.net_addr != 0) {
					  struct in_addr addr;
					  addr.s_addr = ra.dev_addr.net_addr;
					  char assigned_ip_str[INET_ADDRSTRLEN];
					  inet_ntop(AF_INET, &addr, assigned_ip_str, sizeof(assigned_ip_str));

					 int ip_changed = (eee->device.ip_addr != addr.s_addr);

					 if (ip_changed) {
						 eee->device.ip_addr = addr.s_addr;
						 eee->device.ip_prefixlen = ra.dev_addr.net_bitlen ? ra.dev_addr.net_bitlen : 24;

							if (set_ipaddress(&eee->device, 1) < 0) {
							   traceEvent(TRACE_ERROR, "Failed to configure TAP interface with assigned IP");
						 } else {
							  traceEvent(TRACE_NORMAL, "TAP interface configured with IP %s/%u", assigned_ip_str, eee->device.ip_prefixlen);
							}
					 }
					}

					if (first_ok_message_shown == 0) {
							traceEvent(TRACE_NORMAL, "[OK] Edge Peer <<< =======64======= >>> Super Node");
							  first_ok_message_shown = 1;
					} else {
							traceEvent(TRACE_DEBUG, "[OK] Edge Peer <<< =======64======= >>> Super Node");
					}


					if (!initial_connection_complete && eee->daemon) {
#ifdef N2N_HAVE_DAEMON
					 useSyslog = 1; /* traceEvent output now goes to syslog. */
					 prctl(PR_SET_KEEPCAPS, 1L);
						if ( -1 == daemon( 0, 0 ) ) {
						 traceEvent( TRACE_ERROR, "Failed to become daemon." );
						 exit(-5);
						}
#endif
						initial_connection_complete = 1;
					}

                    /* Store our own public address as seen by supernode */
                    eee->my_public_sock = ra.sock;

                    /* TODO: store sn_bak for backup supernode failover */
                    eee->register_lifetime = ra.lifetime;
                    eee->register_lifetime = max( eee->register_lifetime, REGISTER_SUPER_INTERVAL_MIN );
                    eee->register_lifetime = min( eee->register_lifetime, REGISTER_SUPER_INTERVAL_MAX );

                    /* Store supernode version */
                    strcpy(eee->supernode_version, n2n_sw_version);

                    /* Set IP support flags: primary connection type is always supported;
                     * if alt address resolved, supernode supports both families. */
                    eee->sn_ipv4_support = (eee->supernode.family == AF_INET) ? 1 :
                                           (eee->supernode_alt.family == AF_INET ? 1 : 0);
                    eee->sn_ipv6_support = (eee->supernode.family == AF_INET6) ? 1 :
                                           (eee->supernode_alt.family == AF_INET6 ? 1 : 0);

                    /* Do NOT clear pending_peers here - hole-punch may be in progress */
                    } else {
                        /* Duplicate ACK from alt address family: just refresh last_sup */
                        eee->last_sup = now;
                        traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_ACK (alt addr, ack#%u) - refreshing last_sup",
                                   eee->sn_ack_count);
                    }
                }
                else
                {
                    traceEvent( TRACE_WARNING, "Rx REGISTER_SUPER_ACK with wrong or old cookie." );
                }
            }
            else
            {
                traceEvent( TRACE_WARNING, "Rx REGISTER_SUPER_ACK with no outstanding REGISTER_SUPER." );
            }
        }
        else if(msg_type == n2n_deregister)
        {
            n2n_DEREGISTER_t dereg;
            decode_DEREGISTER(&dereg, &cmn, udp_buf, &rem, &idx);

            traceEvent(TRACE_INFO, "Rx DEREGISTER from %s",
                       macaddr_str(mac_buf1, dereg.srcMac));

            PEERS_LOCK(eee);
            /* Remove from known_peers */
            struct peer_info *prev = NULL, *scan = eee->known_peers;
            while (scan) {
                if (memcmp(scan->mac_addr, dereg.srcMac, N2N_MAC_SIZE) == 0) {
                    if (prev) prev->next = scan->next;
                    else eee->known_peers = scan->next;
                    free(scan);
                    break;
                }
                prev = scan;
                scan = scan->next;
            }
            /* Remove from pending_peers too */
            prev = NULL; scan = eee->pending_peers;
            while (scan) {
                if (memcmp(scan->mac_addr, dereg.srcMac, N2N_MAC_SIZE) == 0) {
                    if (prev) prev->next = scan->next;
                    else eee->pending_peers = scan->next;
                    free(scan);
                    break;
                }
                prev = scan;
                scan = scan->next;
            }
            PEERS_UNLOCK(eee);
        }
        else
        {
            /* Not a known message type */
            traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored", (signed int)msg_type);
            return;
        }
    } /* if (community match) */
    else
    {
        traceEvent(TRACE_WARNING, "Received packet with invalid community");
    }
}

/* ***************************************************** */


#ifdef _WIN32
static DWORD tunReadThread(LPVOID lpArg )
{
    n2n_edge_t *eee = (n2n_edge_t*)lpArg;

    while(eee->keep_running)
    {
        readFromTAPSocket(eee);
    }

    return 0;
}

/** Start a second thread in Windows because TUNTAP interfaces do not expose
 *  file descriptors. */
static void startTunReadThread(n2n_edge_t *eee)
{
    HANDLE hThread;
    DWORD dwThreadId;

    hThread = CreateThread(NULL,         /* security attributes */
                           0,            /* use default stack size */
                           (LPTHREAD_START_ROUTINE)tunReadThread, /* thread function */
                           (void*)eee,   /* argument to thread function */
                           0,            /* thread creation flags */
                           &dwThreadId); /* thread id out */
}
#endif

/* ***************************************************** */

/** Resolve the supernode IP address.
 *
 *  REVISIT: This is a really bad idea. The edge will block completely while the
 *           hostname resolution is performed. This could take 15 seconds.
 */
static int supernode2addr(n2n_sock_t * sn, int af, const n2n_sn_name_t addrIn) {
    n2n_sn_name_t addr;
    size_t len;
    int err;

    memcpy( addr, addrIn, N2N_EDGE_SN_HOST_SIZE );
    addr[N2N_EDGE_SN_HOST_SIZE - 1] = '\0'; /* ensure null-terminated */
    len = strlen(addr);

    if ( len > 0) {
        int ip_error = 0;
        char *supernode_port = NULL;

        if (addr[len - 1] != ']') {
            supernode_port = strrchr(addr, ':');
            if ( supernode_port ) {
                sn->port = atoi(supernode_port + 1);
                *(supernode_port) = '\0';
            } else
                sn->port = SUPERNODE_PORT;
        }
        if (sn->port == 0)
            sn->port = SUPERNODE_PORT;

        /* try to resolve as numeric address */
        if ( addr[0] == '[' ) {
            /* cut leading and trailing brackets */
            addr[strlen(addr) - 1] = '\0';
            if ((err = inet_pton(AF_INET6, addr + 1, &sn->addr.v6)) != 1) {
                ip_error = errno;
            } else {
                sn->family = AF_INET6;
            }
        } else {
            if ((err = inet_pton(AF_INET, addr, &sn->addr.v4)) != 1) {
                ip_error = errno;
            } else {
                sn->family = AF_INET;
            }
        }

        /* fallback to resolving as a DNS name */
        if (err != 1) {
            const struct addrinfo aihints = { 0, af, SOCK_DGRAM, 0, 0, NULL, NULL, NULL };
            struct addrinfo * ainfo = NULL;

            err = getaddrinfo( addr, NULL, &aihints, &ainfo );
            if( 0 == err ) {
                /* ainfo is the head of a linked list if non-NULL. */
                if (ainfo) {
                    if (PF_INET == ainfo->ai_family) {
                        struct sockaddr_in* saddr = (struct sockaddr_in*) ainfo->ai_addr;
                        memcpy( sn->addr.v4, &(saddr->sin_addr), IPV4_SIZE );
                        sn->family = AF_INET;
                    } else if (PF_INET6 == ainfo->ai_family) {
                        struct sockaddr_in6 * saddr = (struct sockaddr_in6*) ainfo->ai_addr;
                        memcpy( sn->addr.v6, &(saddr->sin6_addr), IPV6_SIZE );
                        sn->family = AF_INET6;
                    }
                } else {
                    traceEvent(TRACE_WARNING, "Failed to resolve supernode IP address for %s", addr);
                }

                freeaddrinfo(ainfo); /* free everything allocated by getaddrinfo(). */
                ainfo = NULL;

                err = 0;
            } else {
#if _WIN32
                traceEvent(TRACE_WARNING, "Failed to resolve supernode host %s: %ls", addr, gai_strerror(err));
#else
                traceEvent(TRACE_WARNING, "Failed to resolve supernode host %s: %s", addr, gai_strerror(err));
#endif
                err = -1;
                if (ip_error != 0) {
                    traceEvent(TRACE_DEBUG, "Failed to parse supernode as a numeric address %s: %s", addr, strerror(ip_error));
                }
            }
        } else {
            err = 0;
        }
    } else {
        traceEvent(TRACE_WARNING, "Wrong supernode parameter (-l <host:port>)");
        err = -1;
    }

    return err;
}

/* ***************************************************** */

/** Find the address and IP mode for the tuntap device.
 *
 *  s is one of these forms:
 *
 *  <host> := <hostname> | A.B.C.D
 *
 *  <host> | static:<host> | dhcp:<host>
 *
 *  If the mode is present (colon required) then fill ip_mode with that value
 *  otherwise do not change ip_mode. Fill ip_mode with everything after the
 *  colon if it is present; or s if colon is not present.
 *
 *  ip_add and ip_mode are NULL terminated if modified.
 *
 *  return 0 on success and -1 on error
 */
static int scan_address( char * ip_addr, size_t addr_size,
                         char * ip_mode, size_t mode_size,
                         int* prefixlen,
                         const char * s )
{
    int retval = -1;
    size_t addr_end = addr_size;
    char * p;

    if ( ( NULL == s ) || ( NULL == ip_addr) )
    {
        return -1;
    }

    memset(ip_addr, 0, addr_size);

    p = strpbrk(s, "/");
    if ( p )
    {
        if (prefixlen)
        {
            // TODO error check 0 <= prefixlen <=32
            *prefixlen = atoi(p+1);
        }
        addr_end = p - s;
    }

    p = strpbrk(s, ":");

    if ( p )
    {
        /* colon is present */
        if ( ip_mode )
        {
            size_t end=0;

            memset(ip_mode, 0, mode_size);
            end = min( p - s, (ssize_t)(mode_size - 1) ); /* ensure NULL term */
            strncpy( ip_mode, s, end );
            end = min( addr_end - end - 1, addr_size - 1);
            strncpy( ip_addr, p + 1, end ); /* ensure NULL term */
            retval = 0;
        }
    }
    else
    {
        /* colon is not present */
        strncpy( ip_addr, s, addr_end );
    }

    return retval;
}

/** IP6 Address for TUNTAP device
 *
 * s should be in the form of:
 *
 * aa:bb:cc:ee::01
 *
 * or
 *
 * aa:bb:cc:ee::01/48
 *
 * where 48 is the prefix length (netmask lenth), if not
 * provided, the string is not changed.
 */
static int scan_address6( char * ip6_addr, size_t addr_size,
                          int* ip6_prefixlen,
                          const char * s )
{
    int retval = -1;
    char * p;

    if ( ( NULL == s ) || ( NULL == ip6_addr) )
    {
        return -1;
    }

    memset(ip6_addr, 0, addr_size);

    p = strchr(s, '/');

    if ( p )
    {
        if ( ip6_prefixlen )
        {
            size_t end=0;

            // TODO error check 0 <= prefixlen <= 128
            *ip6_prefixlen = atoi(p + 1);
            end = min( p - s, (ssize_t)(addr_size - 1) );
            strncpy( ip6_addr, s, end );
            retval = 0;
        }
    }
    else
    {
        strncpy( ip6_addr, s, addr_size );
    }

    return retval;
}

/** Scan argument for route and add to route list
 */
static int scan_route(char* optarg, struct tuntap_config* tuntap_config) {
    char* dest = optarg;
    char* prefix = NULL;
    char* gateway;
    char* p = NULL;

    prefix = strchr(dest, '/');
    if (!prefix)
    {
        traceEvent(TRACE_ERROR, "%s is not a valid route", optarg);
        return 0;
    }
    *prefix = '\0';
    prefix += 1;
    gateway = strchr(prefix, ',');
    if (!gateway)
    {
        *prefix = '/';
        traceEvent(TRACE_ERROR, "%s is not a valid route", optarg);
        return 0;
    }
    *gateway = '\0';
    gateway += 1;

    assert((tuntap_config->routes_count == 0) == (tuntap_config->routes == NULL));
    if (!tuntap_config->routes)
    {
        tuntap_config->routes = (route*) calloc(16, sizeof(route));
    }
    else if ((tuntap_config->routes_count % 16) == 15)
    {
        tuntap_config->routes = (route*)realloc(tuntap_config->routes,
            ((tuntap_config->routes_count / 16 + 2) * 16) * sizeof(route));
    }

    route* r = &tuntap_config->routes[tuntap_config->routes_count];
    if (inet_pton(AF_INET, dest, r->dest))
    {
        r->family = AF_INET;
        if (!inet_pton(AF_INET, gateway, r->gateway))
        {
            traceEvent(TRACE_ERROR, "%s is not a valid gateway for an IPv4 network", gateway);
            goto fail;
        }
        r->prefixlen = (uint8_t) strtol(prefix, &p, 10);
        if (p == NULL || p == prefix)
        {
            traceEvent(TRACE_ERROR, "%s is not a valid prefix length for an IPv4 network", prefix);
            goto fail;
        }
        else if (r->prefixlen < 0 || r->prefixlen > 32)
        {
            traceEvent(TRACE_ERROR, "%s is not a valid prefix length for an IPv4 network", prefix);
            goto fail;
        }
    } else {
        if (!inet_pton(AF_INET6, dest, r->dest))
        {
            traceEvent(TRACE_ERROR, "%s is neither a valid IPv4 or IPv6 address", dest);
            goto fail;
        }
        r->family = AF_INET6;
        if (!inet_pton(AF_INET6, gateway, r->gateway))
        {
            traceEvent(TRACE_ERROR, "%s is not a valid gateway for an IPv6 network", gateway);
            goto fail;
        }
        r->prefixlen = (uint8_t) strtol(prefix, &p, 10);
        if (p == NULL || p == prefix)
        {
            traceEvent(TRACE_ERROR, "%s is not a valid prefix length for an IPv6 network", prefix);
            goto fail;
        }
        else if (r->prefixlen < 0 || r->prefixlen > 128)
        {
            traceEvent(TRACE_ERROR, "%s is not a valid prefix length for an IPv6 network", prefix);
            goto fail;
        }
    }

    tuntap_config->routes_count++;
    return 1;
fail:
    if (tuntap_config->routes_count == 0)
    {
        free(tuntap_config->routes);
        tuntap_config->routes = NULL;
    }
    else if ((tuntap_config->routes_count % 16) == 15)
    {
        tuntap_config->routes = (route*) reallocarray(tuntap_config->routes, ((tuntap_config->routes_count / 16 + 1) * 16), sizeof(route));
    }
    return 0;
}

static int run_loop(n2n_edge_t * eee );

#define N2N_NETMASK_STR_SIZE    16 /* dotted decimal 12 numbers + 3 dots */
#define N2N_MACNAMSIZ           18 /* AA:BB:CC:DD:EE:FF + NULL*/
#define N2N_IF_MODE_SIZE        16 /* static | dhcp */

/** Entry point to program from kernel. */
int main(int argc, char* argv[])
{
    int     opt;
    int     local_port = 0 /* any port */;
    int     mgmt_port = N2N_EDGE_MGMT_PORT; /* 5644 by default */
    char    mgmt_path[108];
    char    tuntap_dev_name[N2N_IFNAMSIZ] = "n2n0";
    char    ip_mode[N2N_IF_MODE_SIZE]="static";
    ipstr_t ip_addr = "";
    int     ip_prefixlen = 24;
    ipstr_t ip6_addr = "";
    int     ip6_prefixlen = 64;
    int     mtu = DEFAULT_MTU;
    int     got_s = 0;
    struct tuntap_config tuntap_config;
    int encrypt_mode = 2;

#ifndef _WIN32
    uid_t   userid = 0;
    gid_t   groupid = 0;
#endif
#ifdef HAVE_LIBCAP
    cap_t caps, caps_original;
    cap_value_t caps_array[] = { CAP_NET_ADMIN, CAP_SETUID, CAP_SETGID };
    cap_flag_value_t is_flag_set;
#endif

    char    device_mac[N2N_MACNAMSIZ]="";
    char *  encrypt_key=NULL;

    n2n_edge_t eee; /* single instance for this program */

#ifdef HAVE_LIBCAP
#ifdef PR_CAP_AMBIENT
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L);
#endif
    caps_original = cap_get_proc();
    caps = cap_init();
    cap_set_flag(caps, CAP_PERMITTED, 1, caps_array, CAP_SET);
    cap_get_flag(caps_original, CAP_SETUID, CAP_PERMITTED, &is_flag_set);
    if (is_flag_set == CAP_SET)
        cap_set_flag(caps, CAP_PERMITTED, 1, caps_array+1, CAP_SET);
    cap_get_flag(caps_original, CAP_SETGID, CAP_PERMITTED, &is_flag_set);
    if (is_flag_set == CAP_SET)
        cap_set_flag(caps, CAP_PERMITTED, 1, caps_array+2, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
    cap_free(caps_original);
#endif

#ifndef _WIN32
    /* Register signal handlers early so SIGTERM/SIGINT always trigger
     * graceful shutdown and UPnP port cleanup, even during startup. */
    signal(SIGTERM, edge_signal_handler);
    signal(SIGINT,  edge_signal_handler);
#endif

    if (-1 == edge_init(&eee) ) {
        traceEvent( TRACE_ERROR, "Failed in edge_init" );
        exit(1);
    }

    if( getenv( "N2N_KEY" ))
        encrypt_key = strdup( getenv( "N2N_KEY" ));

#ifndef _WIN32
    if ( getenv( "JOURNAL_STREAM" ) )
        useSystemd = true;
#else
    /* Windows: clear default device name so any TAP adapter is accepted */
    tuntap_dev_name[0] = '\0';
#endif
    memset(&tuntap_config, 0, sizeof(tuntap_config));

    memset(&(eee.supernode), 0, sizeof(eee.supernode));
    eee.supernode.family = AF_INET;

/* Check if first argument is a config file (not starting with '-') */
if (argc > 1 && argv[1][0] != '-' && access(argv[1], R_OK) == 0) {
    char linebuffer[MAX_CMDLINE_BUFFER_LENGTH] = {0};
    if (readConfFile(argv[1], linebuffer) < 0) {
        traceEvent(TRACE_ERROR, "Failed to read config file: %s", argv[1]);
        exit(1);
    }

    /* Build new argv from config file and remaining arguments */
    char **config_argv;
    int config_argc;

    /* Parse config file into argv */
    config_argv = buildargv(&config_argc, linebuffer);
    if (!config_argv) {
        traceEvent(TRACE_ERROR, "Failed to parse config file");
        exit(1);
    }

    /* Create new argv array with program name and remaining args */
    char **new_argv = malloc((config_argc + argc - 1) * sizeof(char*));
    new_argv[0] = argv[0];

    /* Copy config file arguments */
    for (int i = 0; i < config_argc; i++) {
        new_argv[i + 1] = config_argv[i];
    }

    /* Copy remaining command line arguments */
    for (int i = 2; i < argc; i++) {
        new_argv[config_argc + i - 1] = argv[i];
    }

    /* Update argc and argv for getopt_long */
    argc = config_argc + argc - 1;
    argv = new_argv;
    optind = 1; /* Reset getopt */
}

    optarg = NULL;
    while((opt = getopt_long(argc,
        argv,
        "46K:k:a:A:bc:Eu:g:m:M:d:l:p:fvhrt:R:B:", long_options, NULL
    )) != EOF) {
        switch (opt) {
        case '4':
            eee.sn_af = AF_INET;
        break;
        case '6':
            eee.sn_af = AF_INET6;
        break;
        case 'B':
        {
            if (!optarg || strlen(optarg) == 0) {
                    fprintf(stderr, "Error: Invalid -B option format. Use -B3 or -B 3\n");
                    exit(1);
            }

            for (int i = 0; optarg[i]; i++) {
                if (!isdigit(optarg[i])) {
                    fprintf(stderr, "Error: Invalid -B option format. Use -B3 or -B 3\n");
                    exit(1);
                }
            }

            encrypt_mode = atoi(optarg);
            if (encrypt_mode < 1 || encrypt_mode > 5 || encrypt_mode == 0) {
                fprintf(stderr, "Error: Invalid encryption mode. Use B1-B5\n");
                exit(1);
            }
            break;
        }
        case'K':
        {
            fprintf(stderr, "Error: -K (keyfile) is no longer supported. Use -k with -B3/-B4/-B5.\n");
            exit(1);
            break;
        }
        case 'a': /* IP address and mode of TUNTAP interface */
        {
            if (optarg && strlen(optarg) > 0) {
                scan_address(ip_addr, N2N_NETMASK_STR_SIZE,
                             ip_mode, N2N_IF_MODE_SIZE,
                             &ip_prefixlen, optarg );
            } else {
                default_ip_assignment = 1;
                strcpy(ip_mode, "static");
                ip_prefixlen = 24;
            }
            break;
        }
        case 'A': /* IP address and mode of TUNTAP interface */
        {
            scan_address6(ip6_addr, INET6_ADDRSTRLEN,
                          &ip6_prefixlen, optarg );
            break;
        }
        case 'c': /* community as a string */
        {
            memset( eee.community_name, 0, N2N_COMMUNITY_SIZE );
            strncpy( (char *)eee.community_name, optarg, N2N_COMMUNITY_SIZE);
            break;
        }
        case 'E': /* multicast ethernet addresses accepted. */
        {
            eee.drop_multicast=0;
            traceEvent(TRACE_DEBUG, "Enabling ethernet multicast traffic\n");
            break;
        }

#ifndef _WIN32
        case 'u': /* unprivileged uid */
        {
            userid = atoi(optarg);
            break;
        }
        case 'g': /* unprivileged uid */
        {
            groupid = atoi(optarg);
            break;
        }
#endif
#ifdef N2N_HAVE_DAEMON
        case 'f' : /* do not fork as daemon */
        {
            eee.daemon=0;
            break;
        }
#endif /* #ifdef N2N_HAVE_DAEMON */

        case 'm' : /* TUNTAP MAC address */
        {
            strncpy(device_mac,optarg,N2N_MACNAMSIZ);
            break;
        }

        case 'M' : /* TUNTAP MTU */
        {
            mtu = atoi(optarg);
            break;
        }

        case 'k': /* encrypt key */
        {
            traceEvent(TRACE_DEBUG, "encrypt_key = '%s'\n", encrypt_key);
            encrypt_key = strdup(optarg);
            break;
        }
        case 'r': /* enable packet routing across n2n endpoints */
        {
            eee.allow_routing = 1;
            break;
        }
        case 'R': /* add a route */
        {
            scan_route(optarg, &tuntap_config);
            eee.allow_routing = 1;
            break;
        }

        case 'l': /* supernode-list */
        {
            if ( eee.sn_num < N2N_EDGE_NUM_SUPERNODES ) {
                strncpy( (eee.sn_ip_array[eee.sn_num]), optarg, N2N_EDGE_SN_HOST_SIZE);
                traceEvent(TRACE_DEBUG, "Adding supernode[%u] = %s\n", (unsigned int)eee.sn_num, (eee.sn_ip_array[eee.sn_num]) );
                ++eee.sn_num;
            } else {
                fprintf(stderr, "Too many supernodes!\n" );
                exit(1);
            }
            break;
        }

#if defined(N2N_CAN_NAME_IFACE)
        case 'd': /* TUNTAP name */
        {
            strncpy(tuntap_dev_name, optarg, N2N_IFNAMSIZ);
            break;
        }
#endif
        case 'p':
        {
            local_port = atoi(optarg);
            break;
        }

        case 't':
        {
            if (optarg[0] == '/') {
                mgmt_port = 0;
                strncpy(mgmt_path, optarg, sizeof(mgmt_path));
            } else
                mgmt_port = atoi(optarg);
            break;
        }

        case 'h': /* help */
        {
            help();
            exit(0);
        }

        case 'v': /* verbose */
        {
            ++traceLevel; /* do 2 -v flags to increase verbosity to DEBUG level*/
            break;
        }

        } /* end switch */
    }

    // Only add default if no user supernodes specified
    if (eee.sn_num == 0) {
        strcpy(eee.sn_ip_array[0], "ouno.eu.org:10084");
        eee.sn_num = 1;
    }

    if (default_ip_assignment == 0 && strlen(ip_addr) == 0) {
        default_ip_assignment = 1;
        tuntap_config.delay_ip_config = 1;
        strcpy(ip_mode, "static");
        ip_prefixlen = 24;
    }

#ifdef HAVE_LIBCAP
    caps = cap_init();
    cap_set_flag(caps, CAP_PERMITTED, 3, caps_array, CAP_SET);
    cap_set_flag(caps, CAP_EFFECTIVE, 2, caps_array + 1, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
    prctl(PR_SET_KEEPCAPS, 1L);
    if ( (userid != 0) || (groupid != 0 ) ) {
        setregid( groupid, groupid );
        setreuid( userid, userid );
    }
    prctl(PR_SET_KEEPCAPS, 0L);
    caps = cap_init();
    cap_set_flag(caps, CAP_PERMITTED, 1, caps_array, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
#endif

    srand((unsigned int) time(NULL));

    if (strlen(ip_addr) > 0 && inet_pton(AF_INET, ip_addr, &tuntap_config.ip_addr) != 1) {
        traceEvent(TRACE_ERROR, "invalid ipv4 address: %s", ip_addr);
    }

    if(!(
#if N2N_CAN_NAME_IFACE && !defined(_WIN32)
        (tuntap_dev_name[0] != 0) &&
#endif
        (eee.community_name[0] != 0)
    ) ) {
        help();
        exit(1);
    }

    traceEvent( TRACE_NORMAL, "Starting n2n edge %s %s", n2n_sw_version, n2n_sw_buildDate );

    for (int i = 0; i< eee.sn_num; ++i) {
        /* Skip the default supernode (last one if it matches default) */
        if (strcmp(eee.sn_ip_array[i], "ouno.eu.org:10084") == 0) {
            continue; // Skip displaying default
        }
        traceEvent( TRACE_NORMAL, "supernode %u => %s\n", i, (eee.sn_ip_array[i]) );
    }

    while (supernode2addr( &(eee.supernode), eee.sn_af, eee.sn_ip_array[eee.sn_idx] ) != 0) {
        // could not resolve IP, sleep and try again
#ifdef _WIN32
        Sleep(5000);
#else
        sleep(5);
#endif
    }

    /* Resolve alternate address family for dual-stack registration */
    memset(&eee.supernode_alt, 0, sizeof(n2n_sock_t));
    {
        int alt_af = (eee.supernode.family == AF_INET6) ? AF_INET : AF_INET6;
        if (supernode2addr(&eee.supernode_alt, alt_af, eee.sn_ip_array[eee.sn_idx]) == 0) {
            n2n_sock_str_t sockbuf_alt;
            traceEvent(TRACE_INFO, "Supernode alt address resolved: %s",
                       sock_to_cstr(sockbuf_alt, &eee.supernode_alt));
        } else {
            memset(&eee.supernode_alt, 0, sizeof(n2n_sock_t));
        }
    }

    /* Check if supernode address is a domain name, enable periodic re-resolution */
    {
        char *supernode_host = eee.sn_ip_array[eee.sn_idx];
        struct in_addr ipv4_addr;
        struct in6_addr ipv6_addr;
        if (inet_pton(AF_INET, supernode_host, &ipv4_addr) != 1 &&
            inet_pton(AF_INET6, supernode_host, &ipv6_addr) != 1)
        {
            eee.re_resolve_supernode_ip = 1;
            traceEvent(TRACE_INFO, "Supernode '%s' is a domain name, enabling periodic resolution", supernode_host);
        }
    }

    if (NULL == encrypt_key) {
        traceEvent(TRACE_DEBUG, "Encryption is disabled in edge.");
        eee.null_transop = 1;
    }

    if ( 0 == strcmp( "dhcp", ip_mode ) ) {
        traceEvent(TRACE_NORMAL, "Dynamic IP address assignment enabled.");

        eee.dyn_ip_mode = 1;
    }

    tuntap_config.if_name = tuntap_dev_name;
    tuntap_config.community_name = (const char*)eee.community_name;
    if (device_mac[0] != '\0') {
        if (6 != sscanf(device_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &tuntap_config.device_mac[0],
            &tuntap_config.device_mac[1],
            &tuntap_config.device_mac[2],
            &tuntap_config.device_mac[3],
            &tuntap_config.device_mac[4],
            &tuntap_config.device_mac[5]
        )) {
            traceEvent(TRACE_ERROR, "not valid mac address: %s", device_mac);
        }
        if ( 1 == (tuntap_config.device_mac[0] % 2) ) {
            traceEvent(TRACE_ERROR, "not a valid singlecast mac address: %s (first octet is uneven)", device_mac);
        }
    }
    tuntap_config.mtu = mtu;
    tuntap_config.dyn_ip4 = eee.dyn_ip_mode;
    if (strlen(ip_addr) > 0) {
        if (inet_pton(AF_INET, ip_addr, &tuntap_config.ip_addr) != 1) {
             traceEvent(TRACE_ERROR, "invalid ipv4 address: %s", ip_addr);
        }
    }
    tuntap_config.ip_prefixlen = ip_prefixlen;

    if (ip6_addr[0] == '\0')
        tuntap_config.ip6_prefixlen = 0;
    else {
        if (inet_pton(AF_INET6, ip6_addr, &tuntap_config.ip6_addr) != 1) {
            traceEvent(TRACE_ERROR, "invalid ipv6 address: %s", ip6_addr);
        }
        tuntap_config.ip6_prefixlen = ip6_prefixlen;
    }

#if defined(HAVE_LIBCAP)
    /* set effective capabilitiy NET_ADMIN */
    caps = cap_init();
    cap_set_flag(caps, CAP_EFFECTIVE, 1, caps_array, CAP_SET);
    cap_set_flag(caps, CAP_PERMITTED, 1, caps_array, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
#elif !defined(_WIN32)
    /* If running suid root then we need to setuid before using the force. */
    if (setuid(0) != 0) {
        traceEvent(TRACE_WARNING, "setuid failed");
    }
    /* setgid( 0 ); */
#endif

    if(tuntap_open(&(eee.device), &tuntap_config) < 0)
        return(-1);

#if defined(HAVE_LIBCAP)
    /* drop capabilities */
    caps = cap_init();
    cap_set_proc(caps);
    cap_free(caps);
#elif !defined(_WIN32)
    if ( (userid != 0) || (groupid != 0 ) ) {
        traceEvent(TRACE_NORMAL, "Interface up. Dropping privileges to uid=%d, gid=%d",
                   (signed int)userid, (signed int)groupid);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        if (setregid(groupid, groupid) != 0) {
            traceEvent(TRACE_WARNING, "setregid failed");
        }
        if (setreuid(userid, userid) != 0) {
            traceEvent(TRACE_WARNING, "setreuid failed");
        }
    }
#endif

  if(local_port > 0)
      traceEvent(TRACE_NORMAL, "Binding to local port %d", (signed int)local_port);

  if (encrypt_mode == 1) {
      traceEvent(TRACE_NORMAL, "Using no encryption");
      eee.null_transop = 1;
  } else if (encrypt_mode == 2) {
      if (!encrypt_key) {
          traceEvent(TRACE_WARNING, "No encryption key provided, falling back to no encryption");
          encrypt_mode = 1;
          eee.null_transop = 1;
      } else {
          traceEvent(TRACE_NORMAL, "Using Twofish encryption");
          if (edge_init_twofish(&eee, (uint8_t*)(encrypt_key), strlen(encrypt_key)) < 0) {
              fprintf(stderr, "Error: twofish setup failed.\n");
              return(-1);
          }
      }
#ifdef N2N_HAVE_AES
  } else if (encrypt_mode == 3) {
      traceEvent(TRACE_NORMAL, "Using AES-CBC encryption");
      if (!encrypt_key) { fprintf(stderr, "Error: B3 requires -k <key>\n"); exit(1); }
      if (edge_init_aes(&eee, (uint8_t*)(encrypt_key), strlen(encrypt_key)) < 0) {
          fprintf(stderr, "Error: AES setup failed.\n");
          return(-1);
      }
#endif
#ifdef N2N_HAVE_CC20
  } else if (encrypt_mode == 4) {
      traceEvent(TRACE_NORMAL, "Using ChaCha20 encryption");
      if (!encrypt_key) { fprintf(stderr, "Error: B4 requires -k <key>\n"); exit(1); }
      if (edge_init_cc20(&eee, (uint8_t*)(encrypt_key), strlen(encrypt_key)) < 0) {
          fprintf(stderr, "Error: ChaCha20 setup failed.\n");
          return(-1);
      }
#endif
  } else if (encrypt_mode == 5) {
      traceEvent(TRACE_NORMAL, "Using Speck encryption");
      if (!encrypt_key) { fprintf(stderr, "Error: B5 requires -k <key>\n"); exit(1); }
      if (edge_init_speck(&eee, (uint8_t*)(encrypt_key), strlen(encrypt_key)) < 0) {
          fprintf(stderr, "Error: Speck setup failed.\n");
          return(-1);
      }
  }

    eee.udp_sock = open_socket(local_port, 1 /*bind ANY*/ );
    if(eee.udp_sock == -1)
    {
        traceEvent( TRACE_ERROR, "Failed to bind main UDP port %u", (signed int)local_port );
        return(-1);
    }

    /* Try to open IPv6 socket on same port for dual-stack support */
    eee.udp_sock6 = open_socket6(local_port, 1 /*bind ANY*/);
    {
        /* Detect actual system connectivity by checking available address families */
        int has_ipv4 = (eee.udp_sock != -1);
        int has_ipv6 = 0;
        if (eee.udp_sock6 != -1) {
            /* Check if system has any real IPv6 address (not just loopback) */
            struct ifaddrs *ifap = NULL;
#ifndef _WIN32
            if (getifaddrs(&ifap) == 0) {
                struct ifaddrs *ifa;
                for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_addr) continue;
                    if (ifa->ifa_addr->sa_family == AF_INET6) {
                        struct sockaddr_in6 *s6 = (struct sockaddr_in6*)ifa->ifa_addr;
                        /* skip loopback ::1 */
                        if (!IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr)) {
                            has_ipv6 = 1;
                            break;
                        }
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
                for (a = addrs; a; a = a->Next) {
                    IP_ADAPTER_UNICAST_ADDRESS *ua;
                    for (ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                        struct sockaddr_in6 *s6 = (struct sockaddr_in6*)ua->Address.lpSockaddr;
                        if (s6->sin6_family == AF_INET6 &&
                            !IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr) &&
                            !IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) {
                            has_ipv6 = 1;
                            break;
                        }
                    }
                    if (has_ipv6) break;
                }
            }
            if (addrs) free(addrs);
#endif
        }

        if (has_ipv4 && has_ipv6)
            traceEvent(TRACE_NORMAL, "Dual-stack: IPv4+IPv6 sockets ready (supernode via %s)",
                       eee.supernode.family == AF_INET6 ? "IPv6" : "IPv4");
        else if (has_ipv6)
            traceEvent(TRACE_NORMAL, "Only IPv6 socket ready");
        else
            traceEvent(TRACE_NORMAL, "Only IPv4 socket ready");

        if (eee.udp_sock6 == -1)
            traceEvent(TRACE_WARNING, "IPv6 UDP socket unavailable, IPv6 peers will use relay only");
    }

#if !defined(_WIN32)
    if (mgmt_port == 0)
    {
        eee.mgmt_sock = open_socket_unix(mgmt_path, 0660);
        if(eee.mgmt_sock == -1)
        {
            traceEvent( TRACE_ERROR, "Failed to bind management socket %s", mgmt_path);
            return(-1);
        }
    }
    else
    {
#endif
        eee.mgmt_sock = open_socket(mgmt_port, 0 /* bind LOOPBACK*/ );
        if(eee.mgmt_sock == -1)
        {
            if (mgmt_port == N2N_EDGE_MGMT_PORT) {
                traceEvent( TRACE_WARNING, "Management socket %u already in use, running without management interface", (unsigned int) mgmt_port);
                eee.mgmt_sock = -1;
            } else {
                traceEvent( TRACE_ERROR, "Failed to bind management socket %u", (unsigned int) mgmt_port);
                return(-1);
            }
        }
#if !defined(_WIN32)
    }
#endif

    traceEvent(TRACE_NORMAL, "edge started");

    /* Attempt UPnP/NAT-PMP port mapping so external peers can reach us.
     * This is compiled in by default and runs automatically at startup.
     * Failure is non-fatal - edge continues without port mapping. */
    {
        /* Determine the actual bound local port (may differ from local_port if 0) */
        uint16_t actual_port = 0;
        if (local_port > 0) {
            actual_port = (uint16_t)local_port;
        } else {
            /* OS assigned a random port - read it back from the socket */
            struct sockaddr_in bound;
            socklen_t blen = sizeof(bound);
            if (getsockname(eee.udp_sock, (struct sockaddr*)&bound, &blen) == 0)
                actual_port = ntohs(bound.sin_port);
        }

        if (actual_port > 0) {
            uint16_t mapped = 0;
            traceEvent(TRACE_INFO, "UPnP/NAT-PMP: attempting port mapping for UDP port %u",
                       (unsigned)actual_port);
            if (upnp_map_port(actual_port, actual_port, &mapped) == UPNP_OK) {
                traceEvent(TRACE_NORMAL,
                           "UPnP/NAT-PMP: mapped UDP port %u",
                           (unsigned)mapped);
                eee.upnp_mapped_port = mapped;
            } else {
                traceEvent(TRACE_INFO,
                           "UPnP/NAT-PMP: no gateway found or mapping failed (NAT traversal via supernode only)");
            }
        }
    }

    set_localip(&eee);
    update_supernode_reg(&eee, n2n_now() );

    return run_loop(&eee);
}

static int run_loop(n2n_edge_t * eee )
{
    int   keep_running=1;
    size_t numPurged;
    time_t lastIfaceCheck=0;
    time_t lastTransop=0;
    time_t lastUpnpRenew=0;
    int   retval = 0;

#ifdef _WIN32
    startTunReadThread(eee);
#endif

    /* Main loop
     *
     * select() is used to wait for input on either the TAP fd or the UDP/TCP
     * socket. When input is present the data is read and processed by either
     * readFromIPSocket() or readFromTAPSocket()
     */

    while(keep_running && g_edge_running)
    {
        int rc, max_sock = 0;
        fd_set socket_mask;
        struct timeval wait_time;
        time_t nowTime;

        FD_ZERO(&socket_mask);
        FD_SET(eee->udp_sock, &socket_mask);
        max_sock = (int) eee->udp_sock;
        if (eee->udp_sock6 != -1) {
            FD_SET(eee->udp_sock6, &socket_mask);
            max_sock = max(max_sock, (int) eee->udp_sock6);
        }
        if (eee->mgmt_sock != -1) {
            FD_SET(eee->mgmt_sock, &socket_mask);
            max_sock = max(max_sock, (int) eee->mgmt_sock);
        }
#ifndef _WIN32
        FD_SET(eee->device.fd, &socket_mask);
        max_sock = max( (int) max_sock, (int) eee->device.fd );
#endif

        wait_time.tv_sec = SOCKET_TIMEOUT_INTERVAL_SECS; wait_time.tv_usec = 0;

        rc = select(max_sock+1, &socket_mask, NULL, NULL, &wait_time);
        nowTime=n2n_now();

        /* Handle signal interruption */
        if (rc < 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
#else
            if (errno == EINTR) {
                continue;
            }
#endif
            traceEvent(TRACE_ERROR, "select() failed: %s", strerror(errno));
            if (errno == EBADF || errno == ENOMEM) {
                retval = -1;
                goto cleanup;
            }
            continue;
        }

        /* Make sure ciphers are updated before the packet is treated. */
        if ( ( nowTime - lastTransop ) > TRANSOP_TICK_INTERVAL )
        {
            lastTransop = nowTime;
            n2n_tick_transop( eee, nowTime );
        }

        if(rc > 0)
        {
            /* Any or all of the FDs could have input; check them all. */
            if(FD_ISSET(eee->udp_sock, &socket_mask))
            {
                readFromIPSocket(eee, eee->udp_sock);
            }

            if(eee->udp_sock6 != -1 && FD_ISSET(eee->udp_sock6, &socket_mask))
            {
                readFromIPSocket(eee, eee->udp_sock6);
            }

            if(eee->mgmt_sock != -1 && FD_ISSET(eee->mgmt_sock, &socket_mask))
            {
                readFromMgmtSocket(eee, &keep_running);
            }

#ifndef _WIN32
            if(FD_ISSET(eee->device.fd, &socket_mask))
            {
                /* Read an ethernet frame from the TAP socket. Write on the IP
                 * socket. */
                readFromTAPSocket(eee);
            }
#endif
        }

        /* Finished processing select data. */

        update_supernode_reg(eee, nowTime);
        check_punch_timeouts(eee, nowTime);

        PEERS_LOCK(eee);
        check_keepalive(eee, nowTime);
        numPurged =  purge_expired_registrations( &(eee->known_peers) );
        numPurged += purge_expired_registrations( &(eee->pending_peers) );
        PEERS_UNLOCK(eee);
        if ( numPurged > 0 )
        {
            traceEvent( TRACE_INFO, "Peer removed: pending=%u, operational=%u",
                        (unsigned int)peer_list_size( eee->pending_peers ),
                        (unsigned int)peer_list_size( eee->known_peers ) );
        }

        if ( eee->dyn_ip_mode &&
             (( nowTime - lastIfaceCheck ) > IFACE_UPDATE_INTERVAL ) )
        {
            traceEvent(TRACE_NORMAL, "Re-checking dynamic IP address.");
            tuntap_get_address( &(eee->device) );
            lastIfaceCheck = nowTime;
        }

        /* Renew UPnP/NAT-PMP lease before it expires */
        if (eee->upnp_mapped_port != 0 &&
            (nowTime - lastUpnpRenew) > UPNP_RENEW_THRESHOLD)
        {
            /* Determine actual local port from socket */
            uint16_t local_port = eee->upnp_mapped_port;
            struct sockaddr_in bound;
            socklen_t blen = sizeof(bound);
            if (getsockname(eee->udp_sock, (struct sockaddr*)&bound, &blen) == 0)
                local_port = ntohs(bound.sin_port);

            if (upnp_renew_port(local_port, eee->upnp_mapped_port) == UPNP_OK) {
                traceEvent(TRACE_INFO, "UPnP/NAT-PMP: lease renewed for port %u",
                           (unsigned)eee->upnp_mapped_port);
            } else {
                traceEvent(TRACE_WARNING,
                           "UPnP/NAT-PMP: lease renewal failed for port %u",
                           (unsigned)eee->upnp_mapped_port);
            }
            lastUpnpRenew = nowTime;
        }

    } /* while */

cleanup:
#ifdef _WIN32
    eee->keep_running = 0;
#endif
    send_deregister( eee, &(eee->supernode));

    /* Notify all known peers */
    {
        struct peer_info *p = eee->known_peers;
        while (p) {
            send_deregister(eee, &(p->sock));
            p = p->next;
        }
    }

    if (eee->udp_sock != -1) {
        closesocket(eee->udp_sock);
        eee->udp_sock = -1;
    }

    tuntap_close(&(eee->device));

    edge_deinit( eee );

    return retval;
}
