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
 * Massimo Torquati <torquati@ntop.org>
 * Matt Gilg
 *
 */

#include "n2n.h"
#include "minilzo.h"
#include <assert.h>

#define PURGE_REGISTRATION_FREQUENCY   60
#define REGISTRATION_TIMEOUT           150


const uint8_t broadcast_addr[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const uint8_t multicast_addr[6] = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x00 }; /* First 3 bytes are meaningful */
const uint8_t ipv6_multicast_addr[6] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00 }; /* First 2 bytes are meaningful */

/* ************************************** */

SOCKET open_socket(uint16_t local_port, int bind_any) {
    SOCKET sock_fd;
    struct sockaddr_in local_address;
    int sockopt = 1;

    if((sock_fd = socket(PF_INET, SOCK_DGRAM, 0))  < 0) {
        traceEvent(TRACE_ERROR, "Unable to create socket [%s][%d]\n", strerror(errno), sock_fd);
        return -1;
    }

#ifndef _WIN32
    fcntl(sock_fd, F_SETFL, O_NONBLOCK);
#endif

    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_port = htons(local_port);
    local_address.sin_addr.s_addr = htonl(bind_any?INADDR_ANY:INADDR_LOOPBACK);

    if(bind(sock_fd, (struct sockaddr*) &local_address, sizeof(local_address)) == -1) {
        traceEvent(TRACE_ERROR, "Bind error [%s]\n", strerror(errno));
        return -1;
    }

    return sock_fd;
}

SOCKET open_socket6(uint16_t local_port, int bind_any) {
    SOCKET sock_fd;
    struct sockaddr_in6 local_address;
    int sockopt = 1;

    if((sock_fd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0) {
        traceEvent(TRACE_ERROR, "Unable to create socket [%s][%d]\n", strerror(errno), sock_fd);
        return -1;
    }

#ifndef _WIN32
    fcntl(sock_fd, F_SETFL, O_NONBLOCK);
#endif

    setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&sockopt, sizeof(sockopt));
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    memset(&local_address, 0, sizeof(local_address));
    local_address.sin6_family = AF_INET6;
    local_address.sin6_port = htons(local_port);
    local_address.sin6_addr = bind_any ? in6addr_any : in6addr_loopback;

    if(bind(sock_fd, (struct sockaddr*) &local_address, sizeof(local_address)) == -1) {
        traceEvent(TRACE_ERROR, "Bind error [%s]\n", strerror(errno));
        return -1;
    }

    return sock_fd;
}

#ifndef _WIN32
SOCKET open_socket_unix(const char* path, mode_t access) {
    SOCKET sock_fd;
    struct sockaddr_un socket_address;
    struct stat stat_buf;

    if (stat(path, &stat_buf) == 0) {
        traceEvent(TRACE_WARNING, "socket exists %s ... deleting\n", path);
        unlink(path);
    } else {
        if (errno != ENOENT) {
            traceEvent(TRACE_WARNING, "could not stat socket [%s]\n", strerror(errno));
            return -1;
        }
    }

    if((sock_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        traceEvent(TRACE_ERROR, "Unable to create socket [%s][%d]\n", strerror(errno), sock_fd);
        return -1;
    }

    fcntl(sock_fd, F_SETFL, O_NONBLOCK);

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sun_family = AF_UNIX;
    strncpy(socket_address.sun_path, path, 108);

#if __linux__
    fchmod(sock_fd, access);
#endif

    if(bind(sock_fd, (struct sockaddr*) &socket_address, sizeof(socket_address)) == -1) {
        traceEvent(TRACE_ERROR, "Bind error [%s]\n", strerror(errno));
        return -1;
    }

    chmod(path, access);

    return sock_fd;
}
#endif // _WIN32

int traceLevel = 2 /* NORMAL */;
bool useSyslog = false, syslog_opened = false, useSystemd = false;

#define N2N_TRACE_DATESIZE 32
void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...) {
    va_list va_ap;

    if(eventTraceLevel <= traceLevel) {
        char buf[2048];
        char out_buf[640];
        char theDate[N2N_TRACE_DATESIZE];
        char *extra_msg = "";
        time_t theTime = time(NULL);
        size_t i;

        /* We have two paths - one if we're logging, one if we aren't
        *   Note that the no-log case is those systems which don't support it (WIN32),
        *                                those without the headers !defined(USE_SYSLOG)
        *                                those where it's parametrically off...
        */

        memset(buf, 0, sizeof(buf));

        va_start (va_ap, format);
        vsnprintf(buf, sizeof(buf)-1, format, va_ap);
        va_end(va_ap);

        if(eventTraceLevel == 0 /* TRACE_ERROR */)
        extra_msg = "ERROR: ";
        else if(eventTraceLevel == 1 /* TRACE_WARNING */)
        extra_msg = "WARNING: ";

        while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

#ifndef _WIN32
        if(useSyslog) {
            if(!syslog_opened) {
                openlog("n2n", LOG_PID, LOG_DAEMON);
                syslog_opened = 1;
            }

            snprintf(out_buf, sizeof(out_buf), "%s%s", extra_msg, buf);
            syslog(LOG_INFO, "%s", out_buf);
        } else {
            if (useSystemd)
                snprintf(out_buf, sizeof(out_buf), "%s%s", extra_msg, buf);
            else {
                strftime(theDate, N2N_TRACE_DATESIZE, "%d/%b/%Y %H:%M:%S", localtime(&theTime));
                for(i=strlen(file)-1; i>0; i--) if(file[i] == '/') { i++; break; };
                snprintf(out_buf, sizeof(out_buf), "%s [%15s:%4d] %s%s", theDate, &file[i], line, extra_msg, buf);
            }
            printf("%s\n", out_buf);
            fflush(stdout);
        }
#else
        if (event_log == INVALID_HANDLE_VALUE) {
            /* running in the console */
            strftime(theDate, N2N_TRACE_DATESIZE, "%d/%b/%Y %H:%M:%S", localtime(&theTime));
            for(i=strlen(file)-1; i>0; i--) if(file[i] == '\\') { i++; break; };
            snprintf(out_buf, sizeof(out_buf), "%s [%15s:%4d] %s%s", theDate, &file[i], line, extra_msg, buf);
            printf("%s\n", out_buf);
            fflush(stdout);
        } else {
            /* running as a service */
            wchar_t out[640];
            swprintf(out, sizeof(out), L"%hs%hs", extra_msg, buf);

            wchar_t* msg[] = {
                scm_name,
                out
            };

            short level = EVENTLOG_ERROR_TYPE;
            if(eventTraceLevel == 1)
                level = EVENTLOG_WARNING_TYPE;
            else if(eventTraceLevel == 2)
                level = EVENTLOG_INFORMATION_TYPE;

            ReportEventW(event_log, level, 0, 0x40020000L, NULL, 2, 0, msg, NULL);
        }
#endif
    }

}

/* *********************************************** */

char * macaddr_str( macstr_t buf,
                    const n2n_mac_t mac )
{
    snprintf(buf, N2N_MACSTR_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
        mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);
    return(buf);
}

/* *********************************************** */

uint8_t is_multi_broadcast(const uint8_t * dest_mac) {

       int is_broadcast = ( memcmp(broadcast_addr, dest_mac, 6) == 0 );
       int is_multicast = ( memcmp(multicast_addr, dest_mac, 3) == 0 );
       int is_ipv6_multicast = ( memcmp(ipv6_multicast_addr, dest_mac, 2) == 0 );

       return is_broadcast || is_multicast || is_ipv6_multicast;

}

/* http://www.faqs.org/rfcs/rfc908.html */


/* *********************************************** */

char* msg_type2str(uint16_t msg_type) {
    switch(msg_type) {
        case MSG_TYPE_REGISTER: return "MSG_TYPE_REGISTER";
        case MSG_TYPE_DEREGISTER: return "MSG_TYPE_DEREGISTER";
        case MSG_TYPE_PACKET: return "MSG_TYPE_PACKET";
        case MSG_TYPE_REGISTER_ACK: return "MSG_TYPE_REGISTER_ACK";
        case MSG_TYPE_REGISTER_SUPER: return "MSG_TYPE_REGISTER_SUPER";
        case MSG_TYPE_REGISTER_SUPER_ACK: return "MSG_TYPE_REGISTER_SUPER_ACK";
        case MSG_TYPE_REGISTER_SUPER_NAK: return "MSG_TYPE_REGISTER_SUPER_NAK";
        case MSG_TYPE_FEDERATION: return "MSG_TYPE_FEDERATION";
        default: return "???";
    }
}

/* *********************************************** */

void hexdump(const uint8_t * buf, size_t len)
{
    size_t i;

    if ( 0 == len ) { return; }

    for(i=0; i<len; i++)
    {
        if((i > 0) && ((i % 16) == 0)) { printf("\n"); }
        printf("%02X ", buf[i] & 0xFF);
    }

    printf("\n");
}

/* *********************************************** */

/** Find the peer entry in list with mac_addr equal to mac.
 *
 *  Does not modify the list.
 *
 *  @return NULL if not found; otherwise pointer to peer entry.
 */
struct peer_info * find_peer_by_mac( struct peer_info * list, const n2n_mac_t mac )
{
  while(list != NULL)
    {
      if( 0 == memcmp(mac, list->mac_addr, 6) )
        {
	  return list;
        }
      list = list->next;
    }

  return NULL;
}


/** Return the number of elements in the list.
 *
 */
size_t peer_list_size( const struct peer_info * list )
{
    size_t retval=0;

    while ( list ) {
      ++retval;
      list = list->next;
    }

  return retval;
}

/** Add new to the head of list. If list is NULL; create it.
 *
 *  The item new is added to the head of the list. New is modified during
 *  insertion. list takes ownership of new.
 */
void peer_list_add(struct peer_info * * list,
                   struct peer_info * element )
{
    element->next = *list;
    element->last_seen = time(NULL);
    *list = element;
}


size_t purge_expired_registrations( struct peer_info ** peer_list ) {
    static time_t last_purge = 0;
    time_t now = time(NULL);
    size_t num_reg = 0;

    if ((now - last_purge) < PURGE_REGISTRATION_FREQUENCY)
        return 0;

    traceEvent(TRACE_DEBUG, "Purging old registrations");

    num_reg = purge_peer_list( peer_list, now-REGISTRATION_TIMEOUT );

    last_purge = now;
    traceEvent(TRACE_DEBUG, "Remove %ld registrations", num_reg);

    return num_reg;
}

/** Purge old items from the peer_list and return the number of items that were removed. */
size_t purge_peer_list( struct peer_info ** peer_list,
                        time_t purge_before )
{
    struct peer_info *scan;
    struct peer_info *prev;
    size_t retval=0;

    scan = *peer_list;
    prev = NULL;
    while(scan != NULL) {
        if(scan->last_seen < purge_before) {
            struct peer_info *next = scan->next;

            if(prev == NULL) {
                *peer_list = next;
            } else {
                prev->next = next;
            }

            ++retval;
            free(scan);
            scan = next;
        } else {
            prev = scan;
            scan = scan->next;
        }
    }

  return retval;
}

/** Purge all items from the peer_list and return the number of items that were removed. */
size_t clear_peer_list( struct peer_info ** peer_list )
{
    struct peer_info *scan;
    struct peer_info *prev;
    size_t retval=0;

    scan = *peer_list;
    prev = NULL;
    while(scan != NULL) {
        struct peer_info *next = scan->next;

        if(prev == NULL) {
            *peer_list = next;
        } else {
            prev->next = next;
        }

        ++retval;
        free(scan);
        scan = next;
    }

    return retval;
}

char * sock_to_cstr( n2n_sock_str_t out, const n2n_sock_t * sock )
{
    ipstr_t buffer;

    if ( NULL == out ) { return NULL; }
    memset(out, 0, N2N_SOCKBUF_SIZE);

    if ( AF_INET6 == sock->family )
    {
        inet_ntop(AF_INET6, &sock->addr, buffer, sizeof(buffer));
        snprintf( out, N2N_SOCKBUF_SIZE, "[%s]:%hu", buffer, sock->port );
        return out;
    }
    else
    {
        inet_ntop(AF_INET, &sock->addr, buffer, sizeof(buffer));
        snprintf( out, N2N_SOCKBUF_SIZE, "%s:%hu", buffer, sock->port );
        return out;
    }
}

uint32_t ip4_prefixlen_to_netmask(uint8_t prefixlen) {
    return prefixlen ? htonl(~((1 << (32 - prefixlen)) - 1)) : 0;
}

/* @return zero if the two sockets are equivalent. */
int sock_equal( const n2n_sock_t * a,
                const n2n_sock_t * b )
{
    if ( a->port != b->port ) { return 1; }
    if ( a->family != b->family ) { return 1; }
    switch (a->family) /* they are the same */
    {
    case AF_INET:
        if ( 0 != memcmp( a->addr.v4, b->addr.v4, IPV4_SIZE ) ) { return 1;};
        break;
    default:
        if ( 0 != memcmp( a->addr.v6, b->addr.v6, IPV6_SIZE ) ) { return 1;};
        break;
    }

    return 0;
}
