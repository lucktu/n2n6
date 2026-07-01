/* (c) 2009 Richard Andrews <andrews@ntop.org> */

/** Routines for encoding and decoding n2n packets on the wire.
 *
 *  encode_X(base,idx,v) prototypes are inspired by the erlang internal
 *  encoding model. Passing the start of a buffer in base and a pointer to an
 *  integer (initially set to zero). Each encode routine increases idx by the
 *  amount written and returns the amount written. In this way complex sequences
 *  of encodings can be represented cleanly. See encode_register() for an
 *  example.
 */

#include "n2n_wire.h"
#include <string.h>

size_t encode_uint8( uint8_t * base,
                  size_t * idx,
                  const uint8_t v )
{
    *(base + (*idx)) = (v & 0xff);
    ++(*idx);
    return 1;
}

size_t decode_uint8( uint8_t * out,
                  const uint8_t * base,
                  size_t * rem,
                  size_t * idx )
{
    if (*rem < 1 ) { return 0; }

    *out = ( base[*idx] & 0xff );
    ++(*idx);
    --(*rem);
    return 1;
}

size_t encode_uint16( uint8_t * base,
                   size_t * idx,
                   const uint16_t v )
{
    *(base + (*idx))     = ( v >> 8) & 0xff;
    *(base + (1 + *idx)) = ( v & 0xff );
    *idx += 2;
    return 2;
}

size_t decode_uint16( uint16_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx )
{
    if (*rem < 2 ) { return 0; }

    *out  = ( base[*idx] & 0xff ) << 8;
    *out |= ( base[1 + *idx] & 0xff );
    *idx += 2;
    *rem -= 2;
    return 2;
}

size_t encode_uint32( uint8_t * base,
                   size_t * idx,
                   const uint32_t v )
{
    *(base + (0 + *idx)) = ( v >> 24) & 0xff;
    *(base + (1 + *idx)) = ( v >> 16) & 0xff;
    *(base + (2 + *idx)) = ( v >> 8) & 0xff;
    *(base + (3 + *idx)) = ( v & 0xff );
    *idx += 4;
    return 4;
}

size_t decode_uint32( uint32_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx )
{
    if (*rem < 4 ) { return 0; }

    *out  = ( base[0 + *idx] & 0xff ) << 24;
    *out |= ( base[1 + *idx] & 0xff ) << 16;
    *out |= ( base[2 + *idx] & 0xff ) << 8;
    *out |= ( base[3 + *idx] & 0xff );
    *idx += 4;
    *rem -= 4;
    return 4;
}

size_t encode_buf( uint8_t * base,
                size_t * idx,
                const void * p,
                size_t s)
{
    memcpy( (base + (*idx)), p, s );
    *idx += s;
    return s;
}

/* Copy from base to out of size bufsize */
size_t decode_buf( uint8_t * out,
                size_t bufsize,
                const uint8_t * base,
                size_t * rem,
                size_t * idx )
{
    if (*rem < bufsize ) { return 0; }

    memcpy( out, (base + *idx), bufsize );
    *idx += bufsize;
    *rem -= bufsize;
    return bufsize;
}



size_t encode_mac( uint8_t * base,
                size_t * idx,
                const n2n_mac_t m )
{
    return encode_buf( base, idx, m, N2N_MAC_SIZE );
}

size_t decode_mac( uint8_t * out, /* of size N2N_MAC_SIZE. This clearer than passing a n2n_mac_t */
                const uint8_t * base,
                size_t * rem,
                size_t * idx )
{
    return decode_buf( out, N2N_MAC_SIZE, base, rem, idx );
}



ssize_t encode_common( uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common )
{
    size_t idx0 = *idx;
    uint16_t flags=0;
    encode_uint8( base, idx, N2N_PKT_VERSION );
    encode_uint8( base, idx, common->ttl );

    flags  = common->pc & N2N_FLAGS_TYPE_MASK;
    flags |= common->flags & N2N_FLAGS_BITS_MASK;

    encode_uint16( base, idx, flags );
    encode_buf( base, idx, common->community, N2N_COMMUNITY_SIZE );

    return (ssize_t)(*idx - idx0);
}

ssize_t decode_common( n2n_common_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx )
{
    size_t idx0=*idx;
    uint8_t dummy=0;
    decode_uint8( &dummy, base, rem, idx );

    if ( N2N_PKT_VERSION != dummy )
    {
        return -1;
    }

    decode_uint8( &(out->ttl), base, rem, idx );
    decode_uint16( &(out->flags), base, rem, idx );
    out->pc = (n2n_pc_t) ( out->flags & N2N_FLAGS_TYPE_MASK );
    out->flags &= N2N_FLAGS_BITS_MASK;

    decode_buf( out->community, N2N_COMMUNITY_SIZE, base, rem, idx );

    return ((ssize_t) (*idx)) - (ssize_t) idx0;
}


ssize_t encode_sock( uint8_t * base,
                 size_t * idx,
                 const n2n_sock_t * sock )
{
    ssize_t retval=0;
    uint16_t f;

    switch (sock->family)
    {
    case AF_INET:
    {
        f = 0;
        retval += encode_uint16(base,idx,f);
        retval += encode_uint16(base,idx,sock->port);
        retval += encode_buf(base,idx,sock->addr.v4,IPV4_SIZE);
        break;
    }
    case AF_INET6:
    {
        f = 0x8000;
        retval += encode_uint16(base,idx,f);
        retval += encode_uint16(base,idx,sock->port);
        retval += encode_buf(base,idx,sock->addr.v6,IPV6_SIZE);
        break;
    }
    default:
        retval = -1;
    }

    return retval;
}


ssize_t decode_sock( n2n_sock_t * sock,
                 const uint8_t * base,
                 size_t * rem,
                 size_t * idx )
{
    size_t idx0 = *idx;
    uint16_t f;

    decode_uint16( &f, base, rem, idx );

    if( f & 0x8000 )
    {
        /* IPv6 */
        sock->family = AF_INET6;
        decode_uint16( &(sock->port), base, rem, idx );
        decode_buf( sock->addr.v6, IPV6_SIZE, base, rem, idx );
    }
    else
    {
        /* IPv4 */
        sock->family = AF_INET;
        decode_uint16( &(sock->port), base, rem, idx );
        memset( sock->addr.v6, 0, IPV6_SIZE ); /* so memcmp() works for equality. */
        decode_buf( sock->addr.v4, IPV4_SIZE, base, rem, idx );
    }

    return (ssize_t)(*idx - idx0);
}

size_t encode_REGISTER( uint8_t * base,
                     size_t * idx,
                     const n2n_common_t * common,
                     const n2n_REGISTER_t * reg )
{
    size_t retval=0;
    retval += encode_common( base, idx, common );
    retval += encode_buf( base, idx, reg->cookie, N2N_COOKIE_SIZE );
    retval += encode_mac( base, idx, reg->srcMac );
    retval += encode_mac( base, idx, reg->dstMac );
    if ( 0 != reg->sock.family )
    {
        retval += encode_sock( base, idx, &(reg->sock) );
    }

    retval += encode_buf( base, idx, reg->version, sizeof(reg->version) );
    retval += encode_buf( base, idx, reg->os_name, sizeof(reg->os_name) );

    return retval;
}

size_t decode_REGISTER( n2n_REGISTER_t * reg,
                     const n2n_common_t * cmn,
                     const uint8_t * base,
                     size_t * rem,
                     size_t * idx )
{
    size_t retval=0;
    memset( reg, 0, sizeof(n2n_REGISTER_t) );
    retval += decode_buf( reg->cookie, N2N_COOKIE_SIZE, base, rem, idx );
    retval += decode_mac( reg->srcMac, base, rem, idx );
    retval += decode_mac( reg->dstMac, base, rem, idx );

    if ( cmn->flags & N2N_FLAGS_SOCKET )
    {
        retval += decode_sock( &(reg->sock), base, rem, idx );
    }

    if (*rem >= sizeof(reg->version)) {
        retval += decode_buf( reg->version, sizeof(reg->version), base, rem, idx );
    } else {
        strcpy(reg->version, "unknown");
    }

    if (*rem >= sizeof(reg->os_name)) {
        retval += decode_buf( reg->os_name, sizeof(reg->os_name), base, rem, idx );
    } else {
        strcpy(reg->os_name, "unknown");
    }

    return retval;
}

size_t encode_DEREGISTER( uint8_t * base,
                     size_t * idx,
                     const n2n_common_t * common,
                     const n2n_DEREGISTER_t * reg )
{
    size_t retval=0;
    retval += encode_common( base, idx, common );
    retval += encode_mac( base, idx, reg->srcMac );
    return retval;
}

size_t decode_DEREGISTER( n2n_DEREGISTER_t * reg,
                     const n2n_common_t * cmn,
                     const uint8_t * base,
                     size_t * rem,
                     size_t * idx )
{
    size_t retval=0;
    memset( reg, 0, sizeof(n2n_DEREGISTER_t) );
    retval += decode_mac( reg->srcMac, base, rem, idx );
    return retval;
}

size_t encode_REGISTER_SUPER( uint8_t * base,
                           size_t * idx,
                           const n2n_common_t * common,
                           const n2n_REGISTER_SUPER_t * reg )
{
    size_t retval=0;
    retval += encode_common( base, idx, common );
    retval += encode_buf( base, idx, reg->cookie, N2N_COOKIE_SIZE );
    retval += encode_mac( base, idx, reg->edgeMac );
    retval += encode_uint32( base, idx, reg->dev_addr.net_addr );
    retval += encode_uint8( base, idx, reg->dev_addr.net_bitlen );
    if ( reg->aflags & N2N_AFLAGS_LOCAL_SOCKET ) {
        retval += encode_uint8( base, idx, 1 );
        retval += encode_sock( base, idx, &reg->local_sock );
    } else {
        retval += encode_uint8( base, idx, 0 );
    }
    retval += encode_uint16( base, idx, 0 );
    retval += encode_uint16( base, idx, 0 );
    return retval;
}

size_t decode_REGISTER_SUPER( n2n_REGISTER_SUPER_t * reg,
                           const n2n_common_t * cmn,
                           const uint8_t * base,
                           size_t * rem,
                           size_t * idx )
{
    size_t retval=0;
    memset( reg, 0, sizeof(n2n_REGISTER_SUPER_t) );
    retval += decode_buf( reg->cookie, N2N_COOKIE_SIZE, base, rem, idx );
    retval += decode_mac( reg->edgeMac, base, rem, idx );
    retval += decode_uint32( &(reg->dev_addr.net_addr), base, rem, idx );
    retval += decode_uint8( &(reg->dev_addr.net_bitlen), base, rem, idx );
    {
        uint8_t num_local = 0;
        retval += decode_uint8( &num_local, base, rem, idx );
        if ( num_local > 0 && *rem >= 8 ) {
            retval += decode_sock( &reg->local_sock, base, rem, idx );
            reg->aflags |= N2N_AFLAGS_LOCAL_SOCKET;
            num_local--;
        }
        while ( num_local > 0 && *rem >= 8 ) {
            n2n_sock_t tmp;
            retval += decode_sock( &tmp, base, rem, idx );
            num_local--;
        }
    }
    retval += decode_uint16( &(reg->auth.scheme), base, rem, idx );
    retval += decode_uint16( &(reg->auth.toksize), base, rem, idx );

    return retval;
}

size_t encode_REGISTER_ACK( uint8_t * base,
                         size_t * idx,
                         const n2n_common_t * common,
                         const n2n_REGISTER_ACK_t * reg )
{
    size_t retval=0;
    retval += encode_common( base, idx, common );
    retval += encode_buf( base, idx, reg->cookie, N2N_COOKIE_SIZE );
    retval += encode_mac( base, idx, reg->dstMac );
    retval += encode_mac( base, idx, reg->srcMac );

    /* The socket in REGISTER_ACK is the socket from which the REGISTER
     * arrived. This is sent back to the sender so it knows what its public
     * socket is. */
    if ( 0 != reg->sock.family )
    {
        retval += encode_sock( base, idx, &(reg->sock) );
    }

    return retval;
}

size_t decode_REGISTER_ACK( n2n_REGISTER_ACK_t * reg,
                         const n2n_common_t * cmn, /* info on how to interpret it */
                         const uint8_t * base,
                         size_t * rem,
                         size_t * idx )
{
    size_t retval=0;
    memset( reg, 0, sizeof(n2n_REGISTER_ACK_t) );
    retval += decode_buf( reg->cookie, N2N_COOKIE_SIZE, base, rem, idx );
    retval += decode_mac( reg->dstMac, base, rem, idx );
    retval += decode_mac( reg->srcMac, base, rem, idx );

    /* The socket in REGISTER_ACK is the socket from which the REGISTER
     * arrived. This is sent back to the sender so it knows what its public
     * socket is. */
    if ( cmn->flags & N2N_FLAGS_SOCKET )
    {
        retval += decode_sock( &(reg->sock), base, rem, idx );
    }

    return retval;
}

size_t encode_REGISTER_SUPER_ACK( uint8_t * base,
                               size_t * idx,
                               const n2n_common_t * common,
                               const n2n_REGISTER_SUPER_ACK_t * reg )
{
    size_t retval=0;
    retval += encode_common( base, idx, common );
    retval += encode_buf( base, idx, reg->cookie, N2N_COOKIE_SIZE );
    retval += encode_mac( base, idx, reg->edgeMac );
    retval += encode_uint32( base, idx, reg->dev_addr.net_addr );
    retval += encode_uint8( base, idx, reg->dev_addr.net_bitlen );
    retval += encode_uint16( base, idx, reg->lifetime );
    retval += encode_sock( base, idx, &(reg->sock) );
    retval += encode_uint8( base, idx, reg->num_sn );
    if ( reg->num_sn > 0 )
    {
        retval += encode_sock( base, idx, &(reg->sn_bak) );
    }
    /* Append sn_caps after existing fields for backward compatibility.
     * Old edges will simply ignore this extra byte. */
    retval += encode_uint8( base, idx, reg->sn_caps );
    /* Append sn_version for supernode version display.
     * Old edges will simply ignore these extra bytes. */
    retval += encode_buf( base, idx, reg->sn_version, 24 );
    return retval;
}

size_t decode_REGISTER_SUPER_ACK( n2n_REGISTER_SUPER_ACK_t * reg,
                               const n2n_common_t * cmn, /* info on how to interpret it */
                               const uint8_t * base,
                               size_t * rem,
                               size_t * idx )
{
    size_t retval=0;

    memset( reg, 0, sizeof(n2n_REGISTER_SUPER_ACK_t) );
    retval += decode_buf( reg->cookie, N2N_COOKIE_SIZE, base, rem, idx );
    retval += decode_mac( reg->edgeMac, base, rem, idx );
    retval += decode_uint32( &(reg->dev_addr.net_addr), base, rem, idx );
    retval += decode_uint8( &(reg->dev_addr.net_bitlen), base, rem, idx );
    retval += decode_uint16( &(reg->lifetime), base, rem, idx );

    /* Socket is mandatory in this message type */
    retval += decode_sock( &(reg->sock), base, rem, idx );

    /* Following the edge socket are an array of backup supernodes. */
    retval += decode_uint8( &(reg->num_sn), base, rem, idx );
    if ( reg->num_sn > 0 )
    {
        /* We only support 0 or 1 at this stage */
        retval += decode_sock( &(reg->sn_bak), base, rem, idx );
    }

    /* sn_caps: optional byte appended by new supernodes for backward compat.
     * If not present (old supernode), sn_caps stays 0 (unknown). */
    if ( *rem >= 1 )
    {
        retval += decode_uint8( &(reg->sn_caps), base, rem, idx );
    }
    /* sn_version: optional 24 bytes appended by new supernodes.
     * If not present (old supernode), sn_version stays empty. */
    if ( *rem >= 24 )
    {
        retval += decode_buf( reg->sn_version, 24, base, rem, idx );
    }

    return retval;
}

int fill_sockaddr( struct sockaddr * addr,
                   size_t addrlen,
                   const n2n_sock_t * sock )
{
    int retval=-1;

    memset(addr, 0, addrlen);

    if ( AF_INET == sock->family ) {
        if ( addrlen >= sizeof(struct sockaddr_in) ) {
            struct sockaddr_in* si = (struct sockaddr_in* )addr;
            si->sin_family = sock->family;
            si->sin_port = htons( sock->port );
            memcpy( &si->sin_addr, sock->addr.v4, IPV4_SIZE );
            retval = 0;
        }
    } else if ( AF_INET6 == sock->family ) {
        if ( addrlen >= sizeof(struct sockaddr_in6) ) {
            struct sockaddr_in6* si = (struct sockaddr_in6*) addr;
            si->sin6_family = sock->family;
            si->sin6_port = htons( sock->port );
            memcpy( &si->sin6_addr, sock->addr.v6, IPV6_SIZE );
            retval = 0;
        }
    }

    return retval;
}


size_t encode_PACKET( uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common,
                   const n2n_PACKET_t * pkt )
{
    size_t retval=0;
    retval += encode_common( base, idx, common );
    retval += encode_mac( base, idx, pkt->srcMac );
    retval += encode_mac( base, idx, pkt->dstMac );
    if ( 0 != pkt->sock.family )
    {
        retval += encode_sock( base, idx, &(pkt->sock) );
    }
    retval += encode_uint16( base, idx, pkt->transform );

    return retval;
}


size_t decode_PACKET( n2n_PACKET_t * pkt,
                   const n2n_common_t * cmn, /* info on how to interpret it */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx )
{
    size_t retval=0;
    memset( pkt, 0, sizeof(n2n_PACKET_t) );
    retval += decode_mac( pkt->srcMac, base, rem, idx );
    retval += decode_mac( pkt->dstMac, base, rem, idx );

    if ( cmn->flags & N2N_FLAGS_SOCKET )
    {
        retval += decode_sock( &(pkt->sock), base, rem, idx );
    }

    retval += decode_uint16( &(pkt->transform), base, rem, idx );

    return retval;
}

size_t encode_PROBE( uint8_t * base,
                     size_t * idx,
                     const n2n_common_t * common,
                     const n2n_PROBE_t * probe )
{
    size_t retval=0;
    retval += encode_common( base, idx, common );
    retval += encode_mac( base, idx, probe->srcMac );
    retval += encode_mac( base, idx, probe->dstMac );
    return retval;
}

size_t decode_PROBE( n2n_PROBE_t * probe,
                     const n2n_common_t * cmn,
                     const uint8_t * base,
                     size_t * rem,
                     size_t * idx )
{
    size_t retval=0;
    memset( probe, 0, sizeof(n2n_PROBE_t) );
    retval += decode_mac( probe->srcMac, base, rem, idx );
    retval += decode_mac( probe->dstMac, base, rem, idx );
    return retval;
}

size_t encode_PROBE_ACK( uint8_t * base,
                         size_t * idx,
                         const n2n_common_t * common,
                         const n2n_PROBE_ACK_t * ack )
{
    size_t retval=0;
    retval += encode_common( base, idx, common );
    retval += encode_mac( base, idx, ack->srcMac );
    retval += encode_mac( base, idx, ack->dstMac );
    retval += encode_sock( base, idx, &(ack->observed_addr) );
    return retval;
}

size_t decode_PROBE_ACK( n2n_PROBE_ACK_t * ack,
                         const n2n_common_t * cmn,
                         const uint8_t * base,
                         size_t * rem,
                         size_t * idx )
{
    size_t retval=0;
    memset( ack, 0, sizeof(n2n_PROBE_ACK_t) );
    retval += decode_mac( ack->srcMac, base, rem, idx );
    retval += decode_mac( ack->dstMac, base, rem, idx );
    retval += decode_sock( &(ack->observed_addr), base, rem, idx );
    return retval;
}


size_t encode_PEER_INFO( uint8_t * base, size_t * idx,
                         const n2n_common_t * common,
                         const n2n_PEER_INFO_t * pkt )
{
    size_t retval = 0;
    retval += encode_common( base, idx, common );
    retval += encode_uint16( base, idx, pkt->aflags );
    retval += encode_mac( base, idx, pkt->mac );
    retval += encode_sock( base, idx, &pkt->sockets[0] );
    if ( pkt->aflags & N2N_AFLAGS_LOCAL_SOCKET )
        retval += encode_sock( base, idx, &pkt->sockets[1] );
    if ( pkt->aflags & N2N_AFLAGS_IPV6_SOCKET )
        retval += encode_sock( base, idx, &pkt->sock6 );
    /* Append version and os_name for backward compat; old edges ignore extra bytes */
    retval += encode_buf( base, idx, pkt->version, sizeof(pkt->version) );
    retval += encode_buf( base, idx, pkt->os_name, sizeof(pkt->os_name) );
    return retval;
}

size_t decode_PEER_INFO( n2n_PEER_INFO_t * pkt,
                         const n2n_common_t * cmn,
                         const uint8_t * base,
                         size_t * rem, size_t * idx )
{
    size_t retval = 0;
    memset( pkt, 0, sizeof(*pkt) );
    retval += decode_uint16( &pkt->aflags, base, rem, idx );
    retval += decode_mac( pkt->mac, base, rem, idx );
    retval += decode_sock( &pkt->sockets[0], base, rem, idx );
    if ( (pkt->aflags & N2N_AFLAGS_LOCAL_SOCKET) && *rem >= 8 )
        retval += decode_sock( &pkt->sockets[1], base, rem, idx );
    if ( (pkt->aflags & N2N_AFLAGS_IPV6_SOCKET) && *rem >= 8 )
        retval += decode_sock( &pkt->sock6, base, rem, idx );
    /* version and os_name: optional, appended by new supernodes */
    if ( *rem >= sizeof(pkt->version) )
        retval += decode_buf( pkt->version, sizeof(pkt->version), base, rem, idx );
    if ( *rem >= sizeof(pkt->os_name) )
        retval += decode_buf( pkt->os_name, sizeof(pkt->os_name), base, rem, idx );
    return retval;
}

size_t encode_QUERY_PEER( uint8_t * base, size_t * idx,
                          const n2n_common_t * common,
                          const n2n_QUERY_PEER_t * pkt )
{
    size_t retval = 0;
    retval += encode_common( base, idx, common );
    retval += encode_mac( base, idx, pkt->srcMac );
    retval += encode_mac( base, idx, pkt->targetMac );
    return retval;
}

size_t decode_QUERY_PEER( n2n_QUERY_PEER_t * pkt,
                          const n2n_common_t * cmn,
                          const uint8_t * base,
                          size_t * rem, size_t * idx )
{
    size_t retval = 0;
    memset( pkt, 0, sizeof(*pkt) );
    retval += decode_mac( pkt->srcMac, base, rem, idx );
    retval += decode_mac( pkt->targetMac, base, rem, idx );
    return retval;
}
