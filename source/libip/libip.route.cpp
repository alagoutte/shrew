
/*
 * Copyright (c) 2007
 *      Shrew Soft Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the software and any
 *    accompanying software that uses the software.  The source code
 *    must either be included in the distribution or be available for no
 *    more than the cost of distribution plus a nominal fee, and must be
 *    freely redistributable under reasonable conditions.  For an
 *    executable file, complete source code means the source code for all
 *    modules it contains.  It does not include source code for modules or
 *    files that typically accompany the major components of the operating
 *    system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY SHREW SOFT INC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED.  IN NO EVENT SHALL SHREW SOFT INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * AUTHOR : Matthew Grooms
 *          mgrooms@shrew.net
 *
 */

#include "libip.h"

//==============================================================================
// Route list class
//==============================================================================

_IPROUTE_LIST::_IPROUTE_LIST()
{
}

_IPROUTE_LIST::~_IPROUTE_LIST()
{
	clean();
}

bool _IPROUTE_LIST::add( in_addr & iface, in_addr & addr, in_addr & mask, in_addr & next )
{
	IPROUTE_ENTRY * route = new IPROUTE_ENTRY;
	if( route == NULL )
		return false;

	route->iface = iface;
	route->addr = addr;
	route->mask = mask;
	route->next = next;

	add_entry( route );

    return true;
}

bool _IPROUTE_LIST::get( in_addr & iface, in_addr & addr, in_addr & mask, in_addr & next )
{
	long index = 0;
	for( ; index < count(); index++ )
	{
		IPROUTE_ENTRY * route = static_cast<IPROUTE_ENTRY*>( get_entry( index ) );
		assert( route != NULL );

		if( route->addr.s_addr != addr.s_addr )
			continue;

		if( route->mask.s_addr != mask.s_addr )
			continue;

		iface = route->iface;
		addr = route->addr;
		mask = route->mask;
		next = route->next;

		del_entry( route );
		delete route;

		return true;
	}

	return false;
}

long _IPROUTE_LIST::count()
{
    return IDB_LIST::count();
}

void _IPROUTE_LIST::clean()
{
    IDB_LIST::clean();
}

//==============================================================================
// BSD specific route handling
//==============================================================================

#ifndef __linux__

//
// NetBSD compatability ( obtained from FreeBSD )
//

#ifndef SA_SIZE
#define SA_SIZE(sa)                                             \
    (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?      \
        sizeof(long)            :                               \
        1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

//
// BSD route message wrapper struct
//

typedef struct _RTMSG
{
	rt_msghdr	hdr;
	char		msg[ 1024 ];

}RTMSG;

//
// BSD route message result function
//

bool rtmsg_result( RTMSG * rtmsg, in_addr * dst, in_addr * gwy, in_addr * msk, in_addr * ifa )
{
	char *	cp = rtmsg->msg;

	for( int i = 1; i; i <<= 1 )
	{
		if( i & rtmsg->hdr.rtm_addrs )
		{
			struct sockaddr * sa = ( struct sockaddr * ) cp;

			switch( i )
			{
				case RTA_DST:
					if( dst != NULL )
						*dst = ( ( sockaddr_in * ) cp )->sin_addr;
					break;

				case RTA_GATEWAY:
					if( gwy != NULL )
						*gwy = ( ( sockaddr_in * ) cp )->sin_addr;
					break;

				case RTA_NETMASK:
					if( msk != NULL )
						*msk = ( ( sockaddr_in * ) cp )->sin_addr;
					break;

				case RTA_IFP:
					break;

				case RTA_IFA:
					if( ifa != NULL )
						*ifa = ( ( sockaddr_in * ) cp )->sin_addr;
					break;
			}

			cp += SA_SIZE( sa );
		}
	}

	return true;
}

//
// BSD IPROUTE class
//

_IPROUTE::_IPROUTE()
{
	seq = 0;
}

// add a route

bool _IPROUTE::add( in_addr & iface, bool local, in_addr addr, in_addr mask, in_addr next )
{
	int s = socket( PF_ROUTE, SOCK_RAW, 0 );
	if( s == -1 )
		return false;

	// set route message header

	RTMSG rtmsg;
	memset( &rtmsg, 0, sizeof( rtmsg ) );

	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_seq = ++seq;
	rtmsg.hdr.rtm_type = RTM_ADD;
	rtmsg.hdr.rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY;
	rtmsg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY;

	rtmsg.hdr.rtm_addrs |= RTA_NETMASK;
		
	// add route destination

	sockaddr_in * dst = ( sockaddr_in * ) rtmsg.msg;

	dst->sin_family = AF_INET;
	dst->sin_len = sizeof( sockaddr_in );
	dst->sin_addr = addr;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route gateway

	sockaddr_in * gwy = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	gwy->sin_family = AF_INET;
	gwy->sin_len = sizeof( sockaddr_in );
	gwy->sin_addr = next;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route netmask

	sockaddr_in * msk = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	msk->sin_family = AF_INET;
	msk->sin_len = sizeof( sockaddr_in );
	msk->sin_addr = mask;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// send route add message

	long l = rtmsg.hdr.rtm_msglen += sizeof( rtmsg.hdr );

	if( write( s, ( char * ) &rtmsg, l ) < 0 )
	{
		close( s );
		return false;
	}

	close( s );

	return true;
}

// delete a route 

bool _IPROUTE::del( in_addr & iface, bool local, in_addr addr, in_addr mask, in_addr next )
{
	int s = socket( PF_ROUTE, SOCK_RAW, 0 );
	if( s == -1 )
		return false;

	// set route message header

	RTMSG rtmsg;
	memset( &rtmsg, 0, sizeof( rtmsg ) );

	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_seq = ++seq;
	rtmsg.hdr.rtm_type = RTM_DELETE;
	rtmsg.hdr.rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY;
	rtmsg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY;

	rtmsg.hdr.rtm_addrs |= RTA_NETMASK;
		
	// add route destination

	sockaddr_in * dst = ( sockaddr_in * ) rtmsg.msg;

	dst->sin_family = AF_INET;
	dst->sin_len = sizeof( sockaddr_in );
	dst->sin_addr = addr;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route gateway

	sockaddr_in * gwy = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	gwy->sin_family = AF_INET;
	gwy->sin_len = sizeof( sockaddr_in );
	gwy->sin_addr = next;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route netmask

	sockaddr_in * msk = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	msk->sin_family = AF_INET;
	msk->sin_len = sizeof( sockaddr_in );
	msk->sin_addr = mask;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// send route delete message

	long l = rtmsg.hdr.rtm_msglen += sizeof( rtmsg.hdr );

	if( write( s, ( char * ) &rtmsg, l ) < 0 )
	{
		close( s );
		return false;
	}

	close( s );

	return true;
}

// get a route ( by addr and mask )

bool _IPROUTE::get( in_addr & iface, bool & local, in_addr & addr, in_addr & mask, in_addr & next )
{
	int s = socket( PF_ROUTE, SOCK_RAW, 0 );
	if( s == -1 )
		return false;

	// set route message header

	RTMSG rtmsg;
	memset( &rtmsg, 0, sizeof( rtmsg ) );

	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_type = RTM_GET;
	rtmsg.hdr.rtm_seq = ++seq;
	rtmsg.hdr.rtm_flags = RTF_UP | RTF_STATIC | RTF_STATIC;
	rtmsg.hdr.rtm_addrs = RTA_DST;

	// add route destination

	sockaddr_in * dst = ( sockaddr_in * ) rtmsg.msg;

	dst->sin_family = AF_INET;
	dst->sin_len = sizeof( sockaddr_in );
	dst->sin_addr = addr;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route netmask

	sockaddr_in * msk = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	msk->sin_family = AF_INET;
	msk->sin_len = sizeof( sockaddr_in );
	msk->sin_addr = mask;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// send route get message

	long l = rtmsg.hdr.rtm_msglen += sizeof( rtmsg.hdr );

	if( write( s, ( char * ) &rtmsg, l ) < 0 )
	{
		close( s );
		return false;
	}

	int pid = getpid();

	// read route result message

	do
	{
		l = read( s, ( char * ) &rtmsg, sizeof( rtmsg ) );
		if( l < 0 )
		{
			close( s );
			return false;
		}
	}
	while( ( rtmsg.hdr.rtm_seq != seq ) ||
		   ( rtmsg.hdr.rtm_pid != pid ) );

	close( s );

	if( ( rtmsg.hdr.rtm_errno ) ||
		( rtmsg.hdr.rtm_msglen > l ) ||
		( rtmsg.hdr.rtm_version != RTM_VERSION ) )
		return false;

	return rtmsg_result( &rtmsg, &addr, &next, &mask, &iface );
}

// get best route ( by address )

bool _IPROUTE::best( in_addr & iface, bool & local, in_addr & addr, in_addr & mask, in_addr & next )
{
	int s = socket( PF_ROUTE, SOCK_RAW, 0 );
	if( s == -1 )
		return false;

	// set route message header

	RTMSG rtmsg;
	memset( &rtmsg, 0, sizeof( rtmsg ) );

	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_type = RTM_GET;
	rtmsg.hdr.rtm_seq = ++seq;
	rtmsg.hdr.rtm_flags = RTF_UP | RTF_HOST | RTF_STATIC;
	rtmsg.hdr.rtm_addrs = RTA_DST | RTA_IFP;

	// add route destination

	sockaddr_in * dst = ( sockaddr_in * ) rtmsg.msg;

	dst->sin_family = AF_INET;
	dst->sin_len = sizeof( sockaddr_in );
	dst->sin_addr = addr;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route interface

	sockaddr_dl * ifp = ( sockaddr_dl * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	ifp->sdl_family = AF_LINK;
	ifp->sdl_len = sizeof( sockaddr_dl );

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_dl );

	// send route get message

	long l = rtmsg.hdr.rtm_msglen += sizeof( rtmsg.hdr );

	if( write( s, ( char * ) &rtmsg, l ) < 0 )
	{
		close( s );
		return false;
	}

	int pid = getpid();

	// read route result message

	do
	{
		l = read( s, ( char * ) &rtmsg, sizeof( rtmsg ) );
		if( l < 0 )
		{
			close( s );
			return false;
		}
	}
	while( ( rtmsg.hdr.rtm_seq != seq ) ||
		   ( rtmsg.hdr.rtm_pid != pid ) );

	close( s );

	if( ( rtmsg.hdr.rtm_errno ) ||
		( rtmsg.hdr.rtm_msglen > l ) ||
		( rtmsg.hdr.rtm_version != RTM_VERSION ) )
		return false;

	return rtmsg_result( &rtmsg, &addr, &next, &mask, &iface );
}

//
// BSD unix systems don't support multiple routes
// to the same destination network. We go for the
// lowest common denominator. Cache the existing
// route information and delete the existing route
// on increment. Retrieve and restore the previous
// route on decrement. 
//

// decrement route costs

bool _IPROUTE::increment( in_addr addr, in_addr mask )
{
	//
	// locate the most specific route for the destination
	//

	in_addr	del_iface;
	bool	del_local;
	in_addr	del_addr;
	in_addr	del_mask;
	in_addr	del_next;

	char txt_iface[ 24 ];
	char txt_addr[ 24 ];
	char txt_mask[ 24 ];
	char txt_next[ 24 ];
	strcpy( txt_addr, inet_ntoa( addr ));
	strcpy( txt_mask, inet_ntoa( mask ));

	if( !get( del_iface, del_local, del_addr, del_mask, del_next ) )
		return true;

	//
	// does this route match the destination exactly
	//

	if( del_addr.s_addr != addr.s_addr )
		return true;

	if( del_mask.s_addr != mask.s_addr )
		return true;

	//
	// add a route entry to our route list
	//

	route_list.add( del_iface, del_addr, del_mask, del_next );

	//
	// delete the existing route
	//

	return del( del_iface, del_local, del_addr, del_mask, del_next );
}

// decrement route costs

bool _IPROUTE::decrement( in_addr addr, in_addr mask )
{
	//
	// locate the cached route info for the destination
	//

	in_addr add_iface;
	bool	add_local;
	in_addr	add_addr = addr;
	in_addr	add_mask = mask;
	in_addr	add_next;

	if( !route_list.get( add_iface, add_addr, add_mask, add_next ) )
		return true;

	//
	// delete the restore the route for the destination
	//

	return add( add_iface, add_local, add_addr, add_mask, add_next );
}

#else

//==============================================================================
// Linux specific route handling
//==============================================================================

//
// netlink message wrapper struct
//

typedef struct _NLMSG
{
    struct nlmsghdr	hdr;
    struct rtmsg	msg;
    char		buff[ 1024 ];

}NLMSG;

//
// Linux IPROUTE class
//

_IPROUTE::_IPROUTE()
{
	seq = 0;
}

//
// Linux generic route message functions
//

unsigned int mask_to_prefix( in_addr mask )
{
	unsigned int plen = 0;
	unsigned int hmsk = ntohl( mask.s_addr );

	plen = 0;

	while( hmsk & 0x80000000 )
	{
		hmsk <<= 1;
		plen++;
	}

	return plen;
}

unsigned int prefix_to_mask( int plen )
{
	unsigned int mask = 0;

	for( int i = 0; i < plen; i++ )
	{
		mask >>= 1;
                mask |= 0x80000000;
	}

	return htonl( mask );
}

int rtmsg_send( NLMSG * nlmsg )
{
	int s = socket( PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE );
	if( s < 0 )
		return -1;

	static struct sockaddr_nl sanl;
	memset( &sanl, 0, sizeof( sanl ) );
	sanl.nl_family = AF_NETLINK;
	sanl.nl_pid = getpid();

	if( bind( s, ( struct sockaddr * ) &sanl, sizeof( sanl ) ) < 0 )
	{
		close( s );
		return -2;
	}

	if( send( s, nlmsg, nlmsg->hdr.nlmsg_len, 0 ) < 0 )
	{
		close( s );
		return -3;
	}

	return s;
}

int rtmsg_recv( int s, in_addr * dst, in_addr * gwy, in_addr * msk, in_addr * ifa )
{
	char	buf[ sizeof( NLMSG ) ];
	memset( buf, 0, sizeof( buf ) );

	char *	p = buf;
	int	nll = 0;
	int	rtl = 0;

	struct nlmsghdr * nlp;
	struct rtmsg * rtp;
	struct rtattr * rtap;

	int	rtn;

	while( true )
	{
		rtn = recv( s, p, sizeof( buf ) - nll, 0 );
		if( !rtn )
			break;

		nlp = ( struct nlmsghdr * ) p;

		if( nlp->nlmsg_type == NLMSG_ERROR )
			return -1;

		if( nlp->nlmsg_type == NLMSG_DONE )
			break;

		// increment the buffer pointer to place
		// next message
		p += rtn;

		// increment the total size by the size of
		// the last received message
		nll += rtn;

		printf( "XX : RTMSG %d RECEIVED ( %d BYTES )\n", nlp->nlmsg_type, rtn );
	}

	nlp = ( struct nlmsghdr * ) buf;

	for( ; NLMSG_OK( nlp, nll ); nlp = NLMSG_NEXT( nlp, nll ) )
	{
		rtp = ( struct rtmsg * ) NLMSG_DATA( nlp );

		if( rtp->rtm_table != RT_TABLE_MAIN )
			continue;

		rtap = ( struct rtattr * ) RTM_RTA( rtp );
		rtl = RTM_PAYLOAD( nlp );

		for( ; RTA_OK( rtap, rtl) ; rtap = RTA_NEXT( rtap, rtl ) )
		{
			switch( rtap->rta_type )
			{
				case RTA_DST:
				{
					memcpy( dst, RTA_DATA( rtap ), sizeof( *dst ) );
					msk->s_addr = prefix_to_mask( rtp->rtm_dst_len );
					break;
				}

				case RTA_GATEWAY:
					memcpy( gwy, RTA_DATA( rtap ), sizeof( *gwy ) );
					break;

				case RTA_OIF:
				{
					struct ifreq ifr;

					int sock = socket( PF_PACKET, SOCK_RAW, 0 );

					ifr.ifr_ifindex = *( ( int * ) RTA_DATA( rtap ) );
					ioctl( sock, SIOCGIFNAME, &ifr );

					ifr.ifr_addr.sa_family = AF_INET;
					ioctl( sock, SIOCGIFADDR, &ifr );

					memcpy( ifa, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof( *ifa ) );

					close( sock );
				}

				default:
					break;
			}
		}
	}

	return 0;
}

// add a route

bool _IPROUTE::add( in_addr & iface, bool local, in_addr addr, in_addr mask, in_addr next )
{
	// set route message header

	NLMSG nlmsg;
	memset( &nlmsg, 0, sizeof( nlmsg ) );

	nlmsg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	nlmsg.hdr.nlmsg_type = RTM_NEWROUTE;

	nlmsg.msg.rtm_family = AF_INET;
	nlmsg.msg.rtm_table = RT_TABLE_MAIN;
	nlmsg.msg.rtm_protocol = RTPROT_STATIC;
	nlmsg.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	nlmsg.msg.rtm_type = RTN_UNICAST;

	// add route destination

	struct rtattr * rta = ( struct rtattr * ) nlmsg.buff;

	rta->rta_type = RTA_DST;
	rta->rta_len = sizeof( struct rtattr ) + sizeof( addr );
	memcpy( ( ( char * ) rta ) + sizeof( struct rtattr ), &addr, sizeof( addr ) );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// add route gateway

	rta = ( struct rtattr * )( nlmsg.buff + nlmsg.hdr.nlmsg_len );

	rta->rta_type = RTA_GATEWAY;
	rta->rta_len = sizeof( struct rtattr ) + sizeof( next );
	memcpy( ( ( char * ) rta ) + sizeof( struct rtattr ), &next, sizeof( next ) );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// set route network mask

	nlmsg.msg.rtm_dst_len = mask_to_prefix( mask );

	// set final message length

	nlmsg.hdr.nlmsg_len += sizeof( struct rtmsg );
	nlmsg.hdr.nlmsg_len = NLMSG_LENGTH( nlmsg.hdr.nlmsg_len );

	int s = rtmsg_send( &nlmsg );
	if( s < 0 )
		return false;

	close( s );

	return true;
}

// delete a route

bool _IPROUTE::del( in_addr & iface, bool local, in_addr addr, in_addr mask, in_addr next )
{
	// set route message header

	NLMSG nlmsg;
	memset( &nlmsg, 0, sizeof( nlmsg ) );

	nlmsg.hdr.nlmsg_flags = NLM_F_REQUEST;
	nlmsg.hdr.nlmsg_type = RTM_DELROUTE;

	nlmsg.msg.rtm_family = AF_INET;
	nlmsg.msg.rtm_table = RT_TABLE_MAIN;
	nlmsg.msg.rtm_protocol = RTPROT_STATIC;
	nlmsg.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	nlmsg.msg.rtm_type = RTN_UNICAST;

	// add route destination

	struct rtattr * rta = ( struct rtattr * ) nlmsg.buff;

	rta->rta_type = RTA_DST;
	rta->rta_len = sizeof( struct rtattr ) + sizeof( addr );
	memcpy( ( ( char * ) rta ) + sizeof( struct rtattr ), &addr, sizeof( addr ) );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// add route gateway

	rta = ( struct rtattr * )( nlmsg.buff + nlmsg.hdr.nlmsg_len );

	rta->rta_type = RTA_GATEWAY;
	rta->rta_len = sizeof( struct rtattr ) + sizeof( next );
	memcpy( ( ( char * ) rta ) + sizeof( struct rtattr ), &next, sizeof( next ) );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// set route network mask

	nlmsg.msg.rtm_dst_len = mask_to_prefix( mask );

	// set final message length

	nlmsg.hdr.nlmsg_len += sizeof( struct rtmsg );
	nlmsg.hdr.nlmsg_len = NLMSG_LENGTH( nlmsg.hdr.nlmsg_len );

	int s = rtmsg_send( &nlmsg );
	if( s < 0 )
		return false;

	close( s );

	return true;
}

// get a route ( by addr and mask )

bool _IPROUTE::get( in_addr & iface, bool & local, in_addr & addr, in_addr & mask, in_addr & next )
{
	// set route message header

	NLMSG nlmsg;
	memset( &nlmsg, 0, sizeof( nlmsg ) );

	nlmsg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
	nlmsg.hdr.nlmsg_type = RTM_GETROUTE;

	nlmsg.msg.rtm_family = AF_INET;
	nlmsg.msg.rtm_table = RT_TABLE_MAIN;
	nlmsg.msg.rtm_protocol = RTPROT_STATIC;
	nlmsg.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	nlmsg.msg.rtm_type = RTN_UNICAST;

	// add route destination

	struct rtattr * rta = ( struct rtattr * ) nlmsg.buff;

	rta->rta_type = RTA_DST;
	rta->rta_len = sizeof( struct rtattr ) + sizeof( addr );
	memcpy( ( ( char * ) rta ) + sizeof( struct rtattr ), &addr, sizeof( addr ) );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// set route network mask

	nlmsg.msg.rtm_dst_len = 32; //mask_to_prefix( mask );

	// set final message length

	nlmsg.hdr.nlmsg_len += sizeof( struct rtmsg );
	nlmsg.hdr.nlmsg_len = NLMSG_LENGTH( nlmsg.hdr.nlmsg_len );

	int s = rtmsg_send( &nlmsg );
	if( s < 0 )
		return false;

	int r = rtmsg_recv( s, &addr, &next, &mask, &iface );

	close( s );

	return ( r >= 0 );
}

// get best route ( by address )

bool _IPROUTE::best( in_addr & iface, bool & local, in_addr & addr, in_addr & mask, in_addr & next )
{
	// set route message header

	NLMSG nlmsg;
	memset( &nlmsg, 0, sizeof( nlmsg ) );

	nlmsg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
	nlmsg.hdr.nlmsg_type = RTM_GETROUTE;

	nlmsg.msg.rtm_family = AF_INET;
	nlmsg.msg.rtm_table = RT_TABLE_MAIN;
	nlmsg.msg.rtm_protocol = RTPROT_STATIC;
	nlmsg.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	nlmsg.msg.rtm_type = RTN_UNICAST;

	// add route destination

	struct rtattr * rta = ( struct rtattr * ) nlmsg.buff;

	rta->rta_type = RTA_DST;
	rta->rta_len = sizeof( struct rtattr ) + sizeof( addr );
	memcpy( ( ( char * ) rta ) + sizeof( struct rtattr ), &addr, sizeof( addr ) );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// set route network mask

	nlmsg.msg.rtm_dst_len = 32;

	// set final message length

	nlmsg.hdr.nlmsg_len += sizeof( struct rtmsg );
	nlmsg.hdr.nlmsg_len = NLMSG_LENGTH( nlmsg.hdr.nlmsg_len );

	int s = rtmsg_send( &nlmsg );
	if( s < 0 )
		return false;

	int r = rtmsg_recv( s, &addr, &next, &mask, &iface );

	close( s );

	return ( r >= 0 );
}

//
// Linux systems appear to give priority to newer
// routes so this is a no-op for now.
//

// decrement route costs

bool _IPROUTE::increment( in_addr addr, in_addr mask )
{
}

// decrement route costs

bool _IPROUTE::decrement( in_addr addr, in_addr mask )
{
}

#endif

//==============================================================================
// Shared unix route functions
//==============================================================================
//

// flush arp table

bool _IPROUTE::flusharp( in_addr & iface )
{
	return true;
}
