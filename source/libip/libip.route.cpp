
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

void text_route( IPROUTE_ENTRY & route, char * text, bool dstonly = false )
{
	char txt_iface[ 24 ];
	char txt_addr[ 24 ];
	char txt_mask[ 24 ];
	char txt_next[ 24 ];

	if( dstonly )
	{
		strcpy( txt_addr, inet_ntoa( route.addr ));
		strcpy( txt_mask, inet_ntoa( route.mask ));

		sprintf( text, "%s/%s",
			txt_addr, txt_mask );
	}
	else
	{
		strcpy( txt_iface, inet_ntoa( route.iface ));
		strcpy( txt_addr, inet_ntoa( route.addr ));
		strcpy( txt_mask, inet_ntoa( route.mask ));
		strcpy( txt_next, inet_ntoa( route.next ));

		sprintf( text, "%s/%s gw %s if %s",
			txt_addr, txt_mask, txt_next, txt_iface );
	}
}

//==============================================================================
// Route entry class
//==============================================================================

_IPROUTE_ENTRY::_IPROUTE_ENTRY()
{
	local = false;
	memset( &iface, 0, sizeof( in_addr ) );
	memset( &addr, 0, sizeof( in_addr ) );
	memset( &mask, 0, sizeof( in_addr ) );
	memset( &next, 0, sizeof( in_addr ) );
}

_IPROUTE_ENTRY & _IPROUTE_ENTRY::operator =( _IPROUTE_ENTRY & entry )
{
	local = entry.local;
	memcpy( &iface, &entry.iface, sizeof( in_addr ) );
	memcpy( &addr, &entry.addr, sizeof( in_addr ) );
	memcpy( &mask, &entry.mask, sizeof( in_addr ) );
	memcpy( &next, &entry.next, sizeof( in_addr ) );

    return *this;
}

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

bool _IPROUTE_LIST::add( IPROUTE_ENTRY & route )
{
	IPROUTE_ENTRY * tmp_route = new IPROUTE_ENTRY;
	if( tmp_route == NULL )
		return false;

	*tmp_route = route;

	add_entry( tmp_route );

    return true;
}

bool _IPROUTE_LIST::get( IPROUTE_ENTRY & route )
{
	long index = 0;
	for( ; index < count(); index++ )
	{
		IPROUTE_ENTRY * tmp_route = static_cast<IPROUTE_ENTRY*>( get_entry( index ) );
		assert( tmp_route != NULL );

		if( tmp_route->addr.s_addr != route.addr.s_addr )
			continue;

		if( tmp_route->mask.s_addr != route.mask.s_addr )
			continue;

		route = *tmp_route;

		del_entry( tmp_route );
		delete tmp_route;

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
// BSD macros used to simplify route address processing
//

#ifdef __APPLE__
#define RT_ROUNDUP(a)		((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#endif

#ifndef RT_ROUNDUP
#define RT_ROUNDUP(a)		((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

//
// BSD route message wrapper struct
//

typedef struct _RTMSG
{
	rt_msghdr	hdr;
	char		msg[ 2048 ];

}RTMSG;

//
// BSD route message send request function
//

int rtmsg_send( RTMSG * rtmsg )
{
	int s = socket( PF_ROUTE, SOCK_RAW, 0 );
	if( s < 0 )
		return -1;

	long l = rtmsg->hdr.rtm_msglen += sizeof( rtmsg->hdr );

	if( write( s, rtmsg, l ) < 0 )
	{
		close( s );
		return -2;
	}

	return s;
}

//
// BSD route message receive result function
//

bool rtmsg_recv( int s, int seq, IPROUTE_ENTRY * route )
{
	RTMSG rtmsg;
	memset( &rtmsg, 0, sizeof( rtmsg ) );

	// read route result message

	pid_t pid = getpid();
	long len;

	do
	{
		len = read( s, &rtmsg, sizeof( rtmsg ) );
		if( len < 0 )
		{
			close( s );
			return false;
		}
	}
	while( ( rtmsg.hdr.rtm_seq != seq ) || ( rtmsg.hdr.rtm_pid != pid ) );

	close( s );

	if( ( rtmsg.hdr.rtm_errno ) || ( rtmsg.hdr.rtm_msglen > len ) ||
		( rtmsg.hdr.rtm_version != RTM_VERSION ) )
		return false;

	route->local = true;
	if( rtmsg.hdr.rtm_flags & RTF_GATEWAY )
		route->local = false;

	char *	cp = rtmsg.msg;
	long	ml = rtmsg.hdr.rtm_msglen;

	for( int i = 1; i; i <<= 1 )
	{
		if( ml <= 0 )
			break;

		if( !( rtmsg.hdr.rtm_addrs & i ) )
			continue;

//		printf( "XXXXXXXXX ml = %lu XXXXXXXX\n", ml );

		struct sockaddr * sa = ( struct sockaddr * ) cp;
		struct sockaddr_dl * dl = ( struct sockaddr_dl * ) sa;

		switch( i )
		{
			case RTA_DST:
//				printf( "XXXXXXXXX RTA_DST->sa_len = %d/%lu XXXXXXXX\n",
//					sa->sa_len, RT_ROUNDUP( sa->sa_len ) );
				if( sa->sa_family == AF_INET )
				{
					route->addr = ( ( sockaddr_in * ) cp )->sin_addr;
//					printf( "XXXXXXXXX route->addr = %s XXXXXXXX\n",
//						inet_ntoa( route->addr ) );
				}
				break;

			case RTA_GATEWAY:
//				printf( "XXXXXXXXX RTA_GATEWAY->sa_len = %d/%lu XXXXXXXX\n",
//					sa->sa_len, RT_ROUNDUP( sa->sa_len ) );
				if( sa->sa_family == AF_INET )
				{
					route->next = ( ( sockaddr_in * ) cp )->sin_addr;
//					printf( "XXXXXXXXX route->next = %s XXXXXXXX\n",
//						inet_ntoa( route->next ) );
				}
				break;

			case RTA_NETMASK:
//				printf( "XXXXXXXXX RTA_NETMASK->sa_len = %d/%lu XXXXXXXX\n",
//					sa->sa_len, RT_ROUNDUP( sa->sa_len ) );
				if( sa->sa_family == AF_INET )
				{
					route->mask = ( ( sockaddr_in * ) cp )->sin_addr;
//					printf( "XXXXXXXXX route->mask = %s XXXXXXXX\n",
//						inet_ntoa( route->mask ) );
				}
				break;

			case RTA_GENMASK:
//				printf( "XXXXXXXXX RTA_GENMASK->sa_len = %d/%lu XXXXXXXX\n",
//					sa->sa_len, RT_ROUNDUP( sa->sa_len ) );
				break;

			case RTA_IFP:
//				printf( "XXXXXXXXX RTA_IFP->sa_len = %d/%lu RTA_IFP->sdl_nlen = %d ( %s ) XXXXXXXX\n",
//					sa->sa_len, RT_ROUNDUP( sa->sa_len ), dl->sdl_nlen, dl->sdl_data );
				break;

			case RTA_IFA:
//				printf( "XXXXXXXXX RTA_IFA->sa_len = %d/%lu XXXXXXXX\n",
//					sa->sa_len, RT_ROUNDUP( sa->sa_len ) );
				if( sa->sa_family == AF_INET )
				{
					route->iface = ( ( sockaddr_in * ) cp )->sin_addr;
//					printf( "XXXXXXXXX route->iface = %s XXXXXXXX\n",
//						inet_ntoa( route->iface ) );
				}
				break;

			default:
//				printf( "XXXXXXXXX 0x%04x->sa_len = %d/%lu XXXXXXXX\n", i,
//					sa->sa_len, RT_ROUNDUP( sa->sa_len ) );
				break;
		}

		cp += RT_ROUNDUP( sa->sa_len );
		ml -= RT_ROUNDUP( sa->sa_len );
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

bool _IPROUTE::add( IPROUTE_ENTRY & route )
{
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
	dst->sin_addr = route.addr;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route gateway

	sockaddr_in * gwy = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	gwy->sin_family = AF_INET;
	gwy->sin_len = sizeof( sockaddr_in );
	gwy->sin_addr = route.next;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route netmask

	sockaddr_in * msk = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	msk->sin_family = AF_INET;
	msk->sin_len = sizeof( sockaddr_in );
	msk->sin_addr = route.mask;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// send route add message

	int s = rtmsg_send( &rtmsg );
	if( s < 0 )
		return false;

	close( s );

	return true;
}

// delete a route 

bool _IPROUTE::del( IPROUTE_ENTRY & route )
{
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
	dst->sin_addr = route.addr;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route gateway

	sockaddr_in * gwy = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	gwy->sin_family = AF_INET;
	gwy->sin_len = sizeof( sockaddr_in );
	gwy->sin_addr = route.next;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route netmask

	sockaddr_in * msk = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	msk->sin_family = AF_INET;
	msk->sin_len = sizeof( sockaddr_in );
	msk->sin_addr = route.mask;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// send route delete message

	int s = rtmsg_send( &rtmsg );
	if( s < 0 )
		return false;

	close( s );

	return true;
}

// get a route ( by addr and mask )

bool _IPROUTE::get( IPROUTE_ENTRY & route )
{
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
	dst->sin_addr = route.addr;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route netmask

	sockaddr_in * msk = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	msk->sin_family = AF_INET;
	msk->sin_len = sizeof( sockaddr_in );
	msk->sin_addr = route.mask;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// send route get message

	int s = rtmsg_send( &rtmsg );
	if( s < 0 )
		return false;

	// read route result message

	return rtmsg_recv( s, seq, &route );
}

// get best route ( by address )

bool _IPROUTE::best( IPROUTE_ENTRY & route )
{
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
	dst->sin_addr = route.addr;

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );

	// add route interface

	sockaddr_dl * ifp = ( sockaddr_dl * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

	ifp->sdl_family = AF_LINK;
	ifp->sdl_len = sizeof( sockaddr_dl );

	rtmsg.hdr.rtm_msglen += sizeof( sockaddr_dl );

	// send route get message

	int s = rtmsg_send( &rtmsg );
	if( s < 0 )
		return false;

	// read route result message

	return rtmsg_recv( s, seq, &route );
}

//
// BSD unix systems don't support multiple routes
// to the same destination network. We go for the
// lowest common denominator. Cache the existing
// route information and delete the existing route
// on increment. Retrieve and restore the previous
// route on decrement. 
//

// increment route costs

bool _IPROUTE::increment( in_addr addr, in_addr mask )
{
	//
	// locate the most specific route for the destination
	//

	IPROUTE_ENTRY route;
	route.addr = addr;
	route.mask = mask;

	if( !get( route ) )
		return true;

	//
	// does this route match the destination exactly
	//

	if( route.addr.s_addr != addr.s_addr )
		return true;

	if( route.mask.s_addr != mask.s_addr )
		return true;

	if( route.local )
		return true;

	//
	// add a route entry to our route list
	//

	route_list.add( route );

	//
	// delete the existing route
	//

	return del( route );
}

// decrement route costs

bool _IPROUTE::decrement( in_addr addr, in_addr mask )
{
	//
	// locate the cached route info for the destination
	//

	IPROUTE_ENTRY route;
	route.addr = addr;
	route.mask = mask;

	if( !route_list.get( route ) )
		return true;

	//
	// delete the restore the route for the destination
	//

	return add( route );
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
	struct nlmsghdr hdr;
	struct rtmsg msg;
	char buff[ 1024 ];

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

bool rtmsg_recv( int s, IPROUTE_ENTRY & route )
{
	char	buff[ sizeof( NLMSG ) ];
	memset( &buff, 0, sizeof( NLMSG ) );

	int rslt = recv( s, buff, sizeof( NLMSG ), 0 );

	close( s );

	if( rslt <= 0 )
		return false;

	struct nlmsghdr * nlmsg = ( struct nlmsghdr * ) buff;
	int nllen = rslt;

	while( NLMSG_OK( nlmsg, nllen ) )
	{
		// printf( "XX : netlink msg type = %i\n", nlmsg->nlmsg_type );

		if( nlmsg->nlmsg_type == RTM_NEWROUTE )
		{
			// printf( "XX : netlink msg type = NLMSG_NEWROUTE\n" );

			struct rtmsg * rtmsg = ( struct rtmsg * ) NLMSG_DATA( nlmsg );
			int rtlen = RTM_PAYLOAD( nlmsg );

			struct rtattr * rta = ( struct rtattr * ) RTM_RTA( rtmsg );

			while( RTA_OK( rta, rtlen ) )
			{
				switch( rta->rta_type )
				{
					case RTA_DST:
						// printf( "XX : netlink attribute = RTA_DST\n" );
						memcpy( &route.addr, RTA_DATA( rta ), sizeof( route.addr ) );
						route.mask.s_addr = prefix_to_mask( rtmsg->rtm_dst_len );
						break;

					case RTA_GATEWAY:
						// printf( "XX : netlink attribute = RTA_GATEWAY\n" );
						memcpy( &route.next, RTA_DATA( rta ), sizeof( route.next ) );
						break;

					case RTA_OIF:
					{
						// printf( "XX : netlink attribute = RTA_OIF\n" );

						struct ifreq ifr;
						int r = socket( PF_PACKET, SOCK_RAW, 0 );
						if( r > 0 )
						{
							ifr.ifr_ifindex = *( ( int * ) RTA_DATA( rta ) );
							ioctl( r, SIOCGIFNAME, &ifr );

							ifr.ifr_addr.sa_family = AF_INET;
							ioctl( r, SIOCGIFADDR, &ifr );

							route.iface = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
							close( r );
						}
						break;
					}

					case RTA_PREFSRC:
						// printf( "XX : netlink attribute = RTA_PREFSRC\n" );
						break;

					case RTA_METRICS:
						// printf( "XX : netlink attribute = RTA_METRICS\n" );
						break;

					case RTA_CACHEINFO:
						// printf( "XX : netlink attribute = RTA_CACHEINFO\n" );
						break;

					default:
						// printf( "XX : unhandled route attribute %i\n", rta->rta_type );
						break;
				}

				rta = RTA_NEXT( rta, rtlen );
			}

			return true;
		}

		if( nlmsg->nlmsg_type == RTM_DELROUTE )
		{
			// printf( "XX : netlink msg type = NLMSG_DELROUTE\n" );
		}

		if( nlmsg->nlmsg_type == RTM_GETROUTE )
		{
			// printf( "XX : netlink msg type = NLMSG_GETROUTE\n" );
		}

		if( nlmsg->nlmsg_type == NLMSG_ERROR )
		{
			// printf( "XX : netlink msg type = NLMSG_ERROR\n" );
			break;
		}

		if( nlmsg->nlmsg_type == NLMSG_DONE )
		{
			// printf( "XX : netlink msg type = NLMSG_DONE\n" );
			break;
		}

		nlmsg = NLMSG_NEXT( nlmsg, nllen );
	}

	return false;
}

// add a route

bool _IPROUTE::add( IPROUTE_ENTRY & route )
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
	rta->rta_len = sizeof( struct rtattr );

	struct in_addr * dst = ( in_addr * )( ( ( char * ) rta ) +  sizeof( struct rtattr ) );
	*dst = route.addr;
	rta->rta_len += sizeof( route.addr );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// add route gateway

	rta = ( struct rtattr * )( nlmsg.buff + nlmsg.hdr.nlmsg_len );
	rta->rta_type = RTA_GATEWAY;
	rta->rta_len = sizeof( struct rtattr );

	struct in_addr * gwy = ( in_addr * )( ( ( char * ) rta ) +  sizeof( struct rtattr ) );
	*gwy = route.next;
	rta->rta_len += sizeof( route.next );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// set route network mask

	nlmsg.msg.rtm_dst_len = mask_to_prefix( route.mask );

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

bool _IPROUTE::del( IPROUTE_ENTRY & route )
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
	rta->rta_len = sizeof( struct rtattr );

	struct in_addr * dst = ( in_addr * )( ( ( char * ) rta ) +  sizeof( struct rtattr ) );
	*dst = route.addr;
	rta->rta_len += sizeof( route.addr );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// add route gateway

	rta = ( struct rtattr * )( nlmsg.buff + nlmsg.hdr.nlmsg_len );
	rta->rta_type = RTA_GATEWAY;
	rta->rta_len = sizeof( struct rtattr );

	struct in_addr * gwy = ( in_addr * )( ( ( char * ) rta ) +  sizeof( struct rtattr ) );
	*gwy = route.next;
	rta->rta_len += sizeof( route.next );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// set route network mask

	nlmsg.msg.rtm_dst_len = mask_to_prefix( route.mask );

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

bool _IPROUTE::get( IPROUTE_ENTRY & route )
{
	// set route message header

	NLMSG nlmsg;
	memset( &nlmsg, 0, sizeof( nlmsg ) );

	nlmsg.hdr.nlmsg_flags = NLM_F_REQUEST;
	nlmsg.hdr.nlmsg_type = RTM_GETROUTE;

	nlmsg.msg.rtm_family = AF_INET;
	nlmsg.msg.rtm_table = RT_TABLE_MAIN;
	nlmsg.msg.rtm_protocol = RTPROT_STATIC;
	nlmsg.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	nlmsg.msg.rtm_type = RTN_UNICAST;

	// add route destination

	struct rtattr * rta = ( struct rtattr * ) nlmsg.buff;
	rta->rta_type = RTA_DST;
	rta->rta_len = sizeof( struct rtattr );

	struct in_addr * dst = ( in_addr * )( ( ( char * ) rta ) +  sizeof( struct rtattr ) );
	*dst = route.addr;
	rta->rta_len += sizeof( route.addr );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// set route network mask

	nlmsg.msg.rtm_dst_len = mask_to_prefix( route.mask );

	// set final message length

	nlmsg.hdr.nlmsg_len += sizeof( struct rtmsg );
	nlmsg.hdr.nlmsg_len = NLMSG_LENGTH( nlmsg.hdr.nlmsg_len );

	int s = rtmsg_send( &nlmsg );
	if( s < 0 )
		return false;

	return rtmsg_recv( s, route );
}

// get best route ( by address )

bool _IPROUTE::best( IPROUTE_ENTRY & route )
{
	// set route message header

	NLMSG nlmsg;
	memset( &nlmsg, 0, sizeof( nlmsg ) );

	nlmsg.hdr.nlmsg_flags = NLM_F_REQUEST;
	nlmsg.hdr.nlmsg_type = RTM_GETROUTE;

	nlmsg.msg.rtm_family = AF_INET;
	nlmsg.msg.rtm_table = RT_TABLE_UNSPEC;
	nlmsg.msg.rtm_protocol = RTPROT_UNSPEC;
	nlmsg.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	nlmsg.msg.rtm_type = RTN_UNSPEC;

	// add route destination

	struct rtattr * rta = ( struct rtattr * ) nlmsg.buff;
	rta->rta_type = RTA_DST;
	rta->rta_len = sizeof( struct rtattr );

	struct in_addr * dst = ( in_addr * )( ( ( char * ) rta ) +  sizeof( struct rtattr ) );
	*dst = route.addr;
	rta->rta_len += sizeof( route.addr );

	nlmsg.hdr.nlmsg_len += rta->rta_len;

	// set route network mask

	nlmsg.msg.rtm_dst_len = 32;

	// set final message length

	nlmsg.hdr.nlmsg_len += sizeof( struct rtmsg );
	nlmsg.hdr.nlmsg_len = NLMSG_LENGTH( nlmsg.hdr.nlmsg_len );

	int s = rtmsg_send( &nlmsg );
	if( s < 0 )
		return false;

	return rtmsg_recv( s, route );
}

//
// Linux systems appear to give priority to newer
// routes so this is a no-op for now.
//

// decrement route costs

bool _IPROUTE::increment( in_addr addr, in_addr mask )
{
	return true;
}

// decrement route costs

bool _IPROUTE::decrement( in_addr addr, in_addr mask )
{
	return true;
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
