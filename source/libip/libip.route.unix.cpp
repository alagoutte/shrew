
#include "libip.h"

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
// BSD route message generic function
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

//	if( mask.s_addr == 0xffffffff )
//		rtmsg.hdr.rtm_flags |= RTF_HOST;
//	else
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

//	if( mask.s_addr != 0xffffffff )
	{
		sockaddr_in * msk = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

		msk->sin_family = AF_INET;
		msk->sin_len = sizeof( sockaddr_in );
		msk->sin_addr = mask;

		rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );
	}

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

//	if( mask.s_addr == 0xffffffff )
//		rtmsg.hdr.rtm_flags |= RTF_HOST;
//	else
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

//	if( mask.s_addr != 0xffffffff )
	{
		sockaddr_in * msk = ( sockaddr_in * )( rtmsg.msg + rtmsg.hdr.rtm_msglen );

		msk->sin_family = AF_INET;
		msk->sin_len = sizeof( sockaddr_in );
		msk->sin_addr = mask;

		rtmsg.hdr.rtm_msglen += sizeof( sockaddr_in );
	}

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
	return true;
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

// decrement route costs

bool _IPROUTE::increment( in_addr addr, in_addr mask )
{
	return true;
}

// increment route costs

bool _IPROUTE::decrement( in_addr addr, in_addr mask )
{
	return true;
}

// flush arp table

bool _IPROUTE::flusharp( in_addr & iface )
{
	return true;
}

#else

//
// Linux IPROUTE class
//

_IPROUTE::_IPROUTE()
{
}

// add a route

bool _IPROUTE::add( in_addr & iface, bool local, in_addr addr, in_addr mask, in_addr next )
{
	return true;
}

// delete a route

bool _IPROUTE::del( in_addr & iface, bool local, in_addr addr, in_addr mask, in_addr next )
{
	return true;
}

// get a route ( by addr and mask )

bool _IPROUTE::get( in_addr & iface, bool & local, in_addr & addr, in_addr & mask, in_addr & next )
{
	return true;
}

// get best route ( by address )

bool _IPROUTE::best( in_addr & iface, bool & local, in_addr & addr, in_addr & mask, in_addr & next )
{
	return true;
}

// decrement route metrics

bool _IPROUTE::increment( in_addr addr, in_addr mask )
{
	return true;
}

// increment route metrics

bool _IPROUTE::decrement( in_addr addr, in_addr mask )
{
	return true;
}

// flush arp table

bool _IPROUTE::flusharp( in_addr & iface )
{
	return true;
}

#endif
