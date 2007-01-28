
#include "libip.h"

typedef struct _RTMSG
{
	rt_msghdr	hdr;
	char		msg[ 512 ];

}RTMSG;

_IPROUTE::_IPROUTE()
{
	seq = 0;
}

//
// add a route
//

bool _IPROUTE::add( in_addr & iface, bool local, unsigned long addr, unsigned long mask, unsigned long next )
{
	return true;
}

//
// delete a route 
//

bool _IPROUTE::del( in_addr & iface, bool local, unsigned long addr, unsigned long mask, unsigned long next )
{
	return true;
}

//
// get a route ( by addr and mask )
//

bool _IPROUTE::get( in_addr & iface, bool & local, unsigned long & addr, unsigned long & mask, unsigned long & next )
{
	return true;
}

//
// best route ( by address )
//

bool _IPROUTE::best( in_addr & iface, bool & local, unsigned long & addr, unsigned long & mask, unsigned long & next )
{
	int s = socket( PF_ROUTE, SOCK_RAW, 0 );
	if( s == -1 )
		return false;

	RTMSG rtmsg;
	memset( &rtmsg, 0, sizeof( rtmsg ) );

	rtmsg.hdr.rtm_type = RTM_GET;  
	rtmsg.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_STATIC;
	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_seq = ++seq;
	rtmsg.hdr.rtm_addrs = RTA_DST | RTA_IFP;

	sockaddr_in * dst = ( sockaddr_in * ) rtmsg.msg;

	dst->sin_family = AF_INET;
	dst->sin_len = sizeof( sockaddr_in );
	dst->sin_addr.s_addr = addr;

	sockaddr_dl * ifp = ( sockaddr_dl * )( rtmsg.msg + sizeof( sockaddr_in ) ) ;

	ifp->sdl_family = AF_LINK;
	ifp->sdl_len = sizeof( sockaddr_dl );

	long l = 0;
	l += sizeof( rtmsg.hdr );
	l += sizeof( sockaddr_in );
	l += sizeof( sockaddr_dl );

	if( write( s, ( char * ) &rtmsg, l ) < 0 )
	{
		close( s );
		return false;
	}

	int pid = getpid();

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

	if( ( rtmsg.hdr.rtm_errno ) ||
		( rtmsg.hdr.rtm_msglen > l ) ||
		( rtmsg.hdr.rtm_version != RTM_VERSION ) )
	{
		close( s );
		return false;
	}

	dst = NULL;
	ifp = NULL;

	sockaddr_in * msk = NULL;
	sockaddr_in * nxt = NULL;

	char * cp = rtmsg.msg;

	for( int i = 1; i; i <<= 1 )
	{
		if( i & rtmsg.hdr.rtm_addrs )
		{
			switch( i )
			{
				case RTA_DST:
					dst = ( sockaddr_in * ) cp;
					break;

				case RTA_GATEWAY:
					nxt = ( sockaddr_in * ) cp;
					break;

				case RTA_NETMASK:
					msk = ( sockaddr_in * ) cp;
					break;

				case RTA_IFP:
					ifp = ( sockaddr_dl * ) cp;
					break;
			}

			cp += ( ( sockaddr * ) cp )->sa_len;
		}
	}

	if( dst )
		printf( "XX : dst = %s\n", inet_ntoa( dst->sin_addr ) );
		
	if( nxt )
		printf( "XX : nxt = %s\n", inet_ntoa( nxt->sin_addr ) );
		
	if( msk )
		printf( "XX : msk = %s\n", inet_ntoa( msk->sin_addr ) );
		
	if( ifp )
		printf( "XX : ifp = %s\n", ifp->sdl_data );
		
	close( s );
	return true;
}

/*

1180            char *cp = m_rtmsg.m_space;
1191            if (cmd == 'a')
1193            else if (cmd == 'c')
1195            else if (cmd == 'g') {
1197                    if (so_ifp.sa.sa_family == 0) {
1196                    cmd = RTM_GET;
1197                    if (so_ifp.sa.sa_family == 0) {
1198                            so_ifp.sa.sa_family = AF_LINK;
1199                            so_ifp.sa.sa_len = sizeof(struct sockaddr_dl);
1200                            rtm_addrs |= RTA_IFP;
1205            rtm.rtm_type = cmd;
1206            rtm.rtm_flags = flags;
1208            rtm.rtm_seq = ++seq;
1210            rtm.rtm_rmx = rt_metrics;
1211            rtm.rtm_inits = rtm_inits;
1210            rtm.rtm_rmx = rt_metrics;
1209            rtm.rtm_addrs = rtm_addrs;
1207            rtm.rtm_version = RTM_VERSION;
1210            rtm.rtm_rmx = rt_metrics;
1211            rtm.rtm_inits = rtm_inits;
1213            printf( "flags = %i\n", rtm.rtm_flags );
1216            if (rtm_addrs & RTA_NETMASK)
1218            NEXTADDR(RTA_DST, so_dst);
1219            NEXTADDR(RTA_GATEWAY, so_gate);
1220            NEXTADDR(RTA_NETMASK, so_mask);
1221            NEXTADDR(RTA_GENMASK, so_genmask);
1222            NEXTADDR(RTA_IFP, so_ifp);
1223            NEXTADDR(RTA_IFA, so_ifa);
1224            rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;
1225            if (verbose)
1224            rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;
1225            if (verbose)
1227            if (debugonly)
1228                    return (0);
1227            if (debugonly)
1229            if ((rlen = write(s, (char *)&m_rtmsg, l)) < 0) {
*/


//
// decrement route costs
//

bool _IPROUTE::increment( unsigned long addr, unsigned long mask )
{
	return true;
}

//
// increment route costs
//

bool _IPROUTE::decrement( unsigned long addr, unsigned long mask )
{
	return true;
}


bool _IPROUTE::flusharp( in_addr & iface )
{
	return true;
}
