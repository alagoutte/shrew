
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

#include "iked.h"

#ifdef UNIX

//
// UNIX socket code
//

#ifndef SOL_UDP
#define SOL_UDP 17
#endif

long _IKED::socket_init()
{
	return LIBIKE_OK;
}

void _IKED::socket_done()
{
	while( list_socket.get_count() )
	{
		SOCK_INFO * sock_info = ( SOCK_INFO * ) list_socket.get_item( 0 );
		close( sock_info->sock );
		list_socket.del_item( sock_info );
		delete sock_info;
	}
}

long _IKED::socket_select( unsigned long timeout )
{
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = timeout * 1000;

	fd_set fdset;
	FD_ZERO( &fdset ); 

	lock_net.lock();

	long count = list_socket.get_count();
	long index = 0;
	int  hival = 0;

	for( ; index < count; index++ )
	{
		SOCK_INFO * sock_info = ( SOCK_INFO * ) list_socket.get_item( index );

		FD_SET( sock_info->sock, &fdset );

		if( hival < sock_info->sock )
			hival = sock_info->sock;
	}

	long result = select( hival + 1, &fdset, NULL, NULL, &tv );

	lock_net.unlock();

	if( result < 0 )
		return LIBIKE_SOCKET;

	return result;
}

long _IKED::socket_create( IKE_SADDR & saddr, bool encap )
{
	SOCK_INFO * sock_info = new SOCK_INFO;
	if( sock_info == NULL )
		return LIBIKE_SOCKET;

	sock_info->saddr = saddr;
	sock_info->sock = socket( PF_INET, SOCK_DGRAM, 0 );

	if( sock_info->sock < 0 )
	{
		log.txt( LOG_ERROR, "!! : socket create failed\n" );
		return LIBIKE_SOCKET;
	}

	struct linger linger = { 0, 0 };
	if( setsockopt( sock_info->sock, SOL_SOCKET, SO_LINGER, &linger, sizeof( linger ) ) < 0 )
	{
		log.txt( LOG_ERROR, "!! : socket set linger option failed\n" );
		return LIBIKE_SOCKET;
	}

	int optval = 1;
	if( setsockopt( sock_info->sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof( optval ) ) < 0 )
	{
		log.txt( LOG_ERROR, "!! : socket set linger option failed\n" );
		return LIBIKE_SOCKET;
	}

	optval = 1;
	if( setsockopt( sock_info->sock, IPPROTO_IP, IP_RECVDSTADDR, &optval, sizeof( optval ) ) < 0)
	{
		log.txt( LOG_ERROR, "!! : socket set recvdstaddr option failed\n" );
		return LIBIKE_SOCKET;
	}

	if( fcntl( sock_info->sock, F_SETFL, O_NONBLOCK ) == -1 )
	{
		log.txt( LOG_ERROR, "!! : socket set non-blocking mode failed\n" );
		return LIBIKE_SOCKET;
	}

	if( bind( sock_info->sock, &sock_info->saddr.saddr, sizeof( sock_info->saddr.saddr4 ) ) < 0 )
	{
		log.txt( LOG_ERROR, "!! : socket bind failed\n" );
		return LIBIKE_SOCKET;
	}

#ifdef OPT_NATT

	if( encap )
	{
		optval = UDP_ENCAP_ESPINUDP;
		if( setsockopt( sock_info->sock, SOL_UDP, UDP_ENCAP, &optval, sizeof( optval ) ) < 0)
		{
			log.txt( LOG_ERROR, "!! : socket set udp-encap option failed\n" );
			return LIBIKE_SOCKET;
		}
	}

#endif

	lock_net.lock();

	list_socket.add_item( sock_info );

	lock_net.unlock();

	char txtaddr[ LIBIKE_MAX_TEXTADDR ];
	iked.text_addr( txtaddr, &saddr, true );

	if( !encap )
	{
		log.txt( LOG_INFO,
			"ii : created ike socket %s\n",
			txtaddr );

		sock_ike_open++;
	}
	else
	{
		log.txt( LOG_INFO,
			"ii : created natt socket %s\n",
			txtaddr );

		sock_natt_open++;
	}

	return LIBIKE_OK;
}

long _IKED::socket_locate( IKE_SADDR & saddr )
{
	long count = list_socket.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		SOCK_INFO * sock_info = ( SOCK_INFO * ) list_socket.get_item( index );

		if( has_sockaddr( &sock_info->saddr.saddr  ) )
			if( cmp_sockaddr( sock_info->saddr.saddr, saddr.saddr, false ) )
				continue;

		u_int16_t port;
		get_sockport( sock_info->saddr.saddr, port );
		set_sockport( saddr.saddr, port );

		return LIBIKE_OK;
	}

	return LIBIKE_SOCKET;
}

long _IKED::header( PACKET_IP & packet, ETH_HEADER & header )
{
	//
	// set the header protocol
	//

	header.prot = htons( PROTO_IP );

	return LIBIKE_OK;
}

long _IKED::recv_ip( PACKET_IP & packet, ETH_HEADER * ethhdr )
{
	//
	// recv packet data
	//

	IKE_SADDR	from;
	IKE_SADDR	dest;

	socklen_t	flen = sizeof( from.saddr4 );

	long count = list_socket.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		SOCK_INFO * sock_info = ( SOCK_INFO * ) list_socket.get_item( index );

		unsigned char buff[ RAWNET_BUFF_SIZE ];
		unsigned char ctrl[ 256 ];

		iovec iov;
		iov.iov_base = buff;
		iov.iov_len = RAWNET_BUFF_SIZE;

		msghdr msg;
		msg.msg_name = (caddr_t)&from;
		msg.msg_namelen = flen;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = 256;
		msg.msg_flags = 0;

		long result = recvmsg( sock_info->sock, &msg, 0 );
		if( result <= 0 )
			continue;

		memcpy(
			&dest.saddr4.sin_addr,
			CMSG_DATA( msg.msg_control ),
			sizeof( dest.saddr4.sin_addr ) );

		//
		// add udp and ip headers
		//

		PACKET_UDP packet_udp;

		packet_udp.write(
			from.saddr4.sin_port,
			sock_info->saddr.saddr4.sin_port );

		packet_udp.add( buff, result );

		packet_udp.done(
			from.saddr4.sin_addr,
			dest.saddr4.sin_addr );

		packet.write(
			from.saddr4.sin_addr,
			dest.saddr4.sin_addr,
			0,
			PROTO_IP_UDP );

		packet.add( packet_udp );
		packet.done();

		//
		// optionally return an ethernet
		// header for this packet
		//

		if( ethhdr != NULL )
		{
			result = header( packet, *ethhdr );
			if( result == LIBIKE_SOCKET )
				return LIBIKE_SOCKET;
		}

		return LIBIKE_OK;
	}

	return LIBIKE_NODATA;
}

long _IKED::send_ip( PACKET_IP & packet, ETH_HEADER * ethhdr )
{
	//
	// read ip packet
	//

	IKE_SADDR saddr_src;
	IKE_SADDR saddr_dst;
	unsigned char prot;

	memset( &saddr_src, 0, sizeof( saddr_src ) );
	memset( &saddr_dst, 0, sizeof( saddr_dst ) );

	saddr_src.saddr4.sin_family = AF_INET;
	saddr_dst.saddr4.sin_family = AF_INET;

	packet.read(
		saddr_src.saddr4.sin_addr,
		saddr_dst.saddr4.sin_addr,
		prot );

	//
	// read udp packet
	//

	PACKET_UDP packet_udp;
	packet.get( packet_udp );

	packet_udp.read(
		saddr_src.saddr4.sin_port,
		saddr_dst.saddr4.sin_port );

	long count = list_socket.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		SOCK_INFO * sock_info = ( SOCK_INFO * ) list_socket.get_item( index );

		if( has_sockaddr( &sock_info->saddr.saddr ) )
		{
			if( !cmp_sockaddr( sock_info->saddr.saddr, saddr_src.saddr, true ) )
				continue;
		}
		else
		{
			u_int16_t port1;
			u_int16_t port2;
			get_sockport( sock_info->saddr.saddr, port1 );
			get_sockport( saddr_src.saddr, port2 );

			if( port1 != port2 )
				continue;
		}

		//
		// send packet data
		//

		long result = sendto(
						sock_info->sock,
						packet_udp.buff() + packet_udp.oset(),
						packet_udp.size() - packet_udp.oset(),
						0,
						&saddr_dst.saddr,
						sizeof( saddr_dst.saddr4 ) );


		if( result <= 0 )
		{
			log.txt( LOG_ERROR, "!! : send error %li\n", result );
			return LIBIKE_SOCKET;
		}

		//
		// optionally return an ethernet
		// header for this packet
		//

		if( ethhdr != NULL )
		{
			result = header( packet, *ethhdr );
			if( result == LIBIKE_SOCKET )
				return LIBIKE_SOCKET;
		}

		return LIBIKE_OK;
	}

	log.txt( LOG_ERROR, "!! : socket not found\n" );

	return LIBIKE_SOCKET;
}

#endif

#ifdef WIN32

//
// WIN32 packet filter code
//

VFLT vflt;

long vneterr( long value )
{
	switch( value )
	{
		case FLT_NO_SOCK:
			return LIBIKE_SOCKET;

		case FLT_NO_DATA:
			return LIBIKE_NODATA;

		case FLT_NO_BUFF:
			return LIBIKE_FAILED;
	}

	return LIBIKE_OK;
}

long _IKED::socket_init()
{
	vflt.init( &log );

	vflt.open();

	FLT_RULE rule;
	memset( &rule, 0, sizeof( rule ) );

	rule.Level   = RLEVEL_DAEMON;
	rule.Group   = 0;
	rule.Action  = FLT_ACTION_MIRROR;
	rule.Flags   = FLT_FLAG_RECV | FLT_FLAG_HAS_IPFRAG;
	rule.Proto   = htons( PROTO_IP );
	rule.IpPro   = PROTO_IP_UDP;

	vflt.rule_add( &rule );

	return LIBIKE_OK;
}

void _IKED::socket_done()
{
	vflt.close();
}

long _IKED::socket_create( IKE_SADDR & saddr, bool encap )
{
	FLT_RULE rule;
	memset( &rule, 0, sizeof( rule ) );

	if( !encap )
	{
		rule.Level   = RLEVEL_DAEMON;
		rule.Group   = 0;
		rule.Action  = FLT_ACTION_DIVERT;
		rule.Flags   = FLT_FLAG_QUICK | FLT_FLAG_RECV;
		rule.Proto   = htons( PROTO_IP );
		rule.IpPro   = PROTO_IP_UDP;
		rule.DstAddr = saddr.saddr4.sin_addr.s_addr;
		rule.DstMask = FLT_MASK_ADDR;
		rule.DstPort = saddr.saddr4.sin_port;

		vflt.rule_add( &rule );

		sock_ike_open++;
	}
	else
	{
		rule.Level   = RLEVEL_DAEMON;
		rule.Group   = 0;
		rule.Action  = FLT_ACTION_DIVERT;
		rule.Flags   = FLT_FLAG_QUICK | FLT_FLAG_RECV | FLT_FLAG_NOT_NATTESP;
		rule.Proto   = htons( PROTO_IP );
		rule.IpPro   = PROTO_IP_UDP;
		rule.DstAddr = saddr.saddr4.sin_addr.s_addr;
		rule.DstMask = FLT_MASK_ADDR;
		rule.DstPort = saddr.saddr4.sin_port;

		vflt.rule_add( &rule );

		sock_natt_open++;
	}

	return LIBIKE_OK;
}

long _IKED::socket_locate( IKE_SADDR & saddr )
{
	saddr.saddr4.sin_port = LIBIKE_IKE_PORT;

	return LIBIKE_OK;
}

long _IKED::socket_select( unsigned long timeout )
{
	long result = vflt.select( timeout );
	if( result <= 0 )
		return vneterr( result );

	return result;
}

long _IKED::header( PACKET_IP & packet, ETH_HEADER & ethhdr )
{
	return vneterr( vflt.head( packet, ethhdr ) );
}

long _IKED::recv_ip( PACKET_IP & packet, ETH_HEADER * ethhdr )
{
	return vneterr( vflt.recv_ip( packet, ethhdr ) );
}

long _IKED::send_ip( PACKET_IP & packet, ETH_HEADER * ethhdr )
{
	return vneterr( vflt.send_ip( packet, FLT_SEND_DN, ethhdr ) );
}

#endif

#ifdef UNIX

//
// UNIX virtual adapter code
//

bool _IKED::vnet_init()
{
	return false;
}

bool _IKED::vnet_get( VNET_ADAPTER ** adapter )
{
	return false;
}

bool _IKED::vnet_rel( VNET_ADAPTER * adapter )
{
	return false;
}

bool _IKED::vnet_set( VNET_ADAPTER * adapter, bool enable )
{
	return false;
}

bool _IKED::vnet_setup(	VNET_ADAPTER * adapter, IKE_XCONF & xconf )
{
	return false;
}

#endif

#ifdef WIN32

//
// WIN32 virtual adapter code
//

VNET vnet;

bool _IKED::vnet_init()
{
	return vnet.init( &log );
}

bool _IKED::vnet_get( VNET_ADAPTER ** adapter )
{
	return vnet.get( adapter );
}

bool _IKED::vnet_rel( VNET_ADAPTER * adapter )
{
	return vnet.rel( adapter );
}

bool _IKED::vnet_set( VNET_ADAPTER * adapter, bool enable )
{
	return vnet.set( adapter, enable );
}

bool _IKED::vnet_setup(	VNET_ADAPTER * adapter, IKE_XCONF & xconf )
{
	long flags = VNET_CFG_NBNS | VNET_CFG_DNSS | VNET_CFG_DNSD;
	if( xconf.opts & IPSEC_OPTS_SPLITDNS )
		flags &= ~VNET_CFG_DNSS;

	return vnet.setup(
			adapter,
			flags,
			xconf.addr,
			xconf.mask,
			&xconf.nbns,
			&xconf.dnss,
			xconf.suffix );
}

#endif

//
// general network helper functions
//

void _IKED::text_addr( char * text, in_addr & addr )
{
	unsigned long haddr = ntohl( addr.s_addr );

	sprintf( text, "%lu.%lu.%lu.%lu",
		0xff & ( haddr >> 24 ),
		0xff & ( haddr >> 16 ),
		0xff & ( haddr >>  8 ),
		0xff & haddr );
}

void _IKED::text_mask( char * text, in_addr & addr )
{
	unsigned long bits;
	unsigned long mask;

	bits = 0;
	mask = ntohl( addr.s_addr );

	while( mask & 0x80000000 )
	{
		mask <<= 1;
		bits++;
	}

	snprintf(
		text,
		LIBIKE_MAX_TEXTADDR,
		"%lu",
		bits );
}

void _IKED::text_addr( char * text, sockaddr * saddr, bool port )
{
	switch( saddr->sa_family )
	{
		case AF_INET:
		{
			sockaddr_in * saddr_in = ( sockaddr_in * ) saddr;

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, saddr_in->sin_addr );

			if( port )
			{
				snprintf(
					text,
					LIBIKE_MAX_TEXTADDR,
					"%s:%u",
					txtaddr,
					ntohs( saddr_in->sin_port ) );
			}
			else
			{
				snprintf(
					text,
					LIBIKE_MAX_TEXTADDR,
					"%s",
					txtaddr );
			}

			break;
		}

		default:

			sprintf( text, "<UNKNOWN AF>" );
	}
}

void _IKED::text_addr( char * text, IKE_SADDR * iaddr, bool port )
{
	text_addr( text, &iaddr->saddr, port );
}

void _IKED::text_addr( char * text, PFKI_ADDR * paddr, bool port, bool netmask )
{
	char txtaddr[ LIBIKE_MAX_TEXTADDR ];
	text_addr( txtaddr, &paddr->saddr, port );

	if( netmask && paddr->prefix )
	{
		snprintf(
			text,
			LIBIKE_MAX_TEXTADDR,
			"%s/%u",
			txtaddr,
			paddr->prefix );
	}
	else
	{
		snprintf(
			text,
			LIBIKE_MAX_TEXTADDR,
			"%s",
			txtaddr );
	}
}

void _IKED::text_ph1id( char * text, IKE_PH1ID * ph1id )
{
	switch( ph1id->type )
	{
		case ISAKMP_ID_IPV4_ADDR:
		{
			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, ph1id->addr );

			snprintf(
				text,
				LIBIKE_MAX_TEXTP1ID,
				"%s",
				txtaddr );

			break;
		}

		case ISAKMP_ID_FQDN:
		case ISAKMP_ID_USER_FQDN:
		{
			BDATA varid;
			varid.set( ph1id->varid );
			varid.add( 0, 1 );

			snprintf(
				text,
				LIBIKE_MAX_TEXTP1ID,
				"%s",
				varid.buff() );

			break;
		}

		case ISAKMP_ID_ASN1_DN:
		case ISAKMP_ID_ASN1_GN:
		{
			BDATA varid;
			asn1_text( ph1id->varid, varid );
			varid.add( 0, 1 );

			snprintf(
				text,
				LIBIKE_MAX_TEXTP1ID,
				"%s",
				varid.buff() );

			break;
		}

		default:

			sprintf( text, "<UNKNOWN P1ID>" );
	}
}

void _IKED::text_ph2id( char * text, IKE_PH2ID * ph2id )
{
	char txtaddr1[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr2[ LIBIKE_MAX_TEXTADDR ];

	switch( ph2id->type )
	{
		case ISAKMP_ID_IPV4_ADDR:

			text_addr( txtaddr1, ph2id->addr1 );

			snprintf(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"%s",
				txtaddr1 );

			break;

		case ISAKMP_ID_IPV4_ADDR_SUBNET:

			text_addr( txtaddr1, ph2id->addr1 );
			text_mask( txtaddr2, ph2id->addr2 );

			snprintf(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"%s/%s",
				txtaddr1,
				txtaddr2 );

			break;

		case ISAKMP_ID_IPV4_ADDR_RANGE:

			text_addr( txtaddr1, ph2id->addr1 );
			text_addr( txtaddr2, ph2id->addr2 );

			snprintf(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"%s-%s",
				txtaddr1,
				txtaddr2 );

			break;

		default:

			sprintf( text, "<UNKNOWN P2ID>" );
	}
}

bool _IKED::find_addr_r( sockaddr_in & raddr, unsigned short rport, char * rname )
{
	//
	// trim whitespaces from the
	// hostname or address string
	//

	if( !rname  )
		return false;

	if( !( *rname ) )
		return false;

	while( rname && *rname == ' ' )
		rname++;

	//
	// determine if this is an ip
	// address or hostname. convert
	// this into a sockaddr struct
	//

	long rsize = sizeof( sockaddr_in );
	memset( &raddr, 0, rsize );

	if( isdigit( rname[ 0 ] ) )
	{
		//
		// looks like an address 
		//

		raddr.sin_family		= AF_INET;
		raddr.sin_addr.s_addr	= inet_addr( rname );
		raddr.sin_port			= htons( rport );
	}
	else
	{
		//
		// looks like a hostname
		//

		struct hostent * hp = gethostbyname( rname );
		if( !hp )
			return false;

		memcpy( &raddr.sin_addr, hp->h_addr, hp->h_length );
		raddr.sin_family = hp->h_addrtype;
		raddr.sin_port = htons( rport );
	}

	return true;
}

bool _IKED::find_addr_l( IKE_SADDR & saddr_r, IKE_SADDR & saddr_l, unsigned short lport )
{
	//
	// determine the best interface to
	// reach the remote host address
	//

	bool	local;
	in_addr	addr = saddr_r.saddr4.sin_addr;
	in_addr	mask;
	in_addr	next;

	bool found = iproute.best(
					saddr_l.saddr4.sin_addr,
					local,
					addr,
					mask,
					next );

	saddr_l.saddr4.sin_family = AF_INET;
	saddr_l.saddr4.sin_port	= htons( lport );

	//
	// log the result
	//

	char txtaddr[ LIBIKE_MAX_TEXTADDR ];
	text_addr( txtaddr, &saddr_l, true );

	if( found )
	{
		log.txt( LOG_DEBUG,
				"ii : local address %s selected for peer\n",
				txtaddr );
	}
	else
	{
		log.txt( LOG_DEBUG,
				"ii : unable to select address for peer at %s\n",
				txtaddr );
	}

	return found;
}


