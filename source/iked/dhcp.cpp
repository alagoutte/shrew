
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

long _IKED::socket_dhcp_create( IDB_TUNNEL * tunnel )
{
	//
	// only initialize once
	//

	if( tunnel->dhcp_sock != INVALID_SOCKET )
		return LIBIKE_OK;

	//
	// create dhcp transaction id
	//

	rand_bytes( &tunnel->dhcp_xid, 4 );

	//
	// create dhcp hw address id
	//

	uint32_t peer_addr = tunnel->saddr_r.saddr4.sin_addr.s_addr;

	tunnel->dhcp_hwaddr[ 0 ] = 0x40;			// locally administered unicast MAC
	tunnel->dhcp_hwaddr[ 1 ] = dhcp_seed[ 1 ];
	tunnel->dhcp_hwaddr[ 2 ] = dhcp_seed[ 2 ] ^ ( ( peer_addr >> 0 ) & 0xff );
	tunnel->dhcp_hwaddr[ 3 ] = dhcp_seed[ 3 ] ^ ( ( peer_addr >> 8 ) & 0xff ); 
	tunnel->dhcp_hwaddr[ 4 ] = dhcp_seed[ 4 ] ^ ( ( peer_addr >> 16 ) & 0xff );
	tunnel->dhcp_hwaddr[ 5 ] = dhcp_seed[ 5 ] ^ ( ( peer_addr >> 24 ) & 0xff );

	//
	// create dhcp socket
	//

	tunnel->dhcp_sock = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
	if( tunnel->dhcp_sock == INVALID_SOCKET )
	{
		log.txt( LLOG_ERROR, "!! : failed to create DHCP socket\n" );
		return LIBIKE_SOCKET;
	}

	//
	// bind socket to address and port
	//

	struct sockaddr_in saddr = tunnel->saddr_l.saddr4;
	saddr.sin_port = htons( UDP_PORT_DHCPS );

	if( bind( tunnel->dhcp_sock, ( sockaddr * ) &saddr, sizeof( saddr ) ) < 0 )
	{
		log.txt( LLOG_ERROR, "!! : failed to bind DHCP socket\n" );
		return LIBIKE_SOCKET;
	}

	//
	// set non-blocking operation
	//

#ifdef WIN32

	u_long arg = 1;
	if( ioctlsocket( tunnel->dhcp_sock, FIONBIO, &arg ) < 0 )
	{
		log.txt( LLOG_ERROR, "!! : failed to set DHCP socket to non-blocking\n" );
		return LIBIKE_SOCKET;
	}

#else

	if( fcntl( tunnel->dhcp_sock, F_SETFL, O_NONBLOCK ) < 0 )
	{
		log.txt( LLOG_ERROR, "!! : failed to set DHCP socket to non-blocking\n" );
		return LIBIKE_SOCKET;
	}

#endif

	char txtaddr[ LIBIKE_MAX_TEXTADDR ];
	text_addr( txtaddr, saddr.sin_addr );

	log.txt( LLOG_DEBUG, "ii : setup DHCP socket for address %s\n", txtaddr );

	//
	// create dhcp ipsec policies
	//

	policy_dhcp_create( tunnel );

	//
	// add tunnel dhcp event
	//

	tunnel->inc( true );
	tunnel->event_dhcp.delay = 1000;

	ith_timer.add( &tunnel->event_dhcp );

	return LIBIKE_OK;
}

long _IKED::socket_dhcp_remove( IDB_TUNNEL * tunnel )
{
	//
	// remove dhcp ipsec policies
	//

	policy_dhcp_remove( tunnel );

	//
	// close dhcp socket
	//

	if( tunnel->dhcp_sock != INVALID_SOCKET )
	{

#ifdef WIN32

		closesocket( tunnel->dhcp_sock );

#else

		close( tunnel->dhcp_sock );

#endif

		tunnel->dhcp_sock = INVALID_SOCKET;
	}

	return LIBIKE_OK;
}

long _IKED::socket_dhcp_send( IDB_TUNNEL * tunnel, PACKET & packet )
{
	//
	// send the packet
	//

	struct sockaddr_in saddr = tunnel->saddr_r.saddr4;
	saddr.sin_port = htons( UDP_PORT_DHCPS );

	int rslt;
	rslt = sendto(
		tunnel->dhcp_sock,
		packet.text(),
		packet.size(),
		0,
		( sockaddr * ) &saddr,
		sizeof( saddr ) );

	if( rslt < 0 )
	{
		log.txt( LLOG_ERROR, "!! : failed to write to DHCP socket\n" );
		return LIBIKE_SOCKET;
	}

	return LIBIKE_OK;
}

long _IKED::socket_dhcp_recv( IDB_TUNNEL * tunnel, PACKET & packet )
{
	char buff[ 1024 ];
	long size = 1024;

	size = recv(
		tunnel->dhcp_sock,
		buff,
		size,
		0 );

	if( size < 0 )
		return LIBIKE_NODATA;

	packet.add(
		buff,
		size );

	return LIBIKE_OK;
}

long _IKED::process_dhcp_send( IDB_TUNNEL * tunnel )
{
	//
	// DHCP over IPsec discover packet
	//

	if( !( tunnel->tstate & TSTATE_VNET_CONFIG ) )
	{
		//
		// alternate hardware types for
		// non-rfc conformant gateways
		//

		if( tunnel->event_dhcp.retry & 1 )
			tunnel->dhcp_hwtype = BOOTP_HW_EHTERNET;
		else
			tunnel->dhcp_hwtype = BOOTP_HW_IPSEC;

		//
		// create dhcp discover packet
		//

		PACKET packet;

		DHCP_HEADER dhcp_head;
		memset( &dhcp_head, 0, sizeof( dhcp_head ) );

		dhcp_head.magic = DHCP_MAGIC;
		dhcp_head.op = BOOTP_REQUEST;			// bootp request
		dhcp_head.htype = tunnel->dhcp_hwtype;	// bootp hardware type
		dhcp_head.hlen = 6;						// hardware address length
		dhcp_head.xid = tunnel->dhcp_xid;		// transaction id

		dhcp_head.hops = 1;                     // router IP ( fake relay )
		dhcp_head.giaddr =                      // ...
			tunnel->saddr_l.saddr4.sin_addr.s_addr;

		memcpy(									// local hardware address id
			dhcp_head.chaddr,					// ...
			tunnel->dhcp_hwaddr, 6 );			// ...

		packet.add(
			&dhcp_head,
			sizeof( dhcp_head ) );

		packet.add_byte( DHCP_OPT_MSGTYPE );	// message type
		packet.add_byte( 1 );					// opt size
		packet.add_byte( DHCP_MSG_DISCOVER );	// message type value

		packet.add_byte( DHCP_OPT_CLIENTID );	// message type
		packet.add_byte( 7 );					// opt size
		packet.add_byte( tunnel->dhcp_hwtype );	// client hw type
		packet.add( dhcp_head.chaddr, 6 );		// client id value
		packet.add_byte( DHCP_OPT_END );

		//
		// send the packet
		//

		tunnel->event_dhcp.retry++;

		log.txt( LLOG_DEBUG, "ii : sending DHCP over IPsec discover\n" );

		socket_dhcp_send( tunnel, packet );
	}

	//
	// DHCP over IPsec request packet
	//

	if( tunnel->tstate & TSTATE_VNET_CONFIG )
	{
		//
		// create dhcp request packet
		//

		PACKET packet;

		DHCP_HEADER dhcp_head;
		memset( &dhcp_head, 0, sizeof( dhcp_head ) );

		dhcp_head.magic = DHCP_MAGIC;
		dhcp_head.op = BOOTP_REQUEST;			// bootp request
		dhcp_head.htype = tunnel->dhcp_hwtype;	// bootp hardware type
		dhcp_head.hlen = 6;						// hardware address length
		dhcp_head.xid = tunnel->dhcp_xid;		// transaction id

		dhcp_head.hops = 1;                     // router IP ( fake relay )
		dhcp_head.giaddr =                      // ...
			tunnel->saddr_l.saddr4.sin_addr.s_addr;

		memcpy(									// local hardware address id
			dhcp_head.chaddr,					// ...
			tunnel->dhcp_hwaddr, 6 );			// ...

		packet.add(
			&dhcp_head,
			sizeof( dhcp_head ) );

		packet.add_byte( DHCP_OPT_MSGTYPE );	// message type
		packet.add_byte( 1 );					// opt size
		packet.add_byte( DHCP_MSG_REQUEST );	// message type value

		packet.add_byte( DHCP_OPT_SERVER );		// server id
		packet.add_byte( 4 );					// opt size
		packet.add( &tunnel->xconf.dhcp, 4 );	// server id value

		packet.add_byte( DHCP_OPT_ADDRESS );	// requested address
		packet.add_byte( 4 );					// opt size
		packet.add( &tunnel->xconf.addr, 4 );	// address value

		packet.add_byte( DHCP_OPT_CLIENTID );	// client id
		packet.add_byte( 7 );					// opt size
		packet.add_byte( BOOTP_HW_IPSEC );		// client hw type
		packet.add( dhcp_head.chaddr, 6 );		// client id value
		packet.add_byte( DHCP_OPT_END );

		//
		// send the packet
		//

		tunnel->event_dhcp.retry++;

		log.txt( LLOG_DEBUG, "ii : sending DHCP over IPsec request\n" );

		socket_dhcp_send( tunnel, packet );
	}

	return LIBIKE_OK;
}

long _IKED::process_dhcp_recv( IDB_TUNNEL * tunnel )
{
	PACKET packet;
	long result = socket_dhcp_recv( tunnel, packet );
	if( result != LIBIKE_OK )
		return LIBIKE_FAILED;

	//
	// examine the dhcp reply header
	//

	DHCP_HEADER dhcp_head;
	if( !packet.get( &dhcp_head, sizeof( dhcp_head ) ) )
	{
		log.txt( LLOG_ERROR, "!! : malformed DHCP reply packet\n" );
		tunnel->dec( true );
		return LIBIKE_FAILED;
	}

	if( ( dhcp_head.op != BOOTP_REPLY ) ||			// bootp reply
		( dhcp_head.hlen != 6 ) ||					// hardware address length
		( dhcp_head.magic != DHCP_MAGIC ) )			// magic cookie
	{
		log.txt( LLOG_ERROR, "!! : invalid DHCP reply parameters\n" );
		tunnel->dec( true );
		return LIBIKE_FAILED;
	}

	if(	( dhcp_head.htype != BOOTP_HW_EHTERNET ) &&	// bootp hardware type
		( dhcp_head.htype != BOOTP_HW_IPSEC ) )
	{
		log.txt( LLOG_ERROR, "!! : invalid DHCP reply hardware type\n" );
		tunnel->dec( true );
		return LIBIKE_FAILED;
	}

	//
	// respond to the solicited type
	//

	tunnel->dhcp_hwtype = dhcp_head.htype;

	//
	// examine the dhcp reply options
	//

	log.txt( LLOG_DEBUG, "ii : reading DHCP reply options\n" );

	IKE_XCONF	config;
	memset( &config, 0, sizeof( config ) );

	uint8_t		type;
	char		txtaddr[ LIBIKE_MAX_TEXTADDR ];
	bool		end = false;

	while( !end )
	{
		unsigned char opt;
		unsigned char len;

		if( !packet.get_byte( opt ) )
			break;

		if( !packet.get_byte( len ) )
			break;

		if( len > ( packet.size() - packet.oset() ) )
			break;

		switch( opt )
		{
			case DHCP_OPT_MSGTYPE:
			{
				config.addr.s_addr = dhcp_head.yiaddr;
				config.opts |= IPSEC_OPTS_ADDR;

				packet.get_byte( type );
				text_addr( txtaddr, config.addr );

				switch( type )
				{
					case DHCP_MSG_OFFER:
						log.txt( LLOG_DEBUG, "ii : - message type = offer ( %s )\n", txtaddr );
						break;

					case DHCP_MSG_ACK:
						log.txt( LLOG_DEBUG, "ii : - message type = ack ( %s )\n", txtaddr );
						break;

					default:
						log.txt( LLOG_ERROR, "!! : invalid DHCP message type ( %i )\n", int( type ) );
						tunnel->dec( true );
						return LIBIKE_FAILED;
				}

				break;
			}

			case DHCP_OPT_SUBMASK:
				if( len >= 4 )
				{
					packet.get( &config.mask, 4 );
					len -= 4;
					text_addr( txtaddr, config.mask );
					log.txt( LLOG_DEBUG, "ii : - IP4 Netmask = %s\n", txtaddr );
					config.opts |= IPSEC_OPTS_MASK;
				}
				packet.get_null( len );
				break;

			case DHCP_OPT_SERVER:
				if( len >= 4 )
				{
					packet.get( &config.dhcp, 4 );
					len -= 4;
					text_addr( txtaddr, config.dhcp );
					log.txt( LLOG_DEBUG, "ii : - IP4 DHCP Server = %s\n", txtaddr );
				}
				packet.get_null( len );
				break;

			case DHCP_OPT_LEASE:
				if( len >= 4 )
				{
					uint32_t d, h, m, s;
					packet.get_quad( s, true );
					tunnel->event_dhcp.lease = s;
					len -= 4;

					d = s / 86400;
					s = s % 86400;
					h = s / 3600;
					s = s % 3600;
					m = s / 60;
					s = s % 60;

					log.txt( LLOG_DEBUG,
						"ii : - IP4 DHCP lease = %d days, %d hours, %d mins, %d secs\n",
						d, h, m, s );
				}
				packet.get_null( len );
				break;

			case DHCP_OPT_DNSS:
				while( len >= 4 )
				{
					len -= 4;
					if( config.nscfg.dnss_count <= IPSEC_DNSS_MAX )
					{
						packet.get(	&config.nscfg.dnss_list[ config.nscfg.dnss_count ], 4 );
						text_addr( txtaddr, config.nscfg.dnss_list[ config.nscfg.dnss_count ] );
						config.nscfg.dnss_count++;
						log.txt( LLOG_DEBUG, "ii : - IP4 DNS Server = %s\n", txtaddr );
					}
					config.opts |= IPSEC_OPTS_DNSS;
				}
				packet.get_null( len );
				break;

			case DHCP_OPT_NBNS:
				while( len >= 4 )
				{
					len -= 4;
					if( config.nscfg.nbns_count <= IPSEC_NBNS_MAX )
					{
						packet.get( &config.nscfg.nbns_list[ config.nscfg.nbns_count ], 4 );
						text_addr( txtaddr, config.nscfg.nbns_list[ config.nscfg.nbns_count ] );
						config.nscfg.nbns_count++;
						log.txt( LLOG_DEBUG, "ii : - IP4 WINS Server = %s\n", txtaddr );
					}
					config.opts |= IPSEC_OPTS_NBNS;
				}
				packet.get_null( len );
				break;

			case DHCP_OPT_DOMAIN:
			{
				long tmp = len;
				if( tmp > 255 )
					tmp = 255;
				if( len >= 1 )
				{
					packet.get( config.nscfg.dnss_suffix, tmp );
					config.nscfg.dnss_suffix[ tmp ] = 0;
					log.txt( LLOG_DEBUG, "ii : - DNS Suffix = %s\n", config.nscfg.dnss_suffix );
					config.opts |= IPSEC_OPTS_DOMAIN;
				}
				packet.get_null( len - tmp );
				break;
			}

			case DHCP_OPT_CLIENTID:
				log.txt( LLOG_DEBUG, "ii : - clientid ( %i bytes )\n", len );
				packet.get_null( len );
				break;

			case DHCP_OPT_END:
				end = true;
				break;

			default:
				log.txt( LLOG_DECODE, "ii : - unknown option ( %02x )\n", opt );
				packet.get_null( len );
				break;
		}
	}

	//
	// DHCP offer
	//

	if( type == DHCP_MSG_OFFER )
	{
		if( !( tunnel->tstate & TSTATE_VNET_CONFIG ) )
		{
			//
			// accept supported options
			//

			tunnel->xconf.dhcp = config.dhcp;
			tunnel->xconf.opts = tunnel->xconf.rqst & config.opts;

			if( tunnel->xconf.opts & IPSEC_OPTS_ADDR )
				tunnel->xconf.addr = config.addr;

			if( tunnel->xconf.opts & IPSEC_OPTS_MASK )
				tunnel->xconf.mask = config.mask;

			if( tunnel->xconf.opts & IPSEC_OPTS_DNSS )
			{
				memcpy( tunnel->xconf.nscfg.dnss_list,
					config.nscfg.dnss_list,
					sizeof( config.nscfg.dnss_list ) );

				tunnel->xconf.nscfg.dnss_count =  config.nscfg.dnss_count;
			}

			if( tunnel->xconf.opts & IPSEC_OPTS_DOMAIN )
				memcpy( tunnel->xconf.nscfg.dnss_suffix,
					config.nscfg.dnss_suffix, CONF_STRLEN );

			if( tunnel->xconf.opts & IPSEC_OPTS_NBNS )
			{
				memcpy( tunnel->xconf.nscfg.nbns_list,
					config.nscfg.nbns_list,
					sizeof( config.nscfg.nbns_list ) );

				tunnel->xconf.nscfg.nbns_count =  config.nscfg.nbns_count;
			}

			tunnel->tstate |= TSTATE_VNET_CONFIG;
			tunnel->ikei->wakeup();
		}
	}

	//
	// DHCP acknowledge
	//

	if( type == DHCP_MSG_ACK )
	{
		if( tunnel->tstate & TSTATE_VNET_CONFIG )
		{
			//
			// setup lease times
			//

			tunnel->event_dhcp.retry = 0;
			tunnel->event_dhcp.renew = time( NULL );
			tunnel->event_dhcp.renew += tunnel->event_dhcp.lease / 2;

			tunnel->ikei->wakeup();
		}
	}

	return LIBIKE_OK;
}
