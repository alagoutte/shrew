
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

#ifdef WIN32

long _IKED::filter_dhcp_create( IDB_TUNNEL * tunnel )
{
	//
	// initialize our vflt device and
	// install a rule to catch dhcp
	// reply packets
	//

	tunnel->vflt_dhcp.init( &log );
	tunnel->vflt_dhcp.open();

	FLT_RULE rule;
	memset( &rule, 0, sizeof( rule ) );

	rule.Level   = RLEVEL_DAEMON;
	rule.Group   = tunnel->refid;
	rule.Action  = FLT_ACTION_DIVERT;
	rule.Flags   = FLT_FLAG_RECV;
	rule.Proto   = htons( PROTO_IP );
	rule.IpPro   = PROTO_IP_UDP;
	rule.SrcAddr = tunnel->saddr_r.saddr4.sin_addr.s_addr;
	rule.SrcMask = FLT_MASK_ADDR;
	rule.DstAddr = tunnel->saddr_l.saddr4.sin_addr.s_addr;
	rule.DstMask = FLT_MASK_ADDR;
	rule.SrcPort = htons( UDP_PORT_DHCPS ) ;
	rule.DstPort = htons( UDP_PORT_DHCPC ) ;

	tunnel->vflt_dhcp.rule_add( &rule );

	//
	// create dhcp ipsec policies
	//

	policy_dhcp_create( tunnel );

	return LIBIKE_OK;
}

long _IKED::filter_dhcp_remove( IDB_TUNNEL * tunnel )
{
	//
	// remove dhcp ipsec policies
	//

	policy_dhcp_remove( tunnel );

	//
	// close our vflt device. the rule
	// will die when the handle closes
	//

	tunnel->vflt_dhcp.close();

	return LIBIKE_OK;
}

long _IKED::filter_dhcp_send( IDB_TUNNEL * tunnel, PACKET_IP & packet )
{
	ETH_HEADER eth_head;
	tunnel->vflt_dhcp.head( packet, eth_head );

	packet.ins(
		&eth_head,
		sizeof( eth_head ) );

	tunnel->vflt_dhcp.filt(
		packet.buff(),
		packet.size(),
		FLT_SEND_DN );

	pcap_decrypt.dump(
		packet.buff(),
		packet.size() );

	return LIBIKE_OK;
}

long _IKED::filter_dhcp_recv( IDB_TUNNEL * tunnel, PACKET_IP & packet )
{
	long result = tunnel->vflt_dhcp.select( 10 );
	if( result == FLT_NO_SOCK )
		return LIBIKE_SOCKET;

	if( result < 1 )
		return LIBIKE_NODATA;

	ETH_HEADER eth_header;

	result = tunnel->vflt_dhcp.recv_ip(
				packet,
				&eth_header );

	switch( result )
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

#else

long _IKED::filter_dhcp_create( IDB_TUNNEL * tunnel )
{
	// locate the interface name by address

	struct ifaddrs *ifa = NULL, *ifp = NULL;

	if( getifaddrs( &ifp ) < 0 )
	{
		log.txt( LLOG_ERROR, "!!: unable to obtain interface address list\n" );
		return LIBIKE_SOCKET;
        }

	char 		ifname[ 32 ];
	uint32_t	ifaddr = tunnel->saddr_l.saddr4.sin_addr.s_addr;

	for( ifa = ifp; ifa != NULL; ifa = ifa->ifa_next )
	{
		if( ifa->ifa_addr->sa_family != AF_INET )
			continue;

		sockaddr_in * saddr = ( sockaddr_in * ) ifa->ifa_addr;

		if( memcmp( &saddr->sin_addr, &ifaddr, 4 ) )
			continue;

		strcpy( ifname, ifa->ifa_name );
		break;
        }

	freeifaddrs( ifp );

	if( ifa == ifp )
	{
		log.txt( LLOG_ERROR, "!!: unable to obtain interface name by address\n" );
		return LIBIKE_SOCKET;
	}


	// open berkley packet filter device

	tunnel->bflt_dhcp = -1;
	long dnum = 0;

	while( ( tunnel->bflt_dhcp < 0 ) && ( dnum < 16 ) )
	{
		char device[ 16 ];
		sprintf( device, "/dev/bpf%d", dnum++ );
		tunnel->bflt_dhcp = open( device, O_RDWR );
	}

	if( tunnel->bflt_dhcp < 0 )
	{
		log.txt( LLOG_ERROR, "!!: failed to open DHCP BPF device\n" );
		return LIBIKE_SOCKET;
	}

	// assign the filter to a network device

	struct ifreq ifr;
	strcpy( ifr.ifr_name, ifname );
	if( ioctl( tunnel->bflt_dhcp, BIOCSETIF, ( uint32_t ) &ifr ) == -1 )
	{
		log.txt( LLOG_ERROR, "!!: unable to assign filter to device\n", ifname );
		return LIBIKE_SOCKET;
	}

	// dont buffer packet data

	int imm_value = 1; 
	if( ioctl( tunnel->bflt_dhcp, BIOCIMMEDIATE, &imm_value ) == -1 ) 
	{
		log.txt( LLOG_ERROR, "!!: unable to set BIOCIMMEDIATE for filter device\n" );
		return LIBIKE_SOCKET;
	}

	// use non-blocking io

	int blk_value = 1;
	if( ioctl( tunnel->bflt_dhcp, FIONBIO, &blk_value ) == -1 )
	{
		log.txt( LLOG_ERROR, "!!: unable to set FIONBIO for filter device\n" );
		return LIBIKE_SOCKET;
	}

	// don't return localy generated packets

	int lgp_value = 0;
	if( ioctl( tunnel->bflt_dhcp, BIOCSSEESENT, &lgp_value ) == -1 )
	{
		log.txt( LLOG_ERROR, "!!: unable to set BIOCGSEESENT for filter device\n" );
		return LIBIKE_SOCKET;
	}

	// get the filter buffer size

	int32_t buff_size;
	if( ioctl( tunnel->bflt_dhcp, BIOCGBLEN, &buff_size ) == -1 )
	{
		log.txt( LLOG_ERROR, "!!: unable to obtain filter buffer size\n" );
		return LIBIKE_SOCKET;
	}

	// setup our bpf filter program ( adapted from ISC DHCP )

	struct bpf_insn dhcp_bpf_filter [] = {

		// Make sure this is an IP packet...
		BPF_STMT (BPF_LD + BPF_H + BPF_ABS, 12),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 10),

		// Make sure it's a UDP packet...
		BPF_STMT (BPF_LD + BPF_B + BPF_ABS, 23),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 8),

		// Make sure this isn't a fragment...
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
		BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 6, 0),

		// Make sure it's from the right source address...
		BPF_STMT (BPF_LD + BPF_W + BPF_IND, 26),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, ifaddr, 0, 4),

		// Get the IP header length...
		BPF_STMT (BPF_LDX + BPF_B + BPF_MSH, 14),

		// Make sure it's from the right source port...
		BPF_STMT (BPF_LD + BPF_H + BPF_IND, 16),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, 67, 0, 1),

		// If we passed all the tests, ask for the whole packet.
		BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

		// Otherwise, drop it.
		BPF_STMT(BPF_RET+BPF_K, 0),
	};

	// assign the bpf filter program

	struct bpf_program bpfp;
	bpfp.bf_insns = dhcp_bpf_filter;
	bpfp.bf_len = sizeof( dhcp_bpf_filter ) / sizeof( struct bpf_insn );;

        if( ioctl( tunnel->bflt_dhcp, BIOCSETF, &bpfp ) == -1 )
        {
                printf( "unable to set filter program\n" );
                printf( "exiting ...\n" );
                return -1;
        }

	return LIBIKE_OK;
}

long _IKED::filter_dhcp_remove( IDB_TUNNEL * tunnel )
{
	close( tunnel->bflt_dhcp );
	return LIBIKE_OK;
}

long _IKED::filter_dhcp_send( IDB_TUNNEL * tunnel, PACKET_IP & packet )
{
	send(
		tunnel->bflt_dhcp,
		packet.buff(),
		packet.size(),
		0 );

	return LIBIKE_OK;
}

long _IKED::filter_dhcp_recv( IDB_TUNNEL * tunnel, PACKET_IP & packet )
{
	char buff[ 1024 ];
	long size = 1024;

	size = recv(
		tunnel->bflt_dhcp,
		buff,
		size,
		0 );

	if( size > 0 )
	{
		packet.add( buff, size );
		return LIBIKE_OK;
	}

	return LIBIKE_NODATA;
}

#endif

long _IKED::process_dhcp_send( IDB_TUNNEL * tunnel )
{
	//
	// DHCP over IPsec discover packet
	//

	if( !( tunnel->state & TSTATE_SENT_CONFIG ) )
	{
		//
		// create dhcp discover packet
		//

		in_addr src, dst;
		memcpy( &src, &tunnel->saddr_l.saddr4.sin_addr, sizeof( src ) );
		memcpy( &dst, &tunnel->saddr_r.saddr4.sin_addr, sizeof( dst ) );

		rand_bytes( &tunnel->dhcp_xid, 4 );

		PACKET_UDP packet_dhcp;

		packet_dhcp.write(
			htons( UDP_PORT_DHCPC ),
			htons( UDP_PORT_DHCPS ) );

		DHCP_HEADER dhcp_head;
		memset( &dhcp_head, 0, sizeof( dhcp_head ) );

		dhcp_head.magic = DHCP_MAGIC;
		dhcp_head.op = BOOTP_REQUEST;			// bootp request
		dhcp_head.htype = BOOTP_HW_IPSEC;		// bootp hardware type
		dhcp_head.hlen = 6;						// hardware address length
		dhcp_head.xid = tunnel->dhcp_xid;	// transaction id

		dhcp_head.chaddr[ 0 ] = 0x40;			// locally administered unicast MAC
		memcpy(									// local ipv4 interface address
			dhcp_head.chaddr + 2,
			&src, sizeof( src ) );

		packet_dhcp.add(
			&dhcp_head,
			sizeof( dhcp_head ) );

		packet_dhcp.add_byte( DHCP_OPT_MSGTYPE );	// message type
		packet_dhcp.add_byte( 1 );					// opt size
		packet_dhcp.add_byte( DHCP_MSG_DISCOVER );	// message type value

		packet_dhcp.add_byte( DHCP_OPT_CLIENTID );	// message type
		packet_dhcp.add_byte( 6 );					// opt size
		packet_dhcp.add( dhcp_head.chaddr, 6 );		// client id value

		packet_dhcp.done( src, dst );

		//
		// wrap in ip packet and send
		//

		PACKET_IP packet;
		packet.write( src, dst, ident++, PROTO_IP_UDP );
		packet.add( packet_dhcp );
		packet.done();

		//
		// send the packet
		//

		log.txt( LLOG_DEBUG, "ii: sending DHCP over IPsec discover\n" );

		filter_dhcp_send( tunnel, packet );

		tunnel->state |= TSTATE_SENT_CONFIG;
	}

	//
	// DHCP over IPsec request packet
	//

	return LIBIKE_OK;
}

long _IKED::process_dhcp_recv( IDB_TUNNEL * tunnel )
{
	PACKET_IP packet_ip;
	long result = filter_dhcp_recv( tunnel, packet_ip );
	if( result != LIBIKE_OK )
		return LIBIKE_FAILED;

	//
	// read the ip header
	//

	IKE_SADDR saddr_src;
	IKE_SADDR saddr_dst;

	memset( &saddr_src, 0, sizeof( saddr_src ) );
	memset( &saddr_dst, 0, sizeof( saddr_dst ) );

	saddr_src.saddr4.sin_family = AF_INET;
	saddr_dst.saddr4.sin_family = AF_INET;

	unsigned char proto;

	packet_ip.read(
		saddr_src.saddr4.sin_addr,
		saddr_dst.saddr4.sin_addr,
		proto );

	//
	// read the udp header
	//

	PACKET_UDP packet_dhcp;

	packet_ip.get( packet_dhcp );

	packet_dhcp.read(
		saddr_src.saddr4.sin_port,
		saddr_dst.saddr4.sin_port );

	//
	// examine the dhcp reply header
	//

	DHCP_HEADER dhcp_head;
	if( !packet_dhcp.get( &dhcp_head, sizeof( dhcp_head ) ) )
	{
		log.txt( LLOG_ERROR, "!! : malformed DHCP reply packet\n" );
		tunnel->dec( true );
		return LIBIKE_FAILED;
	}

	if( ( dhcp_head.op != BOOTP_REPLY ) ||			// bootp reply
		( dhcp_head.htype != BOOTP_HW_IPSEC ) ||	// bootp hardware type
		( dhcp_head.hlen != 6 ) ||					// hardware address length
		( dhcp_head.ciaddr != 0 ) ||				// client address
		( dhcp_head.magic != DHCP_MAGIC ) )			// magic cookie
	{
		log.txt( LLOG_ERROR, "!! : invalid DHCP reply parameters\n" );
		tunnel->dec( true );
		return LIBIKE_FAILED;
	}

	//
	// examine the dhcp reply options
	//

	log.txt( LLOG_DEBUG, "ii : reading DHCP reply options\n" );

	IKE_XCONF	config;
	uint8_t		type = -1;
	uint32_t	temp;
	char		txtaddr[ LIBIKE_MAX_TEXTADDR ];
	bool		end = false;

	while( !end )
	{
		unsigned char opt;
		unsigned char len;

		if( !packet_dhcp.get_byte( opt ) )
			break;

		if( !packet_dhcp.get_byte( len ) )
			break;

		if( len > ( packet_dhcp.size() - packet_dhcp.oset() ) )
			break;

		switch( opt )
		{
			case DHCP_OPT_MSGTYPE:
			{
				packet_dhcp.get_byte( type );
				switch( type )
				{
					case DHCP_MSG_OFFER:
						config.addr.s_addr = dhcp_head.yiaddr;
						text_addr( txtaddr, config.addr );
						log.txt( LLOG_DEBUG, "ii : - message type = offer %s\n", txtaddr );
						break;

					case DHCP_MSG_ACK:
						log.txt( LLOG_DEBUG, "ii : - message type = acknowledge\n" );
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
					packet_dhcp.get_quad( temp, false );
					len -= 4;
					config.mask.s_addr = temp;
					text_addr( txtaddr, config.mask );
					log.txt( LLOG_DEBUG, "ii : - IP4 Netmask = %s\n", txtaddr );
				}
				packet_dhcp.get_null( len );
				break;

			case DHCP_OPT_DNSS:
				if( len >= 4 )
				{
					packet_dhcp.get_quad( temp, false );
					len -= 4;
					config.dnss.s_addr = temp;
					text_addr( txtaddr, config.dnss );
					log.txt( LLOG_DEBUG, "ii : - IP4 DNS Server = %s\n", txtaddr );
				}
				packet_dhcp.get_null( len );
				break;

			case DHCP_OPT_NBNS:
				if( len >= 4 )
				{
					packet_dhcp.get_quad( temp, false );
					len -= 4;
					config.nbns.s_addr = temp;
					text_addr( txtaddr, config.nbns );
					log.txt( LLOG_DEBUG, "ii : - IP4 WINS Server = %s\n", txtaddr );
				}
				packet_dhcp.get_null( len );
				break;

			case DHCP_OPT_DOMAIN:
			{
				long tmp = len;
				if( tmp > 255 )
					tmp = 255;
				if( len >= 1 )
				{
					packet_dhcp.get( config.suffix, tmp );
					config.suffix[ tmp ] = 0;
					log.txt( LLOG_DEBUG, "ii : - DNS Suffix = %s\n", config.suffix );
				}
				packet_dhcp.get_null( len - tmp );
				break;
			}
			case DHCP_OPT_CLIENTID:
				log.txt( LLOG_DEBUG, "ii : - clientid ( %i bytes )\n", len );
				packet_dhcp.get_null( len );
				break;

			case DHCP_OPT_END:
				end = true;
				break;

			default:
				log.txt( LLOG_DECODE, "ii : - unknown option ( %02x )\n", opt );
				packet_dhcp.get_null( len );
				break;
		}
	}

	//
	// DHCP offer
	//

	if( type == DHCP_MSG_OFFER )
	{
		if(  ( tunnel->state & TSTATE_SENT_CONFIG ) &&
			!( tunnel->state & TSTATE_RECV_CONFIG ) )
		{
			//
			// accept supported options
			//

			if( tunnel->xconf.opts & IPSEC_OPTS_ADDR )
				tunnel->xconf.addr = config.addr;

			if( tunnel->xconf.opts & IPSEC_OPTS_MASK )
				tunnel->xconf.mask = config.mask;

			if( tunnel->xconf.opts & IPSEC_OPTS_DNSS )
				tunnel->xconf.dnss = config.dnss;

			if( tunnel->xconf.opts & IPSEC_OPTS_DOMAIN )
				memcpy( tunnel->xconf.suffix, config.suffix, CONF_STRLEN );

			if( tunnel->xconf.opts & IPSEC_OPTS_NBNS )
				tunnel->xconf.nbns = config.nbns;

			tunnel->state |= TSTATE_RECV_CONFIG;
		}
	}

	//
	// DHCP acknowledge
	//

	if( type == DHCP_MSG_ACK )
	{
	}

	return LIBIKE_OK;
}
