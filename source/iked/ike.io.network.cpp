
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

//
// ike network io thread
//

long ITH_NWORK::iked_func( void * arg )
{
	IKED * iked = ( IKED * ) arg;
	return iked->loop_ike_nwork();
}

long _IKED::loop_ike_nwork()
{
	//
	// begin network thread
	//

	loop_ref_inc( "network" );

	ETH_HEADER	eth_header;
	PACKET_IP	packet_ip;

	while( true )
	{
		//
		// attempt to recv packet
		//

		long result = recv_ip(
					packet_ip,
					&eth_header );

		if( result == LIBIKE_SOCKET )
			break;

		if( result == LIBIKE_NODATA )
			continue;

		//
		// dump encrypted packets
		//

		if( dump_encrypt )
			pcap_encrypt.dump(
				eth_header,
				packet_ip );

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
		// convert source ip address
		// to a string for logging
		//

		char txtaddr_src[ LIBIKE_MAX_TEXTADDR ];
		char txtaddr_dst[ LIBIKE_MAX_TEXTADDR ];

		text_addr( txtaddr_src, &saddr_src, false );
		text_addr( txtaddr_dst, &saddr_dst, false );

		//
		// is this a UDP packet
		//

		if( proto == PROTO_IP_UDP )
		{
			//
			// read the udp packet
			//

			PACKET_UDP packet_udp;
			packet_ip.get( packet_udp );

			packet_udp.read(
				saddr_src.saddr4.sin_port,
				saddr_dst.saddr4.sin_port );

			unsigned short port_src = htons( saddr_src.saddr4.sin_port );
			unsigned short port_dst = htons( saddr_dst.saddr4.sin_port );

			//
			// check for NAT-T keep alive
			//

			if( packet_udp.size() < sizeof( IKE_HEADER ) )
			{
				log.txt( LLOG_DEBUG,
					"<- : recv NAT-T:KEEP-ALIVE packet %s:%u -> %s:%u\n",
					txtaddr_src, port_src,
					txtaddr_dst, port_dst );

				continue;
			}

			//
			// examine the packet contents
			// for a NAT-T non-ESP marker
			//

			uint32_t * marker = ( uint32_t * )( packet_udp.buff() + packet_udp.oset() );

			if( marker[ 0 ] )
			{
				//
				// obtain packet payload
				//

				PACKET_IKE packet_ike;
				packet_udp.get( packet_ike );

				log.bin(
					LLOG_DEBUG,
					LLOG_DECODE,
					packet_ike.buff(),
					packet_ike.size(),
					"<- : recv IKE packet %s:%u -> %s:%u",
					txtaddr_src, port_src,
					txtaddr_dst, port_dst );

				//
				// process the ike packet
				//

				process_ike_recv(
					packet_ike,
					saddr_src,
					saddr_dst );

				continue;
			}
			else
			{
				//
				// skip the null marker
				//

				packet_udp.get_null( 4 );

				//
				// obtain IKE packet payload
				//

				PACKET_IKE packet_ike;
				packet_udp.get( packet_ike );

				//
				// process the ike packet
				//

				log.bin(
					LLOG_DEBUG,
					LLOG_DECODE,
					packet_ike.buff(),
					packet_ike.size(),
					"<- : recv NAT-T:IKE packet %s:%u -> %s:%u",
					txtaddr_src, port_src,
					txtaddr_dst, port_dst );

				process_ike_recv(
					packet_ike,
					saddr_src,
					saddr_dst );
			}
		}
	}

	loop_ref_dec( "network" );

	return LIBIKE_OK;
}

long _IKED::process_ike_recv( PACKET_IKE & packet, IKE_SADDR & saddr_src, IKE_SADDR & saddr_dst )
{
	//
	// read packet header
	//

	IKE_COOKIES	cookies;
	uint8_t		payload;
	uint8_t		exchange;
	uint8_t		flags;

	if( !packet.read(
			cookies,
			payload,
			exchange,
			flags ) )
	{
		log.txt( LLOG_ERROR,
			"!! : invalid ISAKMP header\n" );

		return LIBIKE_OK;
	}

	char txtaddr_src[ LIBIKE_MAX_TEXTADDR ];
	text_addr( txtaddr_src, &saddr_src, false );

	//
	// attempt to locate a known sa
	// sa for this packet
	//

	IDB_PH1 * ph1 = NULL;

	if( !idb_list_ph1.find(
			true,
			&ph1,
			NULL,
			XCH_STATUS_ANY,
			XCH_STATUS_ANY,
			&cookies ) )
	{
		//
		// if we are acting as a responder
		// and the packet has an SA as its
		// first payload as well as a null
		// value for the responder cookie
		//

		bool null_cookie = true;
		for( long x = 0; x < ISAKMP_COOKIE_SIZE; x++ )
		{
			if( cookies.r[ x ] )
			{
				null_cookie = false;
				break;
			}
		}

		if( !null_cookie )
		{
			log.txt( LLOG_INFO,
				"ww : ike packet from %s ignored, unknown phase1 sa for peer\n"
				"ww : %08x%08x:%08x%08x\n",
				txtaddr_src,
				htonl( *( long * ) &cookies.i[ 0 ] ),
				htonl( *( long * ) &cookies.i[ 4 ] ),
				htonl( *( long * ) &cookies.r[ 0 ] ),
				htonl( *( long * ) &cookies.r[ 4 ] ) );

			return LIBIKE_OK;
		}

		//
		// attempt to locate a tunnel
		// definition for this peer
		//

		log.txt( LLOG_DEBUG,
			"ii : attempting to locate tunnel for peer %s\n",
			txtaddr_src );

		IDB_TUNNEL * tunnel = NULL;

		if( !idb_list_tunnel.find(
				true,
				&tunnel,
				NULL,
				&saddr_src,
				true,
				false ) )
		{
			//
			// attempt to locate a peer
			// configuration by address
			//

			IDB_PEER * peer;

			if( !idb_list_peer.find(
					true,
					&peer,
					&saddr_src ) )
			{
				log.txt( LLOG_INFO,
					"ww : ike packet from %s ignored, no matching definition for peer\n",
					txtaddr_src );

				return LIBIKE_OK;
			}

			tunnel = new IDB_TUNNEL( peer, NULL, &saddr_dst, &saddr_src );

			if( tunnel == NULL )
			{
				log.txt( LLOG_INFO,
					"ww : ike packet from %s ignored, unable to create tunnel object\n",
					txtaddr_src );

				peer->dec( true );
				return LIBIKE_MEMORY;
			}

			tunnel->add( true );
			peer->dec( true );
		}

		//
		// verify that the exchange type is correct
		// and that we allow contact from this peer
		//
		
		if( exchange != tunnel->peer->exchange )
		{
			log.txt( LLOG_INFO,
				"ww : ike packet from %s ignored, exchange type mismatch for peer\n",
				txtaddr_src );

			tunnel->dec( true );
			return LIBIKE_OK;
		}

		if( ( tunnel->peer->contact != IPSEC_CONTACT_RESP ) &&
			( tunnel->peer->contact != IPSEC_CONTACT_BOTH ) )
		{
			log.txt( LLOG_INFO,
				"ww : ike packet from %s ignored, contact is denied for peer\n",
				txtaddr_src );

			tunnel->dec( true );
			return LIBIKE_OK;
		}

		if( packet.get_msgid() )
		{
			log.txt( LLOG_INFO,
				"ww : ike packet from %s ignored, invalid message id for exchange type\n",
				txtaddr_src );

			tunnel->dec( true );
			return LIBIKE_OK;
		}

		//
		// looks like a valid initial contact attempt.
		// allocate a new SA
		//

		log.txt( LLOG_DEBUG,
			"ii : creating new phase1 handle for peer %s\n",
			txtaddr_src );

		ph1 = new IDB_PH1( tunnel, false, &cookies );
		if( ph1 == NULL )
		{
			log.txt( LLOG_INFO,
				"ww : ike packet from %s ignored, unable to create phase1 handle\n",
				txtaddr_src );

			tunnel->dec( true );
			return LIBIKE_MEMORY;
		}

		ph1->add( true );
		tunnel->dec( true );
	}

	//
	// check the remote port value against
	// the recorded tunnel port value
	//

	if( !phase1_chk_port( ph1, &saddr_src, &saddr_dst ) )
	{
		ph1->dec( true );
		return LIBIKE_FAILED;
	}

	//
	// handle fragmented ike packets
	//

	if( payload == ISAKMP_PAYLOAD_FRAGMENT )
	{
		//
		// if fragmentation was not negotiated
		// then dump the packet
		//

		if( !ph1->vendopts_l.flag.frag )
		{
			log.txt( LLOG_ERROR, "!! : fragmented packet received but local support is disabled\n" );
			ph1->dec( true );
			return LIBIKE_FAILED;
		}

		//
		// process the ike fragment payload
		//

		bool complete = false;
		long result = payload_get_frag( packet, ph1, complete );
		if( result != LIBIKE_OK )
		{
			log.txt( LLOG_ERROR, "!! : unable to process ike fragment payload\n" );
			ph1->dec( true );
			return result;
		}

		//
		// if this was the last ike fragment,
		// the packet data should now have
		// been replaced with a complete packet.
		// otherwise we have nothing more to do
		//

		if( !complete )
		{
			log.txt( LLOG_INFO, "ii : ike fragment received, waiting on complete packet\n" );
			ph1->dec( true );
			return LIBIKE_OK;
		}

		//
		// we have a complete packet, read the
		// complete packets header and proceed
		//

		packet.read(
			cookies,
			payload,
			exchange,
			flags );

		log.txt( LLOG_INFO, "ii : ike fragment received, processing complete packet\n" );
	}

	//
	// process packet based on exchange type
	//

	long result = LIBIKE_OK;

	switch( exchange )
	{
		//
		// phase1 exchange
		//

		case ISAKMP_EXCH_IDENT_PROTECT:
		case ISAKMP_EXCH_AGGRESSIVE:
			result = process_phase1_recv( ph1, packet, payload );
			break;

		//
		// phase2 exchange
		//

		case ISAKMP_EXCH_QUICK:
			result = process_phase2_recv( ph1, packet, payload );
			break;

		//
		// informational exchange
		//

		case ISAKMP_EXCH_INFORMATIONAL:
			result = process_inform_recv( ph1, packet, payload );
			break;

		//
		// transactional config exchange
		//

		case ISAKMP_EXCH_CONFIG:
			result = process_config_recv( ph1, packet, payload );
			break;

		//
		// unknown exchange
		//

		default:
		{
			log.txt( LLOG_ERROR,
				"!! : unhandled exchange type %s ( %i )\n",
				find_name( NAME_EXCHANGE, exchange ),
				exchange );

			result = LIBIKE_OK;
			break;
		}
	}

	ph1->dec( true );
	return result;
}

long _IKED::process_ike_send()
{
	return LIBIKE_OK;
}
