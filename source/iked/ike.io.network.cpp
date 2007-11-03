
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

long ITH_NWORK::func( void * arg )
{
	IKED * iked = ( IKED * ) arg;
	return iked->loop_ike_nwork();
}

long _IKED::loop_ike_nwork()
{
	//
	// begin network thread
	//

	log.txt( LLOG_INFO, "ii : network process thread begin ...\n" );

	refcount++;

	while( state == DSTATE_ACTIVE )
	{
		//
		// wait for packet availablility
		//

		long result = socket_select( 10 );

		if( result == LIBIKE_SOCKET )
		{
			log.txt( LLOG_ERROR, "!! : hard socket error\n" );
			socket_done();
			continue;
		}

		if( result <= 0 )
			continue;

		//
		// process inbound ike packets
		//

		IKE_SADDR saddr_src;
		IKE_SADDR saddr_dst;

		memset( &saddr_src, 0, sizeof( saddr_src ) );
		memset( &saddr_dst, 0, sizeof( saddr_dst ) );

		saddr_src.saddr4.sin_family = AF_INET;
		saddr_dst.saddr4.sin_family = AF_INET;

		unsigned char proto;

		//
		// attempt to recv packet
		//

		ETH_HEADER eth_header;

		PACKET_IP packet_ip;

		result = recv_ip(
					packet_ip,
					&eth_header );

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
			// examine by destination port
			//

			switch( port_dst )
			{
				//
				// IKE packet
				//

				case LIBIKE_IKE_PORT:
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

					break;
				}

				//
				// is this a NAT-T packet
				//

				case LIBIKE_NATT_PORT:
				{
					//
					// check for NAT-T keep alive
					//

					if( packet_udp.size() < ( ( long ) sizeof( UDP_HEADER ) + 4 ) )
					{
						log.txt( LLOG_DEBUG,
							"<- : recv NAT-T:KEEP-ALIVE packet %s:%u -> %s:%u\n",
							txtaddr_src, port_src,
							txtaddr_dst, port_dst );

						break;
					}

					//
					// check for NAT-T non-esp marker
					//

					uint32_t * marker = ( uint32_t * )( packet_udp.buff() + packet_udp.oset() );

					if( !marker[ 0 ] )
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

						log.bin(
							LLOG_DEBUG,
							LLOG_DECODE,
							packet_ike.buff(),
							packet_ike.size(),
							"<- : recv NAT-T:IKE packet %s:%u -> %s:%u",
							txtaddr_src, port_src,
							txtaddr_dst, port_dst );

						//
						// process the ike packet
						//

						process_ike_recv(
							packet_ike,
							saddr_src,
							saddr_dst );
					}

					break;
				}
			}
		}
	}

	refcount--;

	log.txt( LLOG_INFO, "ii : network process thread exit ...\n" );

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

	packet.read(
		cookies,
		payload,
		exchange,
		flags );

	//
	// attempt to locate a known sa
	// sa for this packet
	//

	IDB_PH1 * ph1 = NULL;

	if( !get_phase1( true, &ph1, NULL, 0, 0, &cookies ) )
	{
		//
		// if we are acting as a responder
		// and the packet has an sa as its
		// first payload as well as a null
		// value for the responder cookie
		//

		bool null_cookie = true;

		for( long x = 0; x < ISAKMP_COOKIE_SIZE; x++ )
			if( cookies.r[ x ] )
				null_cookie = false;

		if( !null_cookie )
		{
			log.txt( LLOG_INFO,
				"XX : ike packet from %s ignored\n"
				"XX : unknown phase1 sa for peer\n"
				"XX : %04x%04x:%04x%04x\n",
				inet_ntoa( saddr_src.saddr4.sin_addr ),
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

		IDB_TUNNEL * tunnel = NULL;

		if( !get_tunnel( true, &tunnel, NULL, &saddr_src, true ) )
		{
			//
			// attempt to locate a peer
			// configuration by address
			//

			IDB_PEER * peer;

			if( !get_peer( true, &peer, &saddr_src ) )
			{
				log.txt( LLOG_INFO,
					"XX : ike packet from %s ignored\n"
					"XX : no matching definition for peer\n",
					inet_ntoa( saddr_src.saddr4.sin_addr ) );

				return LIBIKE_OK;
			}

			if( ( peer->contact != IPSEC_CONTACT_RESP ) &&
				( peer->contact != IPSEC_CONTACT_BOTH ) )
			{
				log.txt( LLOG_INFO,
					"XX : ike packet from %s ignored\n"
					"XX : contact is denied for peer\n",
					inet_ntoa( saddr_src.saddr4.sin_addr ) );

				peer->dec( true );

				return LIBIKE_OK;
			}

			tunnel = new IDB_TUNNEL( peer, &saddr_dst, &saddr_src );

			if( tunnel == NULL )
			{
				log.txt( LLOG_INFO,
					"XX : ike packet from %s ignored\n"
					"XX : unable to create tunnel object\n",
					inet_ntoa( saddr_src.saddr4.sin_addr ) );

				peer->dec( true );

				return LIBIKE_MEMORY;
			}

			tunnel->add( true );
			peer->dec( true );
		}

		// verify that the exchange type
		// is correct and that we allow
		// contact from this peer
		//
		
		if( exchange != tunnel->peer->exchange )
		{
			log.txt( LLOG_INFO,
				"XX : ike packet from %s ignored\n"
				"XX : exchange type mismatch for peer\n",
				inet_ntoa( saddr_src.saddr4.sin_addr ) );

			tunnel->dec( true );

			return LIBIKE_OK;
		}

		uint32_t msgid;
		packet.get_msgid( msgid );

		if( msgid )
		{
			log.txt( LLOG_INFO,
				"XX : ike packet from %s ignored\n"
				"XX : invalid message id for exchange type\n",
				inet_ntoa( saddr_src.saddr4.sin_addr ) );

			tunnel->dec( true );

			return LIBIKE_OK;
		}

		//
		// looks like a valid initial
		// contact attempt. allocate a
		// new sa
		//

		ph1 = new IDB_PH1( tunnel, false, &cookies );

		if( ph1 == NULL )
		{
			log.txt( LLOG_INFO,
				"XX : ike packet from %s ignored\n"
				"XX : unable to create ph1 object\n",
				inet_ntoa( saddr_src.saddr4.sin_addr ) );

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

		if( !ph1->frag_l )
		{
			log.txt( LLOG_ERROR, "!! : fragmented packet received but local support is disabled\n" );

			return LIBIKE_FAILED;
		}

		//
		// process the ike fragment payload
		//

		bool complete = false;
		long result = payload_get_frag( packet, ph1, complete );
		if( result != LIBIKE_OK )
		{
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
