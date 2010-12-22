
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

long _IKED::process_phase2_recv( IDB_PH1 * ph1, PACKET_IKE & packet, unsigned char payload )
{
	long result = LIBIKE_OK;

	//
	// log packet type
	//

	log.txt( LLOG_INFO,
		"ii : processing phase2 packet ( %i bytes )\n",
		packet.size() );

	//
	// attempt to locate a known
	// sa for this message id
	//

	uint32_t msgid = packet.get_msgid();

	IDB_PH2 * ph2 = NULL;
	
	if( !idb_list_ph2.find(
			true,
			&ph2,
			ph1->tunnel,
			XCH_STATUS_ANY,
			XCH_STATUS_ANY,
			NULL,
			&msgid,
			NULL,
			NULL ) )
	{
		//
		// looks like a unique phase 2
		// session, allocate a new sa
		//

		ph2 = new IDB_PH2( ph1->tunnel, false, msgid, 0 );
		ph2->add( true );

		//
		// calculate iv for this
		// pahse2 exchange
		//

		ph2->new_msgiv( ph1 );

		//
		// make sure we respond using the
		// isakmp sa that was last seen
		//

		ph2->cookies = ph1->cookies;
	}

	//
	// make sure we are not dealing
	// with an sa marked for death
	//

	if( ph1->status() == XCH_STATUS_DEAD )
	{
		log.txt( LLOG_ERROR, "!! : phase2 packet ignored ( phase1 marked for death )\n" );
		ph2->dec( true );
		return LIBIKE_OK;
	}

	if( ph2->status() == XCH_STATUS_DEAD )
	{
		log.txt( LLOG_ERROR, "!! : phase2 packet ignored ( phase2 marked for death )\n" );
		ph2->dec( true );
		return LIBIKE_OK;
	}

	//
	// make sure we are not dealing
	// whith an imature phase1 sa
	//

	if( ph1->status() < XCH_STATUS_MATURE )
	{
		log.txt( LLOG_ERROR, "!! : config packet ignored ( phase1 not mature )\n" );
		ph2->dec( true );
		return LIBIKE_OK;
	}

	//
	// make sure we are not dealing
	// with a mature sa
	//

	if( ph2->status() >= XCH_STATUS_MATURE )
	{
		log.txt( LLOG_ERROR, "!! : phase2 packet ignored, resending last packet ( phase2 already mature )\n" );
		ph2->resend();
		ph2->dec( true );
		return LIBIKE_OK;
	}

	//
	// attempt to decrypt our packet
	//

	if( packet_ike_decrypt( ph1, packet, &ph2->iv ) != LIBIKE_OK )
	{
		log.txt( LLOG_ERROR, "!! : phase2 packet ignored, resending last packet ( packet decryption error )\n" );
		ph2->resend();
		ph2->dec( true );
		return LIBIKE_OK;
	}

	//
	// if we are dumping decrypted packets,
	// we need to rebuild a full packet to
	// dump to pcap format 
	//

	if( dump_decrypt )
	{
		//
		// strip the isakmp encryption flag
		//

		packet.buff()[ ISAKMP_FLAGS_OFFSET ] &= ~ISAKMP_FLAG_ENCRYPT;

		//
		// build ip dump packet
		//

		PACKET_IP packet_ip_dump;
		packet_ike_encap(
			packet,
			packet_ip_dump,
			ph1->tunnel->saddr_r,
			ph1->tunnel->saddr_l,
			ph1->tunnel->natt_version );

		//
		// obtain ethernet header
		//

		ETH_HEADER ethhdr;
		header( packet_ip_dump, ethhdr );

		//
		// dump the packet
		//

		pcap_decrypt.dump(
			ethhdr,
			packet_ip_dump );
	}
/*
	//
	// read and validate the hash
	//

	if( !packet.get_payload( false, payload ) )
	{
		log.txt( LLOG_ERROR, "!! : phase2 packet ignored ( invalid hash payload )\n" );
		ph2->dec( true );
		return LIBIKE_OK;
	}

	if( payload_get_hash( packet, ph2->hash_r, ph1->hash_size ) != LIBIKE_OK )
	{
		log.txt( LLOG_ERROR, "!! : phase2 packet ignored ( invalid hash value )\n" );
		ph2->dec( true );
		return LIBIKE_OK;
	}

	//
	// populate hash data accumulator
	//

	ph2->hda.size( 0 );
	ph2->hda.add(
		packet.buff() + packet.oset(),
		packet.size() - packet.oset() );

	if( ph2->initiator )
	{
		//
		// check responders hash
		//

		if( !( ph2->xstate & XSTATE_RECV_HA ) )
		{
			//
			// quick mode hash
			//

			if( phase2_chk_hash_r( ph1, ph2 ) != LIBIKE_OK )
				packet.notify = ISAKMP_N_INVALID_HASH_INFORMATION;

			ph2->xstate |= XSTATE_RECV_HA;
//			ph2->lstate |= LSTATE_CHKHASH;
		}
	}
	else
	{
		//
		// check initiators hash
		//

		if( !( ph2->xstate & XSTATE_RECV_HA ) )
		{
			//
			// quick mode hash
			//

			if( phase2_chk_hash_i( ph1, ph2 ) != LIBIKE_OK )
				packet.notify = ISAKMP_N_INVALID_HASH_INFORMATION;

			ph2->xstate |= XSTATE_RECV_HA;
//			ph2->lstate |= LSTATE_CHKHASH;
		}
		else
		{
			//
			// livliness proof hash
			//

			if( phase2_chk_hash_p( ph1, ph2 ) != LIBIKE_OK )
				packet.notify = ISAKMP_N_INVALID_HASH_INFORMATION;

			ph2->xstate |= XSTATE_RECV_LP;
		}
	}
*/
	//
	// read and process all payloads
	//

	ph2->hda.del( true );

	uint8_t next_payload;

	while( payload != ISAKMP_PAYLOAD_NONE )
	{
		//
		// read the payload header
		//

		if( !packet.get_payload( false, next_payload ) )
			break;

		//
		// check the payload type
		//

		switch( payload )
		{

			//
			// read the hash payload
			//

			case ISAKMP_PAYLOAD_HASH:
			{
				if( ( ph2->xstate & XSTATE_RECV_HA ) &&
					( ph2->xstate & XSTATE_RECV_LP ) )
					log.txt( LLOG_INFO, "<< : ignoring duplicate hash payload\n" );
				else
				{
					result = payload_get_hash( packet, ph2->hash_r, ph1->hash_size );

					if( !( ph2->xstate & XSTATE_RECV_HA ) )
						ph2->xstate |= XSTATE_RECV_HA;
					else
						ph2->xstate |= XSTATE_RECV_LP;
				}

				break;
			}

			//
			// security association payload
			//

			case ISAKMP_PAYLOAD_SA:
			{
				if( ph2->xstate & XSTATE_RECV_SA )
					log.txt( LLOG_INFO, "<< : ignoring duplicate security association payload\n" );
				else
				{
					size_t beg = packet.oset() - 4;
					result = payload_get_sa( packet, ph2->plist_r );
					size_t end = packet.oset();

					ph2->hda.add( packet.buff() + beg, end - beg );
				}

				ph2->xstate |= XSTATE_RECV_SA;

				break;
			}

			//
			// nonce payload
			//

			case ISAKMP_PAYLOAD_NONCE:
			{
				if( ph2->xstate & XSTATE_RECV_NO )
					log.txt( LLOG_INFO, "<< : ignoring duplicate nonce payload\n" );
				else
				{
					size_t beg = packet.oset() - 4;
					result = payload_get_nonce( packet, ph2->nonce_r );
					size_t end = packet.oset();

					ph2->hda.add( packet.buff() + beg, end - beg );
				}

				ph2->xstate |= XSTATE_RECV_NO;

				break;
			}

			//
			// identity payload
			//

			case ISAKMP_PAYLOAD_IDENT:
			{
				if( ph2->initiator )
				{
					if( !( ph2->xstate & XSTATE_RECV_IDL ) )
					{
						size_t beg = packet.oset() - 4;
						result = payload_get_ph2id( packet, ph2->ph2id_rd );
						size_t end = packet.oset();

						ph2->hda.add( packet.buff() + beg, end - beg );

						ph2->xstate |= XSTATE_RECV_IDL;

						break;
					}

					if( !( ph2->xstate & XSTATE_RECV_IDR ) )
					{
						size_t beg = packet.oset() - 4;
						result = payload_get_ph2id( packet, ph2->ph2id_rs );
						size_t end = packet.oset();

						ph2->hda.add( packet.buff() + beg, end - beg );

						ph2->xstate |= XSTATE_RECV_IDR;

						break;
					}
				}
				else
				{
					if( !( ph2->xstate & XSTATE_RECV_IDR ) )
					{
						size_t beg = packet.oset() - 4;
						result = payload_get_ph2id( packet, ph2->ph2id_rs );
						size_t end = packet.oset();

						ph2->hda.add( packet.buff() + beg, end - beg );

						ph2->xstate |= XSTATE_RECV_IDR;

						break;
					}

					if( !( ph2->xstate & XSTATE_RECV_IDL ) )
					{
						size_t beg = packet.oset() - 4;
						result = payload_get_ph2id( packet, ph2->ph2id_rd );
						size_t end = packet.oset();

						ph2->hda.add( packet.buff() + beg, end - beg );

						ph2->xstate |= XSTATE_RECV_IDL;

						break;
					}
				}

				if( ( ph2->xstate & XSTATE_RECV_IDR ) &&
				    ( ph2->xstate & XSTATE_RECV_IDL ) )
					log.txt( LLOG_INFO, "<< : ignoring duplicate id payload\n" );

				break;
			}

			//
			// key exchange payload
			//

			case ISAKMP_PAYLOAD_KEX:
			{
				if( ph2->xstate & XSTATE_RECV_KE )
					log.txt( LLOG_INFO, "<< : ignoring duplicate key excahnge payload\n" );
				else
				{
					size_t beg = packet.oset() - 4;
					result = payload_get_kex( packet, ph2->xr );
					size_t end = packet.oset();

					ph2->hda.add( packet.buff() + beg, end - beg );
				}

				ph2->xstate |= XSTATE_RECV_KE;

				break;
			}

			//
			// natt original address ( ignored )
			//

			case ISAKMP_PAYLOAD_NAT_VXX_ORIG:
			case ISAKMP_PAYLOAD_NAT_RFC_ORIG:
			{
				log.txt( LLOG_INFO, "<< : natt original address\n" );

				size_t beg = packet.oset() - 4;
				packet.get_null( packet.get_payload_left() );
				size_t end = packet.oset();

				ph2->hda.add( packet.buff() + beg, end - beg );

				break;
			}

			//
			// notify payload
			//

			case ISAKMP_PAYLOAD_NOTIFY:
			{
				IKE_NOTIFY notify;

				size_t beg = packet.oset() - 4;
				result = payload_get_notify( packet, &notify );
				size_t end = packet.oset();

				ph2->hda.add( packet.buff() + beg, end - beg );

				if( result == LIBIKE_OK )
					ph2->notifications.add( notify );

				break;
			}

			//
			// unhandled payload
			//

			default:

				log.txt( LLOG_ERROR,
					"!! : unhandled phase2 payload \'%s\' ( %i )\n",
					find_name( NAME_PAYLOAD, payload ),
					payload );

				packet.notify = ISAKMP_N_INVALID_PAYLOAD_TYPE;

				result = LIBIKE_DECODE;

				break;
		}

		//
		// check that the entire payload was read
		//

		if( packet.get_payload_left() )
			log.txt( LLOG_ERROR, "!! : unprocessed payload data !!!\n" );

		//
		// check the final paylaod process result
		//

		if( result != LIBIKE_OK )
		{
			ph2->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, packet.notify );
			ph2->dec( true );

			return result;
		}

		//
		// read next payload
		//

		payload = next_payload;
	}

	//
	// now that all payloads have been read,
	// validate any received hash, peer id
	// and proposal payloads
	//

	while( true )
	{
		if( ph2->initiator )
		{
			//
			// check responders quick mode hash
			//

			if( ( ph2->status() < XCH_STATUS_MATURE ) &&
				( ph2->xstate & XSTATE_RECV_HA ) &&
				( ph2->xstate & XSTATE_RECV_SA ) &&
				( ph2->xstate & XSTATE_RECV_NO ) )
			{
				result = phase2_chk_hash_r( ph1, ph2 );

				if( result != LIBIKE_OK )
				{
					packet.notify = ISAKMP_N_INVALID_HASH_INFORMATION;
					break;
				}

				ph2->lstate |= LSTATE_CHKHASH;

				//
				// validate that the remote ids
				// match the ids proposed by us
				//

				result = phase2_chk_params( ph1, ph2, packet );

				if( result != LIBIKE_OK )
					break;

				//
				// log result
				//

				char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
				char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

				text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
				text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

				log.txt( LLOG_INFO,
					"ii : phase2 sa established\n"
					"ii : %s <-> %s\n",
					txtaddr_l,
					txtaddr_r );

				ph2->lstate |= LSTATE_CHKIDS;
			}
		}
		else
		{
			//
			// check initiators quick mode hash
			//

			if(  ( ph2->xstate & XSTATE_RECV_HA ) &&
				 ( ph2->xstate & XSTATE_RECV_SA ) &&
				 ( ph2->xstate & XSTATE_RECV_NO ) &&
				!( ph2->lstate & LSTATE_CHKHASH ) )
			{
				result = phase2_chk_hash_i( ph1, ph2 );

				if( result != LIBIKE_OK )
				{
					packet.notify = ISAKMP_N_INVALID_HASH_INFORMATION;
					break;
				}

				ph2->lstate |= LSTATE_CHKHASH;

				//
				// verify the peer ids against
				// the local policy database
				// and acquire spis
				//

				result = phase2_chk_params( ph1, ph2, packet );

				if( result != LIBIKE_OK )
					break;

				ph2->lstate |= LSTATE_CHKIDS;
			}

			//
			// check initiators liveliness proof hash
			//

			if( ( ph2->status() < XCH_STATUS_MATURE ) &&
				( ph2->xstate & XSTATE_RECV_LP ) )
			{
				result = phase2_chk_hash_p( ph1, ph2 );

				if( result != LIBIKE_OK )
				{
					packet.notify = ISAKMP_N_INVALID_HASH_INFORMATION;
					break;
				}
				else
				{
					//
					// generate our keys
					//

					phase2_gen_keys( ph1, ph2 );

					//
					// log result
					//

					char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
					char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

					text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
					text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

					log.txt( LLOG_INFO,
						"ii : phase2 sa established\n"
						"ii : %s <-> %s\n",
						txtaddr_l,
						txtaddr_r );

					ph2->status( XCH_STATUS_MATURE, XCH_NORMAL, 0 );
					ph2->clean();
				}
			}
		}

		break;
	}

	//
	// check the peer payload results
	//

	if( result != LIBIKE_OK )
	{
		ph2->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, packet.notify );
		ph2->dec( true );

		return result;
	}

	//
	// now build and send any response
	// packets that may be necessary
	//
	// NOTE : responder packets are only
	// sent via the pfkey thread after an
	// outbound SPI is received
	//

	if( ph2->initiator &&
		( ph1->status() != XCH_STATUS_DEAD ) &&
		( ph2->status() < XCH_STATUS_MATURE ) )
		process_phase2_send( ph1, ph2 );

	//
	// cleanup
	//

	ph2->dec( true );

	return LIBIKE_OK;
}

long _IKED::process_phase2_send( IDB_PH1 * ph1, IDB_PH2 * ph2 )
{
	//
	// quick mode initiator
	//

	if( ph2->initiator )
	{
		if(	!( ph2->xstate & XSTATE_SENT_HA ) )
		{
			//
			// hash + sa + nonce [ + ke ] + idi + idr packet
			//

			PACKET_IKE packet;

			packet.set_msgid( ph2->msgid );
			packet.write( ph1->cookies, ISAKMP_PAYLOAD_HASH, ISAKMP_EXCH_QUICK, ISAKMP_FLAG_ENCRYPT );

			size_t off = packet.size();

			ph2->hash_l.size( ph1->hash_size );

			payload_add_hash( packet, ph2->hash_l, ISAKMP_PAYLOAD_SA );

			size_t beg = packet.size();

			payload_add_sa( packet, ph2->plist_l, ISAKMP_PAYLOAD_NONCE );

			//
			// if we are using pfs, the payload
			// order changes to include a kex
			//
			// NOTE : if nonce is omitted,
			//        racoon crashes
			//

			unsigned char next = ISAKMP_PAYLOAD_IDENT;
			if( ph2->dhgr_id )
				next = ISAKMP_PAYLOAD_KEX;

			payload_add_nonce( packet, ph2->nonce_l, next );

			if( ph2->dhgr_id )
				payload_add_kex( packet, ph2->xl, ISAKMP_PAYLOAD_IDENT );

			payload_add_ph2id( packet, ph2->ph2id_ls, ISAKMP_PAYLOAD_IDENT );
			payload_add_ph2id( packet, ph2->ph2id_ld, ISAKMP_PAYLOAD_NONE );

			packet.done();

			size_t end = packet.size();

			ph2->hda.set( packet.buff() + beg, end - beg );

			//
			// calculate quick mode hash
			//

			phase2_gen_hash_i( ph1, ph2, ph2->hash_l );

			memcpy( packet.buff() + off + 4, ph2->hash_l.buff(), ph1->hash_size );

			//
			// calculate iv for this
			// pahse2 exchange
			//

			ph2->new_msgiv( ph1 );

			//
			// send packet
			//

			packet_ike_send( ph1, ph2, packet, true );

			//
			// update sa state
			//

			ph2->xstate |= XSTATE_SENT_HA;
			ph2->xstate |= XSTATE_SENT_SA;
			ph2->xstate |= XSTATE_SENT_NO;
		}

		//
		// hash packet ( livliness proof )
		//

		if(  ( ph2->xstate & XSTATE_RECV_HA ) &&
			 ( ph2->xstate & XSTATE_RECV_SA ) &&
			 ( ph2->xstate & XSTATE_RECV_NO ) && 
			!( ph2->xstate & XSTATE_SENT_LP ) )
		{
			//
			// calculate livliness proof hash
			//

			BDATA hash;
			phase2_gen_hash_p( ph1, ph2, hash );

			//
			// build packet
			//

			PACKET_IKE packet;

			packet.set_msgid( ph2->msgid );
			packet.write( ph1->cookies, ISAKMP_PAYLOAD_HASH, ISAKMP_EXCH_QUICK, ISAKMP_FLAG_ENCRYPT );
			payload_add_hash( packet, hash, ISAKMP_PAYLOAD_NONE );
			packet.done();

			//
			// send packet
			//

			packet_ike_send( ph1, ph2, packet, false );

			//
			// generate our keys
			//

			phase2_gen_keys( ph1, ph2 );

			//
			// update sa state
			//

			ph2->xstate |= XSTATE_SENT_LP;

			ph2->status( XCH_STATUS_MATURE, XCH_NORMAL, 0 );
			ph2->clean();
		}
	}

	//
	// quick mode responder
	//

	if( !ph2->initiator )
	{
		//
		// hash + sa + nonce [ + ke ] + idi + idr packet
		//

		if(  ( ph2->xstate & XSTATE_RECV_HA ) &&
			 ( ph2->xstate & XSTATE_RECV_SA ) &&
			 ( ph2->xstate & XSTATE_RECV_NO ) && 
			!( ph2->xstate & XSTATE_SENT_HA ) )
		{
			//
			// build packet
			//

			PACKET_IKE packet;

			packet.set_msgid( ph2->msgid );
			packet.write( ph1->cookies, ISAKMP_PAYLOAD_HASH, ISAKMP_EXCH_QUICK, ISAKMP_FLAG_ENCRYPT );

			size_t off = packet.size();

			ph2->hash_l.size( ph1->hash_size );

			payload_add_hash( packet, ph2->hash_l, ISAKMP_PAYLOAD_SA );

			size_t beg = packet.size();

			payload_add_sa( packet, ph2->plist_l, ISAKMP_PAYLOAD_NONCE );

			//
			// if we are using pfs, the payload
			// order changes to include a kex
			//
			// NOTE : if nonce is omitted,
			//        racoon crashes
			//

			unsigned char next = ISAKMP_PAYLOAD_IDENT;
			if( ph2->dhgr_id )
				next = ISAKMP_PAYLOAD_KEX;

			payload_add_nonce( packet, ph2->nonce_l, next );

			if( ph2->dhgr_id )
				payload_add_kex( packet, ph2->xl, ISAKMP_PAYLOAD_IDENT );

			payload_add_ph2id( packet, ph2->ph2id_ld, ISAKMP_PAYLOAD_IDENT );

			//
			// if we are claiming the lifetime,
			// the payload order changes to include
			// a notification payload
			//

			next = ISAKMP_PAYLOAD_NONE;
			if( ph2->lstate & LSTATE_CLAIMLT )
				next = ISAKMP_PAYLOAD_NOTIFY;

			payload_add_ph2id( packet, ph2->ph2id_ls, next );

			//
			// possibly add reponder lifetime
			// payloads for all proposals
			//

			if( ph2->lstate & LSTATE_CLAIMLT )
			{
				IKE_PROPOSAL * proposal;
				long pindex = 0;
				long pcount = ph2->plist_l.count();

				for( ; pindex < pcount; pindex++ )
				{
					ph2->plist_l.get( &proposal, pindex );

					unsigned long lval = htonl( proposal->life_sec );

					IKE_NOTIFY notify;
					notify.type = ISAKMP_PAYLOAD_NOTIFY;
					notify.doi = ISAKMP_DOI_IPSEC;
					notify.proto = proposal->proto;
					notify.code = ISAKMP_N_RESPONDER_LIFETIME;
					notify.spi = proposal->spi;

					PACKET_IKE temp;
					IKE_ATTR attrib;

					attrib.atype = ISAKMP_ATTR_LIFE_TYPE;
					attrib.basic = true;
					attrib.bdata = IKE_LIFE_TYPE_SECONDS;

					payload_add_attr( temp, attrib );

					attrib.atype = ISAKMP_ATTR_LIFE_DURATION;
					attrib.basic = false;
					attrib.vdata.set( &lval, sizeof( lval ) );

					payload_add_attr( temp, attrib );

					notify.data.set( temp );

					unsigned char next = ISAKMP_PAYLOAD_NONE;
					if( ( pcount - pindex ) > 1 )
						next = ISAKMP_PAYLOAD_NOTIFY;

					payload_add_notify( packet, &notify, next );
				}
			}

			packet.done();

			size_t end = packet.size();

			ph2->hda.del();
			ph2->hda.set( packet.buff() + beg, end - beg );

			//
			// calculate quick mode hash
			//

			phase2_gen_hash_r( ph1, ph2, ph2->hash_l );

			memcpy( packet.buff() + off + 4, ph2->hash_l.buff(), ph2->hash_l.size() );

			//
			// send packet
			//

			packet_ike_send( ph1, ph2, packet, false );

			//
			// update sa state
			//

			ph2->xstate |= XSTATE_SENT_HA;
			ph2->xstate |= XSTATE_SENT_SA;
			ph2->xstate |= XSTATE_SENT_NO;
		}
	}

	return LIBIKE_OK;
}

long _IKED::phase2_gen_hash_i( IDB_PH1 * ph1, IDB_PH2 * ph2, BDATA & hash )
{
	BDATA input;
	input.add( &ph2->msgid, sizeof( ph2->msgid ) );
	input.add( ph2->hda );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		input.buff(),
		input.size(),
		"== : phase2 hash_i ( input )" );

	hash.size( ph1->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_CTX_init( &ctx_prf );

	HMAC_Init_ex( &ctx_prf, ph1->skeyid_a.buff(), ( int ) ph1->skeyid_a.size(), ph1->evp_hash, NULL );
	HMAC_Update( &ctx_prf, input.buff(), input.size() );
	HMAC_Final( &ctx_prf, hash.buff(), NULL );

	HMAC_CTX_cleanup( &ctx_prf );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		hash.buff(),
		hash.size(),
		"== : phase2 hash_i ( computed )" );

	return LIBIKE_OK;
}

long _IKED::phase2_gen_hash_r( IDB_PH1 * ph1, IDB_PH2 * ph2, BDATA & hash )
{
	BDATA input;
	input.add( &ph2->msgid, sizeof( ph2->msgid ) );

	if( ph2->initiator )
		input.add( ph2->nonce_l );
	else
		input.add( ph2->nonce_r );

	input.add( ph2->hda );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		input.buff(),
		input.size(),
		"== : phase2 hash_r ( input )" );

	hash.size( ph1->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_CTX_init( &ctx_prf );

	HMAC_Init_ex( &ctx_prf, ph1->skeyid_a.buff(), ( int ) ph1->skeyid_a.size(), ph1->evp_hash, NULL );
	HMAC_Update( &ctx_prf, input.buff(), input.size() );
	HMAC_Final( &ctx_prf, hash.buff(), NULL );

	HMAC_CTX_cleanup( &ctx_prf );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		hash.buff(),
		hash.size(),
		"== : phase2 hash_r ( computed )" );

	return LIBIKE_OK;
}

long _IKED::phase2_gen_hash_p( IDB_PH1 * ph1, IDB_PH2 * ph2, BDATA & hash )
{
	BDATA input;
	input.add( 0, 1 );
	input.add( &ph2->msgid, sizeof( ph2->msgid ) );

	if( ph2->initiator )
	{
		input.add( ph2->nonce_l );
		input.add( ph2->nonce_r );
	}
	else
	{
		input.add( ph2->nonce_r );
		input.add( ph2->nonce_l );
	}

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		input.buff(),
		input.size(),
		"== : phase2 hash_p ( input )" );

	hash.size( ph1->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_CTX_init( &ctx_prf );

	HMAC_Init_ex( &ctx_prf, ph1->skeyid_a.buff(), ( int ) ph1->skeyid_a.size(), ph1->evp_hash, NULL );
	HMAC_Update( &ctx_prf, input.buff(), input.size() );
	HMAC_Final( &ctx_prf, hash.buff(), 0 );

	HMAC_CTX_cleanup( &ctx_prf );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		hash.buff(),
		hash.size(),
		"== : phase2 hash_p ( computed )" );

	return LIBIKE_OK;
}

long _IKED::phase2_chk_hash_i( IDB_PH1 * ph1, IDB_PH2 * ph2 )
{
	//
	// generate hash data for comparison
	//

	BDATA hash_c;
	phase2_gen_hash_i( ph1, ph2, hash_c );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		ph2->hash_r.buff(),
		ph2->hash_r.size(),
		"== : phase2 hash_i ( received )" );

	//
	// build text strings for logging
	//

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	//
	// compare hash data
	//

	if( ph2->hash_r != hash_c )
	{
		log.txt( LLOG_ERROR,
			"!! : phase2 sa rejected, initiator quick mode hash invalid\n"
			"!! : %s <-> %s\n",
			txtaddr_l,
			txtaddr_r );

		return LIBIKE_FAILED;
	}

	return LIBIKE_OK;
}

long _IKED::phase2_chk_hash_r( IDB_PH1 * ph1, IDB_PH2 * ph2 )
{
	//
	// generate hash data for comparison
	//

	BDATA hash_c;
	phase2_gen_hash_r( ph1, ph2, hash_c );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		ph2->hash_r.buff(),
		ph2->hash_r.size(),
		"== : phase2 hash_r ( received )" );

	//
	// build text strings for logging
	//

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	//
	// compare hash data
	//

	if( ph2->hash_r != hash_c )
	{
		log.txt( LLOG_ERROR,
			"!! : phase2 sa rejected, responder quick mode hash invalid\n"
			"!! : %s <-> %s\n",
			txtaddr_l,
			txtaddr_r );

		return LIBIKE_FAILED;
	}

	return LIBIKE_OK;
}

long _IKED::phase2_chk_hash_p( IDB_PH1 * ph1, IDB_PH2 * ph2 )
{
	//
	// generate hash data for comparison
	//

	BDATA hash_c;
	phase2_gen_hash_p( ph1, ph2, hash_c );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		ph2->hash_r.buff(),
		ph2->hash_r.size(),
		"== : phase2 hash_p ( received )" );

	//
	// build text strings for logging
	//

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	//
	// compare hash data
	//

	if( ph2->hash_r != hash_c )
	{
		log.txt( LLOG_ERROR,
			"!! : phase2 sa rejected, initiator liveliness proof hash invalid\n"
			"!! : %s <-> %s\n",
			txtaddr_l,
			txtaddr_r );

		return LIBIKE_FAILED;
	}

	return LIBIKE_OK;
}

long _IKED::phase2_chk_params( IDB_PH1 * ph1, IDB_PH2 * ph2, PACKET_IKE & packet )
{
	//
	// are we initiator or responder
	//

	if( !ph2->initiator )
	{
		//
		// configure responder ids
		//

		ph2->ph2id_ls = ph2->ph2id_rd;
		ph2->ph2id_ld = ph2->ph2id_rs;
	}

	//
	// generate address strings
	//

	char txtid_rs[ LIBIKE_MAX_TEXTP2ID ];
	char txtid_rd[ LIBIKE_MAX_TEXTP2ID ];
	char txtid_ls[ LIBIKE_MAX_TEXTP2ID ];
	char txtid_ld[ LIBIKE_MAX_TEXTP2ID ];

	text_ph2id( txtid_rs, &ph2->ph2id_rs );
	text_ph2id( txtid_rd, &ph2->ph2id_rd );
	text_ph2id( txtid_ls, &ph2->ph2id_ls );
	text_ph2id( txtid_ld, &ph2->ph2id_ld );

	//
	// are we initiator or responder
	//

	if( ph2->initiator )
	{
		//
		// select an acceptable proposal
		//

		if( phase2_sel_prop( ph2 ) != LIBIKE_OK )
		{
			packet.notify = ISAKMP_N_NO_PROPOSAL_CHOSEN;
			return LIBIKE_FAILED;
		}

		ph2->lstate |= LSTATE_CHKPROP;

		//
		// validate that the responders
		// ids match the initiator ids
		//

		if( !cmp_ph2id( ph2->ph2id_ls, ph2->ph2id_rd, true ) ||
			!cmp_ph2id( ph2->ph2id_ld, ph2->ph2id_rs, true ) )
		{
			log.txt( LLOG_ERROR, 
				"ii : phase2 rejected, id value mismatch\n"
				"ii : - loc %s -> %s\n" 
				"ii : - rmt %s -> %s\n",
				txtid_ls,
				txtid_ld,
				txtid_rs,
				txtid_rd );

			packet.notify = ISAKMP_N_INVALID_ID_INFORMATION;
			return LIBIKE_FAILED;
		}

		//
		// locate outbound ipsec policy
		//

		IDB_POLICY * policy_out;

		if( !idb_list_policy.find(
				true,
				&policy_out,
				IPSEC_DIR_OUTBOUND,
				IPSEC_POLICY_IPSEC,
				NULL,
				&ph2->plcyid_out,
				NULL,
				NULL,
				NULL,
				NULL ) )
		{
			log.txt( LLOG_ERROR, 
				"ii : phase2 rejected, no matching outbound policy found\n"
				"ii : - loc %s -> %s\n" 
				"ii : - rmt %s -> %s\n",
				txtid_ls,
				txtid_ld,
				txtid_rs,
				txtid_rd );

			packet.notify = ISAKMP_N_INVALID_ID_INFORMATION;
			return LIBIKE_FAILED;
		}

		//
		// check all notification payloads
		// now to catch responder lifetime
		// notifications
		//

		if( ph2->notifications.count() )
		{
			IKE_NOTIFY notify;

			long nindex = 0;
			while( ph2->notifications.get( notify, nindex++ ) )
				inform_chk_notify( ph1, &notify, true );
		}

		//
		// acquire spis from pfkey
		//

		pfkey_send_getspi( policy_out, ph2 );

		//
		// cleanup
		//

		policy_out->dec( true );
	}
	else
	{
		//
		// verify the initiators ids are
		// valid for a localy configured
		// security policy
		//

		IDB_POLICY * policy_in;
		IDB_POLICY * policy_out;

		IKE_PH2ID * ph2id_rs = &ph2->ph2id_rs;
		IKE_PH2ID * ph2id_rd = &ph2->ph2id_rd;

		//
		// if we are using the shared policy
		// level, we match the first policies
		// for the peer using the destination
		// id value only. The source id value
		// is irrelevant as it is generic.
		//

		if( ph2->tunnel->peer->plcy_level == POLICY_LEVEL_SHARED )
			ph2id_rs = NULL;

		//
		// locate inbound ipsec policy
		//

		if( !idb_list_policy.find(
				true,
				&policy_in,
				IPSEC_DIR_INBOUND,
				IPSEC_POLICY_IPSEC,
				NULL,
				NULL,
				&ph2->tunnel->saddr_r,
				&ph2->tunnel->saddr_l,
				ph2id_rs,
				ph2id_rd ) )
		{
			log.txt( LLOG_ERROR, 
				"ii : phase2 rejected, no matching inbound policy found\n"
				"ii : - loc %s -> %s\n" 
				"ii : - rmt %s -> %s\n",
				txtid_ls,
				txtid_ld,
				txtid_rs,
				txtid_rd );

			packet.notify = ISAKMP_N_INVALID_ID_INFORMATION;
			return LIBIKE_FAILED;
		}

		ph2->plcyid_in = policy_in->sp.id;

		//
		// locate outbound ipsec policy
		//

		if( !idb_list_policy.find(
				true,
				&policy_out,
				IPSEC_DIR_OUTBOUND,
				IPSEC_POLICY_IPSEC,
				NULL,
				NULL,
				&ph2->tunnel->saddr_l,
				&ph2->tunnel->saddr_r,
				ph2id_rd,
				ph2id_rs ) )
		{
			log.txt( LLOG_ERROR, 
				"ii : phase2 rejected, no matching outbound policy found\n"
				"ii : - loc %s -> %s\n" 
				"ii : - rmt %s -> %s\n",
				txtid_ls,
				txtid_ld,
				txtid_rs,
				txtid_rd );

			policy_in->dec( true );

			packet.notify = ISAKMP_N_INVALID_ID_INFORMATION;
			return LIBIKE_FAILED;
		}

		ph2->plcyid_out = policy_out->sp.id;

		//
		// compare the protocol parameters
		//

		if( !policy_cmp_prots( policy_in, policy_out ) )
		{
			log.txt( LLOG_ERROR, 
				"ii : phase2 rejected, inbound / outbound policy mismatch\n"
				"ii : - loc %s -> %s\n" 
				"ii : - rmt %s -> %s\n",
				txtid_ls,
				txtid_ld,
				txtid_rs,
				txtid_rd );

			policy_in->dec( true );
			policy_out->dec( true );

			packet.notify = ISAKMP_N_INVALID_ID_INFORMATION;
			return LIBIKE_FAILED;
		}

		//
		// configure the proposal list
		//

		phase2_gen_prop( ph2, policy_out );

		//
		// configure the phase2 dh group
		//

		ph2->setup_dhgrp();

		//
		// select an acceptable proposal
		//

		if( phase2_sel_prop( ph2 ) != LIBIKE_OK )
		{
			policy_in->dec( true );
			policy_out->dec( true );

			packet.notify = ISAKMP_N_NO_PROPOSAL_CHOSEN;
			return LIBIKE_FAILED;
		}

		ph2->lstate |= LSTATE_CHKPROP;

		//
		// acquire spis from pfkey
		//

		pfkey_send_getspi( policy_in, ph2 );
		pfkey_send_getspi( policy_out, ph2 );

		//
		// cleanup
		//

		policy_in->dec( true );
		policy_out->dec( true );
	}

	//
	// ids accepted
	//

	log.txt( LLOG_INFO,
		"ii : phase2 ids accepted\n"
		"ii : - loc %s -> %s\n" 
		"ii : - rmt %s -> %s\n",
		txtid_ls,
		txtid_ld,
		txtid_rs,
		txtid_rd );

	return LIBIKE_OK;
}

long _IKED::phase2_gen_keys( IDB_PH1 * ph1, IDB_PH2 * ph2 )
{
	//
	// if pfs is being used, determine
	// our new shared secret now
	//

	BDATA shared;

	if( ph2->dhgr_id )
	{
		if( level >= LLOG_DECODE )
		{
			BDATA prv;
			prv.size( ph2->dh_size );
			BN_bn2bin( ph2->dh->priv_key, prv.buff() );

			log.bin(
				LLOG_DECODE,
				LLOG_DECODE,
				prv.buff(),
				prv.size(),
				"ii : computed PFS DH private key" );

			log.bin(
				LLOG_DECODE,
				LLOG_DECODE,
				ph2->xl.buff(),
				ph2->xl.size(),
				"ii : computed PFS DH public key" );

			log.bin(
				LLOG_DECODE,
				LLOG_DECODE,
				ph2->xr.buff(),
				ph2->xr.size(),
				"ii : received PFS DH public key" );
		}

		//
		// validate the dh group size
		//

		if( ph2->xr.size() != ph2->dh_size )
		{
			log.txt( LLOG_ERROR,
				"!! : PFS DH group size mismatch ( %d != %d )\n",
				ph2->xr.size(),
				ph2->dh_size );

			ph2->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );
			return LIBIKE_FAILED;
		}

		//
		// determine shared secret
		//

		BIGNUM * gx = BN_new();
		BN_bin2bn( ph2->xr.buff(), ph2->dh_size, gx );

		shared.size( ph2->dh_size );
		long result = DH_compute_key( shared.buff(), gx, ph2->dh );
		BN_free( gx );

		if( result < 0 )
		{
			log.txt( LLOG_ERROR,
				"!! : failed to compute PFS DH shared secret\n" );

			ph2->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_CRYPTO, 0 );
			return LIBIKE_FAILED;
		}

		//
		// fixup shared secret buffer alignment
		//

		if( ph2->dh_size > result )
		{
			shared.size( result );
			shared.ins( 0, ph2->dh_size - result );
		}

		log.bin(
			LLOG_DEBUG,
			LLOG_DECODE,
			shared.buff(),
			shared.size(),
			"== : PFS DH shared secret" );
	}

	//
	// step through our negotiated
	// proposal transform list
	//

	long lifetime = 0;
	long pindex = 0;

	while( true )
	{
		IKE_PROPOSAL * proposal_l;
		IKE_PROPOSAL * proposal_r;

		if( !ph2->plist_l.get( &proposal_l, pindex ) ||
			!ph2->plist_r.get( &proposal_r, pindex ) )
			break;

		lifetime = proposal_l->life_sec;
		proposal_r->life_sec = lifetime;

		phase2_gen_keys( ph1, ph2, IPSEC_DIR_INBOUND, proposal_l, shared );
		phase2_gen_keys( ph1, ph2, IPSEC_DIR_OUTBOUND, proposal_r, shared );

		pindex++;
	}

	//
	// set the initialization time
	// and life time seconds
	//

	ph2->inc( true );
	ph2->inc( true );

	ph2->event_hard.delay = lifetime + 1;

	ph2->event_soft.delay = lifetime + 1;
	ph2->event_soft.delay *= PFKEY_SOFT_LIFETIME_RATE;
	ph2->event_soft.delay /= 100;
	ph2->event_soft.diff = ph2->event_hard.delay - ph2->event_soft.delay;

	ph2->event_hard.delay *= 1000;
	ith_timer.add( &ph2->event_hard );

	ph2->event_soft.delay *= 1000;
	ith_timer.add( &ph2->event_soft );

	ph1->tunnel->stats.sa_good++;

	return LIBIKE_OK;
}

#define PH2_MAX_KEYLEN ( ( EVP_MAX_KEY_LENGTH + HMAC_MAX_MD_CBLOCK ) * 2 )

long _IKED::phase2_gen_keys( IDB_PH1 * ph1, IDB_PH2 * ph2, long dir, IKE_PROPOSAL * proposal, BDATA & shared )
{
	//
	// determine encryption key size
	//

	long key_size_c = 0;

	if( proposal->proto == ISAKMP_PROTO_IPSEC_ESP )
	{
		if( proposal->ciph_kl )
		{
			//
			// variable key size
			//

			key_size_c = ( proposal->ciph_kl + 7 ) / 8;
		}
		else
		{
			//
			// fixed or default key size
			//

			switch( proposal->xform )
			{
				case ISAKMP_ESP_DES:

					key_size_c = EVP_CIPHER_key_length( EVP_des_cbc() );

					break;

				case ISAKMP_ESP_BLOWFISH:

					key_size_c = EVP_CIPHER_key_length( EVP_bf_cbc() );

					break;

				case ISAKMP_ESP_3DES:

					key_size_c = EVP_CIPHER_key_length( EVP_des_ede3_cbc() );

					break;

				case ISAKMP_ESP_CAST:

					key_size_c = EVP_CIPHER_key_length( EVP_cast5_cbc() );

					break;

				case ISAKMP_ESP_AES:

					key_size_c = EVP_CIPHER_key_length( EVP_aes_128_cbc() );

					break;
			}
		}
	}

	//
	// determine authentication key size
	//

	long key_size_h = 0;

	if( ( proposal->proto == ISAKMP_PROTO_IPSEC_AH ) ||
		( proposal->proto == ISAKMP_PROTO_IPSEC_ESP ) )
	{
		switch( proposal->hash_id )
		{
			case ISAKMP_AUTH_HMAC_MD5:

				key_size_h = EVP_MD_size( EVP_md5() );

				break;

			case ISAKMP_AUTH_HMAC_SHA1:

				key_size_h = EVP_MD_size( EVP_sha1() );

				break;

			case ISAKMP_AUTH_HMAC_SHA2_256:

				key_size_h = EVP_MD_size( EVP_sha256() );

				break;

			case ISAKMP_AUTH_HMAC_SHA2_384:

				key_size_h = EVP_MD_size( EVP_sha384() );

				break;

			case ISAKMP_AUTH_HMAC_SHA2_512:

				key_size_h = EVP_MD_size( EVP_sha512() );

				break;
		}
	}

	//
	// do this twice, once for the inbound
	// sa and once for the outbound sa
	//

	unsigned char key_data[ PH2_MAX_KEYLEN ];

	long key_size = key_size_c + key_size_h;
	long skeyid_size = ph1->hash_size;

	//
	// grow our key to be a multiple
	// of SKEYID_d ( HMAC block size )

	if( key_size % skeyid_size )
		key_size += skeyid_size - ( key_size % skeyid_size );

	assert( key_size < PH2_MAX_KEYLEN );

	//
	// create our extended key material
	//
	// KEYMAT = K1 | K2 | K3 | ...
	//
	// K1 = prf( SKEYID_d, [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b )
	// K2 = prf( SKEYID_d, K1 | [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b )
	// K3 = prf( SKEYID_d, K2 | [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b )
	//
	
	HMAC_CTX ctx_prf;
	HMAC_CTX_init( &ctx_prf );

	HMAC_Init_ex( &ctx_prf, ph1->skeyid_d.buff(), ( int ) ph1->skeyid_d.size(), ph1->evp_hash, NULL );

	if( ph2->dhgr_id )
		HMAC_Update( &ctx_prf, shared.buff(), shared.size() );

	HMAC_Update( &ctx_prf, ( unsigned char * ) &proposal->proto, 1 );
	HMAC_Update( &ctx_prf, ( unsigned char * ) &proposal->spi, 4 );

	if( ph2->initiator )
	{
		HMAC_Update( &ctx_prf, ph2->nonce_l.buff(), ph2->nonce_l.size() );
		HMAC_Update( &ctx_prf, ph2->nonce_r.buff(), ph2->nonce_r.size() );
	}
	else
	{
		HMAC_Update( &ctx_prf, ph2->nonce_r.buff(), ph2->nonce_r.size() );
		HMAC_Update( &ctx_prf, ph2->nonce_l.buff(), ph2->nonce_l.size() );
	}

	HMAC_Final( &ctx_prf, key_data, NULL );

	for( long size = skeyid_size; size < key_size; size += skeyid_size )
	{
		HMAC_Init_ex( &ctx_prf, ph1->skeyid_d.buff(), ( int ) ph1->skeyid_d.size(), ph1->evp_hash, NULL );
		HMAC_Update( &ctx_prf, key_data + size - skeyid_size, skeyid_size );

		if( ph2->dhgr_id )
			HMAC_Update( &ctx_prf, shared.buff(), shared.size() );

		HMAC_Update( &ctx_prf, ( unsigned char * ) &proposal->proto, 1 );
		HMAC_Update( &ctx_prf, ( unsigned char * ) &proposal->spi, 4 );

		if( ph2->initiator )
		{
			HMAC_Update( &ctx_prf, ph2->nonce_l.buff(), ph2->nonce_l.size() );
			HMAC_Update( &ctx_prf, ph2->nonce_r.buff(), ph2->nonce_r.size() );
		}
		else
		{
			HMAC_Update( &ctx_prf, ph2->nonce_r.buff(), ph2->nonce_r.size() );
			HMAC_Update( &ctx_prf, ph2->nonce_l.buff(), ph2->nonce_l.size() );
		}

		HMAC_Final( &ctx_prf, key_data + size, 0 );
	}

	HMAC_CTX_cleanup( &ctx_prf );

	//
	// separate encrypt and auth key data
	//

	BDATA ekey;
	BDATA akey;

	if( key_size_c )
	{
		ekey.set( key_data, key_size_c );

		log.bin(
			LLOG_DEBUG,
			LLOG_DECODE,
			ekey.buff(),
			ekey.size(),
			"== : spi cipher key data" );
	}

	if( key_size_h )
	{
		akey.set( key_data + key_size_c, key_size_h );

		log.bin(
			LLOG_DEBUG,
			LLOG_DECODE,
			akey.buff(),
			akey.size(),
			"== : spi hmac key data" );
	}

	//
	// send our sa add/update to pfkey
	//

	pfkey_send_update( ph2, proposal, ekey, akey, dir );

	ph2->lstate |= LSTATE_HASKEYS;

	return LIBIKE_OK;
}
