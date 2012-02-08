
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

long _IKED::process_phase1_recv( IDB_PH1 * ph1, PACKET_IKE & packet, unsigned char payload )
{
	long result = LIBIKE_OK;

	//
	// log packet type
	//

	log.txt( LLOG_INFO,
		"ii : processing phase1 packet ( %i bytes )\n",
		packet.size() );

	//
	// make sure we are not dealing
	// with an sa marked for delete
	//

	if( ph1->status() == XCH_STATUS_DEAD )
	{
		log.txt( LLOG_ERROR, "!! : phase1 packet ignored ( phase1 marked for death )\n" );
		return LIBIKE_OK;
	}

	//
	// make sure we are not dealing
	// with a mature sa
	//

	if( ph1->status() >= XCH_STATUS_MATURE )
	{
		log.txt( LLOG_ERROR, "!! : phase1 packet ignored, resending last packet ( phase1 already mature )\n" );
		ph1->resend();
		return LIBIKE_OK;
	}

	//
	// attempt to decrypt our packet
	//

	if( packet_ike_decrypt( ph1, packet, &ph1->iv ) != LIBIKE_OK )
	{
		log.txt( LLOG_ERROR, "!! : phase1 packet ignored, resending last packet ( packet decryption error )\n" );
		ph1->resend();
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

	//
	// read and process all payloads
	//

	uint8_t next_payload;

	while( payload != ISAKMP_PAYLOAD_NONE )
	{
		//
		// read the payload header
		//

		if( !packet.get_payload( false, next_payload ) )
			break;

		//
		// call the appropriate payload handler
		//

		switch( payload )
		{
			//
			// security association payload
			//

			case ISAKMP_PAYLOAD_SA:

				if( ph1->xstate & XSTATE_RECV_SA )
					log.txt( LLOG_INFO, "<< : ignoring duplicate security association payload\n" );
				else
				{
					size_t beg = packet.oset();
					result = payload_get_sa( packet, ph1->plist_r );
					size_t end = packet.oset();

					if( !ph1->initiator )
						ph1->hda.set( packet.buff() + beg, end - beg );
				}

				ph1->xstate |= XSTATE_RECV_SA;

				break;

			//
			// key exchange payload
			//

			case ISAKMP_PAYLOAD_KEX:

				if( ph1->xstate & XSTATE_RECV_KE )
					log.txt( LLOG_INFO, "<< : ignoring duplicate key excahnge payload\n" );
				else
					result = payload_get_kex( packet, ph1->xr );

				ph1->xstate |= XSTATE_RECV_KE;

				break;

			//
			// nonce payload
			//

			case ISAKMP_PAYLOAD_NONCE:

				if( ph1->xstate & XSTATE_RECV_NO )
					log.txt( LLOG_INFO, "<< : ignoring duplicate nonce payload\n" );
				else
					result = payload_get_nonce( packet, ph1->nonce_r );

				ph1->xstate |= XSTATE_RECV_NO;

				break;

			//
			// identity payload
			//

			case ISAKMP_PAYLOAD_IDENT:

				if( ph1->xstate & XSTATE_RECV_ID )
					log.txt( LLOG_INFO, "<< : ignoring duplicate id payload\n" );
				else
				{
					size_t beg = packet.oset();
					result = payload_get_ph1id( packet, ph1->ph1id_r );
					size_t end = packet.oset();

					if( ph1->initiator )
						ph1->idr.set( packet.buff() + beg, end - beg );
					else
						ph1->idi.set( packet.buff() + beg, end - beg );
				}

				ph1->xstate |= XSTATE_RECV_ID;

				break;

			//
			// certificate payload
			//

			case ISAKMP_PAYLOAD_CERT:
			{
				uint8_t	type;
				BDATA	cert;

				result = payload_get_cert( packet, type, cert );
				if( result == LIBIKE_OK )
					ph1->certs_r.add( type, cert );

				ph1->xstate |= XSTATE_RECV_CT;

				break;
			}

			//
			// certificate request payload
			//

			case ISAKMP_PAYLOAD_CERT_REQ:
			{
				uint8_t	type;
				BDATA	dn;

				result = payload_get_creq( packet, type, dn );
				if( result == LIBIKE_OK )
					ph1->creqs_r.add( type, dn );

				ph1->xstate |= XSTATE_RECV_CR;

				break;
			}

			//
			// signature payload
			//

			case ISAKMP_PAYLOAD_SIGNATURE:

				if( ph1->xstate & XSTATE_RECV_SI )
					log.txt( LLOG_INFO, "<< : ignoring duplicate signature payload\n" );
				else
					result = payload_get_sign( packet, ph1->sign_r );

				ph1->xstate |= XSTATE_RECV_SI;

				break;

			//
			// hash payload
			//

			case ISAKMP_PAYLOAD_HASH:

				if( ph1->xstate & XSTATE_RECV_HA )
					log.txt( LLOG_INFO, "<< : ignoring duplicate hash payload\n" );
				else
					result = payload_get_hash( packet, ph1->hash_r, ph1->hash_size );

				ph1->xstate |= XSTATE_RECV_HA;

				break;

			//
			// nat discovery payload
			//

			case ISAKMP_PAYLOAD_NAT_VXX_DISC:
			case ISAKMP_PAYLOAD_NAT_RFC_DISC:
			{
				BDATA natd;
				result = payload_get_natd( packet, natd, ph1->hash_size );
				if( result == LIBIKE_OK )
					ph1->natd_hash_r.add( natd );

				ph1->xstate |= XSTATE_RECV_ND;

				break;
			}

			//
			// vendor id payload
			//

			case ISAKMP_PAYLOAD_VEND:
			{
				BDATA vend;
				result = payload_get_vend( packet, vend );
				if( result == LIBIKE_OK )
					phase1_chk_vend( ph1, vend );

				break;
			}

			//
			// notify payload
			//

			case ISAKMP_PAYLOAD_NOTIFY:
			{
				IKE_NOTIFY notify;
				result = payload_get_notify( packet, &notify );
				if( result == LIBIKE_OK )
					ph1->notifications.add( notify );

				break;
			}

			//
			// unhandled payload
			//

			default:

				log.txt( LLOG_ERROR,
					"!! : unhandled phase1 payload \'%s\' ( %i )\n",
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
			log.txt( LLOG_ERROR, "!! : unprocessed payload data\n" );

		//
		// now that we have decoded the payload,
		// perform any required processing here
		//

		while( result == LIBIKE_OK )
		{
			//
			// verify the peers proposal
			//

			if(  ( ph1->xstate & XSTATE_RECV_SA ) &&
				!( ph1->lstate & LSTATE_CHKPROP ) )
			{
				//
				// select an acceptable proposal
				//

				result = phase1_sel_prop( ph1 );

				if( result != LIBIKE_OK )
				{
					packet.notify = ISAKMP_N_NO_PROPOSAL_CHOSEN;
					break;
				}

				//
				// obtain negotiated authentication type
				//

				IKE_PROPOSAL * proposal;
				ph1->plist_l.get( &proposal, 0 );
				ph1->auth_id = proposal->auth_id;

				if( ( ph1->auth_id == XAUTH_AUTH_INIT_PSK ) ||
					( ph1->auth_id == XAUTH_AUTH_INIT_RSA ) ||
					( ph1->auth_id == HYBRID_AUTH_INIT_RSA ) )
					ph1->vendopts_l.flag.xauth = true;

				// 
				// setup the sa dhgroup for main mode
				//

				if( ph1->exchange == ISAKMP_EXCH_IDENT_PROTECT )
					ph1->setup_dhgrp( proposal );

				//
				// setup the sa transform
				//

				ph1->setup_xform( proposal );

				ph1->lstate |= LSTATE_CHKPROP;
			}

			//
			// verify the peers identifier
			//

			if(  ( ph1->xstate & XSTATE_RECV_ID ) &&
				!( ph1->lstate & LSTATE_CHKIDS ) )
			{
				result = phase1_chk_idr( ph1 );

				if( result != LIBIKE_OK )
				{
					packet.notify = ISAKMP_N_INVALID_ID_INFORMATION;
					break;
				}

				ph1->lstate |= LSTATE_CHKIDS;
			}

			break;
		}

		//
		// check the final paylaod process result
		//

		if( result != LIBIKE_OK )
		{
			ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, packet.notify );

			return result;
		}

		//
		// read next payload
		//

		payload = next_payload;
	}

	//
	// now build and send any response
	// packets that may be necessary
	//

	if( ph1->status() <= XCH_STATUS_DEAD )
		process_phase1_send( ph1 );

	return LIBIKE_OK;
}

long _IKED::process_phase1_send( IDB_PH1 * ph1 )
{
	//
	// main mode exchange
	//

	if( ph1->exchange == ISAKMP_EXCH_IDENT_PROTECT )
	{
		//
		// isakmp initiator
		//

		if( ph1->initiator )
		{
			//
			// sa + [ + vid's ] packet
			//

			if( !( ph1->xstate & XSTATE_SENT_SA ) )
			{
				//
				// write packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_SA, ph1->exchange, 0 );

				//
				// add payloads
				//

				size_t beg = packet.size() + 4;
				payload_add_sa( packet, ph1->plist_l, ISAKMP_PAYLOAD_VEND );
				size_t end = packet.size();
				ph1->hda.set( packet.buff() + beg, end - beg );

				phase1_add_vend( ph1, packet, ISAKMP_PAYLOAD_NONE );

				packet.done();

				//
				// send packet
				//

				packet_ike_send( ph1, ph1, packet, true );

				ph1->xstate |= XSTATE_SENT_SA;
			}

			//
			// ke + nonce packet
			//

			if(  ( ph1->xstate & XSTATE_RECV_SA ) &&
				!( ph1->xstate & XSTATE_SENT_KE ) )
			{
				//
				// write packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_KEX, ph1->exchange, 0 );

				//
				// add payloads for authentication type
				//

				payload_add_kex( packet, ph1->xl, ISAKMP_PAYLOAD_NONCE );

				switch( ph1->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					{
						payload_add_nonce( packet, ph1->nonce_l, ph1->natt_pldtype );
						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					case HYBRID_AUTH_INIT_RSA:
					{
						payload_add_nonce( packet, ph1->nonce_l, ISAKMP_PAYLOAD_CERT_REQ );
						payload_add_creq( packet, ISAKMP_CERT_X509_SIG, ph1->natt_pldtype );
						ph1->xstate |= XSTATE_SENT_CR;
						break;
					}
				}

				//
				// optionally add nat discovery hash payloads
				//

				if( ph1->natt_pldtype != ISAKMP_PAYLOAD_NONE )
				{
					phase1_gen_natd( ph1 );
					phase1_add_natd( ph1, packet, ISAKMP_PAYLOAD_NONE );
				}

				packet.done();

				//
				// send packet
				//

				packet_ike_send( ph1, ph1, packet, true );

				ph1->xstate |= XSTATE_SENT_KE;
				ph1->xstate |= XSTATE_SENT_NO;
			}

			//
			// id + hash || id + [ cert ] + sig + [ cert req ] packet
			//

			if(  ( ph1->xstate & XSTATE_RECV_KE ) &&
				 ( ph1->xstate & XSTATE_RECV_NO ) &&
				!( ph1->xstate & XSTATE_SENT_ID ) )
			{
				//
				// perform nat traversal check
				//

				phase1_chk_natd( ph1 );

				//
				// calculate key material
				//

				if( phase1_gen_keys( ph1 ) != LIBIKE_OK )
					return LIBIKE_FAILED;

				//
				// write packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_IDENT, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

				//
				// add payloads for authentication type
				//

				switch( ph1->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					case HYBRID_AUTH_INIT_RSA:
					{
						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_HASH );
						size_t pld_end = packet.size();
						ph1->idi.set( packet.buff() + pld_beg, pld_end - pld_beg );

						phase1_gen_hash_i( ph1, ph1->hash_l );
						payload_add_hash( packet, ph1->hash_l, ISAKMP_PAYLOAD_NONE );

						ph1->xstate |= XSTATE_SENT_HA;

						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					{
						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_CERT );
						size_t pld_end = packet.size();
						ph1->idi.set( packet.buff() + pld_beg, pld_end - pld_beg );

						payload_add_cert( packet, ISAKMP_CERT_X509_SIG, ph1->tunnel->peer->cert_l, ISAKMP_PAYLOAD_SIGNATURE );

						BDATA sign;
						phase1_gen_hash_i( ph1, ph1->hash_l );
						prvkey_rsa_encrypt( ph1->tunnel->peer->cert_k, ph1->hash_l, sign );
						payload_add_sign( packet, sign, ISAKMP_PAYLOAD_NONE );

						ph1->xstate |= XSTATE_SENT_CT;
						ph1->xstate |= XSTATE_SENT_SI;

						break;
					}
				}

				packet.done();

				//
				// encrypt and send packet
				//

				packet_ike_send( ph1, ph1, packet, false );

				ph1->xstate |= XSTATE_SENT_ID;
			}
		}

		//
		// isakmp responder
		//

		if( !ph1->initiator )
		{
			//
			// sa packet
			//

			if(  ( ph1->xstate & XSTATE_RECV_SA ) &&
				!( ph1->xstate & XSTATE_SENT_SA ) )
			{
				//
				// write packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_SA, ph1->exchange, 0 );

				//
				// add payloads
				//

				payload_add_sa( packet, ph1->plist_l, ISAKMP_PAYLOAD_VEND );

				phase1_add_vend( ph1, packet, ISAKMP_PAYLOAD_NONE );

				packet.done();

				//
				// send packet
				//

				packet_ike_send( ph1, ph1, packet, true );

				ph1->xstate |= XSTATE_SENT_SA;
			}

			//
			// ke + nonce packet
			//

			if(  ( ph1->xstate & XSTATE_RECV_KE ) &&
				 ( ph1->xstate & XSTATE_RECV_NO ) &&
				!( ph1->xstate & XSTATE_SENT_KE ) )
			{
				//
				// write the packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_KEX, ph1->exchange, 0 );

				//
				// add payloads for authentication type
				//

				payload_add_kex( packet, ph1->xl, ISAKMP_PAYLOAD_NONCE );

				switch( ph1->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					{
						payload_add_nonce( packet, ph1->nonce_l, ph1->natt_pldtype );
						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					case HYBRID_AUTH_INIT_RSA:
					{
						payload_add_nonce( packet, ph1->nonce_l, ISAKMP_PAYLOAD_CERT_REQ );
						payload_add_creq( packet, ISAKMP_CERT_X509_SIG, ph1->natt_pldtype );
						ph1->xstate |= XSTATE_SENT_CR;
						break;
					}
				}

				//
				// optionally add nat discovery hash payloads
				//

				if( ph1->natt_pldtype != ISAKMP_PAYLOAD_NONE )
				{
					phase1_gen_natd( ph1 );
					phase1_add_natd( ph1, packet, ISAKMP_PAYLOAD_NONE );
				}

				packet.done();

				//
				// send packet
				//

				packet_ike_send( ph1, ph1, packet, true );

				ph1->xstate |= XSTATE_SENT_KE;
				ph1->xstate |= XSTATE_SENT_NO;

				//
				// calculate key material
				//

				if( phase1_gen_keys( ph1 ) != LIBIKE_OK )
					return LIBIKE_FAILED;
			}

			//
			// id + hash || id + [ cert ] + sign packet
			//

			if(	 ( ph1->xstate & XSTATE_RECV_ID ) &&
				!( ph1->xstate & XSTATE_SENT_ID ) )
			{
				//
				// perform nat traversal check
				//

				phase1_chk_natd( ph1 );

				//
				// build packet for authentication type
				//

				switch( ph1->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					{
						if( !( ph1->xstate & XSTATE_RECV_HA ) )
							break;

						//
						// write packet header
						//

						PACKET_IKE packet;
						packet.write( ph1->cookies, ISAKMP_PAYLOAD_IDENT, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

						//
						// add payloads
						//

						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_HASH );
						size_t pld_end = packet.size();
						ph1->idr.set( packet.buff() + pld_beg, pld_end - pld_beg );

						phase1_gen_hash_r( ph1, ph1->hash_l );
						payload_add_hash( packet, ph1->hash_l, ISAKMP_PAYLOAD_NONE );

						packet.done();

						//
						// send packet
						//

						packet_ike_send( ph1, ph1, packet, false );

						ph1->xstate |= XSTATE_SENT_ID;
						ph1->xstate |= XSTATE_SENT_HA;

						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					case HYBRID_AUTH_INIT_RSA:
					{
						if( ph1->auth_id == XAUTH_AUTH_INIT_RSA )
						{
							//
							// mutual rsa modes we should see a signature
							//

							if(	!( ph1->xstate & XSTATE_RECV_SI ) )
								break;
						}
						else
						{
							//
							// hybrid rsa modes we should see a hash
							//

							if(	!( ph1->xstate & XSTATE_RECV_HA ) )
								break;
						}

						//
						// write packet header
						//

						PACKET_IKE packet;
						packet.write( ph1->cookies, ISAKMP_PAYLOAD_IDENT, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

						//
						// add payloads
						//

						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_CERT );
						size_t pld_end = packet.size();
						ph1->idr.set( packet.buff() + pld_beg, pld_end - pld_beg );

						payload_add_cert( packet, ISAKMP_CERT_X509_SIG, ph1->tunnel->peer->cert_l, ISAKMP_PAYLOAD_SIGNATURE );

						BDATA sign;
						phase1_gen_hash_r( ph1, ph1->hash_l );
						prvkey_rsa_encrypt( ph1->tunnel->peer->cert_k, ph1->hash_l, sign );
						payload_add_sign( packet, sign, ISAKMP_PAYLOAD_NONE );

						//
						// send packet
						//

						packet_ike_send( ph1, ph1, packet, false );

						ph1->xstate |= XSTATE_SENT_ID;
						ph1->xstate |= XSTATE_SENT_CT;
						ph1->xstate |= XSTATE_SENT_SI;

						break;
					}
				}
			}
		}
	}

	//
	// aggressive mode exchange
	//

	if( ph1->exchange == ISAKMP_EXCH_AGGRESSIVE )
	{
		//
		// isakmp initiator
		//

		if( ph1->initiator )
		{
			//
			// sa + ke + no + id [ + vid's ] packet
			//

			if(	!( ph1->xstate & XSTATE_SENT_SA ) )
			{
				//
				// write packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_SA, ph1->exchange, 0 );

				//
				// add payloads for authentication type
				//

				size_t beg = packet.size() + 4;
				payload_add_sa( packet, ph1->plist_l, ISAKMP_PAYLOAD_KEX );
				size_t end = packet.size();
				ph1->hda.set( packet.buff() + beg, end - beg );

				payload_add_kex( packet, ph1->xl, ISAKMP_PAYLOAD_NONCE );

				switch( ph1->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					{
						payload_add_nonce( packet, ph1->nonce_l, ISAKMP_PAYLOAD_IDENT );
						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					case HYBRID_AUTH_INIT_RSA:
					{	
						payload_add_nonce( packet, ph1->nonce_l, ISAKMP_PAYLOAD_CERT_REQ );
						payload_add_creq( packet, ISAKMP_CERT_X509_SIG, ISAKMP_PAYLOAD_IDENT );
						ph1->xstate |= XSTATE_SENT_CR;
						break;
					}
				}

				beg = packet.size() + 4;
				payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_VEND );
				end = packet.size();
				ph1->idi.set( packet.buff() + beg, end - beg );

				phase1_add_vend( ph1, packet, ISAKMP_PAYLOAD_NONE );

				packet.done();

				//
				// send packet
				//

				packet_ike_send( ph1, ph1, packet, true );

				ph1->xstate |= XSTATE_SENT_SA;
				ph1->xstate |= XSTATE_SENT_KE;
				ph1->xstate |= XSTATE_SENT_NO;
				ph1->xstate |= XSTATE_SENT_ID;
			}

			//
			// hash || [ cert + ] sig [ + natd + natd ] packet
			//

			if(	 ( ph1->xstate & XSTATE_RECV_KE ) &&
				 ( ph1->xstate & XSTATE_RECV_NO ) &&
				 ( ph1->xstate & XSTATE_RECV_ID ) )
			{
				//
				// perform nat traversal check
				//

				phase1_chk_natd( ph1 );

				//
				// build packet for authentication type
				//

				switch( ph1->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					case HYBRID_AUTH_INIT_RSA:
					{
						if( ( ( ( ph1->auth_id == IKE_AUTH_PRESHARED_KEY ) ||
								( ph1->auth_id == XAUTH_AUTH_INIT_PSK ) ) &&
							  ( ph1->xstate & XSTATE_RECV_HA ) && !( ph1->xstate & XSTATE_SENT_HA ) ) ||
							( ( ph1->auth_id == HYBRID_AUTH_INIT_RSA ) &&
							  ( ph1->xstate & XSTATE_RECV_SI ) && !( ph1->xstate & XSTATE_SENT_HA ) ) )
						{
							//
							// calculate key material
							//

							if( phase1_gen_keys( ph1 ) != LIBIKE_OK )
								break;

							//
							// write packet header
							//

							PACKET_IKE packet;
							packet.write( ph1->cookies, ISAKMP_PAYLOAD_HASH, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

							//
							// cisco hybrid authentication uses an extra
							// notification payload containing the group
							// password hash
							//

							uint8_t nextp = ph1->natt_pldtype;
							if( ph1->tunnel->xconf.opts & IPSEC_OPTS_CISCO_GRP )
								nextp = ISAKMP_PAYLOAD_NOTIFY;

							//
							// add payloads
							//

							phase1_gen_hash_i( ph1, ph1->hash_l );
							payload_add_hash( packet, ph1->hash_l, nextp );

							//
							// optionally add unity notification payload
							//

							if( ph1->tunnel->xconf.opts & IPSEC_OPTS_CISCO_GRP )
							{
								//
								// generate the group password hash
								//

								BDATA psk_hash;
								psk_hash.size( ph1->hash_size );

								HMAC_CTX ctx_prf;
								HMAC_CTX_init( &ctx_prf );

								HMAC_Init_ex( &ctx_prf, ph1->skeyid.buff(), ( int ) ph1->skeyid.size(), ph1->evp_hash, NULL );
								HMAC_Update( &ctx_prf, ph1->tunnel->peer->psk.buff(), ph1->tunnel->peer->psk.size() );
								HMAC_Final( &ctx_prf, psk_hash.buff(), NULL );

								HMAC_CTX_cleanup( &ctx_prf );

								//
								// add the notification payload
								//

								IKE_NOTIFY notify;
								notify.type = ISAKMP_PAYLOAD_NOTIFY;
								notify.code = ISAKMP_N_UNITY_GROUP_HASH;
								notify.doi = ISAKMP_DOI_IPSEC;
								notify.proto = ISAKMP_PROTO_ISAKMP;
								notify.spi.size = sizeof( ph1->cookies );
								notify.spi.cookies = ph1->cookies;
								notify.data.set( psk_hash );
								payload_add_notify( packet, &notify, ph1->natt_pldtype );
							}

							//
							// optionally add nat discovery hash payloads
							//

							if( ph1->natt_pldtype != ISAKMP_PAYLOAD_NONE )
							{
								phase1_gen_natd( ph1 );
								phase1_add_natd( ph1, packet, ISAKMP_PAYLOAD_NONE );
							}

							packet.done();

							//
							// send packet
							//

							packet_ike_send( ph1, ph1, packet, false );

							ph1->xstate |= XSTATE_SENT_HA;
						}

						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					{
						if(  ( ph1->xstate & XSTATE_RECV_SI ) &&
							!( ph1->xstate & XSTATE_SENT_SI ) )
						{
							//
							// calculate key material
							//

							if( phase1_gen_keys( ph1 ) != LIBIKE_OK )
								break;

							//
							// write packet header
							//

							PACKET_IKE packet;
							packet.write( ph1->cookies, ISAKMP_PAYLOAD_CERT, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

							//
							// add payloads
							//

							payload_add_cert( packet, ISAKMP_CERT_X509_SIG, ph1->tunnel->peer->cert_l, ISAKMP_PAYLOAD_SIGNATURE );

							BDATA sign;
							phase1_gen_hash_i( ph1, ph1->hash_l );
							prvkey_rsa_encrypt( ph1->tunnel->peer->cert_k, ph1->hash_l, sign );
							payload_add_sign( packet, sign, ph1->natt_pldtype );

							//
							// optionally add nat discovery hash payloads
							//

							if( ph1->natt_pldtype != ISAKMP_PAYLOAD_NONE )
							{
								phase1_gen_natd( ph1 );
								phase1_add_natd( ph1, packet, ISAKMP_PAYLOAD_NONE );
							}

							packet.done();

							//
							// send packet
							//

							packet_ike_send( ph1, ph1, packet, false );

							ph1->xstate |= XSTATE_SENT_CT;
							ph1->xstate |= XSTATE_SENT_SI;
						}

						break;
					}
				}
			}
		}

		//
		// isakmp responder
		//

		if( !ph1->initiator )
		{
			//
			// sa + ke + no + hash || [ cert + ] sig [ + natd + natd ] [ + vid's ] packet
			//

			if(  ( ph1->xstate & XSTATE_RECV_SA ) &&
				 ( ph1->xstate & XSTATE_RECV_KE ) &&
				 ( ph1->xstate & XSTATE_RECV_NO ) &&
				 ( ph1->xstate & XSTATE_RECV_ID ) &&
				!( ph1->xstate & XSTATE_SENT_SA ) )
			{
				//
				// calculate key material
				//

				if( phase1_gen_keys( ph1 ) != LIBIKE_OK )
					return LIBIKE_FAILED;

				//
				// write packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_SA, ph1->exchange, 0 );

				//
				// add payloads
				//

				payload_add_sa( packet, ph1->plist_l, ISAKMP_PAYLOAD_KEX );
				payload_add_kex( packet, ph1->xl, ISAKMP_PAYLOAD_NONCE );
				payload_add_nonce( packet, ph1->nonce_l, ISAKMP_PAYLOAD_IDENT );

				//
				// add payloads for authentication type
				//

				switch( ph1->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					case HYBRID_AUTH_INIT_RSA:
					{
						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_HASH );
						size_t pld_end = packet.size();
						ph1->idr.set( packet.buff() + pld_beg, pld_end - pld_beg );

						phase1_gen_hash_r( ph1, ph1->hash_l );
						payload_add_hash( packet, ph1->hash_l, ISAKMP_PAYLOAD_VEND );

						ph1->xstate |= XSTATE_SENT_HA;

						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					{
						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_CERT );
						size_t pld_end = packet.size();
						ph1->idr.set( packet.buff() + pld_beg, pld_end - pld_beg );

						payload_add_cert( packet, ISAKMP_CERT_X509_SIG, ph1->tunnel->peer->cert_l, ISAKMP_PAYLOAD_CERT_REQ );
						payload_add_creq( packet, ISAKMP_CERT_X509_SIG, ISAKMP_PAYLOAD_SIGNATURE );

						BDATA sign;
						phase1_gen_hash_r( ph1, ph1->hash_l );
						prvkey_rsa_encrypt( ph1->tunnel->peer->cert_k, ph1->hash_l, sign );
						payload_add_sign( packet, sign, ISAKMP_PAYLOAD_VEND );

						ph1->xstate |= XSTATE_SENT_CT;
						ph1->xstate |= XSTATE_SENT_CR;
						ph1->xstate |= XSTATE_SENT_SI;

						break;
					}
				}

				phase1_add_vend( ph1, packet, ph1->natt_pldtype );

				//
				// optionally add nat discovery hash payloads
				//

				if( ph1->natt_pldtype != ISAKMP_PAYLOAD_NONE )
				{
					phase1_gen_natd( ph1 );
					phase1_add_natd( ph1, packet, ISAKMP_PAYLOAD_NONE );
				}

				//
				// send packet
				//

				packet.done();

				packet_ike_send( ph1, ph1, packet, false );

				ph1->xstate |= XSTATE_SENT_SA;
				ph1->xstate |= XSTATE_SENT_KE;
				ph1->xstate |= XSTATE_SENT_NO;
				ph1->xstate |= XSTATE_SENT_ID;
			}

			//
			// post negotiation processing
			//

			if( ( ph1->xstate & XSTATE_RECV_HA ) ||
				( ph1->xstate & XSTATE_RECV_CT ) )
			{
				//
				// check and enable natt if required
				//

				phase1_chk_natd( ph1 );
			}
		}
	}

	//
	// is it time to verify our
	// peers hash or signature
	//

	if( ( ph1->status() < XCH_STATUS_MATURE ) &&
		( ph1->lstate & LSTATE_HASKEYS ) &&
		( ph1->xstate & XSTATE_RECV_ID ) )
	{
		//
		// check the peers hash value
		//

		if( ( ph1->auth_id == IKE_AUTH_PRESHARED_KEY ) ||
			( ph1->auth_id == XAUTH_AUTH_INIT_PSK ) ||
			( ph1->auth_id == HYBRID_AUTH_INIT_RSA && !ph1->initiator ) )
		{
			if( ph1->xstate & XSTATE_RECV_HA )
			{
				if( phase1_chk_hash( ph1 ) == LIBIKE_OK )
					ph1->status( XCH_STATUS_MATURE, XCH_NORMAL, 0 );
				else
					ph1->status( XCH_STATUS_DEAD, XCH_FAILED_PEER_AUTH, ISAKMP_N_AUTHENTICATION_FAILED );

				ph1->clean();
			}
		}

		//
		// check the peers signature value
		//

		if( ( ph1->auth_id == IKE_AUTH_SIG_RSA ) ||
			( ph1->auth_id == XAUTH_AUTH_INIT_RSA ) ||
			( ph1->auth_id == HYBRID_AUTH_INIT_RSA && ph1->initiator ) )
		{
			if( ph1->xstate & XSTATE_RECV_SI )
			{
				if( phase1_chk_sign( ph1 ) == LIBIKE_OK )
					ph1->status( XCH_STATUS_MATURE, XCH_NORMAL, 0 );
				else
					ph1->status( XCH_STATUS_DEAD, XCH_FAILED_PEER_AUTH, ISAKMP_N_AUTHENTICATION_FAILED );

				ph1->clean();
			}
		}
	}

	//
	// if this tunnel has just now
	// completed initialization, we
	// may need to do a few things
	//

	if( ph1->status() == XCH_STATUS_MATURE )
	{
		//
		// special handling for tunnel initialization
		//

		if( !( ph1->tunnel->tstate & TSTATE_INITIALIZED ) )
		{
			//
			// send our inital contact notification
			//

			inform_new_notify( ph1, NULL, ISAKMP_N_INITIAL_CONTACT );

			//
			// add tunnel natt event
			//

			if( ph1->tunnel->natt_version != IPSEC_NATT_NONE )
			{
				ph1->tunnel->inc( true );
				ph1->tunnel->event_natt.delay = ph1->tunnel->peer->natt_rate * 1000;

				ith_timer.add( &ph1->tunnel->event_natt );
			}

			//
			// add tunnel dpd event
			//

			if( ( ph1->tunnel->peer->dpd_mode == IPSEC_DPD_FORCE ) ||
				( ph1->vendopts_l.flag.dpdv1 && ph1->vendopts_r.flag.dpdv1 ) )
			{
				ph1->tunnel->stats.dpd = true;

				ph1->tunnel->inc( true );
				ph1->tunnel->event_dpd.delay = ph1->tunnel->peer->dpd_delay * 1000;

				ith_timer.add( &ph1->tunnel->event_dpd );
			}

			//
			// flag ph1->tunnel as initialized
			//

			ph1->tunnel->tstate |= TSTATE_INITIALIZED;
		}

		//
		// determine the policy level if auto
		//

		if( ph1->tunnel->peer->plcy_level == POLICY_LEVEL_AUTO )
		{
			//
			// unity compatible default to shared level
			// and all others defult to unique
			//

			if( ph1->vendopts_r.flag.unity && !ph1->vendopts_r.flag.kame )
				ph1->tunnel->peer->plcy_level = POLICY_LEVEL_SHARED;
			else
				ph1->tunnel->peer->plcy_level = POLICY_LEVEL_UNIQUE;
		}

		//
		// if we are to generate a policy
		// list before config, do this now
		//

		if( !ph1->initiator )
			if( ph1->tunnel->peer->plcy_mode == POLICY_MODE_COMPAT )
				policy_list_create( ph1->tunnel, ph1->initiator );

		//
		// determine if client configurtaion
		// processing should be initiated
		//

		switch( ph1->tunnel->peer->contact )
		{
			case IPSEC_CONTACT_RESP:
			case IPSEC_CONTACT_BOTH:
			{
				//
				// inititate xauth operation if required
				//

				if( !ph1->initiator && ph1->vendopts_l.flag.xauth )
				{
					IDB_CFG * cfg = new IDB_CFG( ph1, true );
					cfg->add( true );
					process_config_send( ph1, cfg );
					cfg->dec( true );
				}

				break;
			}

			case IPSEC_CONTACT_CLIENT:
			{
				//
				// peer will initiate xauth if required
				//

				if( ph1->initiator && !ph1->vendopts_l.flag.xauth )
				{
					//
					// initiate the client configuration
					// processing unless in push mode
					//

					if( ph1->tunnel->peer->xconf_mode != CONFIG_MODE_PUSH )
					{
						IDB_CFG * cfg = new IDB_CFG( ph1, true );
						cfg->add( true );
						process_config_send( ph1, cfg );
						cfg->dec( true );
					}
				}

				break;
			}
		}

		//
		// obtain our negotiated proposal
		//

		IKE_PROPOSAL * proposal;
		ph1->plist_l.get( &proposal, 0 );

		//
		// add pahse1 soft expire event
		//

		ph1->inc( true );
		ph1->event_soft.delay = proposal->life_sec;
		ph1->event_soft.delay *= PFKEY_SOFT_LIFETIME_RATE;
		ph1->event_soft.delay /= 100;
		ph1->event_soft.delay *= 1000;

		ith_timer.add( &ph1->event_soft );

		//
		// add pahse1 hard expire event
		//

		ph1->inc( true );
		ph1->event_hard.delay = proposal->life_sec;
		ph1->event_hard.delay *= 1000;

		ith_timer.add( &ph1->event_hard );

		//
		// add pahse1 dead event
		//

		ph1->inc( true );
		ph1->event_dead.delay = proposal->life_sec + 6;
		ph1->event_dead.delay *= 1000;

		ith_timer.add( &ph1->event_dead );

		//
		// enable fragmentation support
		//

		if( ph1->vendopts_l.flag.frag && ph1->vendopts_r.flag.frag )
			ph1->tunnel->stats.frag = true;

		//
		// locate any pending phase2
		// handles for this tunnel and
		// begin negotiataions
		//

		IDB_PH2 * ph2;

		while( idb_list_ph2.find(
				true,
				&ph2,
				ph1->tunnel,
				XCH_STATUS_PENDING,
				XCH_STATUS_PENDING,
				NULL,
				NULL,
				NULL,
				NULL ) )
		{
			//
			// begin negotiations
			//

			process_phase2_send( ph1, ph2 );

			//
			// remove pending flag
			//

			ph2->status( XCH_STATUS_LARVAL, XCH_NORMAL, 0 );
			ph2->dec( true );
		}
	}

	return LIBIKE_OK;
}

long _IKED::phase1_gen_keys( IDB_PH1 * ph1 )
{
	//
	// obtain our negotiated proposal
	//

	IKE_PROPOSAL * proposal;
	ph1->plist_l.get( &proposal, 0 );

	//
	// determine shared secret
	//

	if( level >= LLOG_DECODE )
	{
		BDATA prv;
		prv.size( ph1->dh_size );
		BN_bn2bin( ph1->dh->priv_key, prv.buff() );

		log.bin(
			LLOG_DECODE,
			LLOG_DECODE,
			prv.buff(),
			prv.size(),
			"ii : computed DH private key" );

		log.bin(
			LLOG_DECODE,
			LLOG_DECODE,
			ph1->xl.buff(),
			ph1->xl.size(),
			"ii : computed DH public key" );

		log.bin(
			LLOG_DECODE,
			LLOG_DECODE,
			ph1->xr.buff(),
			ph1->xr.size(),
			"ii : received DH public key" );
	}

	//
	// validate the dh group size
	//

	if( ph1->xr.size() != ph1->dh_size )
	{
		log.txt( LLOG_ERROR,
			"!! : DH group size mismatch ( %d != %d )\n",
			ph1->xr.size(),
			ph1->dh_size );

		ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );
		return LIBIKE_FAILED;
	}

	//
	// determine shared secret
	//

	BIGNUM * gx = BN_new();
	BN_bin2bn( ph1->xr.buff(), ph1->dh_size, gx );

	BDATA shared;
	shared.set( 0, ph1->dh_size );
	long result = DH_compute_key( shared.buff(), gx, ph1->dh );
	BN_free( gx );

	if( result < 0 )
	{
		log.txt( LLOG_ERROR,
			"!! : failed to compute DH shared secret\n" );

		ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_CRYPTO, 0 );
		return LIBIKE_FAILED;
	}

	//
	// fixup shared secret buffer alignment
	//

	if( ph1->dh_size > result )
	{
		log.txt( LLOG_DEBUG,
			"ww : short DH shared secret computed\n" );

		shared.size( result );
		shared.ins( 0, ph1->dh_size - result );
	}

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		shared.buff(),
		shared.size(),
		"== : DH shared secret" );

	//
	// compute SKEYID
	//

	unsigned char	skeyid_data[ HMAC_MAX_MD_CBLOCK ];
	long			skeyid_size = EVP_MD_size( ph1->evp_hash );

	switch( proposal->auth_id )
	{
		//
		// preshared key
		//
		// SKEYID = prf( pre-shared-key, Ni_b | Nr_b )
		//

		case IKE_AUTH_PRESHARED_KEY:
		case XAUTH_AUTH_INIT_PSK:
		case XAUTH_AUTH_RESP_PSK:
		{
			HMAC_CTX ctx_prf;
			HMAC_CTX_init( &ctx_prf );

			HMAC_Init_ex( &ctx_prf, ph1->tunnel->peer->psk.buff(), ( int ) ph1->tunnel->peer->psk.size(), ph1->evp_hash, NULL );

			if( ph1->initiator )
			{
				HMAC_Update( &ctx_prf, ph1->nonce_l.buff(), ph1->nonce_l.size() );
				HMAC_Update( &ctx_prf, ph1->nonce_r.buff(), ph1->nonce_r.size() );
			}
			else
			{
				HMAC_Update( &ctx_prf, ph1->nonce_r.buff(), ph1->nonce_r.size() );
				HMAC_Update( &ctx_prf, ph1->nonce_l.buff(), ph1->nonce_l.size() );
			}

			HMAC_Final( &ctx_prf, skeyid_data, NULL );

			HMAC_CTX_cleanup( &ctx_prf );

			break;
		}

		//
		// digital signature
		//
		// SKEYID = prf( Ni_b | Nr_b, g^xy )
		//

		case IKE_AUTH_SIG_RSA:
		case HYBRID_AUTH_INIT_RSA:
		case HYBRID_AUTH_RESP_RSA:
		case XAUTH_AUTH_INIT_RSA:
		case XAUTH_AUTH_RESP_RSA:
		{
			BDATA nonce;

			if( ph1->initiator )
			{
				nonce.add( ph1->nonce_l );
				nonce.add( ph1->nonce_r );
			}
			else
			{
				nonce.add( ph1->nonce_r );
				nonce.add( ph1->nonce_l );
			}

			HMAC_CTX ctx_prf;
			HMAC_CTX_init( &ctx_prf );

			HMAC_Init_ex( &ctx_prf, nonce.buff(), ( int ) nonce.size(), ph1->evp_hash, NULL );
			HMAC_Update( &ctx_prf, shared.buff(), shared.size() );
			HMAC_Final( &ctx_prf, skeyid_data, NULL );

			HMAC_CTX_cleanup( &ctx_prf );

			break;
		}	
	}

	ph1->skeyid.set( skeyid_data, skeyid_size );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		skeyid_data,
		skeyid_size,
		"== : SETKEYID" );

	//
	// compute SKEYID_d
	//

	HMAC_CTX ctx_prf;
	HMAC_CTX_init( &ctx_prf );

	HMAC_Init_ex( &ctx_prf, ph1->skeyid.buff(), ( int ) ph1->skeyid.size(), ph1->evp_hash, NULL );
	HMAC_Update( &ctx_prf, shared.buff(), shared.size() );
	HMAC_Update( &ctx_prf, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ( unsigned char * ) "\0", 1 );
	HMAC_Final( &ctx_prf, skeyid_data, NULL );

	ph1->skeyid_d.set( skeyid_data, skeyid_size );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		skeyid_data,
		skeyid_size,
		"== : SETKEYID_d" );

	//
	// compute SKEYID_a
	//

	HMAC_Init_ex( &ctx_prf, ph1->skeyid.buff(), ( int ) ph1->skeyid.size(), ph1->evp_hash, NULL );
	HMAC_Update( &ctx_prf, skeyid_data, skeyid_size );
	HMAC_Update( &ctx_prf, shared.buff(), shared.size() );
	HMAC_Update( &ctx_prf, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ( unsigned char * ) "\1", 1 );
	HMAC_Final( &ctx_prf, skeyid_data, NULL );

	ph1->skeyid_a.set( skeyid_data, skeyid_size );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		skeyid_data,
		skeyid_size,
		"== : SETKEYID_a" );

	//
	// compute SKEYID_e
	//

	HMAC_Init_ex( &ctx_prf, ph1->skeyid.buff(), ( int ) ph1->skeyid.size(), ph1->evp_hash, NULL );
	HMAC_Update( &ctx_prf, skeyid_data, skeyid_size );
	HMAC_Update( &ctx_prf, shared.buff(), shared.size() );
	HMAC_Update( &ctx_prf, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ( unsigned char * ) "\2", 1 );
	HMAC_Final( &ctx_prf, skeyid_data, NULL );

	ph1->skeyid_e.set( skeyid_data, skeyid_size );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		skeyid_data,
		skeyid_size,
		"== : SETKEYID_e" );

	//
	// clobber dh shared secret
	//

	shared.del( true );

	// compute cipher key data

	unsigned char	key_data[ EVP_MAX_KEY_LENGTH + HMAC_MAX_MD_CBLOCK ];
	long			key_size = EVP_CIPHER_key_length( ph1->evp_cipher );

	if( proposal->ciph_kl )
		key_size = ( proposal->ciph_kl + 7 ) / 8;

	//
	// if the cipher requires more key material
	// than SKEYID_e provides, extend it using
	// a recursive algorithm
	//

	if( skeyid_size < key_size )
	{
		// grow our key to be a multiple
		// of SKEYID_e ( HMAC block size )

		if( key_size % skeyid_size )
			key_size += skeyid_size - ( key_size % skeyid_size );

		// create extended key data

		HMAC_Init_ex( &ctx_prf, skeyid_data, skeyid_size, ph1->evp_hash, NULL );
		HMAC_Update( &ctx_prf, ( unsigned char * ) "\0", 1 );
		HMAC_Final( &ctx_prf, key_data, NULL );

		for( long size = skeyid_size; size < key_size; size += skeyid_size )
		{
			HMAC_Init_ex( &ctx_prf, skeyid_data, skeyid_size, ph1->evp_hash, NULL );
			HMAC_Update( &ctx_prf, key_data + size - skeyid_size, skeyid_size );
			HMAC_Final( &ctx_prf, key_data + size, NULL );
		}
	}
	else
	{
		// copy the key data

		memcpy( key_data, skeyid_data, key_size );
	}

	HMAC_CTX_cleanup( &ctx_prf );

	if( proposal->ciph_kl )
		key_size = ( proposal->ciph_kl + 7 ) / 8;

	ph1->key.set( key_data, key_size );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		key_data,
		key_size,
		"== : cipher key" );

	//
	// compute cipher iv data
	//

	unsigned char iv_data[ HMAC_MAX_MD_CBLOCK ];
	unsigned long iv_size = EVP_CIPHER_iv_length( ph1->evp_cipher );

	EVP_MD_CTX ctx_hash;
	EVP_DigestInit( &ctx_hash, ph1->evp_hash );

	if( ph1->initiator )
	{
		EVP_DigestUpdate( &ctx_hash, ph1->xl.buff(), ph1->xl.size() );
		EVP_DigestUpdate( &ctx_hash, ph1->xr.buff(), ph1->xr.size() );
	}
	else
	{
		EVP_DigestUpdate( &ctx_hash, ph1->xr.buff(), ph1->xr.size() );
		EVP_DigestUpdate( &ctx_hash, ph1->xl.buff(), ph1->xl.size() );
	}

	EVP_DigestFinal( &ctx_hash, iv_data, NULL );
	EVP_MD_CTX_cleanup( &ctx_hash );

	ph1->iv.set( iv_data, iv_size );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		iv_data,
		iv_size,
		"== : cipher iv" );

	//
	// flag key material calculated
	//

	ph1->lstate |= LSTATE_HASKEYS;

	return LIBIKE_OK;
}

long _IKED::phase1_gen_hash_i( IDB_PH1 * sa, BDATA & hash )
{
	//
	// compute the initiators hash
	//

	hash.size( sa->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_CTX_init( &ctx_prf );

	HMAC_Init_ex( &ctx_prf, sa->skeyid.buff(), ( int ) sa->skeyid.size(), sa->evp_hash, NULL );

	if( sa->initiator )
	{
		HMAC_Update( &ctx_prf, sa->xl.buff(), sa->xl.size() );
		HMAC_Update( &ctx_prf, sa->xr.buff(), sa->xr.size() );
	}
	else
	{
		HMAC_Update( &ctx_prf, sa->xr.buff(), sa->xr.size() );
		HMAC_Update( &ctx_prf, sa->xl.buff(), sa->xl.size() );
	}

	HMAC_Update( &ctx_prf, sa->cookies.i, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, sa->cookies.r, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, sa->hda.buff(), sa->hda.size() );
	HMAC_Update( &ctx_prf, sa->idi.buff(), sa->idi.size() );
	HMAC_Final( &ctx_prf, hash.buff(), NULL );

	HMAC_CTX_cleanup( &ctx_prf );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		hash.buff(),
		hash.size(),
		"== : phase1 hash_i ( computed )" );

	return LIBIKE_OK;
}

long _IKED::phase1_gen_hash_r( IDB_PH1 * sa, BDATA & hash )
{
	//
	// compute the responders hash
	//

	hash.size( sa->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_CTX_init( &ctx_prf );

	HMAC_Init_ex( &ctx_prf, sa->skeyid.buff(), ( int ) sa->skeyid.size(), sa->evp_hash, NULL );

	if( sa->initiator )
	{
		HMAC_Update( &ctx_prf, sa->xr.buff(), sa->xr.size() );
		HMAC_Update( &ctx_prf, sa->xl.buff(), sa->xl.size() );
	}
	else
	{
		HMAC_Update( &ctx_prf, sa->xl.buff(), sa->xl.size() );
		HMAC_Update( &ctx_prf, sa->xr.buff(), sa->xr.size() );
	}

	HMAC_Update( &ctx_prf, sa->cookies.r, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, sa->cookies.i, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, sa->hda.buff(), sa->hda.size() );
	HMAC_Update( &ctx_prf, sa->idr.buff(), sa->idr.size() );
	HMAC_Final( &ctx_prf, hash.buff(), NULL );

	HMAC_CTX_cleanup( &ctx_prf );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		hash.buff(),
		hash.size(),
		"== : phase1 hash_r ( computed )" );

	return LIBIKE_OK;
}

inline uint8_t vendpld( long & count, uint8_t next )
{
	if( --count )
		return ISAKMP_PAYLOAD_VEND;
	else
		return next;
}

long _IKED::phase1_add_vend( IDB_PH1 * ph1, PACKET_IKE & packet, uint8_t next )
{
	//
	// determine vendor id count
	//

	long vid_count = 0;

	if( ph1->vendopts_l.flag.xauth )
		vid_count++;

	if( ph1->vendopts_l.flag.natt )
	{
		if( ph1->tunnel->peer->natt_mode == IPSEC_NATT_ENABLE )
			vid_count += 5;

		if( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE_DRAFT )
			vid_count += 2;

		if( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE_RFC )
			vid_count += 3;
	}

	if( ph1->vendopts_l.flag.frag )
		vid_count++;

	if( ph1->vendopts_l.flag.dpdv1 )
		vid_count += 2;

	if( ph1->vendopts_l.flag.ssoft )
		vid_count++;

	if( ph1->vendopts_l.flag.netsc )
		vid_count++;

	if( ph1->vendopts_l.flag.swind )
		vid_count++;

	if( ph1->vendopts_l.flag.unity )
		vid_count++;

	if( ph1->vendopts_l.flag.chkpt )
		vid_count++;

	//
	// optionally add xauth vendor id payload
	//

	if( ph1->vendopts_l.flag.xauth )
	{
		payload_add_vend( packet, vend_xauth, vendpld( vid_count, next ) );
		log.txt( LLOG_INFO, "ii : local supports XAUTH\n" );
	}

	//
	// optionally add natt vendor id payloads
	//

	if( ph1->vendopts_l.flag.natt )
	{
		//
		// add natt draft 00-01 id paylaods
		//

		if( ( ph1->tunnel->peer->natt_mode == IPSEC_NATT_ENABLE ) ||
			( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE_DRAFT ) )
		{
			payload_add_vend( packet, vend_natt_v00, vendpld( vid_count, next ) );
			log.txt( LLOG_INFO, "ii : local supports nat-t ( draft v00 )\n" );
			payload_add_vend( packet, vend_natt_v01, vendpld( vid_count, next ) );
			log.txt( LLOG_INFO, "ii : local supports nat-t ( draft v01 )\n" );
		}

		//
		// add natt draft 02-rfc id paylaods
		//

		if( ( ph1->tunnel->peer->natt_mode == IPSEC_NATT_ENABLE ) ||
			( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE_RFC ) )
		{
			payload_add_vend( packet, vend_natt_v02, vendpld( vid_count, next ) );
			log.txt( LLOG_INFO, "ii : local supports nat-t ( draft v02 )\n" );
			payload_add_vend( packet, vend_natt_v03, vendpld( vid_count, next ) );
			log.txt( LLOG_INFO, "ii : local supports nat-t ( draft v03 )\n" );
			payload_add_vend( packet, vend_natt_rfc, vendpld( vid_count, next ) );
			log.txt( LLOG_INFO, "ii : local supports nat-t ( rfc )\n" );
		}
	}

	//
	// optionally add fragmentation vendor id payload
	//

	if( ph1->vendopts_l.flag.frag )
	{
		payload_add_vend( packet, vend_frag, vendpld( vid_count, next ) );
		log.txt( LLOG_INFO, "ii : local supports FRAGMENTATION\n" );
	}

	//
	// optionally add dpd vendor id payload
	//

	if( ph1->vendopts_l.flag.dpdv1 )
	{
		payload_add_vend( packet, vend_dpd1, vendpld( vid_count, next ) );
		payload_add_vend( packet, vend_dpd1_ng, vendpld( vid_count, next ) );
		log.txt( LLOG_INFO, "ii : local supports DPDv1\n" );
	}

	//
	// optionally add shrew soft vendor id payload
	//

	if( ph1->vendopts_l.flag.ssoft )
	{
		payload_add_vend( packet, vend_ssoft, vendpld( vid_count, next ) );
		log.txt( LLOG_INFO, "ii : local is SHREW SOFT compatible\n" );
	}

	//
	// optionally add netscreen vendor payload
	//

	if( ph1->vendopts_l.flag.netsc )
	{
		payload_add_vend( packet, vend_netsc, vendpld( vid_count, next ) );
		log.txt( LLOG_INFO, "ii : local is NETSCREEN compatible\n" );
	}

	//
	// optionally add sidewinder vendor payload
	//

	if( ph1->vendopts_l.flag.swind )
	{
		payload_add_vend( packet, vend_swind, vendpld( vid_count, next ) );
		log.txt( LLOG_INFO, "ii : local is SIDEWINDER compatible\n" );
	}

	//
	// optionally add unity vendor id payload
	//

	if( ph1->vendopts_l.flag.unity )
	{
		BDATA vend_unity2;
		vend_unity2.add( vend_unity );	// base vendor id
		vend_unity2.add( 0x01, 1 );		// major version
		vend_unity2.add( 0x00, 1 );		// minor version

		payload_add_vend( packet, vend_unity2, vendpld( vid_count, next ) );
		log.txt( LLOG_INFO, "ii : local is CISCO UNITY compatible\n" );
	}

	//
	// optionally add checkpoint vendor payload ( must be last )
	//

	if( ph1->vendopts_l.flag.chkpt )
	{
		uint32_t prod;
		uint32_t vers;
		uint32_t feat;

		if( ph1->tunnel->peer->contact != IPSEC_CONTACT_CLIENT )
			prod = htonl( 1 );			// 01 == gateway
		else
			prod = htonl( 2 );			// 02 == client

		vers = htonl( 5006 );			// NG AI R56
		feat = htonl( 0x18800000 );		// all features

		BDATA vend_chkpt2;
		vend_chkpt2.add( vend_chkpt );	// base vendor id
		vend_chkpt2.add( &prod, 4 );	// client
		vend_chkpt2.add( &vers, 4 );	// version
		vend_chkpt2.add( 0, 4 );		// timestamp
		vend_chkpt2.add( 0, 4 );		// reserved
		vend_chkpt2.add( &feat, 4 );	// features

		payload_add_vend( packet, vend_chkpt2, vendpld( vid_count, next ) );
		log.txt( LLOG_INFO, "ii : local is CHECKPOINT compatible\n" );
	}

	return LIBIKE_OK;
}

inline bool vendcmp( BDATA & vend1, BDATA & vend2, bool prefix = false )
{
	if( prefix )
	{
		if( vend1.size() < vend2.size() )
			return false;
	}
	else
	{
		if( vend1.size() != vend2.size() )
			return false;
	}

	return !memcmp(
				vend1.buff(),
				vend2.buff(),
				vend2.size() );
}

long _IKED::phase1_chk_vend( IDB_PH1 * ph1, BDATA & vend )
{
	//
	// check for xauth vendor id
	//

	if( vendcmp( vend, vend_xauth ) )
	{
		ph1->vendopts_r.flag.xauth = true;
		log.txt( LLOG_INFO, "ii : peer supports XAUTH\n" );
		return LIBIKE_OK;
	}

	//
	// check for fragmentation vendor id
	//

	if( vendcmp( vend, vend_frag ) )
	{
		ph1->vendopts_r.flag.frag = true;
		log.txt( LLOG_INFO, "ii : peer supports FRAGMENTATION\n" );
		return LIBIKE_OK;
	}

	//
	// check for dead peer detection vendor id
	//

	if( vendcmp( vend, vend_dpd1 ) || vendcmp( vend, vend_dpd1_ng ) )
	{
		ph1->vendopts_r.flag.dpdv1 = true;
		log.txt( LLOG_INFO, "ii : peer supports DPDv1\n" );
		return LIBIKE_OK;
	}

	//
	// check for heartbeat notify detection vendor id
	//

	if( vendcmp( vend, vend_hbeat ) )
	{
		ph1->vendopts_r.flag.hbeat = true;
		log.txt( LLOG_INFO, "ii : peer supports HEARTBEAT-NOTIFY\n" );
		return LIBIKE_OK;
	}

	//
	// check for natt v00 vendor id
	//

	if( vendcmp( vend, vend_natt_v00 ) )
	{
		if( ( ph1->tunnel->peer->natt_mode == IPSEC_NATT_ENABLE ) ||
			( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE_DRAFT ) )
		{
			if( ph1->natt_version < IPSEC_NATT_V00 )
			{
				ph1->vendopts_r.flag.natt = true;
				ph1->natt_version = IPSEC_NATT_V00;
				ph1->natt_pldtype = ISAKMP_PAYLOAD_NAT_VXX_DISC;
			}
		}

		log.txt( LLOG_INFO, "ii : peer supports nat-t ( draft v00 )\n" );
		return LIBIKE_OK;
	}

	//
	// check for natt v01 vendor id
	//

	if( vendcmp( vend, vend_natt_v01 ) )
	{
		if( ( ph1->tunnel->peer->natt_mode == IPSEC_NATT_ENABLE ) ||
			( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE_DRAFT ) )
		{
			if( ph1->natt_version < IPSEC_NATT_V01 )
			{
				ph1->vendopts_r.flag.natt = true;
				ph1->natt_version = IPSEC_NATT_V01;
				ph1->natt_pldtype = ISAKMP_PAYLOAD_NAT_VXX_DISC;
			}
		}

		log.txt( LLOG_INFO, "ii : peer supports nat-t ( draft v01 )\n" );
		return LIBIKE_OK;
	}

	//
	// check for natt v02 vendor id
	//

	if( vendcmp( vend, vend_natt_v02 ) )
	{
		if( ( ph1->tunnel->peer->natt_mode == IPSEC_NATT_ENABLE ) ||
			( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE_RFC ) )
		{
			if( ph1->natt_version < IPSEC_NATT_V02 )
			{
				ph1->vendopts_r.flag.natt = true;
				ph1->natt_version = IPSEC_NATT_V02;
				ph1->natt_pldtype = ISAKMP_PAYLOAD_NAT_VXX_DISC;
			}
		}

		log.txt( LLOG_INFO, "ii : peer supports nat-t ( draft v02 )\n" );
		return LIBIKE_OK;
	}

	//
	// check for natt v03 vendor id
	//

	if( vendcmp( vend, vend_natt_v03 ) )
	{
		if( ( ph1->tunnel->peer->natt_mode == IPSEC_NATT_ENABLE ) ||
			( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE_RFC ) )
		{
			if( ph1->natt_version < IPSEC_NATT_V03 )
			{
				ph1->vendopts_r.flag.natt = true;
				ph1->natt_version = IPSEC_NATT_V03;
				ph1->natt_pldtype = ISAKMP_PAYLOAD_NAT_VXX_DISC;
			}
		}

		log.txt( LLOG_INFO, "ii : peer supports nat-t ( draft v03 )\n" );
		return LIBIKE_OK;
	}

	//
	// check for natt rfc vendor id
	//

	if( vendcmp( vend, vend_natt_rfc ) )
	{
		if( ( ph1->tunnel->peer->natt_mode == IPSEC_NATT_ENABLE ) ||
			( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE_RFC ) )
		{
			ph1->vendopts_r.flag.natt = true;
			ph1->natt_version = IPSEC_NATT_RFC;
			ph1->natt_pldtype = ISAKMP_PAYLOAD_NAT_RFC_DISC;
		}

		log.txt( LLOG_INFO, "ii : peer supports nat-t ( rfc )\n" );
		return LIBIKE_OK;
	}

	//
	// check for shrew soft vendor id
	//

	if( vendcmp( vend, vend_ssoft ) )
	{
		ph1->vendopts_r.flag.ssoft = true;
		ph1->vendopts_r.flag.unity = true;
		log.txt( LLOG_INFO, "ii : peer is SHREW SOFT compatible\n" );
		return LIBIKE_OK;
	}

	//
	// check for kame vendor id
	//

	if( vendcmp( vend, vend_kame ) )
	{
		ph1->vendopts_r.flag.kame = true;
		log.txt( LLOG_INFO, "ii : peer is IPSEC-TOOLS compatible\n" );
		return LIBIKE_OK;
	}

	//
	// check for netscreen vendor id
	//

	if( vendcmp( vend, vend_netsc ) )
	{
		ph1->vendopts_r.flag.netsc = true;
		log.txt( LLOG_INFO, "ii : peer is NETSCREEN compatible\n" );
		return LIBIKE_OK;
	}

	//
	// check for zywall vendor id
	//

	if( vendcmp( vend, vend_zwall ) )
	{
		ph1->vendopts_r.flag.zwall = true;
		log.txt( LLOG_INFO, "ii : peer is ZYWALL compatible\n" );
		return LIBIKE_OK;
	}

	//
	// check for sidewinder vendor id
	//

	if( vendcmp( vend, vend_swind ) )
	{
		ph1->vendopts_r.flag.swind = true;
		log.txt( LLOG_INFO, "ii : peer is SIDEWINDER compatible\n" );
		return LIBIKE_OK;
	}

	//
	// check for unity vendor id
	//

	if( vendcmp( vend, vend_unity, true ) )
	{
		//
		// if we are communcating with a
		// cisco unity device, set the
		// policy init flag. this forces
		// a single phase2 SA negotiation
		// for the first policy created
		// 

		ph1->tunnel->tstate |= TSTATE_POLICY_INIT;

		ph1->vendopts_r.flag.unity = true;
		log.txt( LLOG_INFO, "ii : peer is CISCO UNITY compatible\n" );
		return LIBIKE_OK;
	}

	//
	// check for checkpoint vendor id
	//

	if( vendcmp( vend, vend_chkpt, true ) )
	{
		ph1->vendopts_r.flag.chkpt = true;
		log.txt( LLOG_INFO, "ii : peer is CHECKPOINT compatible\n" );
		return LIBIKE_OK;
	}

	log.bin(
		LLOG_DEBUG,
		LLOG_DEBUG,
		vend.buff(),
		vend.size(),
		"ii : unknown vendor id" );

	return LIBIKE_OK;
}

long _IKED::phase1_chk_hash( IDB_PH1 * ph1 )
{
	//
	// generate hash data for comparison
	//

	BDATA hash_c;

	if( ph1->initiator )
	{
		phase1_gen_hash_r( ph1, hash_c );

		log.bin(
			LLOG_DEBUG,
			LLOG_DECODE,
			ph1->hash_r.buff(),
			hash_c.size(),
			"== : phase1 hash_r ( received )" );
	}
	else
	{
		phase1_gen_hash_i( ph1, hash_c );

		log.bin(
			LLOG_DEBUG,
			LLOG_DECODE,
			ph1->hash_r.buff(),
			hash_c.size(),
			"== : phase1 hash_i ( received )" );
	}

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	if( hash_c != ph1->hash_r )
	{
		log.txt( LLOG_INFO,
			"!! : phase1 sa rejected, invalid auth data\n"
			"!! : %s <-> %s\n"
			"!! : %04x%04x:%04x%04x\n",
			txtaddr_l,
			txtaddr_r,
			htonl( *( long * ) &ph1->cookies.i[ 0 ] ),
			htonl( *( long * ) &ph1->cookies.i[ 4 ] ),
			htonl( *( long * ) &ph1->cookies.r[ 0 ] ),
			htonl( *( long * ) &ph1->cookies.r[ 4 ] ) );

		return LIBIKE_FAILED;
	}

	log.txt( LLOG_INFO,
		"ii : phase1 sa established\n"
		"ii : %s <-> %s\n"
		"ii : %04x%04x:%04x%04x\n",
		txtaddr_r,
		txtaddr_l,
		htonl( *( long * ) &ph1->cookies.i[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.i[ 4 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 4 ] ) );

	return LIBIKE_OK;
}

long _IKED::phase1_chk_sign( IDB_PH1 * ph1 )
{
	//
	// verify the peer certificates
	// using the ca cert specified
	// in the peer configuration
	//

	BDATA cert;

	if( !cert_verify( ph1->certs_r, ph1->tunnel->peer->cert_r, cert ) )
	{
		log.txt( LLOG_ERROR, "!! : unable to verify remote peer certificate\n" );
		return LIBIKE_FAILED;
	}

	//
	// read the public key from the
	// peer provided certificate
	//

	BDATA pubkey;

	if( !pubkey_rsa_read( cert, pubkey ) )
	{
		log.txt( LLOG_ERROR, "!! : unable to extract public key from remote peer certificate\n" );
		return LIBIKE_FAILED;
	}

	//
	// use the public key to decrypt
	// the signiature data provided
	// by the remote peer
	//

	if( !pubkey_rsa_decrypt( pubkey, ph1->sign_r, ph1->hash_r ) )
	{
		log.txt( LLOG_ERROR, "!! : unable to compute remote peer signed hash\n" );
		return LIBIKE_FAILED;
	}

	//
	// check hash value
	//

	return phase1_chk_hash( ph1 );
}

long _IKED::phase1_gen_natd( IDB_PH1 * ph1 )
{
	if( ph1->lstate & LSTATE_GENNATD )
		return LIBIKE_OK;

	BDATA natd;
	if( !natd.size( ph1->hash_size ) )
		return LIBIKE_MEMORY;

	//
	// compute the nat discovery
	// hash for remote address
	//

	EVP_MD_CTX ctx_hash;
	EVP_DigestInit( &ctx_hash, ph1->evp_hash );
	EVP_DigestUpdate( &ctx_hash, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	EVP_DigestUpdate( &ctx_hash, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	EVP_DigestUpdate( &ctx_hash, &ph1->tunnel->saddr_r.saddr4.sin_addr.s_addr, 4 );
	EVP_DigestUpdate( &ctx_hash, &ph1->tunnel->saddr_r.saddr4.sin_port, 2 );
	EVP_DigestFinal( &ctx_hash, natd.buff(), NULL );
	EVP_MD_CTX_cleanup( &ctx_hash );

	ph1->natd_hash_l.add( natd );

	//
	// compute the nat discovery
	// hash for local address
	//

	EVP_DigestInit( &ctx_hash, ph1->evp_hash );
	EVP_DigestUpdate( &ctx_hash, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	EVP_DigestUpdate( &ctx_hash, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	EVP_DigestUpdate( &ctx_hash, &ph1->tunnel->saddr_l.saddr4.sin_addr.s_addr, 4 );
	EVP_DigestUpdate( &ctx_hash, &ph1->tunnel->saddr_l.saddr4.sin_port, 2 );
	EVP_DigestFinal( &ctx_hash, natd.buff(), NULL );
	EVP_MD_CTX_cleanup( &ctx_hash );

	ph1->natd_hash_l.add( natd );

	ph1->lstate |= LSTATE_GENNATD;

	return LIBIKE_OK;
}

bool _IKED::phase1_add_natd( IDB_PH1 * ph1, PACKET_IKE & packet, uint8_t next )
{
	BDATA natd;

	long index = 0;
	long count = ph1->natd_hash_l.count();

	for( long index = 0; index < count; index++ )
	{
		ph1->natd_hash_l.get( natd, index );

		if( index < ( count - 1 ) )
			payload_add_natd( packet, natd, ph1->natt_pldtype );
		else
			payload_add_natd( packet, natd, next );
	}

	return true;
}

bool _IKED::phase1_chk_natd( IDB_PH1 * ph1 )
{
	//
	// if we are rekeying, skip this
	//

	if( ph1->tunnel->lstate & TSTATE_NATT_FLOAT )
		return true;

	//
	// verify that both support natt
	//

	switch( ph1->tunnel->peer->natt_mode )
	{
		case IPSEC_NATT_DISABLE:
			log.txt( LLOG_INFO, "ii : nat-t is disabled locally\n" );
			break;

		case IPSEC_NATT_ENABLE:
		{
			bool xlated_l = true;
			bool xlated_r = true;
			BDATA natd_l;
			BDATA natd_r;

			//
			// make sure remote peer negotiated natt
			//

			if( !ph1->natt_version )
			{
				log.txt( LLOG_INFO, "ii : nat-t is unsupported by remote peer\n" );
				break;
			}

			//
			// make sure local nat discovery hashes
			// have been generated
			//

			phase1_gen_natd( ph1 );

			//
			// compare the remote destination
			// hash to all local source hashes
			//

			if( !ph1->natd_hash_r.get( natd_r, 0 ) )
			{
				log.txt( LLOG_ERROR,
					"!! : no remote desitnation hash available for comparison\n" );
				break;
			}

			for( long index = 1; index < ph1->natd_hash_l.count(); index++ )
			{
				ph1->natd_hash_l.get( natd_l, index );
				if( natd_r == natd_l )
				{
					xlated_l = false;
					break;
				}
			}

			if( xlated_l )
				log.txt( LLOG_INFO,
					"ii : nat discovery - local address is translated\n" );

			//
			// compare the local destination
			// hash to all remote source hashes
			//

			if( !ph1->natd_hash_l.get( natd_l, 0 ) )
			{
				log.txt( LLOG_ERROR,
					"!! : no local desitnation hash available for comparison\n" );
				break;
			}

			for( long index = 1; index < ph1->natd_hash_r.count(); index++ )
			{
				ph1->natd_hash_r.get( natd_r, index );
				if( natd_l == natd_r )
				{
					xlated_r = false;
					break;
				}
			}

			if( xlated_r )
				log.txt( LLOG_INFO,
					"ii : nat discovery - remote address is translated\n" );

			//
			// only set the nat-t port if translation was detected
			//

			if( xlated_l || xlated_r )
			{
				ph1->tunnel->natt_version = ph1->natt_version;
				break;
			}

			log.txt( LLOG_INFO,
				"ii : disabled nat-t ( no nat detected )\n" );

			break;
		}

		case IPSEC_NATT_FORCE_DRAFT:

			log.txt( LLOG_INFO, "ii : forcing nat-t to enabled ( draft )\n" );

			//
			// set natt to negotiated version or draft v00
			//

			if( ph1->natt_version != IPSEC_NATT_NONE )
				ph1->tunnel->natt_version = ph1->natt_version;
			else
				ph1->tunnel->natt_version = IPSEC_NATT_V00;

			break;

		case IPSEC_NATT_FORCE_RFC:

			log.txt( LLOG_INFO, "ii : forcing nat-t to enabled ( rfc )\n" );

			//
			// set natt to negotiated version or rfc
			//

			if( ph1->natt_version != IPSEC_NATT_NONE )
				ph1->tunnel->natt_version = ph1->natt_version;
			else
				ph1->tunnel->natt_version = IPSEC_NATT_RFC;

			break;

		case IPSEC_NATT_FORCE_CISCO:

			log.txt( LLOG_INFO, "ii : forcing nat-t to cisco-udp\n" );

			//
			// set natt to cisco-udp
			//

			ph1->tunnel->natt_version = IPSEC_NATT_CISCO;

			break;
	}
	
	//
	// switch to natt ports if required
	//

	ph1->tunnel->lstate |= TSTATE_NATT_FLOAT;

	if( ph1->tunnel->natt_version >= IPSEC_NATT_V02 )
	{
		//
		// switch our local port to natt
		//

		if( socket_lookup_port(	ph1->tunnel->saddr_l, true ) != LIBIKE_OK )
		{
			log.txt( LLOG_INFO,
				"ii : unable to locate local nat-t udp port\n" );

			return false;
		}

		log.txt( LLOG_INFO,
			"ii : switching to src nat-t udp port %u\n",
			ntohs( ph1->tunnel->saddr_l.saddr4.sin_port ) );

		//
		// switch the peer port to natt
		//

		ph1->tunnel->saddr_r.saddr4.sin_port = ph1->tunnel->peer->natt_port;

		log.txt( LLOG_INFO,
			"ii : switching to dst nat-t udp port %u\n",
			ntohs( ph1->tunnel->saddr_r.saddr4.sin_port ) );

		//
		// setup our filter
		//

#ifdef WIN32

		iked.tunnel_filter_add( ph1->tunnel, true );

#endif

		return true;
	}

	return false;
}

bool _IKED::phase1_chk_port( IDB_PH1 * ph1, IKE_SADDR * saddr_r, IKE_SADDR * saddr_l )
{
	//
	// check if our peer has floated ports
	//

	if( saddr_r->saddr4.sin_port != ph1->tunnel->saddr_r.saddr4.sin_port )
	{

		if( ph1->initiator )
		{
			if( ph1->tunnel->peer->natt_mode == IPSEC_NATT_NONE )
			{
				log.txt( LLOG_INFO,
					"ii : initiator port values floated but nat-t is disabled\n" );

				return false;
			}

			if( ph1->tunnel->lstate & TSTATE_NATT_FLOAT )
			{
				log.txt( LLOG_INFO,
					"ww : initiator port values should only float once per session\n" );

				return true;
			}
		}
		else
		{
			log.txt( LLOG_DEBUG,
				"ii : responder port values have floated\n" );
		}

		//
		// float our port to natt
		//

		ph1->tunnel->saddr_l.saddr4.sin_port = saddr_l->saddr4.sin_port;

		//
		// float the peer port to natt
		//

		ph1->tunnel->saddr_r.saddr4.sin_port = saddr_r->saddr4.sin_port;

		//
		// switch the tunnel to the
		// negotiated natt version
		//

		ph1->tunnel->natt_version = ph1->natt_version;

		log.txt( LLOG_INFO,
			"ii : floating to nat-t udp ports %u -> %u\n",
			ntohs( ph1->tunnel->saddr_r.saddr4.sin_port ),
			ntohs( ph1->tunnel->saddr_l.saddr4.sin_port ) );
		//
		// setup our filter
		//

#ifdef WIN32

		iked.tunnel_filter_add( ph1->tunnel, true );

#endif

		ph1->tunnel->lstate |= TSTATE_NATT_FLOAT;
	}

	return true;
}

long _IKED::phase1_chk_idr( IDB_PH1 * ph1 )
{
	//
	// create a phase1 remote id based
	// on our tunnel configuration data
	//

	IKE_PH1ID idt;
	if( !gen_ph1id_r( ph1, idt ) )
		return LIBIKE_FAILED;

	//
	// compare the id values
	//

	if( !cmp_ph1id( idt, ph1->ph1id_r, ph1->vendopts_l.flag.natt ) )
		return LIBIKE_FAILED;

	return LIBIKE_OK;
}
