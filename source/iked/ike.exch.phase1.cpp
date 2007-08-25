
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
	// make sure we are not dealing
	// whit a sa marked as dead
	//

	if( ph1->lstate & LSTATE_DELETE )
	{
		log.txt( LOG_ERROR, "!! : ignore phase1 packet, sa marked for death\n" );

		return LIBIKE_OK;
	}

	//
	// decrypt packet
	//

	packet_ike_decrypt( ph1, packet, &ph1->iv );

	//
	// if we are dumping the ike packets,
	// we need to rebuild a full packet
	// to dump to pcap format 
	//

	if( dump_ike )
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
			ph1->tunnel->natt_v );

		//
		// obtain ethernet header
		//

		ETH_HEADER ethhdr;
		header( packet_ip_dump, ethhdr );

		//
		// dump the packet
		//

		pcap_ike.dump(
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
					log.txt( LOG_INFO, "<< : ignoring duplicate security association payload\n" );
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
					log.txt( LOG_INFO, "<< : ignoring duplicate key excahnge payload\n" );
				else
					result = payload_get_kex( packet, ph1->xr );

				ph1->xstate |= XSTATE_RECV_KE;

				break;

			//
			// nonce payload
			//

			case ISAKMP_PAYLOAD_NONCE:

				if( ph1->xstate & XSTATE_RECV_NO )
					log.txt( LOG_INFO, "<< : ignoring duplicate nonce payload\n" );
				else
					result = payload_get_nonce( packet, ph1->nonce_r );

				ph1->xstate |= XSTATE_RECV_NO;

				break;

			//
			// identity payload
			//

			case ISAKMP_PAYLOAD_IDENT:

				if( ph1->xstate & XSTATE_RECV_ID )
					log.txt( LOG_INFO, "<< : ignoring duplicate id payload\n" );
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

				if( ph1->xstate & XSTATE_RECV_CT )
					log.txt( LOG_INFO, "<< : ignoring duplicate certificate payload\n" );
				else
					result = payload_get_cert( packet, ph1->ctype_r, ph1->cert_r );

				ph1->xstate |= XSTATE_RECV_CT;

				break;

			//
			// certificate request payload
			//

			case ISAKMP_PAYLOAD_CERT_REQ:

				if( ph1->xstate & XSTATE_RECV_CR )
					log.txt( LOG_INFO, "<< : ignoring duplicate cert request payload\n" );
				else
					result = payload_get_creq( packet, ph1->ctype_l );

				ph1->xstate |= XSTATE_RECV_CR;

				break;

			//
			// signature payload
			//

			case ISAKMP_PAYLOAD_SIGNATURE:

				if( ph1->xstate & XSTATE_RECV_SI )
					log.txt( LOG_INFO, "<< : ignoring duplicate signature payload\n" );
				else
					result = payload_get_sign( packet, ph1->sign_r );

				ph1->xstate |= XSTATE_RECV_SI;

				break;

			//
			// hash payload
			//

			case ISAKMP_PAYLOAD_HASH:

				if( ph1->xstate & XSTATE_RECV_HA )
					log.txt( LOG_INFO, "<< : ignoring duplicate hash payload\n" );
				else
					result = payload_get_hash( packet, ph1->hash_r, ph1->hash_size );

				ph1->xstate |= XSTATE_RECV_HA;

				break;

			//
			// vendor id payload
			//

			case ISAKMP_PAYLOAD_VEND:
			{
				BDATA vend;

				result = payload_get_vend( packet, vend );

				phase1_chk_vend( ph1, vend );

				break;
			}

			//
			// nat discovery payload
			//

			case ISAKMP_PAYLOAD_NAT_V02_DISC:
			case ISAKMP_PAYLOAD_NAT_RFC_DISC:
			{
				if( !( ph1->xstate & XSTATE_RECV_NDL ) )
				{
					result = payload_get_natd( packet, ph1->natd_rd, ph1->hash_size );
					ph1->xstate |= XSTATE_RECV_NDL;
					break;
				}

//				if( !( ph1->xstate & XSTATE_RECV_NDR ) )
				{
					result = payload_get_natd( packet, ph1->natd_rs, ph1->hash_size );
					ph1->xstate |= XSTATE_RECV_NDR;
					break;
				}

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
					ph1->nlist.add( notify );

				break;
			}

			//
			// unhandled payload
			//

			default:

				log.txt( LOG_ERROR,
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

		size_t bytes_left;
		packet.chk_payload( bytes_left );
		if( bytes_left )
			log.txt( LOG_ERROR, "XX : warning, unprocessed payload data !!!\n" );

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
				// determine xauth negotiation
				//

				IKE_PROPOSAL * proposal;
				ph1->plist_l.get( &proposal, 0 );

				if( ( proposal->auth_id == XAUTH_AUTH_INIT_PSK ) ||
					( proposal->auth_id == XAUTH_AUTH_INIT_RSA ) ||
					( proposal->auth_id == HYBRID_AUTH_INIT_RSA ) )
					ph1->xauth_l = true;

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
			//
			// potentialy notify our peer
			//

			if( packet.notify && ph1->tunnel->peer->notify )
				inform_new_notify( ph1, NULL, packet.notify );

			//
			// flag sa for removal
			//

			ph1->lstate |= LSTATE_DELETE;

			return result;
		}

		//
		// read next payload
		//

		payload = next_payload;
	}

	//
	// check and enable natt if ready
	//

	if( !( ph1->lstate & LSTATE_CHKNATD ) &&
		 ( ph1->xstate & XSTATE_RECV_NDL ) &&
		 ( ph1->xstate & XSTATE_RECV_NDR ) )
		phase1_chk_natd( ph1 );

	//
	// now build and send any response
	// packets that may be necessary
	//

	if( !( ph1->lstate & LSTATE_DELETE ) )
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
				// add sa payload
				//

				size_t beg = packet.size() + 4;
				payload_add_sa( packet, ph1->plist_l, ISAKMP_PAYLOAD_VEND );
				size_t end = packet.size();

				ph1->hda.set( packet.buff() + beg, end - beg );

				//
				// add vendor payloads
				//

				phase1_add_vend( ph1, packet );

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
				// determine the nat discovery payload type
				//

				unsigned char last = ISAKMP_PAYLOAD_NONE;

				if( ph1->tunnel->natt_v != IPSEC_NATT_NONE )
				{
					phase1_gen_natd( ph1 );

					if( ph1->natt_v == IPSEC_NATT_V02 )
						last = ISAKMP_PAYLOAD_NAT_V02_DISC;

					if( ph1->natt_v == IPSEC_NATT_RFC )
						last = ISAKMP_PAYLOAD_NAT_RFC_DISC;
				}

				//
				// write packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_KEX, ph1->exchange, 0 );

				//
				// add key exchange and noonce payloads
				//

				payload_add_kex( packet, ph1->xl, ISAKMP_PAYLOAD_NONCE );
				payload_add_nonce( packet, ph1->nonce_l, last );

				//
				// optionally add nat discovery hash payloads
				//

				if( ph1->tunnel->natt_v != IPSEC_NATT_NONE )
				{
					phase1_gen_natd( ph1 );
					payload_add_natd( packet, ph1->natd_ld, last );
					payload_add_natd( packet, ph1->natd_ls, ISAKMP_PAYLOAD_NONE );
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
				// calculate key material
				//

				phase1_gen_keys( ph1 );

				//
				// obtain our negotiated proposal
				//

				IKE_PROPOSAL * proposal;
				ph1->plist_l.get( &proposal, 0 );

				//
				// write packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_IDENT, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

				switch( proposal->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					case HYBRID_AUTH_INIT_RSA:
					{
						//
						// add the local id payload
						//

						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_HASH );
						size_t pld_end = packet.size();

						ph1->idi.set( packet.buff() + pld_beg, pld_end - pld_beg );

						//
						// calculate and add the hash payload
						//

						phase1_gen_hash_i( ph1, ph1->hash_l );

						payload_add_hash( packet, ph1->hash_l, ISAKMP_PAYLOAD_NONE );

						ph1->xstate |= XSTATE_SENT_HA;

						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					{
						//
						// add the local id payload
						//

						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_CERT );
						size_t pld_end = packet.size();

						ph1->idi.set( packet.buff() + pld_beg, pld_end - pld_beg );

						//
						// add the local certificate payload
						//

						payload_add_cert( packet, ISAKMP_CERT_X509_SIG, ph1->tunnel->peer->cert_l, ISAKMP_PAYLOAD_SIGNATURE );

						//
						// calculate the hash and rsa signature
						//

						phase1_gen_hash_i( ph1, ph1->hash_l );

						BDATA sign;
						sign.set( ph1->hash_l );
						prvkey_rsa_encrypt( ph1->tunnel->peer->key, sign );

						//
						// add the signature and certificate request payloads
						//

						payload_add_sign( packet, sign, ISAKMP_PAYLOAD_CERT_REQ );
						payload_add_creq( packet, ISAKMP_CERT_X509_SIG, ISAKMP_PAYLOAD_NONE );

						ph1->xstate |= XSTATE_SENT_CT;
						ph1->xstate |= XSTATE_SENT_SI;
						ph1->xstate |= XSTATE_SENT_CR;

						break;
					}
				}

				packet.done();

				//
				// encrypt and send packet
				//

				packet_ike_send( ph1, ph1, packet, true );

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
				// add sa payload
				//

				payload_add_sa( packet, ph1->plist_l, ISAKMP_PAYLOAD_VEND );

				//
				// add vendor payloads
				//

				phase1_add_vend( ph1, packet );

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
				PACKET_IKE packet;

				packet.write( ph1->cookies, ISAKMP_PAYLOAD_KEX, ph1->exchange, 0 );
				payload_add_kex( packet, ph1->xl, ISAKMP_PAYLOAD_NONCE );
				payload_add_nonce( packet, ph1->nonce_l, ISAKMP_PAYLOAD_NONE );
				packet.done();

				//
				// send responders packet
				//

				packet_ike_send( ph1, ph1, packet, true );

				ph1->xstate |= XSTATE_SENT_KE;
				ph1->xstate |= XSTATE_SENT_NO;

				//
				// calculate key material
				//

				phase1_gen_keys( ph1 );
			}

			//
			// id + hash || id + [ cert ] + sign packet
			//

			if(	 ( ph1->xstate & XSTATE_RECV_ID ) &&
				!( ph1->xstate & XSTATE_SENT_ID ) )
			{
				//
				// obtain our negotiated proposal
				//

				IKE_PROPOSAL * proposal;
				ph1->plist_l.get( &proposal, 0 );

				switch( proposal->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					{
						if( !( ph1->xstate & XSTATE_RECV_HA ) )
							break;

						PACKET_IKE packet;

						packet.write( ph1->cookies, ISAKMP_PAYLOAD_IDENT, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_HASH );
						size_t pld_end = packet.size();

						ph1->idr.set( packet.buff() + pld_beg, pld_end - pld_beg );

						phase1_gen_hash_r( ph1, ph1->hash_l );

						payload_add_hash( packet, ph1->hash_l, ISAKMP_PAYLOAD_NONE );
						packet.done();

						//
						// send responder packet
						//

						packet_ike_send( ph1, ph1, packet, true );

						ph1->xstate |= XSTATE_SENT_ID;
						ph1->xstate |= XSTATE_SENT_HA;

						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					case HYBRID_AUTH_INIT_RSA:
					{
						if( proposal->auth_id == XAUTH_AUTH_INIT_RSA )
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

						PACKET_IKE packet;

						packet.write( ph1->cookies, ISAKMP_PAYLOAD_IDENT, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_CERT );
						size_t pld_end = packet.size();

						ph1->idr.set( packet.buff() + pld_beg, pld_end - pld_beg );

						phase1_gen_hash_r( ph1, ph1->hash_l );

						payload_add_cert( packet, ISAKMP_CERT_X509_SIG, ph1->tunnel->peer->cert_l, ISAKMP_PAYLOAD_SIGNATURE );

						BDATA sign;
						sign.set( ph1->hash_l );
						prvkey_rsa_encrypt( ph1->tunnel->peer->key, sign );

						payload_add_sign( packet, sign, ISAKMP_PAYLOAD_NONE );

						//
						// send responder packet
						//

						packet_ike_send( ph1, ph1, packet, true );

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
				// add and store the sa payload
				//

				size_t beg = packet.size() + 4;
				payload_add_sa( packet, ph1->plist_l, ISAKMP_PAYLOAD_KEX );
				size_t end = packet.size();

				ph1->hda.set( packet.buff() + beg, end - beg );

				//
				// add the key echange and nonce payloads
				//

				payload_add_kex( packet, ph1->xl, ISAKMP_PAYLOAD_NONCE );
				payload_add_nonce( packet, ph1->nonce_l, ISAKMP_PAYLOAD_IDENT );

				//
				// add and store the phase1 id payload
				//

				beg = packet.size() + 4;
				payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_VEND );
				end = packet.size();

				ph1->idi.set( packet.buff() + beg, end - beg );

				//
				// add vendor payloads
				//

				phase1_add_vend( ph1, packet );

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
				// obtain our negotiated proposal
				//

				IKE_PROPOSAL * proposal;
				ph1->plist_l.get( &proposal, 0 );

				switch( proposal->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					case HYBRID_AUTH_INIT_RSA:
					{
						if( ( ( ( proposal->auth_id == IKE_AUTH_PRESHARED_KEY ) ||
								( proposal->auth_id == XAUTH_AUTH_INIT_PSK ) ) &&
							  ( ph1->xstate & XSTATE_RECV_HA ) && !( ph1->xstate & XSTATE_SENT_HA ) ) ||
							( ( proposal->auth_id == HYBRID_AUTH_INIT_RSA ) &&
							  ( ph1->xstate & XSTATE_RECV_SI ) && !( ph1->xstate & XSTATE_SENT_HA ) ) )
						{
							phase1_gen_keys( ph1 );
							phase1_gen_hash_i( ph1, ph1->hash_l );

							//
							// if both endpoints support natt and
							// at least one address is translated
							//

							unsigned char last = ISAKMP_PAYLOAD_NONE;

							if( ph1->tunnel->natt_v != IPSEC_NATT_NONE )
							{
								phase1_gen_natd( ph1 );

								if( ph1->natt_v == IPSEC_NATT_V02 )
									last = ISAKMP_PAYLOAD_NAT_V02_DISC;

								if( ph1->natt_v == IPSEC_NATT_RFC )
									last = ISAKMP_PAYLOAD_NAT_RFC_DISC;
							}

							//
							// write packet header
							//

							PACKET_IKE packet;
							packet.write( ph1->cookies, ISAKMP_PAYLOAD_HASH, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

							//
							// add the liveliness proof hash payload
							//

							payload_add_hash( packet, ph1->hash_l, last );

							//
							// optionally add nat discovery hash payloads
							//

							if( last != ISAKMP_PAYLOAD_NONE )
							{
								payload_add_natd( packet, ph1->natd_ld, last );
								payload_add_natd( packet, ph1->natd_ls, ISAKMP_PAYLOAD_NONE );
							}

							packet.done();

							//
							// send packet
							//

							packet_ike_send( ph1, ph1, packet, true );

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
							phase1_gen_keys( ph1 );
							phase1_gen_hash_i( ph1, ph1->hash_l );

							//
							// if both endpoints support natt and
							// at least one address is translated
							//

							unsigned char last = ISAKMP_PAYLOAD_NONE;

							if( ph1->tunnel->natt_v != IPSEC_NATT_NONE )
							{
								phase1_gen_natd( ph1 );

								if( ph1->natt_v == IPSEC_NATT_V02 )
									last = ISAKMP_PAYLOAD_NAT_V02_DISC;

								if( ph1->natt_v == IPSEC_NATT_RFC )
									last = ISAKMP_PAYLOAD_NAT_RFC_DISC;
							}

							//
							// write packet header
							//

							PACKET_IKE packet;
							packet.write( ph1->cookies, ISAKMP_PAYLOAD_CERT, ph1->exchange, ISAKMP_FLAG_ENCRYPT );

							//
							// add our certificate payload
							//

							payload_add_cert( packet, ISAKMP_CERT_X509_SIG, ph1->tunnel->peer->cert_l, ISAKMP_PAYLOAD_SIGNATURE );

							//
							// compute and add our rsa signature
							//

							BDATA sign;
							sign.set( ph1->hash_l );
							prvkey_rsa_encrypt( ph1->tunnel->peer->key, sign );

							payload_add_sign( packet, sign, last );

							//
							// optionally add nat discovery hash payloads
							//

							if( last != ISAKMP_PAYLOAD_NONE )
							{
								payload_add_natd( packet, ph1->natd_ld, last );
								payload_add_natd( packet, ph1->natd_ls, ISAKMP_PAYLOAD_NONE );
							}

							packet.done();

							//
							// send packet
							//

							packet_ike_send( ph1, ph1, packet, true );

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
				// if both endpoints support natt and
				// at least one address is translated
				//

				unsigned char last = ISAKMP_PAYLOAD_NONE;

				if( ph1->tunnel->natt_v != IPSEC_NATT_NONE )
				{
					phase1_gen_natd( ph1 );

					if( ph1->natt_v == IPSEC_NATT_V02 )
						last = ISAKMP_PAYLOAD_NAT_V02_DISC;

					if( ph1->natt_v == IPSEC_NATT_RFC )
						last = ISAKMP_PAYLOAD_NAT_RFC_DISC;
				}

				//
				// write packet header
				//

				PACKET_IKE packet;
				packet.write( ph1->cookies, ISAKMP_PAYLOAD_SA, ph1->exchange, 0 );

				//
				// add the sa, key echange and nonce payloads
				//

				payload_add_sa( packet, ph1->plist_l, ISAKMP_PAYLOAD_KEX );
				payload_add_kex( packet, ph1->xl, ISAKMP_PAYLOAD_NONCE );
				payload_add_nonce( packet, ph1->nonce_l, ISAKMP_PAYLOAD_IDENT );

				//
				// generate our keys
				//

				phase1_gen_keys( ph1 );

				//
				// obtain our negotiated proposal
				//

				IKE_PROPOSAL * proposal;
				ph1->plist_l.get( &proposal, 0 );

				switch( proposal->auth_id )
				{
					case IKE_AUTH_PRESHARED_KEY:
					case XAUTH_AUTH_INIT_PSK:
					case HYBRID_AUTH_INIT_RSA:
					{
						//
						// add and store the phase1 id payload
						//

						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_HASH );
						size_t pld_end = packet.size();

						ph1->idr.set( packet.buff() + pld_beg, pld_end - pld_beg );

						//
						// generate and add our hash payload
						//

						phase1_gen_hash_r( ph1, ph1->hash_l );
						payload_add_hash( packet, ph1->hash_l, ISAKMP_PAYLOAD_VEND );

						ph1->xstate |= XSTATE_SENT_HA;

						break;
					}

					case IKE_AUTH_SIG_RSA:
					case XAUTH_AUTH_INIT_RSA:
					{
						//
						//
						// add and store the phase1 id payload
						//

						size_t pld_beg = packet.size() + 4;
						payload_add_ph1id( packet, ph1->ph1id_l, ISAKMP_PAYLOAD_CERT );
						size_t pld_end = packet.size();

						ph1->idr.set( packet.buff() + pld_beg, pld_end - pld_beg );

						//
						// add our cert payload
						//

						payload_add_cert( packet, ISAKMP_CERT_X509_SIG, ph1->tunnel->peer->cert_l, ISAKMP_PAYLOAD_SIGNATURE );

						//
						// generate and add our signature payload
						//

						phase1_gen_hash_r( ph1, ph1->hash_l );

						BDATA sign;
						sign.set( ph1->hash_l );
						prvkey_rsa_encrypt( ph1->tunnel->peer->key, sign );

						payload_add_sign( packet, sign, ISAKMP_PAYLOAD_VEND );

						ph1->xstate |= XSTATE_SENT_CT;
						ph1->xstate |= XSTATE_SENT_SI;

						break;
					}
				}

				//
				// add vendor payloads
				//

				phase1_add_vend( ph1, packet );

				//
				// send packet
				//

				packet.done();

				packet_ike_send( ph1, ph1, packet, true );

				ph1->xstate |= XSTATE_SENT_SA;
				ph1->xstate |= XSTATE_SENT_KE;
				ph1->xstate |= XSTATE_SENT_NO;
				ph1->xstate |= XSTATE_SENT_ID;
			}
		}
	}

	//
	// is it time to verify our
	// peers hash or signature
	//

	if( !( ph1->lstate & LSTATE_MATURE ) &&
		 ( ph1->lstate & LSTATE_HASKEYS ) &&
		 ( ph1->xstate & XSTATE_RECV_ID ) )
	{
		//
		// obtain our negotiated proposal
		//

		IKE_PROPOSAL * proposal;
		ph1->plist_l.get( &proposal, 0 );

		//
		// check the peers hash value
		//

		if( ( proposal->auth_id == IKE_AUTH_PRESHARED_KEY ) ||
			( proposal->auth_id == XAUTH_AUTH_INIT_PSK ) ||
			( proposal->auth_id == HYBRID_AUTH_INIT_RSA && !ph1->initiator ) )
		{
			if( ph1->xstate & XSTATE_RECV_HA )
			{
				if( phase1_chk_hash( ph1 ) == LIBIKE_OK )
				{
					ph1->clean();
					ph1->lstate |= LSTATE_MATURE;
				}
				else
				{
					ph1->lstate |= LSTATE_DELETE;

					if( ph1->tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
						ph1->tunnel->close = TERM_PEER_AUTH;

					//
					// potentialy notify the peer
					//

					if( ph1->tunnel->peer->notify )
						inform_new_notify( ph1, NULL, ISAKMP_N_AUTHENTICATION_FAILED );
				}
			}
		}

		//
		// check the peers signature value
		//

		if( ( proposal->auth_id == IKE_AUTH_SIG_RSA ) ||
			( proposal->auth_id == XAUTH_AUTH_INIT_RSA ) ||
			( proposal->auth_id == HYBRID_AUTH_INIT_RSA && ph1->initiator ) )
		{
			if( ph1->xstate & XSTATE_RECV_SI )
			{
				if( phase1_chk_sign( ph1 ) == LIBIKE_OK )
				{
					ph1->clean();
					ph1->lstate |= LSTATE_MATURE;
				}
				else
				{
					ph1->lstate |= LSTATE_DELETE;

					if( ph1->tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
						ph1->tunnel->close = TERM_PEER_AUTH;

					//
					// potentialy notify the peer
					//

					if( ph1->tunnel->peer->notify )
						inform_new_notify( ph1, NULL, ISAKMP_N_AUTHENTICATION_FAILED );
				}
			}
		}
	}

	//
	// if this tunnel has just now
	// completed initialization, we
	// may need to do a few things
	//

	if( ph1->lstate & LSTATE_MATURE )
	{
		//
		// potentialy send our inital
		// contact notification and
		// send our modecfg request
		//

		if( !( ph1->tunnel->state & TSTATE_INITIALIZED ) )
		{
			inform_new_notify( ph1, NULL, ISAKMP_N_INITIAL_CONTACT );

			//
			// flag ph1->tunnel as initialized
			//

			ph1->tunnel->state |= TSTATE_INITIALIZED;
		}

		//
		// if we are to generate a policy
		// list before config, do this now
		//

		if( !ph1->initiator )
			if( ph1->tunnel->peer->plcy_mode == POLICY_MODE_COMPAT )
				policy_list_create( ph1->tunnel, ph1->initiator );

		//
		// we may need to initiate a config
		// exchange right now if we need to
		// initiate xauth to verify our peer
		// when acting as a responder or if
		// we need to acquire configuration
		// info from our peer when acting as
		// the initiator
		//

		if( ( !ph1->initiator &&  ph1->xauth_l ) ||
			(  ph1->initiator && !ph1->xauth_l ) )
		{
			IDB_CFG * cfg = new IDB_CFG( ph1->tunnel, true, 0 );
			cfg->add( true );
			process_config_send( ph1, cfg );
			cfg->dec( true );
		}

		//
		// obtain our negotiated proposal
		//

		IKE_PROPOSAL * proposal;
		ph1->plist_l.get( &proposal, 0 );

		//
		// add pahse1 dead event
		//

		ph1->inc( true );
		ph1->event_hard.delay = proposal->life_sec * 1000;

		ith_timer.add( &ph1->event_hard );

		//
		// add pahse1 natt event
		//

		if( ph1->tunnel->natt_v != IPSEC_NATT_NONE )
		{
			ph1->tunnel->stats.natt = true;

			ph1->inc( true );
			ph1->event_natt.delay = ph1->tunnel->peer->natt_rate * 1000;

			ith_timer.add( &ph1->event_natt );
		}

		//
		// add pahse1 dpd event
		//

		if( ( ph1->tunnel->peer->dpd_mode == IPSEC_DPD_FORCE ) ||
			( ph1->dpd_l && ph1->dpd_r ) )
		{
			ph1->tunnel->stats.dpd = true;

			ph1->inc( true );
			ph1->event_dpd.delay = ph1->tunnel->peer->dpd_rate * 1000;

			ith_timer.add( &ph1->event_dpd );
		}

		if( ph1->frag_l && ph1->frag_r )
			ph1->tunnel->stats.frag = true;

		//
		// locate any pending phase2
		// handles for this tunnel and
		// begin negotiataions
		//

		IDB_PH2 * ph2;

		while( get_phase2(
				true,
				&ph2,
				ph1->tunnel,
				LSTATE_PENDING,
				0,
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

			ph2->lstate &= ~LSTATE_PENDING;

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
	// validate the dh group size
	//

	if( ph1->xr.size() != ph1->dh_size )
	{
		log.txt( LOG_ERROR,
			"!! : dh group size mismatch ( %d != %d )\n",
			ph1->xr.size(),
			ph1->dh_size );

		return LIBIKE_FAILED;
	}

	//
	// compute shared secret
	//

	BIGNUM * gx = BN_new();
	BN_bin2bn( ph1->xr.buff(), ph1->dh_size, gx );

	BDATA shared;
	shared.set( 0, ph1->dh_size );
	DH_compute_key( shared.buff(), gx, ph1->dh );
	BN_free( gx );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
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
			HMAC_Init(
				&ctx_prf,
				ph1->tunnel->peer->psk.buff(),
				( int ) ph1->tunnel->peer->psk.size(),
				ph1->evp_hash );

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
			HMAC_cleanup( &ctx_prf );

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
				nonce.set( ph1->nonce_l );
				nonce.add( ph1->nonce_r );
			}
			else
			{
				nonce.set( ph1->nonce_r );
				nonce.add( ph1->nonce_l );
			}

			HMAC_CTX ctx_prf;
			HMAC_Init( &ctx_prf, nonce.buff(), ( int ) nonce.size(), ph1->evp_hash );
			HMAC_Update( &ctx_prf, shared.buff(), shared.size() );
			HMAC_Final( &ctx_prf, skeyid_data, NULL );
			HMAC_cleanup( &ctx_prf );

			break;
		}	
	}

	ph1->skeyid.set( skeyid_data, skeyid_size );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
		skeyid_data,
		skeyid_size,
		"== : SETKEYID" );

	//
	// compute SKEYID_d
	//

	HMAC_CTX ctx_prf;
	HMAC_Init( &ctx_prf, ph1->skeyid.buff(), ( int ) ph1->skeyid.size(), ph1->evp_hash );
	HMAC_Update( &ctx_prf, shared.buff(), shared.size() );
	HMAC_Update( &ctx_prf, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ( unsigned char * ) "\0", 1 );
	HMAC_Final( &ctx_prf, skeyid_data, NULL );
	HMAC_cleanup( &ctx_prf );

	ph1->skeyid_d.set( skeyid_data, skeyid_size );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
		skeyid_data,
		skeyid_size,
		"== : SETKEYID_d" );

	//
	// compute SKEYID_a
	//

	HMAC_Init( &ctx_prf, ph1->skeyid.buff(), ( int ) ph1->skeyid.size(), ph1->evp_hash );
	HMAC_Update( &ctx_prf, skeyid_data, skeyid_size );
	HMAC_Update( &ctx_prf, shared.buff(), shared.size() );
	HMAC_Update( &ctx_prf, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ( unsigned char * ) "\1", 1 );
	HMAC_Final( &ctx_prf, skeyid_data, NULL );
	HMAC_cleanup( &ctx_prf );

	ph1->skeyid_a.set( skeyid_data, skeyid_size );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
		skeyid_data,
		skeyid_size,
		"== : SETKEYID_a" );

	//
	// compute SKEYID_e
	//

	HMAC_Init( &ctx_prf, ph1->skeyid.buff(), ( int ) ph1->skeyid.size(), ph1->evp_hash );
	HMAC_Update( &ctx_prf, skeyid_data, skeyid_size );
	HMAC_Update( &ctx_prf, shared.buff(), shared.size() );
	HMAC_Update( &ctx_prf, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	HMAC_Update( &ctx_prf, ( unsigned char * ) "\2", 1 );
	HMAC_Final( &ctx_prf, skeyid_data, NULL );
	HMAC_cleanup( &ctx_prf );

	ph1->skeyid_e.set( skeyid_data, skeyid_size );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
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
		// resize our key to be a multiple
		// of SKEYID_e ( HMAC block size )

		if( key_size % skeyid_size )
			key_size += skeyid_size - ( key_size % skeyid_size );

		// create extended key data

		HMAC_Init( &ctx_prf, skeyid_data, skeyid_size, ph1->evp_hash );
		HMAC_Update( &ctx_prf, ( unsigned char * ) "\0", 1 );
		HMAC_Final( &ctx_prf, key_data, NULL );

		for( long size = skeyid_size; size < key_size; size += skeyid_size )
		{
			unsigned int temp;

			HMAC_Init( &ctx_prf, skeyid_data, skeyid_size, ph1->evp_hash );
			HMAC_Update( &ctx_prf, key_data + size - skeyid_size, skeyid_size );
			HMAC_Final( &ctx_prf, key_data + size, &temp );
		}

		HMAC_cleanup( &ctx_prf );
	}
	else
	{
		// copy the key data

		memcpy( key_data, skeyid_data, key_size );
	}

	if( proposal->ciph_kl )
		key_size = ( proposal->ciph_kl + 7 ) / 8;

	ph1->key.set( key_data, key_size );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
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
		LOG_DEBUG,
		LOG_DECODE,
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
	// compute the initiators signed hash
	//

	hash.set( 0, sa->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_Init( &ctx_prf, sa->skeyid.buff(), ( int ) sa->skeyid.size(), sa->evp_hash );

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
	HMAC_cleanup( &ctx_prf );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
		hash.buff(),
		hash.size(),
		"== : phase1 hash_i ( computed )" );

	return LIBIKE_OK;
}

long _IKED::phase1_gen_hash_r( IDB_PH1 * sa, BDATA & hash )
{
	//
	// compute the responders signed hash
	//

	hash.set( 0, sa->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_Init( &ctx_prf, sa->skeyid.buff(), ( int ) sa->skeyid.size(), sa->evp_hash );

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
	HMAC_cleanup( &ctx_prf );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
		hash.buff(),
		hash.size(),
		"== : phase1 hash_r ( computed )" );

	return LIBIKE_OK;
}

long _IKED::phase1_add_vend( IDB_PH1 * ph1, PACKET_IKE & packet )
{
	//
	// optionally add xauth vendor id payload
	//

	if( ph1->xauth_l )
		payload_add_vend( packet, vend_xauth, ISAKMP_PAYLOAD_VEND );

	//
	// optionally add natt vendor id payload
	//

	if( ph1->natt_l )
	{
		payload_add_vend( packet, vend_natt_v02, ISAKMP_PAYLOAD_VEND );
		payload_add_vend( packet, vend_natt_rfc, ISAKMP_PAYLOAD_VEND );
	}

	//
	// optionally add fragmentation vendor id payload
	//

	if( ph1->frag_l )
		payload_add_vend( packet, vend_frag, ISAKMP_PAYLOAD_VEND );

	//
	// optionally add dpd vendor id payload
	//

	if( ph1->dpd_l )
		payload_add_vend( packet, vend_dpd1, ISAKMP_PAYLOAD_VEND );

	//
	// add unity vendor id payload
	//

	payload_add_vend( packet, vend_unity, ISAKMP_PAYLOAD_NONE );

	return LIBIKE_OK;
}

long _IKED::phase1_chk_vend( IDB_PH1 * ph1, BDATA & vend )
{
	//
	// check for xauth vendor id
	//

	if( vend.size() == vend_xauth.size() )
		if( !memcmp( vend.buff(), vend_xauth.buff(), vend_xauth.size() ) )
		{
			ph1->xauth_r = true;
			log.txt( LOG_INFO, "ii : peer supports XAUTH\n" );
			return LIBIKE_OK;
		}

	//
	// check for fragmentation vendor id
	//

	if( vend.size() == vend_frag.size() )
		if( !memcmp( vend.buff(), vend_frag.buff(), vend_frag.size() ) )
		{
			ph1->frag_r = true;
			log.txt( LOG_INFO, "ii : peer supports FRAGMENTATION\n" );
			return LIBIKE_OK;
		}

	//
	// check for natt v02 vendor id
	//

	if( vend.size() == vend_natt_v02.size() )
		if( !memcmp( vend.buff(), vend_natt_v02.buff(), vend_natt_v02.size() ) )
		{
			ph1->natt_r = true;
			ph1->natt_v = IPSEC_NATT_V02;
			log.txt( LOG_INFO, "ii : peer supports NAT-T V02\n" );
			return LIBIKE_OK;
		}

	//
	// check for natt rfc vendor id
	//

	if( vend.size() == vend_natt_rfc.size() )
		if( !memcmp( vend.buff(), vend_natt_rfc.buff(), vend_natt_rfc.size() ) )
		{
			ph1->natt_r = true;
			ph1->natt_v = IPSEC_NATT_RFC;
			log.txt( LOG_INFO, "ii : peer supports NAT-T RFC\n" );
			return LIBIKE_OK;
		}

	//
	// check for unity vendor id
	//

	if( vend.size() == vend_unity.size() )
		if( !memcmp( vend.buff(), vend_unity.buff(), vend_unity.size() ) )
		{
			log.txt( LOG_INFO, "ii : peer supports UNITY\n" );
			return LIBIKE_OK;
		}

	//
	// check for dead peer detection vendor id
	//

	if( vend.size() == vend_dpd1.size() )
		if( !memcmp( vend.buff(), vend_dpd1.buff(), vend_dpd1.size() ) )
		{
			ph1->dpd_r = true;
			log.txt( LOG_INFO, "ii : peer supports DPDv1\n" );
			return LIBIKE_OK;
		}

	//
	// check for kame vendor id
	//

	if( vend.size() == vend_kame.size() )
		if( !memcmp( vend.buff(), vend_kame.buff(), vend_kame.size() ) )
		{
			log.txt( LOG_INFO, "ii : peer is IPSEC-TOOLS\n" );
			return LIBIKE_OK;
		}

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
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

	BDATA hash;

	if( ph1->initiator )
	{
		phase1_gen_hash_r( ph1, hash );

		log.bin(
			LOG_DEBUG,
			LOG_DECODE,
			ph1->hash_r.buff(),
			hash.size(),
			"== : phase1 hash_r ( received )" );
	}
	else
	{
		phase1_gen_hash_i( ph1, hash );

		log.bin(
			LOG_DEBUG,
			LOG_DECODE,
			ph1->hash_r.buff(),
			hash.size(),
			"== : phase1 hash_i ( received )" );
	}

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	long result = memcmp( hash.buff(), ph1->hash_r.buff(), ph1->hash_size );
	if( result )
	{
		log.txt( LOG_INFO,
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

	log.txt( LOG_INFO,
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
	// verify the peer certificate
	// using the ca cert specified
	// in the peer configuration
	//

	if( !cert_verify( ph1->cert_r, ph1->tunnel->peer->cert_r ) )
	{
		log.txt( LOG_ERROR, "!! : unable to verify remote peer certificate\n" );
		return LIBIKE_FAILED;
	}

	//
	// read the public key from the
	// peer provided certificate
	//
	//

	EVP_PKEY * evp_pkey = NULL;

	if( !pubkey_rsa_read( ph1->cert_r, &evp_pkey ) )
	{
		log.txt( LOG_ERROR, "!! : unable to extract public key from remote peer certificate\n" );
		return LIBIKE_FAILED;
	}

	//
	// use the public key to decrypt
	// the signiature data provided
	// by the remote peer
	//

	ph1->hash_r.set( ph1->sign_r );

	if( !pubkey_rsa_decrypt( evp_pkey, ph1->hash_r ) )
	{
		log.txt( LOG_ERROR, "!! : unable to compute remote peer signed hash\n" );
		return LIBIKE_FAILED;
	}

	//
	// check hash value
	//

	return phase1_chk_hash( ph1 );
}

long _IKED::phase1_gen_natd( IDB_PH1 * ph1 )
{
	//
	// compute the nat discovery
	// hash for local address
	//

	if( !ph1->natd_ls.set( 0, ph1->hash_size ) )
		return LIBIKE_MEMORY;

	EVP_MD_CTX ctx_hash;
	EVP_DigestInit( &ctx_hash, ph1->evp_hash );
	EVP_DigestUpdate( &ctx_hash, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	EVP_DigestUpdate( &ctx_hash, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	EVP_DigestUpdate( &ctx_hash, &ph1->tunnel->saddr_l.saddr4.sin_addr.s_addr, 4 );
	EVP_DigestUpdate( &ctx_hash, &ph1->tunnel->saddr_l.saddr4.sin_port, 2 );
	EVP_DigestFinal( &ctx_hash, ph1->natd_ls.buff(), NULL );
	EVP_MD_CTX_cleanup( &ctx_hash );

	//
	// compute the nat discovery
	// hash for remote address
	//

	if( !ph1->natd_ld.set( 0, ph1->hash_size ) )
		return LIBIKE_MEMORY;

	EVP_DigestInit( &ctx_hash, ph1->evp_hash );
	EVP_DigestUpdate( &ctx_hash, ph1->cookies.i, ISAKMP_COOKIE_SIZE );
	EVP_DigestUpdate( &ctx_hash, ph1->cookies.r, ISAKMP_COOKIE_SIZE );
	EVP_DigestUpdate( &ctx_hash, &ph1->tunnel->saddr_r.saddr4.sin_addr.s_addr, 4 );
	EVP_DigestUpdate( &ctx_hash, &ph1->tunnel->saddr_r.saddr4.sin_port, 2 );
	EVP_DigestFinal( &ctx_hash, ph1->natd_ld.buff(), NULL );
	EVP_MD_CTX_cleanup( &ctx_hash );

	ph1->lstate |= LSTATE_GENNATD;

	return LIBIKE_OK;
}

bool _IKED::phase1_chk_natd( IDB_PH1 * ph1 )
{
	bool enable = false;

	//
	// generate nat discovery if neccessary
	//

	if( !( ph1->lstate & LSTATE_GENNATD ) )
		phase1_gen_natd( ph1 );

	//
	// verify that both support natt
	//

	if( ph1->tunnel->peer->natt_mode == IPSEC_NATT_FORCE )
	{
		log.txt( LOG_INFO, "ii : forcing nat traversal to enabled\n" );

		enable = true;
	}
	else
	{
		if( !ph1->natt_l )
		{
			log.txt( LOG_INFO, "ii : local nat traversal is disabled\n" );

			return false;
		}

		if( !ph1->natt_r )
		{
			log.txt( LOG_INFO, "ii : remote nat traversal is disabled\n" );

			return false;
		}
	}

	//
	// compare the remote destination
	// hash to the local source hash
	//

	if( ph1->natd_rd.size() == ph1->natd_ls.size() )
	{
		if( memcmp(
				ph1->natd_rd.buff(),
				ph1->natd_ls.buff(),
				ph1->natd_ls.size() ) )
		{
			log.txt( LOG_INFO,
				"ii : nat discovery - local address is translated\n" );

			enable = true;
		}
	}

	//
	// compare the remote source hash
	// to the local destination hash
	//

	if( ph1->natd_rs.size() == ph1->natd_ld.size() )
	{
		if( memcmp(
				ph1->natd_rs.buff(),
				ph1->natd_ld.buff(),
				ph1->natd_ld.size() ) )
		{
			log.txt( LOG_INFO,
				"ii : nat discovery - remote address is translated\n" );

			enable = true;
		}
	}

	if( enable && ph1->initiator )
	{
		//
		// switch our port to natt
		//

		ph1->tunnel->saddr_l.saddr4.sin_port = ph1->tunnel->peer->natt_port;

		//
		// switch the peer port to natt
		//

		ph1->tunnel->saddr_r.saddr4.sin_port = ph1->tunnel->peer->natt_port;

		//
		// switch the tunnel to the
		// negotiated natt version
		//

		ph1->tunnel->natt_v = ph1->natt_v;

		log.txt( LOG_INFO,
			"ii : switching to NAT-T UDP port %u\n",
			ntohs( ph1->tunnel->peer->natt_port ) );
	}

	ph1->lstate |= LSTATE_CHKNATD;

	return enable;
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
			log.txt( LOG_ERROR, "!! : responder port values have changed\n" );
			return false;
		}
		else
		{
			if( ph1->tunnel->peer->natt_mode == IPSEC_NATT_NONE )
			{
				if( !ph1->natt_l )
				{
					log.txt( LOG_INFO,
						"ii : local nat traversal is disabled but initiator port floated\n" );

					return false;
				}

				if( !ph1->natt_r )
				{
					log.txt( LOG_INFO,
						"ii : remote nat traversal is disabled but initiator port floated\n" );

					return false;
				}
			}
		}

		if( ph1->lstate & LSTATE_HASNATP )
		{
			log.txt( LOG_ERROR,
				"!! : remote port should only float once per session\n" );

			return false;
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

		ph1->tunnel->natt_v = ph1->natt_v;

		log.txt( LOG_INFO,
			"ii : floating to NAT-T UDP ports %u -> %u\n",
			ntohs( ph1->tunnel->saddr_r.saddr4.sin_port ),
			ntohs( ph1->tunnel->saddr_l.saddr4.sin_port ) );

		ph1->lstate |= LSTATE_HASNATP;
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

	if( !cmp_ph1id( idt, ph1->ph1id_r, ph1->natt_l ) )
		return LIBIKE_FAILED;

	return LIBIKE_OK;
}
