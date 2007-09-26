
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
// phase1 event functions
//

bool _ITH_EVENT_PH1DPD::func()
{
	long diff = ph1->dpd_req - ph1->dpd_res;

	if( diff >= 2 )
	{
		iked.log.txt( LLOG_INFO,
				"ii : phase1 sa dpd timeout\n"
				"ii : %04x%04x:%04x%04x\n",
				htonl( *( long * ) &ph1->cookies.i[ 0 ] ),
				htonl( *( long * ) &ph1->cookies.i[ 4 ] ),
				htonl( *( long * ) &ph1->cookies.r[ 0 ] ),
				htonl( *( long * ) &ph1->cookies.r[ 4 ] ) );

		if( ph1->tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
			ph1->tunnel->close = TERM_PEER_DEAD;

		ph1->lstate |= ( LSTATE_EXPIRE | LSTATE_NOTIFY | LSTATE_DELETE );
		ph1->dec( true );

		return false;
	}

	//
	// obtain next sequence number
	// and convert to network byte
	// order
	//

	uint32_t dpdseq = htonl( ph1->dpd_req++ );

	//
	// add sequence number and send
	//

	BDATA bdata;
	bdata.add( &dpdseq, sizeof( dpdseq ) );

	iked.inform_new_notify( ph1, NULL, ISAKMP_N_DPD_R_U_THERE, &bdata );

	return true;
}

bool _ITH_EVENT_PH1DHCP::func()
{
	//
	// check for retry timeout
	//

	if( retry > 8 )
	{
		ph1->tunnel->close = TERM_PEER_DHCP;
		ph1->dec( true );

		return false;
	}

	//
	// check renew time
	//

	time_t current = time( NULL );

	if( current > renew )
		iked.process_dhcp_recv( ph1 );

	if( current > renew )
		iked.process_dhcp_send( ph1 );

	return true;
}

bool _ITH_EVENT_PH1NATT::func()
{
	//
	// encapsulate natt keep alive
	//

	PACKET_UDP packet_udp;

	packet_udp.write(
		ph1->tunnel->saddr_l.saddr4.sin_port,
		ph1->tunnel->saddr_r.saddr4.sin_port );

	packet_udp.add_byte( 0xff );

	packet_udp.done(
		ph1->tunnel->saddr_l.saddr4.sin_addr,
		ph1->tunnel->saddr_r.saddr4.sin_addr );

	PACKET_IP packet_ip;

	packet_ip.write(
		ph1->tunnel->saddr_l.saddr4.sin_addr,
		ph1->tunnel->saddr_r.saddr4.sin_addr,
		iked.ident++,
		PROTO_IP_UDP );

	packet_ip.add( packet_udp );

	packet_ip.done();

	//
	// send ike packet
	//

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	iked.text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	iked.text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	iked.log.txt( LLOG_DEBUG,
		"-> : send NAT-T:KEEP-ALIVE packet %s -> %s\n",
		txtaddr_l, 
		txtaddr_r );

	iked.send_ip(
		packet_ip );

	return true;
}

bool _ITH_EVENT_PH1HARD::func()
{
	iked.log.txt( LLOG_INFO,
		"ii : phase1 sa is dead\n"
		"ii : %04x%04x:%04x%04x\n",
		htonl( *( long * ) &ph1->cookies.i[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.i[ 4 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 4 ] ) );

	if( ph1->tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
		ph1->tunnel->close = TERM_EXPIRE;

	ph1->lstate |= ( LSTATE_EXPIRE | LSTATE_NOTIFY | LSTATE_DELETE );
	ph1->dec( true );

	return false;
}

//
// phase1 security association class
//

_IDB_PH1::_IDB_PH1( IDB_TUNNEL * set_tunnel, bool set_initiator, IKE_COOKIES * set_cookies )
{
	evp_cipher = NULL;
	evp_hash = NULL;

	memset( &cookies, 0, sizeof( cookies ) );

	xauth_l = false;
	xauth_r = false;

	unity_l = true;		// always true for now
	unity_r = false;

	natt_l = false;
	natt_r = false;

	dpd_l = false;
	dpd_r = false;

	dpd_req = 0;
	dpd_res = 0;

	frag_l = false;
	frag_r = false;

	natted_l = false;
	natted_r = false;

	ctype_l = 0;
	ctype_r = 0;

	hash_size = 0;

	//
	// initialize associated tunnel
	//

	tunnel = set_tunnel;

	//
	// initialize initiator value
	//
	
	initiator = set_initiator;

	//
	// initialize exchange type
	//
	
	exchange = tunnel->peer->exchange;

	//
	// initialize proposal list
	//

	iked.phase1_gen_prop( this );

	//
	// initialize local id
	//

	iked.gen_ph1id_l( this, ph1id_l );

	//
	// initialize cookie
	//

	if( initiator )
		iked.rand_bytes( cookies.i, ISAKMP_COOKIE_SIZE );
	else
	{
		if( set_cookies != NULL )
			memcpy( cookies.i, set_cookies->i, ISAKMP_COOKIE_SIZE );

		iked.rand_bytes( cookies.r, ISAKMP_COOKIE_SIZE );
	}

	//
	// initialize nonce data
	//

	nonce_l.set( 0, ISAKMP_NONCE_SIZE );
	iked.rand_bytes( nonce_l.buff(), ISAKMP_NONCE_SIZE );

	//
	// determine ike fragmentation negotiation
	//

	if( tunnel->peer->frag_ike_mode >= IPSEC_FRAG_ENABLE )
		frag_l = true;

	if( tunnel->peer->frag_ike_mode == IPSEC_FRAG_FORCE )
		frag_r = true;

	//
	// determine natt negotiation
	//

	if( tunnel->peer->natt_mode >= IPSEC_NATT_ENABLE )
		natt_l = true;

	//
	// determine dpd negotiation
	//

	if( tunnel->peer->dpd_mode >= IPSEC_DPD_ENABLE )
	{
		dpd_l = true;

		long dpdseq;
		iked.rand_bytes( &dpdseq, sizeof( dpdseq ) );
		dpdseq >>= 2;

		dpd_req = dpdseq;
		dpd_res = dpdseq;
	}

	if( tunnel->peer->dpd_mode == IPSEC_DPD_FORCE )
		dpd_r = true;

	//
	// locate the first isakmp proposal
	//

	IKE_PROPOSAL * proposal;
	tunnel->peer->prop_list.get( &proposal, 0, ISAKMP_PROTO_ISAKMP );

	//
	// if we are the initiator, preset
	// our isakmp proposal to the first
	// entry in our peer proposal list
	//

	if( initiator )
	{
		//
		// determine xauth negotiation
		//

		if( ( proposal->auth_id == XAUTH_AUTH_INIT_PSK ) ||
			( proposal->auth_id == XAUTH_AUTH_INIT_RSA ) ||
			( proposal->auth_id == HYBRID_AUTH_INIT_RSA ) )
			xauth_l = true;
	}

	//
	// aggressive mode must include a
	// key exchange payload in the
	// first packet. make sure we setup
	// the dhgroup in advance
	//

	if( tunnel->peer->exchange == ISAKMP_EXCH_AGGRESSIVE )
		setup_dhgrp( proposal );

	//
	// initialize event info
	//

	event_dpd.ph1 = this;
	event_dhcp.ph1 = this;
	event_dhcp.lease = 0;
	event_dhcp.renew = 0;
	event_dhcp.retry = 0;
	event_dhcp.ph1 = this;
	event_natt.ph1 = this;
	event_hard.ph1 = this;

	//
	// build text strings for logging
	//

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	iked.text_addr( txtaddr_l, &tunnel->saddr_l, true );
	iked.text_addr( txtaddr_r, &tunnel->saddr_r, true );

	//
	// phase 1 created
	//

	iked.log.txt( LLOG_DEBUG,
		"DB : new phase1 ( ISAKMP %s )\n"
		"DB : exchange type is %s\n"
		"DB : %s <-> %s\n"
		"DB : %08x%08x:%08x%08x\n",
		iked.find_name( NAME_INITIATOR, initiator ),
		iked.find_name( NAME_EXCHANGE, exchange ),
		txtaddr_l,
		txtaddr_r,
		htonl( *( long * ) &cookies.i[ 0 ] ),
		htonl( *( long * ) &cookies.i[ 4 ] ),
		htonl( *( long * ) &cookies.r[ 0 ] ),
		htonl( *( long * ) &cookies.r[ 4 ] ) );
}

_IDB_PH1::~_IDB_PH1()
{
	clean();
}

//
//
//

bool _IDB_PH1::setup_dhgrp( IKE_PROPOSAL * proposal )
{
	//
	// initialize dh group
	//

	dh = dh_setup_group( proposal->dhgr_id );
	dh_size = BN_num_bytes( dh->p );
	dh_create_e( dh, dh_size );

	xl.set( 0, dh_size );
	BN_bn2bin( dh->pub_key, xl.buff() );

	return true;
}

bool _IDB_PH1::setup_xform( IKE_PROPOSAL * proposal )
{
	//
	// select cipher and hash crypto objects
	//

	switch( proposal->ciph_id )
	{
		case IKE_CIPHER_DES:

			evp_cipher = EVP_des_cbc();

			break;

		case IKE_CIPHER_BLOWFISH:

			evp_cipher = EVP_bf_cbc();

			break;

		case IKE_CIPHER_3DES:

			evp_cipher = EVP_des_ede3_cbc();

			break;

		case IKE_CIPHER_CAST:

			evp_cipher = EVP_cast5_cbc();

			break;

		case IKE_CIPHER_AES:
		{
			switch( proposal->ciph_kl )
			{
				case 128:

					evp_cipher = EVP_aes_128_cbc();

					break;

				case 192:

					evp_cipher = EVP_aes_192_cbc();

					break;

				case 256:

					evp_cipher = EVP_aes_256_cbc();

					break;

				default:

					return false;
			}

			break;
		}

		default:
			return false;
	}

	switch( proposal->hash_id )
	{
		case IKE_HASH_MD5:

			evp_hash = EVP_md5();

			break;

		case IKE_HASH_SHA1:

			evp_hash = EVP_sha1();

			break;

		default:
			return false;
	}

	hash_size = EVP_MD_size( evp_hash );

	return true;
}

void _IDB_PH1::clean()
{
	if( dh )
	{
		DH_free( dh );
		dh = NULL;
	}

	nonce_l.del( true );
	nonce_r.del( true );

	xl.del( true );
	xr.del( true );

	hash_l.del( true );
	hash_r.del( true );

	hda.del( true );;

	idi.del( true );
	idr.del( true );

	natd_ls.del( true );
	natd_ld.del( true );
	natd_rs.del( true );
	natd_rd.del( true );

	cert_r.del( true );
	sign_r.del( true );

	resend_clear();
}

bool _IDB_PH1::frag_add( unsigned char * data, unsigned long size, long index, bool last )
{
	//
	// create our new ike fragment
	//

	IKE_FRAG * frag = new IKE_FRAG;
	if( frag == NULL )
		return false;

	//
	// set the fragment info
	//

	frag->index = index;
	frag->last = last;
	frag->data.set( data, size );

	//
	// add the fragment to our list
	//

	return frags.add_item( frag );
}

bool _IDB_PH1::frag_get( PACKET_IKE & packet )
{
	bool frag_done = false;
	int	frag_index = 1;

	//
	// check to see if we have a
	// complete ike packet
	//

	while( !frag_done )
	{
		//
		// step through all fragments
		// and look for the next index
		//

		int count = frags.get_count();
		int index = 0;

		for( ; index < count; index++ )
		{
			IKE_FRAG * frag = ( IKE_FRAG * ) frags.get_item( index );

			//
			// does this match our next index
			//

			if( frag->index == frag_index )
			{
				//
				// is this the last fragment
				//

				if( frag->last )
				{
					frag_done = true;
					break;
				}

				//
				// not the last fragment, look
				// for the next one
				//

				frag_index++;
				continue;
			}
		}

		//
		// if we made a complete pass through
		// our fragment list and did not find
		// the next fragment, we dont have a
		// complete packet yet
		//

		if( index == count )
			return false;
	}

	//
	// reassemble the packet from ike
	// fragments stored in our list
	//

	packet.reset();
	frag_done = false;
	frag_index = 1;

	while( !frag_done )
	{
		//
		// step through all fragments
		// and look for the next index
		//

		int count = frags.get_count();
		int index = 0;

		for( ; index < count; index++ )
		{
			IKE_FRAG * frag = ( IKE_FRAG * ) frags.get_item( index );

			//
			// does this match our next index
			//

			if( frag->index == frag_index )
			{
				//
				// add the data to our packet
				//

				packet.add(	frag->data );

				//
				// is this the last fragment
				//

				if( frag->last )
				{
					frag_done = true;
					break;
				}

				//
				// not the last fragment, look
				// for the next one
				//

				frag_index++;
				continue;
			}
		}
	}

	//
	// purge our fragment list
	//

	while( frags.get_count() )
	{
		IKE_FRAG * frag = ( IKE_FRAG * ) frags.get_item( 0 );
		frags.del_item( frag );
		delete frag;
	}

	return true;
}

bool _IKED::get_phase1( bool lock, IDB_PH1 ** ph1, IDB_TUNNEL * tunnel, long lstate, long nolstate, IKE_COOKIES * cookies )
{
	if( ph1 != NULL )
		*ph1 = NULL;

	if( lock )
		lock_sdb.lock();

	//
	// step through our list of sa's
	// and locate a match
	//

	long count = list_phase1.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		//
		// get the next sa in our list
		//

		IDB_PH1 * tmp_ph1 = ( IDB_PH1 * ) list_phase1.get_item( index );

		//
		// match sa mature state
		//

		if( lstate )
			if( !( tmp_ph1->lstate & lstate ) )
				continue;

		//
		// match sa not state flags
		//

		if( nolstate )
			if( tmp_ph1->lstate & nolstate )
				continue;

		//
		// match the tunnel id
		//

		if( tunnel != NULL )
			if( tmp_ph1->tunnel != tunnel )
				continue;

		//
		// match the cookies
		//

		if( cookies != NULL )
		{
			//
			// next match the initiator cookie
			//

			if( memcmp( tmp_ph1->cookies.i, cookies->i, ISAKMP_COOKIE_SIZE ) )
			{
				//
				// the initiator cookie should
				// always match if we are to
				// return a known sa
				//

				continue;
			}

			//
			// next match the responder cookie
			//

			if( memcmp( tmp_ph1->cookies.r, cookies->r, ISAKMP_COOKIE_SIZE ) )
			{
				//
				// responder cookie did not match,
				// if we are the intiator for this
				// sa, the responder cookie is null
				// and we are waiting on an sa
				// payload, it should match
				//

				if( tmp_ph1->initiator )
				{
					//
					// check to see if we solicited
					// a response from this host
					//

					if( !( tmp_ph1->xstate & XSTATE_SENT_SA ) ||
						 ( tmp_ph1->xstate & XSTATE_RECV_SA ) )
						 continue;

					//
					// check the responder cookie
					// for a null value
					//

					for( long x = 0; x < ISAKMP_COOKIE_SIZE; x++ )
						if( tmp_ph1->cookies.r[ x ] )
							continue;

					//
					// store the responders cookie in
					// our existing sa
					//

					memcpy( tmp_ph1->cookies.r, cookies->r, ISAKMP_COOKIE_SIZE );
				}
			}
		}

		//
		// looks like we found a match
		//

		log.txt( LLOG_DEBUG, "DB : phase1 found\n" );

		//
		// increase our refrence count
		//

		if( ph1 != NULL )
		{
			tmp_ph1->inc( false );
			*ph1 = tmp_ph1;
		}

		if( lock )
			lock_sdb.unlock();

		return true;
	}

	log.txt( LLOG_DEBUG, "DB : phase1 not found\n" );

	if( lock )
		lock_sdb.unlock();

	return false;
}

bool _IDB_PH1::add( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	inc( false );
	tunnel->inc( false );

	bool result = iked.list_phase1.add_item( this );

	iked.log.txt( LLOG_DEBUG, "DB : phase1 added\n" );

	if( lock )
		iked.lock_sdb.unlock();

	return result;
}

bool _IDB_PH1::inc( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	refcount++;

	iked.log.txt( LLOG_LOUD,
		"DB : phase1 ref increment ( ref count = %i, phase1 count = %i )\n",
		refcount,
		iked.list_phase1.get_count() );

	if( lock )
		iked.lock_sdb.unlock();

	return true;
}

bool _IDB_PH1::dec( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	//
	// if we are marked for deletion,
	// attempt to remove any events
	// that may be scheduled
	//

	if( lstate & LSTATE_DELETE )
	{
		if( iked.ith_timer.del( &event_resend ) )
		{
			refcount--;
			iked.log.txt( LLOG_DEBUG,
				"DB : phase1 resend event canceled ( ref count = %i )\n",
				refcount );
		}

		if( iked.ith_timer.del( &event_dhcp ) )
		{
			refcount--;
			iked.log.txt( LLOG_DEBUG,
				"DB : phase1 dhcp event canceled ( ref count = %i )\n",
				refcount );
		}

		if( iked.ith_timer.del( &event_dpd ) )
		{
			refcount--;
			iked.log.txt( LLOG_DEBUG,
				"DB : phase1 dpd event canceled ( ref count = %i )\n",
				refcount );
		}

		if( iked.ith_timer.del( &event_natt ) )
		{
			refcount--;
			iked.log.txt( LLOG_DEBUG,
				"DB : phase1 natt event canceled ( ref count = %i )\n",
				refcount );
		}

		if( iked.ith_timer.del( &event_hard ) )
		{
			refcount--;
			iked.log.txt( LLOG_DEBUG,
				"DB : phase1 hard event canceled ( ref count = %i )\n",
				refcount );
		}
	}

	assert( refcount > 0 );

	refcount--;

	//
	// check for deletion
	//

	if( refcount || !( lstate & LSTATE_DELETE ) )
	{
		iked.log.txt( LLOG_LOUD,
			"DB : phase1 ref decrement ( ref count = %i, phase1 count = %i )\n",
			refcount,
			iked.list_phase1.get_count() );

		if( lock )
			iked.lock_sdb.unlock();

		return false;
	}

	//
	// send a delete message if required
	//

	if(  ( lstate & LSTATE_MATURE ) && 
		!( lstate & LSTATE_NOTIFY ) )
		iked.inform_new_delete( this, NULL );

	//
	// terminate client thread if relevant
	//

	if( tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
		if( !tunnel->close )
			tunnel->close = TERM_PEER_DEAD;

	//
	// cleaup after client based tunnels
	//

	if( !initiator )
	{
		if( tunnel->peer->plcy_mode != POLICY_MODE_DISABLE )
			iked.policy_list_remove( tunnel, false );

		if( tunnel->xconf.opts & IPSEC_OPTS_ADDR )
			tunnel->peer->xconf_source->pool4_rel( tunnel->xconf.addr );
	}

	//
	// if this sa never reached maturity,
	// locate any pending phase2 handles
	// for this tunnel and delete them
	//

	if( !( lstate & LSTATE_MATURE ) )
	{
		long count = iked.list_phase2.get_count();
		long index = 0;

		for( ; index < count; index++ )
		{
			//
			// get the next phase2 in our list
			// and attempt to match tunnel ids
			// 

			IDB_PH2 * ph2 = ( IDB_PH2 * ) iked.list_phase2.get_item( index );
			if( ( ph2->tunnel == tunnel ) &&
				( ph2->lstate & LSTATE_PENDING ) )
			{
				ph2->inc( false );
				ph2->lstate |= LSTATE_DELETE;

				if( ph2->dec( false ) )
				{
					index--;
					count--;
				}
			}
		}
	}

	//
	// remove from our list
	//

	iked.list_phase1.del_item( this );

	//
	// log deletion
	//

	if( !( lstate & LSTATE_EXPIRE ) )
		iked.log.txt( LLOG_INFO,
			"DB : phase1 deleted before expire time ( phase1 count = %i )\n",
			iked.list_phase1.get_count() );
	else
		iked.log.txt( LLOG_INFO,
			"DB : phase1 deleted after expire time ( phase1 count = %i )\n",
			iked.list_phase1.get_count() );

	//
	// derefrence our tunnel
	//

	tunnel->dec( false );

	if( lock )
		iked.lock_sdb.unlock();

	//
	// free
	//

	delete this;

	return true;
}
