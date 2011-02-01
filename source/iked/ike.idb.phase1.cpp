
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

//==============================================================================
// ike phase1 exchange events
//==============================================================================

bool _ITH_EVENT_PH1SOFT::func()
{
	iked.log.txt( LLOG_INFO,
		"ii : phase1 sa is expiring\n"
		"ii : %04x%04x:%04x%04x\n",
		htonl( *( long * ) &ph1->cookies.i[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.i[ 4 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 4 ] ) );

	//
	// if the tunnel peer definition states
	// that we are to act as a client, replace
	// this phase1 sa and add it to our list
	//

	if( ph1->tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
	{
		IDB_PH1 * addph1 = new IDB_PH1( ph1->tunnel, true, NULL );
		addph1->add( false );
		iked.process_phase1_send( addph1 );
		addph1->dec( false );
	}

	ph1->status( XCH_STATUS_EXPIRING, XCH_NORMAL, 0 );
	ph1->dec( true );

	//
	// FIXME : dpd and natt events should stop for
	//         this sa after the new sa negotiates
	//

	return false;
}

bool _ITH_EVENT_PH1HARD::func()
{
	iked.log.txt( LLOG_INFO,
		"ii : phase1 sa is expired\n"
		"ii : %04x%04x:%04x%04x\n",
		htonl( *( long * ) &ph1->cookies.i[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.i[ 4 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 4 ] ) );

	ph1->status( XCH_STATUS_EXPIRED, XCH_FAILED_EXPIRED, 0 );
	ph1->dec( true );

	return false;
}

bool _ITH_EVENT_PH1DEAD::func()
{
	iked.log.txt( LLOG_INFO,
		"ii : phase1 sa is dead\n"
		"ii : %04x%04x:%04x%04x\n",
		htonl( *( long * ) &ph1->cookies.i[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.i[ 4 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 0 ] ),
		htonl( *( long * ) &ph1->cookies.r[ 4 ] ) );

	ph1->status( XCH_STATUS_DEAD, XCH_FAILED_EXPIRED, 0 );
	ph1->dec( true );

	return false;
}

//==============================================================================
// ike phase1 exchange handle list
//==============================================================================

IDB_PH1 * _IDB_LIST_PH1::get( int index )
{
	return static_cast<IDB_PH1*>( get_entry( index ) );
}

bool _IDB_LIST_PH1::find( bool lock, IDB_PH1 ** ph1, IDB_TUNNEL * tunnel, XCH_STATUS min, XCH_STATUS max, IKE_COOKIES * cookies )
{
	if( ph1 != NULL )
		*ph1 = NULL;

	if( lock )
		iked.lock_idb.lock();

	//
	// step through our list of sa's
	// and locate a match
	//

	long ph1_count = count();
	long ph1_index = 0;

	for( ; ph1_index < ph1_count; ph1_index++ )
	{
		//
		// get the next sa in our list
		//

		IDB_PH1 * tmp_ph1 = get( ph1_index );

		//
		// match sa minimum status level
		//

		if( min != XCH_STATUS_ANY )
			if( tmp_ph1->status() < min )
				continue;

		//
		// match sa maximum status level
		//

		if( max != XCH_STATUS_ANY )
			if( tmp_ph1->status() > max )
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

		iked.log.txt( LLOG_DEBUG, "DB : phase1 found\n" );

		//
		// increase our refrence count
		//

		if( ph1 != NULL )
		{
			tmp_ph1->inc( false );
			*ph1 = tmp_ph1;
		}

		if( lock )
			iked.lock_idb.unlock();

		return true;
	}

	iked.log.txt( LLOG_DEBUG, "DB : phase1 not found\n" );

	if( lock )
		iked.lock_idb.unlock();

	return false;
}

//==============================================================================
// ike phase1 exchange handle list entry
//==============================================================================

_IDB_PH1::_IDB_PH1( IDB_TUNNEL * set_tunnel, bool set_initiator, IKE_COOKIES * set_cookies )
{
	evp_cipher = NULL;
	evp_hash = NULL;
	hash_size = 0;

	memset( &cookies, 0, sizeof( cookies ) );

	vendopts_l.flags = 0;
	vendopts_r.flags = 0;

	natt_version = IPSEC_NATT_NONE;
	natt_pldtype = ISAKMP_PAYLOAD_NONE;

	hash_size = 0;

	//
	// initialize associated tunnel
	//

	tunnel = set_tunnel;
	tunnel->inc( true );

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

	nonce_l.size( ISAKMP_NONCE_SIZE );
	iked.rand_bytes( nonce_l.buff(), ISAKMP_NONCE_SIZE );

	//
	// always advertise as shrew soft
	//

	vendopts_l.flag.ssoft = true;

	//
	// determine if this is a client tunnel
	//

	if( tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
	{
		vendopts_l.flag.netsc = true;
		vendopts_l.flag.zwall = true;
		vendopts_l.flag.swind = true;
		vendopts_l.flag.unity = true;

		if( tunnel->xconf.opts & IPSEC_OPTS_VEND_CHKPT )
			vendopts_l.flag.chkpt = true;
	}

	//
	// determine ike fragmentation negotiation
	//

	if( tunnel->peer->frag_ike_mode >= IPSEC_FRAG_ENABLE )
		vendopts_l.flag.frag = true;

	if( tunnel->peer->frag_ike_mode == IPSEC_FRAG_FORCE )
		vendopts_r.flag.frag = true;

	//
	// determine natt negotiation
	//

	if( ( tunnel->peer->natt_mode >= IPSEC_NATT_ENABLE ) &&
		( tunnel->peer->natt_mode != IPSEC_NATT_FORCE_CISCO ) )
		vendopts_l.flag.natt = true;

	//
	// determine dpd negotiation
	//

	if( tunnel->peer->dpd_mode >= IPSEC_DPD_ENABLE )
		vendopts_l.flag.dpdv1 = true;

	if( tunnel->peer->dpd_mode == IPSEC_DPD_FORCE )
		vendopts_r.flag.dpdv1 = true;

	//
	// locate the first isakmp proposal
	//

	IKE_PROPOSAL * proposal;
	tunnel->peer->proposals.get( &proposal, 0, ISAKMP_PROTO_ISAKMP );

	//
	// if we are the initiator, obtain
	// the authentication type
	//

	if( initiator )
	{
		auth_id = proposal->auth_id;

		//
		// determine xauth negotiation
		//

		if( ( proposal->auth_id == XAUTH_AUTH_INIT_PSK ) ||
			( proposal->auth_id == XAUTH_AUTH_INIT_RSA ) ||
			( proposal->auth_id == HYBRID_AUTH_INIT_RSA ) )
			vendopts_l.flag.xauth = true;
	}

	//
	// aggressive mode must include a kex
	// payload in the first packet. make
	// sure we setup the dhgroup in advance
	//

	if( tunnel->peer->exchange == ISAKMP_EXCH_AGGRESSIVE )
		setup_dhgrp( proposal );

	//
	// initialize event info
	//

	event_soft.ph1 = this;
	event_hard.ph1 = this;
	event_dead.ph1 = this;

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

	//
	// derefrence our tunnel
	//

	tunnel->dec( false );
}

//------------------------------------------------------------------------------
// abstract functions from parent class
//

const char * _IDB_PH1::name()
{
	static const char * xname = "phase1";
	return xname;
}

IKED_RC_LIST * _IDB_PH1::list()
{
	return &iked.idb_list_ph1;
}

void _IDB_PH1::beg()
{
}

void _IDB_PH1::end()
{
	//
	// clear the resend queue
	//

	resend_clear( false, true );

	//
	// remove scheduled events
	//

	if( iked.ith_timer.del( &event_soft ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : phase1 soft event canceled ( ref count = %i )\n",
			idb_refcount );
	}

	if( iked.ith_timer.del( &event_hard ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : phase1 hard event canceled ( ref count = %i )\n",
			idb_refcount );
	}

	if( iked.ith_timer.del( &event_dead ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : phase1 dead event canceled ( ref count = %i )\n",
			idb_refcount );
	}

	//
	// send a delete message if required
	//

	if( ( lstate & LSTATE_HASKEYS ) &&
		( xch_errorcode != XCH_FAILED_EXPIRED ) &&
		( xch_errorcode != XCH_FAILED_PEER_DELETE ) )
		iked.inform_new_delete( this, NULL );

	//
	// if this sa has reached maturity,
	// locate any config handles used by
	// this sa and delete them
	//
	// FIXME : There must be a better way
	//

	if( lstate & LSTATE_HASKEYS )
	{
		//
		// FIXME : Use find here
		//

		long cfg_count = iked.idb_list_cfg.count();
		long cfg_index = 0;

		for( ; cfg_index < cfg_count; cfg_index++ )
		{
			//
			// get the next config in our list
			// and attempt to match by pointer
			// 

			IDB_CFG * cfg = iked.idb_list_cfg.get( cfg_index );
			if( cfg->ph1ref == this )
			{
				cfg->inc( false );

				cfg->status( XCH_STATUS_DEAD, XCH_FAILED_PENDING, 0 );

				if( cfg->dec( false ) )
				{
					cfg_index--;
					cfg_count--;
				}
			}
		}
	}

	//
	// if this sa never reached maturity,
	// locate any pending phase2 handles
	// for this tunnel and delete them
	//
	// FIXME : This should be timer driven
	//

	if( !( lstate & LSTATE_HASKEYS ) )
	{
		//
		// FIXME : Use find here
		//

		long ph2_count = iked.idb_list_ph2.count();
		long ph2_index = 0;

		for( ; ph2_index < ph2_count; ph2_index++ )
		{
			//
			// get the next phase2 in our list
			// and attempt to match tunnel ids
			// 

			IDB_PH2 * ph2 = iked.idb_list_ph2.get( ph2_index );
			if( ( ph2->tunnel == tunnel ) && ( ph2->status() == XCH_STATUS_PENDING ) )
			{
				ph2->inc( false );

				ph2->status( XCH_STATUS_DEAD, XCH_FAILED_PENDING, 0 );

				if( ph2->dec( false ) )
				{
					ph2_index--;
					ph2_count--;
				}
			}
		}
	}

	//
	// log deletion
	//

	if( xch_errorcode != XCH_FAILED_EXPIRED )
		iked.log.txt( LLOG_INFO, "ii : phase1 removal before expire time\n" );
	else
		iked.log.txt( LLOG_INFO, "ii : phase1 removal after expire time\n" );

	//
	// if we have negotiated a replacement
	// isakmp sa, change our delete status
	// to expired. some gateways will send
	// a delete message for the old sa and
	// we don't want to treat this as an
	// error condition below.
	//

	if( xch_errorcode == XCH_FAILED_PEER_DELETE )
		if( iked.idb_list_ph1.find(
				false,
				NULL,
				tunnel,
				XCH_STATUS_MATURE,
				XCH_STATUS_MATURE,
				NULL ) )
			xch_errorcode = XCH_FAILED_EXPIRED;

	//
	// if this is a client tunnel and there
	// was an error negotiating phase1, set
	// a close error message and wakeup the
	// client thread
	//

	if( tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
	{
		if( xch_errorcode != XCH_FAILED_EXPIRED )
		{
			tunnel->close = xch_errorcode;

			if( tunnel->ikei != NULL )
				tunnel->ikei->wakeup();
		}
	}
}

//------------------------------------------------------------------------------
// additional functions
//

bool _IDB_PH1::setup_dhgrp( IKE_PROPOSAL * proposal )
{
	//
	// initialize dh group
	//

	if( !dh_init( proposal->dhgr_id, &dh, &dh_size ) )
	{
		iked.log.txt( LLOG_ERROR, "ii : failed to setup DH group\n" );
		return false;
	}

	xl.size( dh_size );
	long result = BN_bn2bin( dh->pub_key, xl.buff() );

	//
	// fixup public buffer alignment
	//

	if( dh_size > result )
	{
		iked.log.txt( LLOG_DEBUG, "ww : short DH public value\n" );
		xl.size( result );
		xl.ins( 0, dh_size - result );
	}

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

		case IKE_HASH_SHA2_256:

			evp_hash = EVP_sha256();

			break;

		case IKE_HASH_SHA2_384:

			evp_hash = EVP_sha384();

			break;

		case IKE_HASH_SHA2_512:

			evp_hash = EVP_sha512();

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

	natd_hash_l.clean();
	natd_hash_r.clean();

	certs_r.clean();
	creqs_r.clean();
	sign_r.del( true );
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

	return frags.add_entry( frag );
}

bool _IDB_PH1::frag_get( PACKET_IKE & packet )
{
	bool frag_done = false;
	int  frag_index = 1;

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

		int list_count = frags.count();
		int list_index = 0;

		for( ; list_index < list_count; list_index++ )
		{
			IKE_FRAG * frag = static_cast<IKE_FRAG*>( frags.get_entry( list_index ) );

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

				//
				// reset the fragement list index
				//

				list_index = -1;

				continue;
			}
		}

		//
		// if we made a complete pass through
		// our fragment list and did not find
		// the next fragment, we dont have a
		// complete packet yet
		//

		if( list_index == list_count )
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

		int list_count = frags.count();
		int list_index = 0;

		for( ; list_index < list_count; list_index++ )
		{
			IKE_FRAG * frag = static_cast<IKE_FRAG*>( frags.get_entry( list_index ) );

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

				//
				// reset the fragement list index
				//

				list_index = -1;

				continue;
			}
		}
	}

	//
	// purge our fragment list
	//

	frags.clean();

	return true;
}
