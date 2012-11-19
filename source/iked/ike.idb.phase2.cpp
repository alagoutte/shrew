
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
// ike phase2 exchange events
//==============================================================================

bool _ITH_EVENT_PH2SOFT::func()
{
	iked.log.txt( LLOG_INFO,
			"ii : phase2 sa will expire in %i seconds\n", diff );

	if( ph2->nailed )
		iked.pfkey_init_phase2(
			true,
			IPSEC_POLICY_IPSEC,
			ph2->plcyid_out,
			0 );

	ph2->status( XCH_STATUS_EXPIRING, XCH_NORMAL, 0 );
	ph2->dec( true );

	return false;
}

bool _ITH_EVENT_PH2HARD::func()
{
	iked.log.txt( LLOG_INFO,
			"ii : phase2 sa is dead\n" );

	ph2->status( XCH_STATUS_DEAD, XCH_FAILED_EXPIRED, 0 );
	ph2->dec( true );

	return false;
}

//==============================================================================
// ike phase2 exchange handle list
//==============================================================================

IDB_PH2 * _IDB_LIST_PH2::get( int index )
{
	return static_cast<IDB_PH2*>( get_entry( index ) );
}

bool _IDB_LIST_PH2::find( bool lock, IDB_PH2 ** ph2, IDB_TUNNEL * tunnel, XCH_STATUS min, XCH_STATUS max, u_int32_t * seqid, uint32_t * msgid, IKE_SPI * spi_l, IKE_SPI * spi_r )
{
	if( ph2 != NULL )
		*ph2 = NULL;

	if( lock )
		iked.lock_idb.lock();

	//
	// step through our list of sa's
	// and locate a match
	//

	long ph2_count = count();
	long ph2_index = 0;

	for( ; ph2_index < ph2_count; ph2_index++ )
	{
		//
		// get the next sa in our list
		//

		IDB_PH2 * tmp_ph2 = get( ph2_index );

		//
		// match sa minimum status level
		//

		if( min != XCH_STATUS_ANY )
			if( tmp_ph2->status() < min )
				continue;

		//
		// match sa maximum status level
		//

		if( max != XCH_STATUS_ANY )
			if( tmp_ph2->status() > max )
				continue;

		//
		// match the tunnel id
		//

		if( tunnel != NULL )
			if( tmp_ph2->tunnel != tunnel )
				continue;

		//
		// match the seqid
		//

		if( seqid != NULL )
			if( ( tmp_ph2->seqid_in != *seqid ) &&
				( tmp_ph2->seqid_out != *seqid ) )
				continue;

		//
		// match the msgid
		//

		if( msgid != NULL )
			if( tmp_ph2->msgid != *msgid )
				continue;

		//
		// match a local spi value
		//

		if( spi_l != NULL )
		{
			IKE_PROPOSAL * proposal;
			long pindex = 0;
			bool found;

			while( ( found = tmp_ph2->plist_l.get( &proposal, pindex++ ) ) )
				if( proposal->spi.size == spi_l->size )
					if( !memcmp( &proposal->spi, spi_l, spi_l->size ) )
						break;

			if( !found )
				continue;
		}

		//
		// match a remote spi value
		//

		if( spi_r != NULL )
		{
			IKE_PROPOSAL * proposal;
			long pindex = 0;
			bool found;

			while( ( found = tmp_ph2->plist_r.get( &proposal, pindex++ ) ) )
				if( proposal->spi.size == spi_r->size )
					if( !memcmp( &proposal->spi, spi_r, spi_r->size ) )
						break;

			if( !found )
				continue;
		}

		iked.log.txt( LLOG_DEBUG, "DB : phase2 found\n" );

		//
		// increase our refrence count
		//

		if( ph2 != NULL )
		{
			tmp_ph2->inc( false );
			*ph2 = tmp_ph2;
		}

		if( lock )
			iked.lock_idb.unlock();

		return true;
	}

	iked.log.txt( LLOG_DEBUG, "DB : phase2 not found\n" );

	if( lock )
		iked.lock_idb.unlock();

	return false;
}

void _IDB_LIST_PH2::flush()
{
	iked.lock_idb.lock();

	long ph2_count = count();
	long ph2_index = 0;

	for( ; ph2_index < ph2_count; ph2_index++ )
	{
		IDB_PH2 * ph2 = get( ph2_index );

		ph2->inc( false );

		ph2->status( XCH_STATUS_DEAD, XCH_FAILED_FLUSHED, 0 );

		if( ph2->dec( false ) )
		{
			ph2_index--;
			ph2_count--;
		}
	}

	iked.lock_idb.unlock();
}

//==============================================================================
// ike phase2 exchange handle list entry
//==============================================================================

_IDB_PH2::_IDB_PH2( IDB_TUNNEL * set_tunnel, bool set_initiator, uint32_t set_msgid, uint32_t set_seqid_in )
{
	memset( &cookies, 0, sizeof( cookies ) );
	seqid_in = 0;
	seqid_out = 0;
	plcyid_in = 0;
	plcyid_out = 0;

	nailed = false;
	spicount = 0;
	dhgr_id = 0;

	//
	// initialize the tunnel id
	//

	tunnel = set_tunnel;
	tunnel->inc( true );

	//
	// initialize sa
	//

	initiator = set_initiator;
	exchange = ISAKMP_EXCH_QUICK;

	//
	// initialize msgid
	//

	if( set_msgid )
		msgid = set_msgid;
	else
		new_msgid();

	//
	// initialize seqids
	//

	if( set_seqid_in )
		seqid_in = set_seqid_in;
	else
		iked.rand_bytes( &seqid_in, sizeof( seqid_in ) );

	iked.rand_bytes( &seqid_out, sizeof( seqid_out ) );

	//
	// initialize nonce data
	//

	nonce_l.size( ISAKMP_NONCE_SIZE );
	iked.rand_bytes( nonce_l.buff(), ISAKMP_NONCE_SIZE );

	//
	// initialize event info
	//

	event_soft.ph2 = this;
	event_hard.ph2 = this;

	//
	// phase 2 created
	//

	iked.log.txt( LLOG_DEBUG,
		"DB : new phase2 ( IPSEC %s )\n",
		iked.find_name( NAME_INITIATOR, initiator ) );
}

_IDB_PH2::~_IDB_PH2()
{
	clean();

	//
	// dereference our tunnel
	//

	tunnel->dec( false );
}

//------------------------------------------------------------------------------
// abstract functions from parent class
//

const char * _IDB_PH2::name()
{
	static const char * xname = "phase2";
	return xname;
}

IKED_RC_LIST * _IDB_PH2::list()
{
	return &iked.idb_list_ph2;
}

void _IDB_PH2::beg()
{
}

void _IDB_PH2::end()
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
			"DB : phase2 soft event canceled ( ref count = %i )\n",
			idb_refcount );
	}

	if( iked.ith_timer.del( &event_hard ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : phase2 hard event canceled ( ref count = %i )\n",
			idb_refcount );
	}

	//
	// send a delete message if required
	//

	if( ( lstate & LSTATE_HASKEYS ) &&
		( xch_errorcode != XCH_FAILED_EXPIRED ) &&
		( xch_errorcode != XCH_FAILED_PEER_DELETE ) )
	{
		IDB_PH1 * ph1;
		if( iked.idb_list_ph1.find(
				false,
				&ph1,
				tunnel,
				XCH_STATUS_MATURE,
				XCH_STATUS_EXPIRED,
				NULL ) )
		{
			iked.inform_new_delete( ph1, this );

			ph1->dec( false );
		}
	}

	//
	// inform pfkey interface
	//

	if( ( lstate & LSTATE_HASKEYS ) &&
		( xch_errorcode != XCH_FAILED_FLUSHED ) &&
		( xch_errorcode != XCH_FAILED_EXPIRED ) )
		iked.pfkey_send_delete( this );

	//
	// update tunnel stats
	//

	if( lstate & LSTATE_HASKEYS )
		tunnel->stats.sa_dead++;
	else
		tunnel->stats.sa_fail++;

	//
	// log deletion
	//

	if( xch_errorcode != XCH_FAILED_EXPIRED )
		iked.log.txt( LLOG_INFO, "ii : phase2 removal before expire time\n" );
	else
		iked.log.txt( LLOG_INFO, "ii : phase2 removal after expire time\n" );
}

//------------------------------------------------------------------------------
// additional functions
//

bool _IDB_PH2::setup_dhgrp()
{
	//
	// if we are performing pfs, initialize dh group
	//

	if( dhgr_id )
	{
		if( !dh_init( dhgr_id, &dh, &dh_size ) )
		{
			iked.log.txt( LLOG_ERROR, "ii : failed to setup PFS DH group\n" );
			return false;
		}

		xl.size( dh_size );
		long result = BN_bn2bin( dh->pub_key, xl.buff() );

		//
		// fixup public buffer alignment
		//

		if( dh_size > result )
		{
			iked.log.txt( LLOG_DEBUG, "ww : short PFS DH public value\n" );
			xl.size( result );
			xl.ins( 0, dh_size - result );
		}
	}

	return true;
}

void _IDB_PH2::clean()
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

	hda.del( true );
}
