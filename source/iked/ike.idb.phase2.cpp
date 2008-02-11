
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
// IDB subclass list section
//

LIST list_phase2;

char * _IDB_PH2::name()
{
	static char * xname = "phase2";
	return xname;
}

LIST * _IDB_PH2::list()
{
	return &list_phase2;
}

//
// phase2 event functions
//

bool _ITH_EVENT_PH2SOFT::func()
{
	iked.log.txt( LLOG_INFO,
			"ii : phase2 sa will expire in %i seconds\n", diff );

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

//
// phase2 security association class
//

_IDB_PH2::_IDB_PH2( IDB_TUNNEL * set_tunnel, bool set_initiator, uint32_t set_msgid, uint32_t set_seqid_in )
{
	msgid = 0;
	seqid_in = 0;
	seqid_out = 0;
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
		iked.rand_bytes( &msgid, sizeof( msgid ) );

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
	// send a delete message if required
	//

	if( ( lstate & LSTATE_HASKEYS ) &&
		( xch_errorcode != XCH_FAILED_EXPIRED ) &&
		( xch_errorcode != XCH_FAILED_PEER_DELETE ) )
	{
		IDB_PH1 * ph1;
		if( iked.get_phase1( false, &ph1, tunnel, XCH_STATUS_MATURE, XCH_STATUS_DEAD, NULL ) )
		{
			iked.inform_new_delete( ph1, this );
			ph1->dec( false );
		}
	}

	//
	// log deletion
	//

	if( xch_errorcode != XCH_FAILED_EXPIRED )
		iked.log.txt( LLOG_INFO, "ii : phase2 removal before expire time\n" );
	else
		iked.log.txt( LLOG_INFO, "ii : phase2 removal after expire time\n" );

	//
	// inform pfkey interface
	//

	if( ( xch_errorcode != XCH_FAILED_FLUSHED ) &&
		( lstate & LSTATE_HASSPI ) )
		iked.pfkey_send_delete( this );

	//
	// update tunnel stats
	//

	if( lstate & LSTATE_HASKEYS )
		tunnel->stats.sa_dead++;
	else
		tunnel->stats.sa_fail++;

	//
	// dereference our tunnel
	//

	tunnel->dec( false );
}

bool _IDB_PH2::setup_dhgrp()
{
	//
	// if we are performing pfs, initialize dh group
	//

	if( dhgr_id )
	{
		dh = dh_setup_group( dhgr_id );
		dh_size = BN_num_bytes( dh->p );
		dh_create_e( dh, dh_size );

		xl.size( dh_size );
		BN_bn2bin( dh->pub_key, xl.buff() );
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

	resend_clear();
}

bool _IKED::get_phase2( bool lock, IDB_PH2 ** ph2, IDB_TUNNEL * tunnel, XCH_STATUS min, XCH_STATUS max, u_int32_t * seqid, uint32_t * msgid, IKE_SPI * spi_l, IKE_SPI * spi_r )
{
	if( ph2 != NULL )
		*ph2 = NULL;

	if( lock )
		lock_sdb.lock();

	//
	// step through our list of sa's
	// and locate a match
	//

	long count = list_phase2.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		//
		// get the next sa in our list
		//

		IDB_PH2 * tmp_ph2 = ( IDB_PH2 * ) list_phase2.get_item( index );

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

			while( found = tmp_ph2->plist_l.get( &proposal, pindex++ ) )
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

			while( found = tmp_ph2->plist_r.get( &proposal, pindex++ ) )
				if( proposal->spi.size == spi_r->size )
					if( !memcmp( &proposal->spi, spi_r, spi_r->size ) )
						break;

			if( !found )
				continue;
		}

		log.txt( LLOG_DEBUG, "DB : phase2 found\n" );

		//
		// increase our refrence count
		//

		if( ph2 != NULL )
		{
			tmp_ph2->inc( false );
			*ph2 = tmp_ph2;
		}

		if( lock )
			lock_sdb.unlock();

		return true;
	}

	log.txt( LLOG_DEBUG, "DB : phase2 not found\n" );

	if( lock )
		lock_sdb.unlock();

	return false;
}

void _IDB_PH2::beg()
{
}

void _IDB_PH2::end()
{
	//
	// remove scheduled events
	//

	if( iked.ith_timer.del( &event_resend ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : phase2 resend event canceled ( ref count = %i )\n",
			idb_refcount );
	}

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
}
