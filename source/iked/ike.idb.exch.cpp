
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
// generic exchange events
//==============================================================================

bool _ITH_EVENT_RESEND::func()
{
	bool result = xch->resend();
	
	if( !result )
		xch->dec( true );

	return result;
}

//==============================================================================
// generic exchange handle list entry
//==============================================================================

_IDB_XCH::_IDB_XCH()
{
	tunnel = NULL;

	xch_status = XCH_STATUS_LARVAL;
	xch_errorcode = XCH_NORMAL;
	xch_notifycode = 0;

	initiator = false;
	exchange = 0;

	msgid = 0;
	lstate = 0;
	xstate = 0;

	lock.name( "xch" );

	//
	// initialize event info
	//

	event_resend.xch = this;
	event_resend.attempt = 0;
}

_IDB_XCH::~_IDB_XCH()
{
	event_resend.ipqueue.clean();
}

XCH_STATUS _IDB_XCH::status()
{
	lock.lock();

	XCH_STATUS cur_status = xch_status;

	lock.unlock();

	return xch_status;
}

XCH_STATUS _IDB_XCH::status( XCH_STATUS status, XCH_ERRORCODE errorcode, uint16_t notifycode )
{
	lock.lock();

	XCH_STATUS cur_status = xch_status;

	if( cur_status != XCH_STATUS_DEAD )
	{
		cur_status = xch_status = status;
		xch_errorcode = errorcode;
		xch_notifycode = notifycode;

		if( status == XCH_STATUS_DEAD )
			setflags( ENTRY_FLAG_DEAD );
	}

	lock.unlock();

	return cur_status;
}

void _IDB_XCH::new_msgid()
{
	iked.rand_bytes( &msgid, sizeof( msgid ) );
}

bool _IDB_XCH::new_msgiv( IDB_PH1 * ph1 )
{
	if( ph1->evp_cipher == NULL )
		return false;

	unsigned char iv_data[ EVP_MAX_MD_SIZE ];
	unsigned long iv_size = EVP_CIPHER_iv_length( ph1->evp_cipher );

	EVP_MD_CTX ctx_hash;
	EVP_DigestInit( &ctx_hash, ph1->evp_hash );
	EVP_DigestUpdate( &ctx_hash, ph1->iv.buff(), ph1->iv.size() );
	EVP_DigestUpdate( &ctx_hash, &msgid, 4 );
	EVP_DigestFinal( &ctx_hash, iv_data, NULL );
	EVP_MD_CTX_cleanup( &ctx_hash );

	iv.set( iv_data, iv_size );

	iked.log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		iv.buff(),
		iv.size(),
		"== : new %s iv",
		name() );

	return true;
}

bool _IDB_XCH::resend()
{
	if( event_resend.attempt > iked.retry_count )
	{
		iked.log.txt( LLOG_INFO,
				"ii : resend limit exceeded for %s exchange\n",
				name() );

		status( XCH_STATUS_DEAD, XCH_FAILED_TIMEOUT, 0 );

		return false;
	}

	lock.lock();

	long count = event_resend.ipqueue.count();
	long index = 0;

	for( ; index < count; index++ )
	{
		PACKET_IP packet;
		event_resend.ipqueue.get( packet, index );

		iked.send_ip(
			packet );
	}

	lock.unlock();

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	iked.text_addr( txtaddr_l, &tunnel->saddr_l, true );
	iked.text_addr( txtaddr_r, &tunnel->saddr_r, true );

	iked.log.txt( LLOG_INFO,
		"-> : resend %i %s packet(s) [%i/%i] %s -> %s\n",
		count,
		name(),
		event_resend.attempt,
		iked.retry_count,
		txtaddr_l,
		txtaddr_r );

	event_resend.attempt++;

	return true;
}

bool _IDB_XCH::resend_queue( PACKET_IP & packet )
{
	//
	// queue a packet
	//

	lock.lock();

	bool added = event_resend.ipqueue.add( packet );

	lock.unlock();

	return added;
}

void _IDB_XCH::resend_purge()
{
	//
	// purge our queue
	//

	lock.lock();

	event_resend.ipqueue.clean();

	lock.unlock();
}

bool _IDB_XCH::resend_sched( bool lock )
{
	if( lock )
		iked.lock_idb.lock();

	//
	// avoid events on dead exchanges
	//

	if( status() != XCH_STATUS_DEAD )
	{
		//
		// add our resend event
		//

		event_resend.delay = iked.retry_delay * 1000;

		if( iked.ith_timer.add( &event_resend ) )
		{
			idb_refcount++;
			iked.log.txt( LLOG_DEBUG,
				"DB : %s resend event scheduled ( ref count = %i )\n",
				name(),
				idb_refcount );
		}
	}

	if( lock )
		iked.lock_idb.unlock();

	return true;
}

void _IDB_XCH::resend_clear( bool lock, bool purge )
{
	if( !event_resend.ipqueue.count() )
		return;

	if( lock )
		iked.lock_idb.lock();

	//
	// reset our attempt counter
	//

	event_resend.attempt = 0;

	//
	// remove resend event
	//

	if( iked.ith_timer.del( &event_resend ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : %s resend event canceled ( ref count = %i )\n",
			name(),
			idb_refcount );
	}

	//
	// optionally purge our queue
	//

	if( purge )
		resend_purge();

	if( lock )
		iked.lock_idb.unlock();
}

//==============================================================================
// generic sa exchange handle list entry
//==============================================================================

_IDB_XCH_SA::_IDB_XCH_SA()
{
	dh = NULL;
	dh_size = 0;
}

_IDB_XCH_SA::~_IDB_XCH_SA()
{
}
