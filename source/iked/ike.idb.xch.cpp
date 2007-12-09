
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
// generic exchange handle event functions
//

bool _ITH_EVENT_RESEND::func()
{
	//
	// call our exchange specific re-send
	// function which returns true if we
	// are allowed to re-transmit packets
	//

	if( !xch->resend( attempt, ipqueue.count() ) )
	{
		xch->dec( true );
		return false;
	}

	iked.lock_ipq.lock();

	long count = ipqueue.count();
	long index = 0;

	for( ; index < count; index++ )
	{
		PACKET_IP packet;
		ipqueue.get( packet, index );

		iked.send_ip(
			packet );
	}

	iked.lock_ipq.unlock();

	attempt++;

	return true;
}

_ITH_EVENT_RESEND::~_ITH_EVENT_RESEND()
{
}

//
// generic exchange handle class
//

_IDB_XCH::_IDB_XCH()
{
	tunnel = NULL;

	exchange = 0;
	initiator = false;

	xstate = 0;

	dh = NULL;
	dh_size = 0;

	hash_size = 0;

	//
	// initialize event info
	//

	event_resend.xch = this;
}

_IDB_XCH::~_IDB_XCH()
{
}

bool _IDB_XCH::resend_queue( PACKET_IP & packet )
{
	//
	// queue our new packet
	//

	iked.lock_ipq.lock();

	bool added = event_resend.ipqueue.add( packet );

	iked.lock_ipq.unlock();

	return added;
}

bool _IDB_XCH::resend_sched()
{
	//
	// reset our attempt counter
	//

	event_resend.attempt = 0;

	//
	// add our resend event
	//

	inc( true );
	event_resend.delay = iked.retry_delay * 1000;

	iked.ith_timer.add( &event_resend );
	
	return true;
}

void _IDB_XCH::resend_clear()
{
	if( iked.ith_timer.del( &event_resend ) )
	{
		iked.lock_ipq.lock();

		event_resend.ipqueue.flush();

		iked.lock_ipq.unlock();

		dec( true );
	}
}

