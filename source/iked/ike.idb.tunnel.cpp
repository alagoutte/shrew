
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
// tunnel event functions
//

bool _ITH_EVENT_TUNDHCP::func()
{
	//
	// check for tunnel close or
	// retry timeout
	//

	if( tunnel->close || ( retry > 8 ) )
	{
		tunnel->close = TERM_PEER_DHCP;
		tunnel->dec( true );

		return false;
	}

	//
	// check renew time
	//

	time_t current = time( NULL );

	if( current > renew )
		iked.process_dhcp_recv( tunnel );

	if( current > renew )
		iked.process_dhcp_send( tunnel );

	return true;
}

//
// tunnel configuration class
//

_IDB_TUNNEL::_IDB_TUNNEL( IDB_PEER * set_peer, IKE_SADDR * set_saddr_l, IKE_SADDR * set_saddr_r )
{
	refcount = 0;
	state = 0;
	close = 0;
	natt_v = IPSEC_NATT_NONE;

	dhcp_sock = INVALID_SOCKET;

	force_all = false;

	//
	// initialize the tunnel id
	//

	refid = iked.tunnelid++;
	peer = set_peer;
	saddr_l = *set_saddr_l;
	saddr_r = *set_saddr_r;

	memset( &stats, 0, sizeof( stats ) );
	memset( &xconf, 0, sizeof( xconf ) );

	//
	// set the default xconf addr
	//

	xconf.addr = saddr_r.saddr4.sin_addr;

	//
	// initialize event info
	//

	event_dhcp.tunnel = this;
	event_dhcp.lease = 0;
	event_dhcp.renew = 0;
	event_dhcp.retry = 0;
}

_IDB_TUNNEL::~_IDB_TUNNEL()
{
}

bool _IKED::get_tunnel( bool lock, IDB_TUNNEL ** tunnel, long * tunnelid, IKE_SADDR * saddr, bool port )
{
	if( tunnel != NULL )
		*tunnel = NULL;

	if( lock )
		lock_sdb.lock();

	long count = list_tunnel.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		IDB_TUNNEL * tmp_tunnel = ( IDB_TUNNEL * ) list_tunnel.get_item( index );

		//
		// match the tunnel id
		//

		if( tunnelid != NULL )
			if( tmp_tunnel->refid != *tunnelid )
				continue;

		//
		// match the peer address
		//

		if( saddr != NULL )
			if( !cmp_sockaddr( tmp_tunnel->saddr_r.saddr, saddr->saddr, port ) )
				continue;

		log.txt( LLOG_DEBUG, "DB : tunnel found\n" );

		//
		// increase our refrence count
		//

		if( tunnel != NULL )
		{
			tmp_tunnel->inc( false );
			*tunnel = tmp_tunnel;
		}

		if( lock )
			lock_sdb.unlock();

		return true;
	}

	log.txt( LLOG_DEBUG, "DB : tunnel not found\n" );

	if( lock )
		lock_sdb.unlock();

	return false;
}

bool _IDB_TUNNEL::add( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	inc( false );
	peer->inc( false );

	bool result = iked.list_tunnel.add_item( this );

	iked.log.txt( LLOG_DEBUG, "DB : tunnel added\n" );

	if( lock )
		iked.lock_sdb.unlock();

	//
	// setup our filter
	//

#ifdef WIN32

	iked.filter_tunnel_add( this, false );

#endif

	return result;
}

bool _IDB_TUNNEL::inc( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	refcount++;

	iked.log.txt( LLOG_LOUD,
		"DB : tunnel ref increment ( ref count = %i, tunnel count = %i )\n",
		refcount,
		iked.list_tunnel.get_count() );

	if( lock )
		iked.lock_sdb.unlock();

	return true;
}

bool _IDB_TUNNEL::dec( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	//
	// if we are closing the tunnel,
	// attempt to remove any events
	// that may be scheduled
	//

	if( close )
	{
		if( iked.ith_timer.del( &event_dhcp ) )
		{
			refcount--;
			iked.log.txt( LLOG_DEBUG,
				"DB : tunnel dhcp event canceled ( ref count = %i )\n",
				refcount );
		}
	}

	assert( refcount > 0 );

	refcount--;

	//
	// check for deletion
	//

	if( refcount )
	{
		iked.log.txt( LLOG_LOUD,
			"DB : tunnel ref decrement ( ref count = %i, tunnel count = %i )\n",
			refcount,
			iked.list_tunnel.get_count() );

		if( lock )
			iked.lock_sdb.unlock();

		return false;
	}

	//
	// remove from our list
	//

	iked.list_tunnel.del_item( this );

	//
	// log deletion
	//

	iked.log.txt( LLOG_DEBUG,
		"DB : tunnel deleted ( tunnel count = %i )\n",
		iked.list_tunnel.get_count() );

	//
	// dereference our peer
	//

	peer->dec( false );

	if( lock )
		iked.lock_sdb.unlock();

	//
	// cleanup our filter
	//

#ifdef WIN32

	iked.filter_tunnel_del( this );

#endif

	//
	// free
	//

	delete this;

	return true;
}

void _IDB_TUNNEL::end( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	iked.log.txt( LLOG_INFO, "DB : removing all tunnel refrences\n" );

	//
	// check for config object refrences
	//

	long count = iked.list_config.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		//
		// get the next config in our list
		// and attempt to match tunnel ids
		//

		IDB_CFG * cfg = ( IDB_CFG * ) iked.list_config.get_item( index );

		if( cfg->tunnel == this )
		{
			cfg->inc( false );
			cfg->lstate |= LSTATE_DELETE;

			if( cfg->dec( false ) )
			{
				index--;
				count--;
			}
		}
	}

	//
	// check for phase2 object refrences
	//

	count = iked.list_phase2.get_count();
	index = 0;

	for( ; index < count; index++ )
	{
		//
		// get the next phase2 in our list
		// and attempt to match tunnel ids
		//

		IDB_PH2 * ph2 = ( IDB_PH2 * ) iked.list_phase2.get_item( index );
		if( ph2->tunnel == this )
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

	//
	// check for phase1 object refrences
	//

	count = iked.list_phase1.get_count();
	index = 0;

	for( ; index < count; index++ )
	{
		//
		// get the next phase1 in our list
		// and attempt to match tunnel ids
		//

		IDB_PH1 * ph1 = ( IDB_PH1 * ) iked.list_phase1.get_item( index );
		if( ph1->tunnel == this )
		{
			ph1->inc( false );
			ph1->lstate |= LSTATE_DELETE;

			if( ph1->dec( false ) )
			{
				index--;
				count--;
			}
		}
	}

	if( lock )
		iked.lock_sdb.unlock();
}
