
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
// ike peer list
//==============================================================================

IDB_PEER * _IDB_LIST_PEER::get( int index )
{
	return static_cast<IDB_PEER*>( get_entry( index ) );
}

bool _IDB_LIST_PEER::find( bool lock, IDB_PEER ** peer, IKE_SADDR * saddr )
{
	if( peer != NULL )
		*peer = NULL;

	if( lock )
		iked.lock_idb.lock();

	long peer_count = count();
	long peer_index = 0;

	for( ; peer_index < peer_count; peer_index++ )
	{
		IDB_PEER * tmp_peer = get( peer_index );

		//
		// match the peer address
		//

		if( saddr != NULL )
			if( has_sockaddr( &tmp_peer->saddr.saddr ) )
				if( !cmp_sockaddr( tmp_peer->saddr.saddr, saddr->saddr, false ) )
					continue;

		iked.log.txt( LLOG_DEBUG, "DB : peer found\n" );

		//
		// increase our refrence count
		//

		if( peer != NULL )
		{
			tmp_peer->inc( false );
			*peer = tmp_peer;
		}

		if( lock )
			iked.lock_idb.unlock();

		return true;
	}

	iked.log.txt( LLOG_DEBUG, "DB : peer not found\n" );

	if( lock )
		iked.lock_idb.unlock();

	return false;
}

//==============================================================================
// ike peer list entry
//==============================================================================

_IDB_PEER::_IDB_PEER( IKE_PEER * set_peer )
{
	// handle idb zero reference condition

	iked.lock_run.lock();

	if( iked.peercount++ == 0 )
		iked.cond_idb.reset();

	iked.lock_run.unlock();

	if( set_peer != NULL )
		*static_cast<IKE_PEER*>( this ) = *set_peer;
}

_IDB_PEER::~_IDB_PEER()
{
	// handle idb zero reference condition

	iked.lock_run.lock();

	if( --iked.peercount == 0 )
		iked.cond_idb.alert();

	iked.lock_run.unlock();
}

//------------------------------------------------------------------------------
// abstract functions from parent class
//

const char * _IDB_PEER::name()
{
	static const char * xname = "peer";
	return xname;
}

IKED_RC_LIST * _IDB_PEER::list()
{
	return &iked.idb_list_peer;
}

void _IDB_PEER::beg()
{
}

void _IDB_PEER::end()
{
	iked.log.txt( LLOG_INFO, "DB : removing all peer tunnel references\n" );

	//
	// check for tunnel object references
	//

	long tunnel_count = iked.idb_list_tunnel.count();
	long tunnel_index = 0;

	for( ; tunnel_index < tunnel_count; tunnel_index++ )
	{
		//
		// get the next tunnel in our list
		// and attempt to match peer ids
		//

		IDB_TUNNEL * tunnel = iked.idb_list_tunnel.get( tunnel_index );

		if( tunnel->peer == this )
		{
			tunnel->inc( false );

			if( tunnel->dec( false, true ) )
			{
					tunnel_index--;
					tunnel_count--;
			}
		}
	}
}
