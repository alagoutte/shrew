
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

_IDB_PEER::_IDB_PEER( IKE_PEER * set_peer )
{
	key = NULL;

	if( set_peer != NULL )
	{
		IKE_PEER * tmp_peer = this;
		memcpy( tmp_peer, set_peer, sizeof( IKE_PEER ) );
	}
}

_IDB_PEER::~_IDB_PEER()
{
	if( key != NULL )
		EVP_PKEY_free( key );

	IDB_NETMAP * netmap;
	while( netmap_get( &netmap, 0 ) )
		netmap_del( netmap );
}

bool _IKED::get_peer( bool lock, IDB_PEER ** peer, IKE_SADDR * saddr )
{
	if( peer != NULL )
		*peer = NULL;

	if( lock )
		lock_sdb.lock();

	long count = list_peer.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		IDB_PEER * tmp_peer = ( IDB_PEER * ) list_peer.get_item( index );

		//
		// match the peer address
		//

		if( saddr != NULL )
			if( has_sockaddr( &tmp_peer->saddr.saddr ) )
				if( !cmp_sockaddr( tmp_peer->saddr.saddr, saddr->saddr, false ) )
					continue;

		log.txt( LOG_DEBUG, "DB : peer found\n" );

		//
		// increase our refrence count
		//

		if( peer != NULL )
		{
			tmp_peer->inc( false );
			*peer = tmp_peer;
		}

		if( lock )
			lock_sdb.unlock();

		return true;
	}

	log.txt( LOG_DEBUG, "DB : peer not found\n" );

	if( lock )
		lock_sdb.unlock();

	return false;
}

bool _IDB_PEER::add( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	inc( false );

	bool result = iked.list_peer.add_item( this );

	iked.log.txt( LOG_DEBUG, "DB : peer added\n" );

	if( lock )
		iked.lock_sdb.unlock();
	
	return result;
}

bool _IDB_PEER::inc( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	refcount++;

	iked.log.txt( LOG_LOUD,
		"DB : peer ref increment ( ref count = %i, peer count = %i )\n",
		refcount,
		iked.list_peer.get_count() );

	if( lock )
		iked.lock_sdb.unlock();

	return true;
}

bool _IDB_PEER::dec( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	assert( refcount > 0 );

	refcount--;

	if( refcount || !( lstate & LSTATE_DELETE ) )
	{
		iked.log.txt( LOG_LOUD,
			"DB : peer ref decrement ( ref count = %i, peer count = %i )\n",
			refcount,
			iked.list_peer.get_count() );

		if( lock )
			iked.lock_sdb.unlock();

		return false;
	}

	//
	// remove from our list
	//

	iked.list_peer.del_item( this );

	//
	// log deletion
	//

	iked.log.txt( LOG_DEBUG,
		"DB : peer deleted ( peer count = %i )\n",
		iked.list_peer.get_count() );

	if( lock )
		iked.lock_sdb.unlock();

	delete this;

	return true;
}

void _IDB_PEER::end( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	iked.log.txt( LOG_INFO, "DB : removing all peer refrences\n" );

	//
	// check for tunnel object refrences
	//

	long count = iked.list_tunnel.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		//
		// get the next tunnel in our list
		// and attempt to match peer ids
		//

		IDB_TUNNEL * tunnel = ( IDB_TUNNEL * ) iked.list_tunnel.get_item( index );

		if( tunnel->peer == this )
			tunnel->end( false );
	}

	if( lock )
		iked.lock_sdb.unlock();
}


bool _IDB_PEER::netmap_add( IKE_ILIST * ilist, long	mode, BDATA * group )
{
	IDB_NETMAP * netmap = new IDB_NETMAP;
	if( netmap == NULL )
		return false;

	if( group != NULL )
		netmap->group.set( *group );

	netmap->ilist = ilist;
	netmap->mode = mode;

	return netmaps.add_item( netmap );
}

bool _IDB_PEER::netmap_del( IDB_NETMAP * netmap )
{
	if( netmaps.del_item( netmap ) )
	{
		delete netmap;
		return true;
	}

	return false;
}

bool _IDB_PEER::netmap_get( IDB_NETMAP ** netmap, long index )
{
	*netmap = ( IDB_NETMAP * ) netmaps.get_item( index );
	return ( *netmap != NULL );
}
