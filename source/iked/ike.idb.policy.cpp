
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

_IDB_POLICY::_IDB_POLICY( PFKI_SPINFO * spinfo )
{
	memset( &paddr_src, 0, sizeof( paddr_src ) );
	memset( &paddr_dst, 0, sizeof( paddr_dst ) );

	memset( &sp, 0, sizeof( sp ) );
	memset( xforms, 0, sizeof( xforms ) );

	route = false;

	if( spinfo != NULL )
	{
		PFKI_SPINFO * tmp_spinfo = this;
		memcpy( tmp_spinfo, spinfo, sizeof( PFKI_SPINFO ) );
	}
}

bool _IKED::get_policy( bool lock, IDB_POLICY ** policy, long dir, u_int16_t type, u_int32_t * plcyid, IKE_SADDR * src, IKE_SADDR * dst, IKE_PH2ID * ids, IKE_PH2ID * idd )
{
	if( policy != NULL )
		*policy = NULL;

	if( lock )
		lock_sdb.lock();

	//
	// step through our list of policys
	// and see if they match the msgid
	//

	long count = list_policy.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		//
		// get the next policy in our list
		//

		IDB_POLICY * tmp_policy = ( IDB_POLICY * ) list_policy.get_item( index );

		//
		// compare policy direction
		//

		if( tmp_policy->sp.dir != dir )
			continue;

		//
		// compare policy type
		//

		if( tmp_policy->sp.type != type )
			continue;

		//
		// compare policy id
		//

		if( plcyid != NULL )
			if( *plcyid != tmp_policy->sp.id )
				continue;

		//
		// compare the policy endpoint addresses
		//

		IKE_SADDR psrc;
		IKE_SADDR pdst;

		if( ( src != NULL ) || ( dst != NULL ) )
			policy_get_addrs( tmp_policy, psrc, pdst );

		if( src != NULL )
			if( !cmp_ikeaddr( psrc, *src, false ) )
				continue;

		if( dst != NULL )
			if( !cmp_ikeaddr( pdst, *dst, false ) )
				continue;

		//
		// compare ipv4 ids ( non-exact )
		//

		if( ids != NULL )
		{
			IKE_PH2ID ph2id;
			paddr_ph2id( tmp_policy->paddr_src, ph2id );

			if( !cmp_ph2id( ph2id, *ids, false ) )
				continue;
		}

		if( idd != NULL )
		{
			IKE_PH2ID ph2id;
			paddr_ph2id( tmp_policy->paddr_dst, ph2id );

			if( !cmp_ph2id( ph2id, *idd, false ) )
				continue;
		}

		log.txt( LLOG_DEBUG, "DB : policy found\n" );

		//
		// increase our refrence count
		//

		if( policy != NULL )
		{
			tmp_policy->inc( false );
			*policy = tmp_policy;
		}

		if( lock )
			lock_sdb.unlock();

		return true;
	}

	log.txt( LLOG_DEBUG, "DB : policy not found\n" );

	if( lock )
		lock_sdb.unlock();

	return false;
}

bool _IDB_POLICY::add( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	inc( false );

	bool result = iked.list_policy.add_item( this );

	iked.log.txt( LLOG_DEBUG, "DB : policy added\n" );

	if( lock )
		iked.lock_sdb.unlock();
	
	return result;

}

bool _IDB_POLICY::inc( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	refcount++;

	iked.log.txt( LLOG_LOUD,
		"DB : policy ref increment ( ref count = %i, policy count = %i )\n",
		refcount,
		iked.list_policy.get_count() );

	if( lock )
		iked.lock_sdb.unlock();

	return true;
}

bool _IDB_POLICY::dec( bool lock )
{
	if( lock )
		iked.lock_sdb.lock();

	assert( refcount > 0 );

	refcount--;

	if( refcount || !( lstate & LSTATE_DELETE ) )
	{
		iked.log.txt( LLOG_LOUD,
			"DB : policy ref decrement ( ref count = %i, policy count = %i )\n",
			refcount,
			iked.list_policy.get_count() );

		if( lock )
			iked.lock_sdb.unlock();

		return false;
	}


	//
	// remove the sa from our list
	//

	iked.list_policy.del_item( this );

	//
	// log deletion
	//

	iked.log.txt( LLOG_DEBUG,
		"DB : policy deleted ( policy count = %i )\n",
		iked.list_policy.get_count() );

	if( lock )
		iked.lock_sdb.unlock();

	//
	// free
	//

	delete this;

	return true;
}

