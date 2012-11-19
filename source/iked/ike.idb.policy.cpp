
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
// policy list
//==============================================================================

IDB_POLICY * _IDB_LIST_POLICY::get( int index )
{
	return static_cast<IDB_POLICY*>( get_entry( index ) );
}

bool _IDB_LIST_POLICY::find( bool lock, IDB_POLICY ** policy, long dir, u_int16_t type, u_int32_t * seq, u_int32_t * plcyid, IKE_SADDR * src, IKE_SADDR * dst, IKE_PH2ID * ids, IKE_PH2ID * idd )
{
	if( policy != NULL )
		*policy = NULL;

	if( lock )
		iked.lock_idb.lock();

	//
	// step through our list of policys
	// and see if they match the msgid
	//

	long policy_count = count();
	long policy_index = 0;

	for( ; policy_index < policy_count; policy_index++ )
	{
		//
		// get the next policy in our list
		//

		IDB_POLICY * tmp_policy = get( policy_index );

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
		// compare policy sequence
		//

		if( seq != NULL )
			if( *seq != tmp_policy->seq )
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
			iked.policy_get_addrs( tmp_policy, psrc, pdst );

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
			iked.paddr_ph2id( tmp_policy->paddr_src, ph2id );

			if( !iked.cmp_ph2id( ph2id, *ids, false ) )
				continue;
		}

		if( idd != NULL )
		{
			IKE_PH2ID ph2id;
			iked.paddr_ph2id( tmp_policy->paddr_dst, ph2id );

			if( !iked.cmp_ph2id( ph2id, *idd, false ) )
				continue;
		}

		iked.log.txt( LLOG_DEBUG, "DB : policy found\n" );

		//
		// increase our refrence count
		//

		if( policy != NULL )
		{
			tmp_policy->inc( false );
			*policy = tmp_policy;
		}

		if( lock )
			iked.lock_idb.unlock();

		return true;
	}

	iked.log.txt( LLOG_DEBUG, "DB : policy not found\n" );

	if( lock )
		iked.lock_idb.unlock();

	return false;
}

void _IDB_LIST_POLICY::flush()
{
	clean();
}

//==============================================================================
// policy list entry
//==============================================================================

_IDB_POLICY::_IDB_POLICY( PFKI_SPINFO * spinfo )
{
	memset( &paddr_src, 0, sizeof( paddr_src ) );
	memset( &paddr_dst, 0, sizeof( paddr_dst ) );

	memset( &sp, 0, sizeof( sp ) );
	memset( xforms, 0, sizeof( xforms ) );
	
	flags = 0;

	iked.rand_bytes( &spinfo->seq, sizeof( spinfo->seq ) );

	if( spinfo != NULL )
		*static_cast<PFKI_SPINFO*>( this ) = *spinfo;
}

_IDB_POLICY::~_IDB_POLICY()
{
}

//------------------------------------------------------------------------------
// abstract functions from parent class
//

const char * _IDB_POLICY::name()
{
	static const char * xname = "policy";
	return xname;
}

IKED_RC_LIST * _IDB_POLICY::list()
{
	return &iked.idb_list_policy;
}

void _IDB_POLICY::beg()
{
}

void _IDB_POLICY::end()
{
}

