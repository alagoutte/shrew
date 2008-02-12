
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

#include "idb.h"

//==============================================================================
// standard IDB list classes
//

_IDB_ENTRY::_IDB_ENTRY()
{
}

_IDB_ENTRY::~_IDB_ENTRY()
{
}

_IDB_LIST::_IDB_LIST()
{
}

_IDB_LIST::~_IDB_LIST()
{
}

long _IDB_LIST::count()
{
	return get_count();
}

void _IDB_LIST::clean()
{
	while( count() )
		delete del_entry( 0 );
}

bool _IDB_LIST::add_entry( IDB_ENTRY * entry )
{
	return add_item( entry );
}

bool _IDB_LIST::del_entry( IDB_ENTRY * entry )
{
	return del_item( entry );
}

IDB_ENTRY * _IDB_LIST::del_entry( int index )
{
	return static_cast< IDB_ENTRY* >( del_item( index ) );
}

IDB_ENTRY * _IDB_LIST::get_entry( int index )
{
	return static_cast< IDB_ENTRY* >( get_item( index ) );
}

//==============================================================================
// reference counted IDB classes
//

_IDB_RC_ENTRY::_IDB_RC_ENTRY()
{
	idb_flags = 0;
	idb_refcount = 0;
}

_IDB_RC_ENTRY::~_IDB_RC_ENTRY()
{
}

bool _IDB_RC_ENTRY::add( bool lock )
{
	if( lock )
		list()->rc_lock()->lock();

	inc( false );

	list()->add_entry( this );

	list()->rc_log()->txt(
		LLOG_DEBUG,
		"DB : %s added ( obj count = %i )\n",
		name(),
		list()->get_count() );

	if( lock )
		list()->rc_lock()->unlock();
	
	return true;
}

bool _IDB_RC_ENTRY::inc( bool lock )
{
	if( lock )
		list()->rc_lock()->lock();

	idb_refcount++;

	list()->rc_log()->txt(
		LLOG_LOUD,
		"DB : %s ref increment ( ref count = %i, obj count = %i )\n",
		name(),
		idb_refcount,
		list()->get_count() );

	if( lock )
		list()->rc_lock()->unlock();

	return true;
}

bool _IDB_RC_ENTRY::dec( bool lock, bool setdel )
{
	if( lock )
		list()->rc_lock()->lock();

	if( setdel )
	{
		setflags( IDB_FLAG_DEAD );
		clrflags( IDB_FLAG_NOEND );
	}

	if(  chkflags( IDB_FLAG_DEAD ) &&
		!chkflags( IDB_FLAG_ENDED ) &&
		!chkflags( IDB_FLAG_NOEND ) )
	{
		setflags( IDB_FLAG_ENDED );
		end();
	}

	assert( idb_refcount > 0 );

	idb_refcount--;

	if( idb_refcount || !( idb_flags & IDB_FLAG_DEAD ) )
	{
		list()->rc_log()->txt(
			LLOG_LOUD,
			"DB : %s ref decrement ( ref count = %i, obj count = %i )\n",
			name(),
			idb_refcount,
			list()->get_count() );

		if( lock )
			list()->rc_lock()->unlock();

		return false;
	}

	list()->del_entry( this );

	if( lock )
		list()->rc_lock()->unlock();

	char *	tmp_name = name();
	LIST *	tmp_list = list();
	LOG *	tmp_log = list()->rc_log();
	long	tmp_count = tmp_list->get_count();

	delete this;

	tmp_log->txt( LLOG_DEBUG,
		"DB : %s deleted ( obj count = %i )\n",
		tmp_name,
		tmp_count );

	return true;
}

_IDB_RC_LIST::_IDB_RC_LIST()
{
}

_IDB_RC_LIST::~_IDB_RC_LIST()
{
}

void _IDB_RC_LIST::clean()
{
	rc_lock()->lock();

	long obj_count = count();
	long obj_index = 0;

	for( ; obj_index < obj_count; obj_index++ )
	{
		IDB_RC_ENTRY * entry = static_cast<IDB_RC_ENTRY*>( get_entry( obj_index ) );

		entry->inc( false );
		if( entry->dec( false, true ) )
		{
			obj_index--;
			obj_count--;
		}
	}

	rc_lock()->unlock();
}