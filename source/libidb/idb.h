
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

#ifndef _IDB_H_
#define _IDB_H_

#include "export.h"
#include "libip.h"
#include "liblog.h"
#include "libith.h"

//==============================================================================
// standard IDB list classes
//==============================================================================

typedef class DLX _IDB_ENTRY
{
	public:

	_IDB_ENTRY();
	virtual ~_IDB_ENTRY();

}IDB_ENTRY;

typedef class DLX _IDB_LIST : public LIST
{
	public:

	_IDB_LIST();
	virtual ~_IDB_LIST();

	long			count();
	virtual	void	clean();

	bool		add_entry( IDB_ENTRY * entry );
	bool		del_entry( IDB_ENTRY * entry );
	IDB_ENTRY * del_entry( int index );
	IDB_ENTRY * get_entry( int index );

}IDB_LIST;

//==============================================================================
// reference counted IDB classes
//==============================================================================

class _IDB_RC_LIST;

#define IDB_FLAG_DEAD		1
#define IDB_FLAG_ENDED		2
#define IDB_FLAG_NOEND		4

typedef class DLX _IDB_RC_ENTRY : public IDB_ENTRY
{
	protected:

	long		idb_flags;
	long		idb_refcount;

	inline long chkflags( long flags )
	{
		return ( idb_flags & flags );
	}

	inline long setflags( long flags )
	{
		return idb_flags |= flags;
	}

	inline long clrflags( long flags )
	{
		return idb_flags &= ~flags;
	}

	virtual void beg() = 0;
	virtual void end() = 0;

	public:

	_IDB_RC_ENTRY();
	virtual ~_IDB_RC_ENTRY();

	virtual char *			name() = 0;
	virtual _IDB_RC_LIST *	list() = 0;

	bool add( bool lock );
	bool inc( bool lock );
	bool dec( bool lock, bool setdel = false );

}IDB_RC_ENTRY;

typedef class DLX _IDB_RC_LIST : public IDB_LIST
{
	public:

	_IDB_RC_LIST();
	virtual ~_IDB_RC_LIST();

	virtual	void	clean();

	virtual ITH_LOCK	* rc_lock() = 0;
	virtual LOG			* rc_log() = 0;

}IDB_RC_LIST;

#endif
