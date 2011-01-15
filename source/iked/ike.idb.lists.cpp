
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
// basic data list
//

_IDB_LIST_BDATA::~_IDB_LIST_BDATA()
{
	for( long index = 0; index < count(); index++ )
	{
		IDB_ENTRY_BDATA * bentry = static_cast<IDB_ENTRY_BDATA*>( get_entry( index ) );
		delete bentry;
	}
}

bool _IDB_LIST_BDATA::add( BDATA & bdata )
{
	IDB_ENTRY_BDATA * bentry = new IDB_ENTRY_BDATA;
	if( bentry == NULL )
		return false;

	*static_cast<BDATA*>( bentry ) = bdata;

	return add_entry( bentry );
}

bool _IDB_LIST_BDATA::get( BDATA & bdata, long index )
{
	IDB_ENTRY_BDATA * bentry = static_cast<IDB_ENTRY_BDATA*>( get_entry( index ) );
	if( bentry == NULL )
		return false;

	bdata = *static_cast<BDATA*>( bentry );

	return true;
}

//==============================================================================
// IKE proposal list
//

_IDB_LIST_PROPOSAL::~_IDB_LIST_PROPOSAL()
{
	for( long index = 0; index < count(); index++ )
	{
		IDB_ENTRY_PROPOSAL * pentry = static_cast<IDB_ENTRY_PROPOSAL*>( get_entry( index ) );
		delete pentry;
	}
}

bool _IDB_LIST_PROPOSAL::add( IKE_PROPOSAL * proposal, bool pnext )
{
	IDB_ENTRY_PROPOSAL * pentry = new IDB_ENTRY_PROPOSAL;
	if( pentry == NULL )
		return false;

	pentry->pnext = pnext;
	*static_cast<IKE_PROPOSAL*>( pentry ) = *proposal;
	add_entry( pentry );

	return true;
}

bool _IDB_LIST_PROPOSAL::get( IKE_PROPOSAL ** proposal, long pindex, uint8_t proto )
{
	while( pindex < count() )
	{
		IDB_ENTRY_PROPOSAL * pentry = static_cast<IDB_ENTRY_PROPOSAL*>( get_entry( pindex ) );
		if( pentry == NULL )
			return false;

		if( !proto || ( proto == pentry->proto ) )
		{
			*proposal = static_cast<IKE_PROPOSAL*>( pentry );
			return true;
		}

		pindex++;
	}

	return false;
}

bool _IDB_LIST_PROPOSAL::nextb( long & bindex, long & pindex, long & pcount )
{
	if( bindex == -1 )
		return false;

	while( bindex < count() )
	{
		IDB_ENTRY_PROPOSAL * pentry = static_cast<IDB_ENTRY_PROPOSAL*>( get_entry( bindex ) );
		if( pentry == NULL )
			return false;

		if( pentry->pnext )
		{
			long pnumb = pentry->pnumb;

			pindex = bindex;
			pcount = 1;
			bindex++;

			while( 1 )
			{
				pentry = static_cast<IDB_ENTRY_PROPOSAL*>( get_entry( bindex ) );
				if( pentry == NULL )
				{
					bindex = -1;
					break;
				}

				if( pentry->pnext )
				{
					if( pnumb != pentry->pnumb )
						break;

					pcount++;
				}

				bindex++;
			}

			return true;
		}

		bindex++;
	}

	return false;
}

bool _IDB_LIST_PROPOSAL::nextp( IKE_PROPOSAL ** proposal, long & pindex, long & tindex, long & tcount )
{
	if( pindex == -1 )
		return false;

	while( pindex < count() )
	{
		IDB_ENTRY_PROPOSAL * pentry = static_cast<IDB_ENTRY_PROPOSAL*>( get_entry( pindex ) );
		if( pentry == NULL )
			return false;

		if( pentry->pnext )
		{
			*proposal = static_cast<IKE_PROPOSAL*>( pentry );

			tindex = pindex;
			tcount = 1;
			pindex++;

			while( 1 )
			{
				pentry = static_cast<IDB_ENTRY_PROPOSAL*>( get_entry( pindex ) );
				if( pentry == NULL )
				{
					pindex = -1;
					break;
				}

				if( pentry->pnext )
					break;

				tcount++;
				pindex++;
			}

			return true;
		}

		pindex++;
	}

	return false;
}

bool _IDB_LIST_PROPOSAL::nextt( IKE_PROPOSAL ** proposal, long & tindex )
{
	if( tindex == -1 )
		return false;

	IDB_ENTRY_PROPOSAL * pentry = static_cast<IDB_ENTRY_PROPOSAL*>( get_entry( tindex++ ) );
	if( pentry == NULL )
		return false;

	*proposal = static_cast<IKE_PROPOSAL*>( pentry );

	pentry = static_cast<IDB_ENTRY_PROPOSAL*>( get_entry( tindex ) );
	if( pentry == NULL )
	{
		tindex = -1;
	}
	else
	{
		if( pentry->pnext )
			tindex = -1;
	}

	return true;
}

//==============================================================================
// IKE notification list
//

_IDB_LIST_NOTIFY::~_IDB_LIST_NOTIFY()
{
	for( long index = 0; index < count(); index++ )
	{
		IDB_ENTRY_NOTIFY * nentry = static_cast<IDB_ENTRY_NOTIFY*>( get_entry( index ) );
		delete nentry;
	}
}

bool _IDB_LIST_NOTIFY::add( IKE_NOTIFY & notify )
{
	IDB_ENTRY_NOTIFY * nentry = new IDB_ENTRY_NOTIFY;
	if( nentry == NULL )
		return false;

	nentry->type	= notify.type;
	nentry->code	= notify.code;
	nentry->doi		= notify.doi;
	nentry->proto	= notify.proto;
	nentry->spi		= notify.spi;
	nentry->data	= notify.data;

	return add_entry( nentry );
}

bool _IDB_LIST_NOTIFY::get( IKE_NOTIFY & notify, long index )
{
	IDB_ENTRY_NOTIFY * nentry = static_cast<IDB_ENTRY_NOTIFY*>( get_entry( index ) );
	if( nentry == NULL )
		return false;

	notify.type		= nentry->type;
	notify.code		= nentry->code;
	notify.doi		= nentry->doi;
	notify.proto	= nentry->proto;
	notify.spi		= nentry->spi;
	notify.data		= nentry->data;

	return true;
}

//==============================================================================
// IKE certificate list
//

_IDB_LIST_CERT::~_IDB_LIST_CERT()
{
	for( long index = 0; index < count(); index++ )
	{
		IDB_ENTRY_CERT * centry = static_cast<IDB_ENTRY_CERT*>( get_entry( index ) );
		delete centry;
	}
}

bool _IDB_LIST_CERT::add( uint8_t & type, BDATA & data )
{
	IDB_ENTRY_CERT * centry = new IDB_ENTRY_CERT;
	if( centry == NULL )
		return false;

	centry->type = type;
	centry->data = data;

	return add_entry( centry );
}

bool _IDB_LIST_CERT::get( uint8_t & type, BDATA & data, long index )
{
	IDB_ENTRY_CERT * centry = static_cast<IDB_ENTRY_CERT*>( get_entry( index ) );
	if( centry == NULL )
		return false;

	type = centry->type;
	data = centry->data;

	return true;
}

//==============================================================================
// phase2 ID list
//

_IDB_LIST_PH2ID::~_IDB_LIST_PH2ID()
{
	for( long index = 0; index < count(); index++ )
	{
		IDB_ENTRY_PH2ID * ientry = static_cast<IDB_ENTRY_PH2ID*>( get_entry( index ) );
		delete ientry;
	}
}

bool _IDB_LIST_PH2ID::add( IKE_PH2ID & ph2id )
{
	IDB_ENTRY_PH2ID * ientry = new IDB_ENTRY_PH2ID;
	if( ientry == NULL )
		return false;

	*static_cast<IKE_PH2ID*>( ientry ) = ph2id;

	return add_entry( ientry );
}

bool _IDB_LIST_PH2ID::get( IKE_PH2ID & ph2id, long index )
{
	IDB_ENTRY_PH2ID * ientry = static_cast<IDB_ENTRY_PH2ID*>( get_entry( index ) );
	if( ientry == NULL )
		return false;

	ph2id = *static_cast<IKE_PH2ID*>( ientry );

	return true;
}

//==============================================================================
// network map list ( list of phase2 ID lists )
//

_IDB_LIST_NETMAP::~_IDB_LIST_NETMAP()
{
	for( long index = 0; index < count(); index++ )
	{
		IDB_ENTRY_NETMAP * nentry = static_cast<IDB_ENTRY_NETMAP*>( get_entry( index ) );
		delete nentry;
	}
}

bool _IDB_LIST_NETMAP::add( IDB_LIST_PH2ID * idlist, long mode, BDATA * group )
{
	IDB_ENTRY_NETMAP * nentry = new IDB_ENTRY_NETMAP;
	if( nentry == NULL )
		return false;

	if( group != NULL )
		nentry->group = *group;

	nentry->idlist = idlist;
	nentry->mode = mode;

	return add_entry( nentry );
}

bool _IDB_LIST_NETMAP::get( IDB_ENTRY_NETMAP ** nentry, long index )
{
	*nentry = static_cast<IDB_ENTRY_NETMAP*>( get_entry( index ) );
	return ( *nentry != NULL );
}

//==============================================================================
// generic iked reference counted list
//

_IKED_RC_ENTRY::_IKED_RC_ENTRY()
{
	idb_flags = 0;
	idb_refcount = 0;
}

_IKED_RC_ENTRY::~_IKED_RC_ENTRY()
{
}

void _IKED_RC_ENTRY::callend()
{
	if( !chkflags( ENTRY_FLAG_ENDCALLED ) )
	{
		setflags( ENTRY_FLAG_ENDCALLED );
		end();
	}
}

bool _IKED_RC_ENTRY::add( bool lock )
{
	if( lock )
		list()->lock();

	inc( false );

	list()->add_entry( this );

	iked.log.txt(
		LLOG_DEBUG,
		"DB : %s added ( obj count = %i )\n",
		name(),
		list()->count() );

	if( lock )
		list()->unlock();
	
	return true;
}

void _IKED_RC_ENTRY::inc( bool lock )
{
	if( lock )
		list()->lock();

	idb_refcount++;

	iked.log.txt(
		LLOG_LOUD,
		"DB : %s ref increment ( ref count = %i, obj count = %i )\n",
		name(),
		idb_refcount,
		list()->count() );

	if( lock )
		list()->unlock();
}

bool _IKED_RC_ENTRY::dec( bool lock, bool setdel )
{
	if( lock )
		list()->lock();

	if( setdel )
		setflags( ENTRY_FLAG_DEAD );

	if( chkflags( ENTRY_FLAG_DEAD ) )
		callend();

	assert( idb_refcount > 0 );

	idb_refcount--;

	if( idb_refcount || ( !chkflags( ENTRY_FLAG_DEAD ) && !chkflags( ENTRY_FLAG_IMMEDIATE ) ) )
	{
		iked.log.txt(
			LLOG_LOUD,
			"DB : %s ref decrement ( ref count = %i, obj count = %i )\n",
			name(),
			idb_refcount,
			list()->count() );

		if( lock )
			list()->unlock();

		return false;
	}

	list()->del_entry( this );

	iked.log.txt(
		LLOG_DEBUG,
		"DB : %s deleted ( obj count = %i )\n",
		name(),
		list()->count() );

	if( lock )
		list()->unlock();

	delete this;

	return true;
}

_IKED_RC_LIST::_IKED_RC_LIST()
{
}

_IKED_RC_LIST::~_IKED_RC_LIST()
{
}

void _IKED_RC_LIST::clean()
{
	lock();

	long obj_count = count();
	long obj_index = 0;

	for( ; obj_index < obj_count; obj_index++ )
	{
		IKED_RC_ENTRY * entry = static_cast<IKED_RC_ENTRY*>( get_entry( obj_index ) );

		entry->inc( false );
		if( entry->dec( false, true ) )
		{
			obj_index--;
			obj_count--;
		}
	}

	unlock();
}

bool _IKED_RC_LIST::lock()
{
	return iked.lock_idb.lock();
}

bool _IKED_RC_LIST::unlock()
{
	return iked.lock_idb.unlock();
}
