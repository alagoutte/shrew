
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
// PROPOSAL LIST
//

_IKE_PLIST::_IKE_PLIST()
{
}

_IKE_PLIST::~_IKE_PLIST()
{
	clean();
}

long _IKE_PLIST::count()
{
	return prop_list.get_count();
}

void _IKE_PLIST::clean()
{
	while( prop_list.get_count() )
	{
		IKE_PENTRY * pentry = ( IKE_PENTRY * ) prop_list.get_item( 0 );
		prop_list.del_item( pentry );
		delete pentry;
	}
}

bool _IKE_PLIST::add( IKE_PROPOSAL * proposal, bool pnext )
{
	IKE_PENTRY * pentry = new IKE_PENTRY;
	if( pentry == NULL )
		return false;

	pentry->pnext = pnext;

	memcpy( &pentry->proposal, proposal, sizeof( IKE_PROPOSAL ) );

	prop_list.add_item( pentry );

	return true;
}

bool _IKE_PLIST::get( IKE_PROPOSAL ** proposal, long pindex, uint8_t proto )
{
	while( pindex < prop_list.get_count() )
	{
		IKE_PENTRY * pentry = ( IKE_PENTRY * ) prop_list.get_item( pindex );
		if( pentry == NULL )
			return false;

		if( !proto || ( proto == pentry->proposal.proto ) )
		{
			*proposal = &pentry->proposal;
			return true;
		}

		pindex++;
	}

	return false;
}

bool _IKE_PLIST::nextb( long & bindex, long & pindex, long & pcount )
{
	if( bindex == -1 )
		return false;

	while( bindex < prop_list.get_count() )
	{
		IKE_PENTRY * pentry = ( IKE_PENTRY * ) prop_list.get_item( bindex );
		if( pentry == NULL )
			return false;

		if( pentry->pnext )
		{
			long pnumb = pentry->proposal.pnumb;

			pindex = bindex;
			pcount = 1;
			bindex++;

			while( 1 )
			{
				pentry = ( IKE_PENTRY * ) prop_list.get_item( bindex );
				if( pentry == NULL )
				{
					bindex = -1;
					break;
				}

				if( pentry->pnext )
				{
					if( pnumb != pentry->proposal.pnumb )
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

bool _IKE_PLIST::nextp( IKE_PROPOSAL ** proposal, long & pindex, long & tindex, long & tcount )
{
	if( pindex == -1 )
		return false;

	while( pindex < prop_list.get_count() )
	{
		IKE_PENTRY * pentry = ( IKE_PENTRY * ) prop_list.get_item( pindex );
		if( pentry == NULL )
			return false;

		if( pentry->pnext )
		{
			*proposal = &pentry->proposal;

			tindex = pindex;
			tcount = 1;
			pindex++;

			while( 1 )
			{
				pentry = ( IKE_PENTRY * ) prop_list.get_item( pindex );
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

bool _IKE_PLIST::nextt( IKE_PROPOSAL ** proposal, long & tindex )
{
	if( tindex == -1 )
		return false;

	IKE_PENTRY * pentry = ( IKE_PENTRY * ) prop_list.get_item( tindex++ );
	if( pentry == NULL )
		return false;

	*proposal = &pentry->proposal;

	pentry = ( IKE_PENTRY * ) prop_list.get_item( tindex );
	if( pentry == NULL )
		tindex = -1;
	else
	{
		if( pentry->pnext )
			tindex = -1;
	}

	return true;
}

//
// CERTIFICATE LIST
//

_IKE_CLIST::_IKE_CLIST()
{
}

_IKE_CLIST::~_IKE_CLIST()
{
	while( true )
	{
		BDATA * tmp_cert = ( BDATA * ) list_certs.get_item( 0 );
		if( tmp_cert == NULL )
			break;

		list_certs.del_item( tmp_cert );
		delete tmp_cert;
	}
}

long _IKE_CLIST::count()
{
	return list_certs.get_count();
}

bool _IKE_CLIST::add( BDATA & cert )
{
	BDATA * tmp_cert = new BDATA;
	if( tmp_cert == NULL )
		return false;

	tmp_cert->add( cert );

	list_certs.add_item( tmp_cert );

	return true;
}

bool _IKE_CLIST::get( BDATA & cert, long index )
{
	BDATA * tmp_cert = ( BDATA * ) list_certs.get_item( index );
	if( tmp_cert == NULL )
		return false;

	cert.size( 0 );
	cert.add( *tmp_cert );

	return true;
}

//
// IPV4ID LIST
//

_IKE_ILIST::_IKE_ILIST()
{
}

_IKE_ILIST::~_IKE_ILIST()
{
	while( true )
	{
		IKE_PH2ID * tmp_ph2id = ( IKE_PH2ID * ) list_ph2id.get_item( 0 );
		if( tmp_ph2id == NULL )
			break;

		list_ph2id.del_item( tmp_ph2id );
		delete tmp_ph2id;
	}
}

long _IKE_ILIST::count()
{
	return list_ph2id.get_count();
}

bool _IKE_ILIST::add( IKE_PH2ID & ph2id )
{
	IKE_PH2ID * tmp_ph2id = new IKE_PH2ID;
	if( tmp_ph2id == NULL )
		return false;

	memcpy( tmp_ph2id, &ph2id, sizeof( ph2id ) );

	list_ph2id.add_item( tmp_ph2id );

	return true;
}

bool _IKE_ILIST::get( IKE_PH2ID & ph2id, long index )
{
	IKE_PH2ID * tmp_ph2id = ( IKE_PH2ID * ) list_ph2id.get_item( index );
	if( tmp_ph2id == NULL )
		return false;

	memcpy( &ph2id, tmp_ph2id, sizeof( ph2id ) );

	return true;
}

//
// NOTIFICATION LIST
//

_IKE_NLIST::~_IKE_NLIST()
{
	while( list_notify.get_count() )
	{
		IKE_NOTIFY * tmp_notify = ( IKE_NOTIFY * ) list_notify.get_item( 0 );
		list_notify.del_item( tmp_notify );
		delete tmp_notify;
	}
}

long _IKE_NLIST::count()
{
	return list_notify.get_count();
}

bool _IKE_NLIST::add( IKE_NOTIFY & notify )
{
	IKE_NOTIFY * tmp_notify = new IKE_NOTIFY;
	if( tmp_notify == NULL )
		return false;

	tmp_notify->type	= notify.type;
	tmp_notify->code	= notify.code;
	tmp_notify->doi		= notify.doi;
	tmp_notify->proto	= notify.proto;
	tmp_notify->spi		= notify.spi;

	tmp_notify->data.set( notify.data );

	list_notify.add_item( tmp_notify );

	return true;
}

bool _IKE_NLIST::get( IKE_NOTIFY & notify, long index )
{
	IKE_NOTIFY * tmp_notify = ( IKE_NOTIFY * ) list_notify.get_item( index );
	if( tmp_notify == NULL )
		return false;

	notify.type		= tmp_notify->type;
	notify.code		= tmp_notify->code;
	notify.doi		= tmp_notify->doi;
	notify.proto	= tmp_notify->proto;
	notify.spi		= tmp_notify->spi;

	notify.data.set( tmp_notify->data );

	return true;
}

//
// DOMAIN SUFFIX LIST
//

_IKE_DLIST::~_IKE_DLIST()
{
	while( list_suffix.get_count() )
	{
		BDATA * tmp_suffix = ( BDATA * ) list_suffix.get_item( 0 );
		list_suffix.del_item( tmp_suffix );
		delete tmp_suffix;
	}
}

long _IKE_DLIST::count()
{
	return list_suffix.get_count();
}

bool _IKE_DLIST::add( BDATA & suffix )
{
	BDATA * tmp_suffix = new BDATA;
	if( tmp_suffix == NULL )
		return false;

	tmp_suffix->set( suffix );

	list_suffix.add_item( tmp_suffix );

	return true;
}

bool _IKE_DLIST::get( BDATA & suffix, long index )
{
	BDATA * tmp_suffix = ( BDATA * ) list_suffix.get_item( index );
	if( tmp_suffix == NULL )
		return false;

	suffix.set( *tmp_suffix );

	return true;
}

