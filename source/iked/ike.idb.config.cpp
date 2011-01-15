
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
// ike configuration exchange handle list
//==============================================================================

IDB_CFG * _IDB_LIST_CFG::get( int index )
{
	return static_cast<IDB_CFG*>( get_entry( index ) );
}

bool _IDB_LIST_CFG::find( bool lock, IDB_CFG ** cfg, IDB_PH1 * ph1 )
{
	if( cfg != NULL )
		*cfg = NULL;

	if( lock )
		iked.lock_idb.lock();

	//
	// step through our list of configs
	// and see if they match the msgid
	//

	long index = 0;

	for( ; index < count(); index++ )
	{
		//
		// get the next config in our list
		//

		IDB_CFG * tmp_cfg = get( index );

		//
		// match the phase1 id
		//

		if( tmp_cfg->ph1ref != ph1 )
			continue;

		iked.log.txt( LLOG_DEBUG, "DB : config found\n" );

		//
		// increase our refrence count
		//

		if( cfg != NULL )
		{
			tmp_cfg->inc( false );
			*cfg = tmp_cfg;
		}

		if( lock )
			iked.lock_idb.unlock();

		return true;
	}

	iked.log.txt( LLOG_DEBUG, "DB : config not found\n" );

	if( lock )
		iked.lock_idb.unlock();

	return false;
}


//==============================================================================
// ike configuration exchange handle list entry
//==============================================================================

_IDB_CFG::_IDB_CFG( IDB_PH1 * set_ph1ref, bool set_initiator )
{
	mtype = 0;
	ident = 0;

	ph1ref = set_ph1ref;			// never accessed directly
	tunnel = set_ph1ref->tunnel;
	tunnel->inc( true );

	initiator = set_initiator;

	//
	// skip xauth if disabled
	//

	if( !set_ph1ref->vendopts_l.flag.xauth )
		xstate |= CSTATE_SENT_XRSLT | CSTATE_RECV_XRSLT;

	//
	// skip configuration if already negotiated
	// using pull mode or if the mode is set to
	// none ( manual )
	//

	if( tunnel->peer->xconf_mode == CONFIG_MODE_PULL )
		if( tunnel->tstate & TSTATE_VNET_CONFIG )
			xstate |= CSTATE_SENT_XCONF | CSTATE_RECV_XCONF;

	if( ( tunnel->peer->xconf_mode == CONFIG_MODE_DHCP ) ||
		( tunnel->peer->xconf_mode == CONFIG_MODE_NONE ) )
		xstate |= CSTATE_SENT_XCONF | CSTATE_RECV_XCONF;
}

_IDB_CFG::~_IDB_CFG()
{
	clean();

	//
	// dereference tunnel
	//

	tunnel->dec( false );
}

//------------------------------------------------------------------------------
// abstract functions from parent class
//

const char * _IDB_CFG::name()
{
	static const char * xname = "config";
	return xname;
}

IKED_RC_LIST * _IDB_CFG::list()
{
	return &iked.idb_list_cfg;
}

void _IDB_CFG::beg()
{
}

void _IDB_CFG::end()
{
	//
	// clear the resend queue
	//

	resend_clear( false, true );
}

//------------------------------------------------------------------------------
// additional functions
//

bool _IDB_CFG::attr_add_b( unsigned short atype, unsigned short bdata )
{
	IKE_ATTR * attr = new IKE_ATTR;
	if( attr == NULL )
		return false;

	attr->atype = atype;
	attr->basic = true;
	attr->bdata = bdata;

	return attrs.add_entry( attr );
}

bool _IDB_CFG::attr_add_v( unsigned short atype, const void * vdata, size_t vsize )
{
	IKE_ATTR * attr = new IKE_ATTR;
	if( attr == NULL )
		return false;

	attr->atype = atype;
	attr->basic = false;
	attr->vdata.set( ( char * ) vdata, vsize );

	return attrs.add_entry( attr );
}

bool _IDB_CFG::attr_has( unsigned short atype )
{
	long index = 0;
	long count = attr_count();

	for( ; index < count; index++ )
	{
		IKE_ATTR * attr = attr_get( index );

		if( attr->atype == atype )
			return true;
	}
	return false;
}

IKE_ATTR * _IDB_CFG::attr_get( long index )
{
	return static_cast<IKE_ATTR*>( attrs.get_entry( index ) );
}

long _IDB_CFG::attr_count()
{
	return attrs.count();
}

void _IDB_CFG::attr_reset()
{
	attrs.clean();
}

bool _IDB_CFG::setup()
{
	return true;
}

void _IDB_CFG::clean()
{
	attr_reset();
}

