
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

#include "libike.h"

void _IKEI_MSG::init( long type )
{
	del();
	header.type = type;
}

long _IKEI_MSG::get_basic( long * value, BDATA * bdata )
{
	IKEI_BASIC basic;
	if( !get( &basic, sizeof( basic ) ) )
		return IPCERR_FAILED;

	if( value != NULL )
		*value = basic.value;

	if( bdata != NULL )
		if( !get( *bdata, basic.bsize ) )
			return IPCERR_FAILED;

	return IPCERR_OK;
}

long _IKEI_MSG::set_basic( long value, BDATA * bdata )
{
	IKEI_BASIC basic;
	basic.value = value;

	if( bdata != NULL )
		basic.bsize = bdata->size();
	else
		basic.bsize = 0;

	if( !add( &basic, sizeof( basic ) ) )
		return IPCERR_FAILED;

	if( bdata != NULL )
		if( !add( *bdata ) )
			return IPCERR_FAILED;

	return IPCERR_OK;
}

long _IKEI_MSG::get_struct( long * value, void * sdata, size_t ssize )
{
	IKEI_BASIC basic;
	if( !get( &basic, sizeof( basic ) ) )
		return IPCERR_FAILED;

	if( value != NULL )
		*value = basic.value;

	if( sdata != NULL )
		if( !get( sdata, ssize ) )
			return IPCERR_FAILED;

	return IPCERR_OK;
}

long _IKEI_MSG::set_struct( long value, void * sdata, size_t ssize )
{
	IKEI_BASIC basic;
	basic.value = value;

	if( sdata != NULL )
		basic.bsize = ssize;
	else
		basic.bsize = 0;

	if( !add( &basic, sizeof( basic ) ) )
		return IPCERR_FAILED;

	if( sdata != NULL )
		if( !add( sdata, ssize ) )
			return IPCERR_FAILED;

	return IPCERR_OK;
}

long _IKEI_MSG::get_result( long * msgres )
{
	return get_basic( msgres );
}

long _IKEI_MSG::set_result( long msgres )
{
	init( IKEI_MSGID_RESULT );
	return set_basic( msgres );
}

long _IKEI_MSG::get_status( long * status, BDATA * str )
{
	return get_basic( status, str );
}

long _IKEI_MSG::set_status( long status, BDATA * str )
{
	init( IKEI_MSGID_STATUS );
	return set_basic( status, str );
}

long _IKEI_MSG::set_status( long status, const char * str )
{
	BDATA text;
	text.set( str, strlen( str ) + 1 );

	return set_status( status, &text );
}

long _IKEI_MSG::get_stats( IKEI_STATS * stats )
{
	return get_struct( 0, stats, sizeof( IKEI_STATS ) );
}

long _IKEI_MSG::set_stats( IKEI_STATS * stats )
{
	init( IKEI_MSGID_STATS );
	return set_struct( 0, stats, sizeof( IKEI_STATS ) );
}

long _IKEI_MSG::get_enable( long * enable )
{
	return get_basic( enable );
}

long _IKEI_MSG::set_enable( long enable )
{
	init( IKEI_MSGID_ENABLE );
	return set_basic( enable );
}

long _IKEI_MSG::get_suspend( long * suspend )
{
	return get_basic( suspend );
}

long _IKEI_MSG::set_suspend( long suspend )
{
	init( IKEI_MSGID_SUSPEND );
	return set_basic( suspend );
}

long _IKEI_MSG::get_peer( IKE_PEER * peer )
{
	return get_struct( 0, peer, sizeof( IKE_PEER ) );
}

long _IKEI_MSG::set_peer( IKE_PEER * peer )
{
	init( IKEI_MSGID_PEER );
	return set_struct( 0, peer, sizeof( IKE_PEER ) );
}

long _IKEI_MSG::get_proposal( IKE_PROPOSAL * proposal )
{
	return get_struct( 0, proposal, sizeof( IKE_PROPOSAL ) );
}

long _IKEI_MSG::set_proposal( IKE_PROPOSAL * proposal )
{
	init( IKEI_MSGID_PROPOSAL );
	return set_struct( 0, proposal, sizeof( IKE_PROPOSAL ) );
}

long _IKEI_MSG::get_client( IKE_XCONF * xconf )
{
	return get_struct( 0, xconf, sizeof( IKE_XCONF ) );
}

long _IKEI_MSG::set_client( IKE_XCONF * xconf )
{
	init( IKEI_MSGID_CLIENT );
	return set_struct( 0, xconf, sizeof( IKE_XCONF ) );
}

long _IKEI_MSG::get_network( long * type, IKE_PH2ID * ph2id )
{
	return get_struct( type, ph2id, sizeof( IKE_PH2ID ) );
}

long _IKEI_MSG::set_network( long type, IKE_PH2ID * ph2id )
{
	init( IKEI_MSGID_NETWORK );
	return set_struct( type, ph2id, sizeof( IKE_PH2ID ) );
}

long _IKEI_MSG::get_cfgstr( long * type, BDATA * str )
{
	return get_basic( type, str );
}

long _IKEI_MSG::set_cfgstr( long type, BDATA * str )
{
	init( IKEI_MSGID_CFGSTR );
	return set_basic( type, str );
}

long _IKEI::attach( long timeout )
{
	return ITH_IPCC::attach( IKEI_PIPE_NAME, timeout );
}

void _IKEI::wakeup()
{
	ITH_IPCC::wakeup();
}

void _IKEI::detach()
{
	ITH_IPCC::detach();
}

long _IKEI::recv_message( IKEI_MSG & msg )
{
	msg.oset( 0 );
	msg.size( sizeof( IKEI_HEADER ) );

	size_t size = msg.size();

	long result = io_recv( msg.buff(), size );

	if( ( result == IPCERR_OK ) || ( result == IPCERR_BUFFER ) )
	{
		msg.oset( 0 );
		if( !msg.get( &msg.header, sizeof( IKEI_HEADER ) ) )
			return IPCERR_FAILED;

		if( msg.header.size > msg.size() )
			result = IPCERR_BUFFER;
	}

	if( result == IPCERR_BUFFER )
	{
		msg.size( msg.header.size );
		if( msg.size() < msg.header.size )
			return IPCERR_FAILED;

		size = msg.size() - sizeof( IKEI_HEADER );
		result = io_recv( msg.buff() + sizeof( IKEI_HEADER ), size );
	}

	return result;
}

long _IKEI::send_message( IKEI_MSG & msg )
{
	msg.header.size = msg.size() + sizeof( msg.header );
	msg.ins( &msg.header, sizeof( msg.header ) );

	return io_send( msg.buff(), msg.header.size );
}

long _IKEI::send_message( IKEI_MSG & msg, long * rslt )
{
	long result;

	result = send_message( msg );
	if( result != IPCERR_OK )
		return result;

	IKEI_MSG msg_rslt;

	result = recv_message( msg_rslt );
	if( result != IPCERR_OK )
		return result;

	return msg_rslt.get_result( rslt );
}

long _IKES::init()
{
	return ITH_IPCS::init( IKEI_PIPE_NAME, false );
}

void _IKES::done()
{
	ITH_IPCS::done();
}

long _IKES::inbound( IKEI ** ikei )
{
	IPCCONN ipcconn;

	long result = ITH_IPCS::inbound( IKEI_PIPE_NAME, ipcconn );

	if( result == IPCERR_OK )
	{
		*ikei = new IKEI;
		if( *ikei == NULL )
			return IPCERR_FAILED;
	
		(*ikei)->io_conf( ipcconn );
	}

	return result;
}

void _IKES::wakeup()
{
	ITH_IPCS::wakeup();
}
