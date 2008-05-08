
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

long _IKEI_MSG::set_status( long status, char * str )
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

bool _IKEI::attach( long timeout )
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

long _IKEI::send_message( IKEI_MSG & msg )
{
	msg.header.size = msg.size() + sizeof( msg.header );
	msg.ins( &msg.header, sizeof( msg.header ) );

	return io_send( msg.buff(), msg.header.size );
}

long _IKEI::recv_message( IKEI_MSG & msg )
{
	msg.oset( 0 );
	msg.size( sizeof( IKEI_HEADER ) );

	size_t size = msg.size();

	long result = io_recv( msg.buff(), size );

	if( ( result == IPCERR_OK ) || ( result == IPCERR_BUFFER ) )
	{
		if( !msg.get( &msg.header, sizeof( IKEI_HEADER ) ) )
			return IPCERR_FAILED;

		if( msg.header.size > msg.size() )
			result = IPCERR_BUFFER;
	}

	if( result == IPCERR_BUFFER )
	{
		msg.size( msg.header.size );
		size = msg.size() - sizeof( IKEI_HEADER );

		result = io_recv( msg.buff() + sizeof( IKEI_HEADER ), size );
	}

	return result;
}

long _IKEI::send_recv_message( IKEI_MSG & msg )
{
	long result = send_message( msg );
	if( result != IPCERR_OK )
		return result;

	return recv_message( msg );
}

bool _IKES::init()
{
	return ITH_IPCS::init( IKEI_PIPE_NAME, false );
}

IKEI * _IKES::inbound()
{
	IPCCONN ipcconn;
	if( !ITH_IPCS::inbound( IKEI_PIPE_NAME, ipcconn ) )
		return NULL;

	IKEI * ikei = new IKEI;
	if( ikei != NULL )
		ikei->io_conf( ipcconn );

	return ikei;
}

#ifdef UNIX

_IKEI::_IKEI()
{
	sock = -1;
}

_IKEI::~_IKEI()
{
	detach();
}

long _IKEI::attach( long timeout )
{
	sock = socket( AF_UNIX, SOCK_STREAM, 0 );
	if( sock == -1 )
		return IKEI_FAILED;

	struct sockaddr_un saddr;
	saddr.sun_family = AF_UNIX;

	long sun_len =  strlen( IKEI_SOCK_NAME ) +
			sizeof( saddr.sun_family );

#ifndef __linux__
	sun_len += sizeof( saddr.sun_len );
	saddr.sun_len = sun_len;
#endif

	strcpy( saddr.sun_path, IKEI_SOCK_NAME );

	if( connect( sock, ( struct sockaddr * ) &saddr, sun_len ) < 0 )
		return IKEI_FAILED;

	return IKEI_OK;
}

void _IKEI::detach()
{
	if( sock != -1 )
	{
		close( sock );
		sock = -1;
	}
}

long _IKEI::wait_msg( IKEI_MSG & msg, long timeout )
{
	fd_set fdset;
	FD_ZERO( &fdset );
	FD_SET( sock, &fdset );

	struct timeval tv;
	tv.tv_sec = timeout / 100;
	tv.tv_usec = timeout % 100;

	if( select( sock + 1, &fdset, NULL, NULL, &tv ) <= 0 )
		return IKEI_NODATA;

	ssize_t size = recv( sock, &msg, sizeof( msg ), MSG_PEEK );
	if( size != sizeof( msg ) )
		return IKEI_FAILED;

	return IKEI_OK;
}

long _IKEI::recv_msg( void * data, size_t & size )
{
	if( recv( sock, data, sizeof( IKEI_MSG ), 0 ) <= 0 )
		return IKEI_FAILED;

	IKEI_MSG * msg = ( IKEI_MSG * ) data;

	unsigned char * buff = ( unsigned char * ) data;

	long result = recv( sock,
					buff + sizeof( IKEI_MSG ),
					msg->size - sizeof( IKEI_MSG ),
					0 );

	if( result < 0 )
		return IKEI_FAILED;

	size = result + sizeof( IKEI_MSG );

	return IKEI_OK;
}

long _IKEI::send_msg( void * data, size_t size )
{
	long result = send( sock, data, size, 0 );
	if( result < 0 )
		return IKEI_FAILED;

	return IKEI_OK;
}

_IKES::_IKES()
{
	sock = -1;
}

_IKES::~_IKES()
{
	if( sock != -1 )
		close( sock );
}

bool _IKES::init()
{
	unlink( IKEI_SOCK_NAME );

	sock = socket( AF_UNIX, SOCK_STREAM, 0 );
	if( sock == -1 )
		return false;

	struct sockaddr_un saddr;
	saddr.sun_family = AF_UNIX;

	long sun_len =  strlen( IKEI_SOCK_NAME ) +
			sizeof( saddr.sun_family );

#ifndef __linux__
        sun_len += sizeof( saddr.sun_len );
        saddr.sun_len = sun_len;
#endif

	strcpy( saddr.sun_path, IKEI_SOCK_NAME );

	if( bind( sock, ( struct sockaddr * ) &saddr, sun_len ) < 0 )
		return false;

	if( chmod( IKEI_SOCK_NAME, S_IRWXU | S_IRWXG | S_IRWXO ) < 0 )
		return false;

	if( listen( sock, 5 ) < 0 )
		return false;

	return true;
}

IKEI * _IKES::inbound()
{
	fd_set fdset;
	FD_ZERO( &fdset );
	FD_SET( sock, &fdset );

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 10000;

	if( select( sock + 1, &fdset, NULL, NULL, &tv ) <= 0 )
		return NULL;

	int csock = accept( sock, NULL, NULL );
	if( csock < 0 )
		return NULL;

	IKEI * ikei = new IKEI;
	ikei->sock = csock;

	return ikei;
}

#endif
