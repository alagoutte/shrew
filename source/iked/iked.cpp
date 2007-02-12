
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

_IKED::_IKED()
{
	state = DSTATE_ACTIVE;
	refcount = 0;
	tunnelid = 2;
	policyid = 1;

	retry_count = 2;
	retry_delay = 10;

	sock_ike_open = 0;
	sock_natt_open = 0;

	rand_bytes( &ident, 2 );

	unsigned char xauth[] = VEND_XAUTH;
	vend_xauth.set( xauth, sizeof( xauth ) );

	unsigned char unity[] = VEND_UNITY;
	vend_unity.set( unity, sizeof( unity ) );

	unsigned char frag[] = VEND_FRAG;
	vend_frag.set( frag, sizeof( frag ) );

	unsigned char natt_v02[] = VEND_NATT_V02;
	vend_natt_v02.set( natt_v02, sizeof( natt_v02 ) );

	unsigned char natt_rfc[] = VEND_NATT_RFC;
	vend_natt_rfc.set( natt_rfc, sizeof( natt_rfc ) );

	unsigned char dpd1[] = VEND_DPD1;
	vend_dpd1.set( dpd1, sizeof( dpd1 ) );

	unsigned char kame[] = VEND_KAME;
	vend_kame.set( kame, sizeof( kame ) );

	dump_ike = false;
	dump_pub = false;

	conf_fail = false;
}

_IKED::~_IKED()
{
	//
	// cleaup our netgroup list
	//

	IKE_ILIST * ilist;
	while( true )
	{
		 ilist = ( IKE_ILIST * ) list_netgrp.get_item( 0 );
		 if( ilist == NULL )
			 break;
		 list_netgrp.del_item( ilist );
		 delete ilist;
	}

	//
	// cleaup our policy list
	//

	IDB_POLICY * policy;
	while( true )
	{
		 policy = ( IDB_POLICY * ) list_policy.get_item( 0 );
		 if( policy == NULL )
			 break;

		 list_policy.del_item( policy );
		 delete policy;
	}
}

bool _IKED::rand_bytes( void * buff, long size )
{
	RAND_pseudo_bytes( ( unsigned char * ) buff, size );
	return true;
}

long _IKED::init( long setlevel )
{
	//
	// initialize ike service interface
	//

	if( !ikes.init() )
	{
		printf( "one at a time please !!!\n" );
		return LIBIKE_FAILED;
	}

	//
	// ititialize openssl
	//

	OpenSSL_add_all_algorithms();

	//
	// open our log ( debug and echo )
	//

	log.open( NULL, LOG_DEBUG, true );

	//
	// output our identity
	//

	log.txt( LOG_NONE,
		"## : IKE Daemon, ver %d.%d.%d\n"
		"## : Copyright %i Shrew Soft Inc.\n"
		"## : This product linked %s\n",
		CLIENT_VER_MAJ,
		CLIENT_VER_MIN,
		CLIENT_VER_BLD,
		CLIENT_YEAR,
		SSLeay_version( SSLEAY_VERSION ) );

	//
	// load our configuration
	//

	if( !conf_load( PATH_CONF ) )
		return LIBIKE_FAILED;

	//
	// open our log ( config settings )
	//

	if( setlevel )
		level = setlevel;

	if( !log.open( path_log, level, true ) )
	{
		log.txt( LOG_ERROR, "!! : failed to open %s\n", path_log );
		return LIBIKE_FAILED;
	}
	else
		log.txt( LOG_INFO, "ii : opened %s\'\n", path_log );

	//
	// open our packet dump interfaces
	//

	if( dump_ike )
	{
		if( !pcap_ike.open( path_ike ) )
			log.txt( LOG_ERROR, "!! : failed to open %s\n", path_ike );
		else
			log.txt( LOG_INFO, "ii : opened %s\'\n", path_ike );
	}

	if( dump_pub )
	{
		if( !pcap_pub.open( path_pub ) )
			log.txt( LOG_ERROR, "!! : failed to open %s\n", path_pub );
		else
			log.txt( LOG_INFO, "ii : opened %s\'\n", path_pub );
	}

	//
	// initialize our vnet interface
	//

	vnet_init();

	//
	// initialize our socket interface
	//

	socket_init();

	//
	// socket stuff
	//

	if( !sock_ike_open )
	{
		IKE_SADDR saddr;
		memset( &saddr, 0, sizeof( saddr ) );
		saddr.saddr4.sin_family	= AF_INET;
#ifdef UNIX
		saddr.saddr4.sin_len = sizeof( sockaddr_in );
#endif
		saddr.saddr4.sin_port = htons( LIBIKE_IKE_PORT );

		if( socket_create( saddr, false ) != LIBIKE_OK )
		{
			char txtaddr[ 16 ];
			text_addr( txtaddr, &saddr, true );
			log.txt( LOG_ERROR,
				"!! : unable to open ike socket for %s\n",
				txtaddr );

			return LIBIKE_FAILED;
		}
	}

#ifdef OPT_NATT

	if( !sock_natt_open )
	{
		IKE_SADDR saddr;
		memset( &saddr, 0, sizeof( saddr ) );
		saddr.saddr4.sin_family	= AF_INET;
#ifdef UNIX
		saddr.saddr4.sin_len = sizeof( sockaddr_in );
#endif
		saddr.saddr4.sin_port = htons( LIBIKE_NATT_PORT );

		if( socket_create( saddr, true ) != LIBIKE_OK )
		{
			char txtaddr[ 16 ];
			text_addr( txtaddr, &saddr, true );
			log.txt( LOG_ERROR,
				"!! : unable to open natt socket for %s\n",
				txtaddr );

			return LIBIKE_FAILED;
		}
	}

#endif

	//
	// start our ike network thread
	//

	ith_nwork.exec( this );

	//
	// start our ike pfkey thread
	//

	ith_pfkey.exec( this );

	//
	// start our execution timer
	//

	ith_timer.run( 100 );

	//
	// give the thread a fair chance
	// at starting up before return
	//

	Sleep( 1000 );

	return LIBIKE_OK;
}

void _IKED::loop()
{
	//
	// accept admin connections
	//

	while( refcount > 0 )
	{
		attach_ike_admin();
		Sleep( 10 );
	}

	socket_done();

	log.close();
}

long _IKED::halt()
{
	log.txt( LOG_INFO,
		"ii : halt signal received, shutting down\n" );

	//
	// remove all peers
	//

	lock_sdb.lock();

	long count = iked.list_peer.get_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		IDB_PEER * peer = ( IDB_PEER * ) iked.list_peer.get_item( index );

		peer->end( false );
		peer->inc( false );
		peer->lstate |= LSTATE_DELETE;

		if( peer->dec( false ) )
		{
			index--;
			count--;
		}
	}	

	lock_sdb.unlock();

	while( list_peer.get_count() )
		Sleep( 1000 );

	state = DSTATE_TERMINATE;

	return LIBIKE_OK;
}
