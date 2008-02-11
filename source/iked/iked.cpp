
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
	dnsgrpid = 0;
	logflags = LOGFLAG_ECHO;

	retry_count = 2;
	retry_delay = 5;

	sock_ike_open = 0;
	sock_natt_open = 0;

	rand_bytes( &ident, 2 );

	lock_sdb.setname( "sdb" );
	lock_net.setname( "net" );

	unsigned char xauth[] = VEND_XAUTH;
	vend_xauth.set( xauth, sizeof( xauth ) );

	unsigned char frag[] = VEND_FRAG;
	vend_frag.set( frag, sizeof( frag ) );

	unsigned char dpd1[] = VEND_DPD1;
	vend_dpd1.set( dpd1, sizeof( dpd1 ) );

	unsigned char hbeat[] = VEND_HBEAT;
	vend_hbeat.set( hbeat, sizeof( hbeat ) );

	unsigned char natt_v00[] = VEND_NATT_V00;
	vend_natt_v00.set( natt_v00, sizeof( natt_v00 ) );

	unsigned char natt_v01[] = VEND_NATT_V01;
	vend_natt_v01.set( natt_v01, sizeof( natt_v01 ) );

	unsigned char natt_v02[] = VEND_NATT_V02;
	vend_natt_v02.set( natt_v02, sizeof( natt_v02 ) );

	unsigned char natt_v03[] = VEND_NATT_V03;
	vend_natt_v03.set( natt_v03, sizeof( natt_v03 ) );

	unsigned char natt_rfc[] = VEND_NATT_RFC;
	vend_natt_rfc.set( natt_rfc, sizeof( natt_rfc ) );

	unsigned char ssoft[] = VEND_SSOFT;
	vend_ssoft.set( ssoft, sizeof( ssoft ) );

	unsigned char kame[] = VEND_KAME;
	vend_kame.set( kame, sizeof( kame ) );

	unsigned char unity[] = VEND_UNITY;
	vend_unity.set( unity, sizeof( unity ) );

	unsigned char netsc[] = VEND_NETSC;
	vend_netsc.set( netsc, sizeof( netsc ) );

	unsigned char zwall[] = VEND_ZWALL;
	vend_zwall.set( zwall, sizeof( zwall ) );

	unsigned char swind[] = VEND_SWIND;
	vend_swind.set( swind, sizeof( swind ) );

	unsigned char chkpt[] = VEND_CHKPT;
	vend_chkpt.set( chkpt, sizeof( chkpt ) );

	dump_decrypt = false;
	dump_encrypt = false;

	conf_fail = false;
}

_IKED::~_IKED()
{
/*
	//
	// cleaup our netgroup list
	//

	IDB_LIST_PH2ID * idlist;
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
*/
}

bool _IKED::rand_bytes( void * buff, long size )
{
	RAND_pseudo_bytes( ( unsigned char * ) buff, size );
	return true;
}

long _IKED::init( long setlevel )
{

	//
	// check that we are root
	//

#ifdef UNIX

	if( getuid() )
	{
		printf( "you must be root to run this program !!!\n" );
		return LIBIKE_FAILED;
	}

#endif

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

	log.open( NULL, LLOG_DEBUG, logflags );

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

	bool logging = log.open( path_log, level, logflags );
	
	//
	// output our identity
	//

	log.txt( LLOG_NONE,
		"## : IKE Daemon, ver %d.%d.%d\n"
		"## : Copyright %i Shrew Soft Inc.\n"
		"## : This product linked %s\n",
		CLIENT_VER_MAJ,
		CLIENT_VER_MIN,
		CLIENT_VER_BLD,
		CLIENT_YEAR,
		SSLeay_version( SSLEAY_VERSION ) );

	if( logflags & LOGFLAG_SYSTEM )
		log.txt( LLOG_INFO, "ii : opened system log facility\n" );
	else
	{
		if( !logging )
			log.txt( LLOG_ERROR, "!! : failed to open %s\n", path_log );
		else
			log.txt( LLOG_INFO, "ii : opened \'%s\'\n", path_log );
	}

	//
	// open our packet dump interfaces
	//

	if( dump_decrypt )
	{
		if( !pcap_decrypt.open( path_decrypt ) )
			log.txt( LLOG_ERROR, "!! : failed to open %s\n", path_decrypt );
		else
			log.txt( LLOG_INFO, "ii : opened \'%s\'\n", path_decrypt );
	}

	if( dump_encrypt )
	{
		if( !pcap_encrypt.open( path_encrypt ) )
			log.txt( LLOG_ERROR, "!! : failed to open %s\n", path_encrypt );
		else
			log.txt( LLOG_INFO, "ii : opened \'%s\'\n", path_encrypt );
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
	// default socket initialization
	//

	if( !sock_ike_open )
	{
		IKE_SADDR saddr;
		memset( &saddr, 0, sizeof( saddr ) );
		SET_SALEN( &saddr.saddr4, sizeof( sockaddr_in ) );
		saddr.saddr4.sin_family	= AF_INET;
		saddr.saddr4.sin_port = htons( LIBIKE_IKE_PORT );

		if( socket_create( saddr, false ) != LIBIKE_OK )
		{
			char txtaddr[ 16 ];
			text_addr( txtaddr, &saddr, true );
			log.txt( LLOG_ERROR,
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
		SET_SALEN( &saddr.saddr4, sizeof( sockaddr_in ) );
		saddr.saddr4.sin_family	= AF_INET;
		saddr.saddr4.sin_port = htons( LIBIKE_NATT_PORT );

		if( socket_create( saddr, true ) != LIBIKE_OK )
		{
			char txtaddr[ 16 ];
			text_addr( txtaddr, &saddr, true );
			log.txt( LLOG_ERROR,
				"!! : unable to open natt socket for %s\n",
				txtaddr );

			return LIBIKE_FAILED;
		}
	}

#endif

	return LIBIKE_OK;
}

void _IKED::loop()
{
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
	// give the threads a fair chance
	// at starting up before return
	//

	Sleep( 500 );

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
	log.txt( LLOG_INFO,
		"ii : halt signal received, shutting down\n" );

	//
	// remove all peers
	//
/*
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
*/
	state = DSTATE_TERMINATE;

	return LIBIKE_OK;
}
