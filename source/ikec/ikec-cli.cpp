
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

#include "ikec-cli.h"

const char * prompt( EditLine * e )
{
	return "<< : enter xauth username : ";
}

bool _IKEC_CLI::get_username()
{
	read_str( username );
}

bool _IKEC_CLI::get_password()
{
	read_pwd( password, "<< : enter xauth password : " );
}

bool _IKEC_CLI::get_filepass( BDATA & path )
{
	log( 0, "file password required for %s\n", path.text() );
	read_pwd( fpass, "<< : enter file password : " );
}

bool _IKEC_CLI::set_state()
{
	switch( cstate )
	{
		case IKEC_STATE_DISCONNECTED:
			log( 0, "disconnected\n" );
			break;

		case IKEC_STATE_CONNECTING:
			log( 0, "connecting\n" );
			break;

		case IKEC_STATE_CONNECTED:
			log( 0, "connected\n" );
			break;

		case IKEC_STATE_DISCONNECTING:
			log( 0, "disconnecting\n" );
			break;
	}
}

bool _IKEC_CLI::set_stats()
{
}

bool _IKEC_CLI::set_status( long & status, BDATA & text )
{
	switch( status )
	{
		case STATUS_ENABLED:
			log( status, "tunnel enabled\n" );
			break;

		case STATUS_DISABLED:
			log( status, "tunnel disabled\n" );
			break;

		case STATUS_BANNER:
			log( status, "login banner \n\n%s\n",
				 text.text() );
			break;

		default:
			log( status, "%s", text.text() );
	}
}

_IKEC_CLI::_IKEC_CLI()
{
	// init line editor
	el = el_init( "ikec", stdin, stdout, stderr );
	el_set( el, EL_EDITOR, "emacs" );
	el_set( el, EL_PROMPT, &prompt );
}

_IKEC_CLI::~_IKEC_CLI()
{
	// free line editor
	el_end( el );
}

bool _IKEC_CLI::log( long code, const char * format, ... )
{
	switch( code )
	{
		case STATUS_INFO:
			printf( "%s", ">> : " );
			break;

		case STATUS_WARN:
			printf( "%s", "ww : " );
			break;

		case STATUS_FAIL:
			printf( "%s", "!! : " );
			break;

		default:
			printf( "%s", "ii : " );
			break;
	}

	va_list list;
	va_start( list, format );
	vprintf( format, list );

	return true;
}

bool _IKEC_CLI::read_key( char & value )
{
	return el_getc( el, &value ) != -1;
}

bool _IKEC_CLI::read_str( BDATA & value )
{
	int size = 0;
	const char * line;

	while( size < 1 )
	{
		line = el_gets( el, &size );
		if( line == NULL )
			return false;
	}

	value.del();
	value.set( line, --size );

	return true;
}

bool _IKEC_CLI::read_pwd( BDATA & value, const char * prompt )
{
	//
	// using libedit to accept password
	// input is maddening. there is no
	// way to disable echo
	//

	const char * line = getpass( prompt );
	printf( "%s", "\n" );

	value.del();
	value.set( line, strlen( line ) );

	return true;
}

void _IKEC_CLI::show_stats()
{
	static char state_disconnected[] = "disconnected";
	static char state_connecting[] = "connecting";
	static char state_connected[] = "connected";
	static char state_disconnecting[] = "disconnecting";

	static char xport_ike_esp[] = "IKE | ESP";
	static char xport_ike_natt_cisco[] = "IKE | CISCO-UDP / ESP";
	static char xport_ike_natt_v00[] = "NAT-T v00 / IKE | ESP";
	static char xport_ike_natt_v01[] = "NAT-T v01 / IKE | ESP";
	static char xport_ike_natt_v02[] = "NAT-T v02 / IKE | ESP";
	static char xport_ike_natt_v03[] = "NAT-T v03 / IKE | ESP";
	static char xport_ike_natt_rfc[] = "NAT-T RFC / IKE | ESP";

	static char enabled[] = "enabled";
	static char disabled[] = "disabled";

	char * state;
	char * xport;
	char * frag;
	char * dpd;

	switch( cstate )
	{
		case IKEC_STATE_DISCONNECTED:
			state = state_disconnected;
			break;

		case IKEC_STATE_CONNECTING:
			state = state_connecting;
			break;

		case IKEC_STATE_CONNECTED:
			state = state_connected;
			break;

		case IKEC_STATE_DISCONNECTING:
			state = state_disconnecting;
			break;
	}

	switch( stats.natt )
	{
		case IPSEC_NATT_NONE:
			xport = xport_ike_esp;
			break;

		case IPSEC_NATT_CISCO:
			xport = xport_ike_natt_cisco;
			break;

		case IPSEC_NATT_V00:
			xport = xport_ike_natt_v00;
			break;

		case IPSEC_NATT_V01:
			xport = xport_ike_natt_v01;
			break;

		case IPSEC_NATT_V02:
			xport = xport_ike_natt_v02;
			break;

		case IPSEC_NATT_V03:
			xport = xport_ike_natt_v03;
			break;

		case IPSEC_NATT_RFC:
			xport = xport_ike_natt_rfc;
			break;
	}

	if( !stats.frag )
		frag = disabled;
	else
		frag = enabled;

	if( !stats.dpd )
		dpd = disabled;
	else
		dpd = enabled;

	log( 0,
		"current connection satus\n"
		" - : tunnel state      = %s\n"
		" - : IPsec SAs in use  = %i\n"
		" - : IPsec SAs dead    = %i\n"
		" - : IPsec SAs failed  = %i\n"
		" - : transport used    = %s\n"
		" - : ike fragmenataion = %s\n"
		" - : dead peer detect  = %s\n",
		state,
		stats.sa_good,
		stats.sa_dead,
		stats.sa_fail,
		xport,
		frag,
		dpd );
}
