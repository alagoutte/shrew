
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

#include "ikec.h"

int main( int argc, char ** argv )
{
	IKEC ikec;

	signal( SIGPIPE, SIG_IGN );

	ikec.log( 0,
		"## : VPN Connect, ver %d.%d.%d\n"
		"## : Copyright %i Shrew Soft Inc.\n"
		"## : press the <h> key for help\n",
		CLIENT_VER_MAJ,
		CLIENT_VER_MIN,
		CLIENT_VER_BLD,
		CLIENT_YEAR );

	// read our command line args

	if( ikec.read_opts( argc, argv ) != OPT_RESULT_SUCCESS )
	{
		ikec.show_help();
		return -1;
	}

	// load our site configuration

	if( ikec.config_load() )
	{
		// autoconnect if requested

		if( ikec.auto_connect() )
			ikec.vpn_connect( true );
	}

	// process user input

	bool exit = false;

	while( !exit )
	{
		char next;
		if( !ikec.read_key( next ) )
			next = 'q';

		switch( next )
		{
			case 'c': // <c> connect
				ikec.vpn_connect( true );
				break;

			case 'd': // <d> disconnect
				ikec.vpn_disconnect();
				break;

			case 'h': // <h> help
			case '?': // <?> help
				ikec.log( 0, "%s",
					"Use the following keys to control client connectivity\n"
					" - : <c> connect\n"
					" - : <d> disconnect\n"
					" - : <h> help\n"
					" - : <s> status\n"
					" - : <q> quit\n" );
				break;

			case 'q': // <q> quit
				exit = true;
				break;

			case 's': // <s> status
				ikec.show_stats();
				break;
		}
	}

	return 0;
}
