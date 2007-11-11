
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

IKEC ikec;

int main( int argc, char ** argv )
{
	signal( SIGPIPE, SIG_IGN );

	// init the app

	QApplication a( argc, argv );

	// create our root window

	root w;

	// init our ikec object

	ikec.init( &w );

	// read our command line args

	bool syntax_error = true;

	for( int argi = 0; argi < argc; argi++ )
	{
		// remote site name

		if( !strcmp( argv[ argi ], "-r" ) )
		{
			if( ++argi >= argc )
				break;

			ikec.file_spec( argv[ argi++ ] );
			syntax_error = false;
		}
	}

	if( syntax_error )
	{
		ikec.log( STATUS_FAIL,
			"invalid parameters specified ...\n" );

		ikec.log( STATUS_INFO,
			"ikec -r \"name\" [ -u <user> ][ -p <pass> ][ -a ]\n"
			"  -r\tsite configuration path\n"
			"  -u\tconnection user name\n"
			"  -p\tconnection user password\n"
			"  -a\tauto connect\n" );

		w.pushButtonConnect->setHidden( true );
		w.groupBoxCredentials->setHidden( true );
	}
	else
	{
		// load site config

		if( ikec.config.file_read( ikec.file_path() ) )
		{
			// config loaded

			ikec.log( STATUS_INFO, "config loaded for site \'%s\'\n",
				ikec.file_spec() );
		}
		else
		{
			// config load failed

			ikec.log( STATUS_INFO, "failed to load \'%s\'\n",
				ikec.file_spec() );

			w.pushButtonConnect->setHidden( true );
			w.groupBoxCredentials->setHidden( true );
		}

		// hide the credentials group
		// if the autentication method
		// does not require xauth

		char auth_method[ 64 ] = { 0 };
		ikec.config.get_string( "auth-method", auth_method, 63, 0 );

		if( strstr( auth_method, "xauth" ) == NULL )
			w.groupBoxCredentials->setHidden( true );
	}

	// show the root window

	w.show();

	a.connect( &a, SIGNAL( lastWindowClosed() ), &a, SLOT( quit() ) );

	return a.exec();
}
