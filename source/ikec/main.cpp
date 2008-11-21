
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

	ikecRoot r;

	// init our ikec object

	ikec.init( &r );

	// read our command line args

	bool syntax_error = false;
	bool auto_connect = false;

	for( int argi = 0; argi < argc; argi++ )
	{
		// remote site name

		if( !strcmp( argv[ argi ], "-r" ) )
		{
			if( ++argi >= argc )
			{
				syntax_error = true;
				break;
			}

			ikec.file_spec( argv[ argi ] );
			continue;
		}

		// remote site username

		if( !strcmp( argv[ argi ], "-u" ) )
		{
			if( ++argi >= argc )
			{
				syntax_error = true;
				break;
			}

			r.lineEditUsername->setText( argv[ argi ] );
			continue;
		}

		// remote site password

		if( !strcmp( argv[ argi ], "-p" ) )
		{
			if( ++argi >= argc )
			{
				syntax_error = true;
				break;
			}

			r.lineEditPassword->setText( argv[ argi ] );
			syntax_error = false;
			
			continue;
		}

		// auto connect

		if( !strcmp( argv[ argi ], "-a" ) )
		{
			auto_connect = true;
			continue;
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

		r.pushButtonConnect->setHidden( true );
		r.groupBoxCredentials->setHidden( true );
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

			r.pushButtonConnect->setHidden( true );
			r.groupBoxCredentials->setHidden( true );
		}

		// hide the credentials group
		// if the autentication method
		// does not require xauth

		char auth_method[ 64 ] = { 0 };
		ikec.config.get_string( "auth-method", auth_method, 63, 0 );

		if( strstr( auth_method, "xauth" ) == NULL )
			r.groupBoxCredentials->setHidden( true );
	}

	// show the root window

	r.show();

	// auto connect if requested

	if( auto_connect )
		r.siteConnect();

	a.connect( &a, SIGNAL( lastWindowClosed() ), &a, SLOT( quit() ) );

	return a.exec();
}
