
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

#include "config.h"

bool file_to_name( BDATA & path, BDATA & name )
{
	name.del();

	char * lastslash = strrchr( path.text(), PATH_DELIM );
	if( lastslash == NULL )
		name.set( path.text(), path.size() - 1 );
	else
		name.set( lastslash + 1, strlen( lastslash + 1 ) );

	return ( name.size() > 0 );
}

bool _CONFIG_MANAGER::update_config( CONFIG & config )
{
	long version = 0;
	config.get_number( "version", &version );

	if( version >= CONFIG_VERSION )
		return false;

	while( version < CONFIG_VERSION )
	{
		switch( version )
		{
			case 0: // 0 -> 1
			{
				//
				// update the auth-mutual-psk string
				// to a binary value
				//

				BDATA data;
				if( config.get_string( "auth-mutual-psk", data, 0 ) )
				{
					data.size( data.size() - 1 );
					config.set_binary( "auth-mutual-psk", data );
				}

				break;
			}

			case 1: // 1 -> 2
			{
				//
				// update client-dns-enable number to
				// client-dns-used
				//

				long numb;

				if( config.get_number( "client-dns-enable", &numb ) )
				{
					config.del( "client-dns-enable" );
					config.set_number( "client-dns-used", numb );
				}
			
				break;
			}

			case 2: // 2 -> 3
			{
				//
				// update client-dns-suffix-auto
				//

				long numb1 = 0;
				long numb2 = 1;
				BDATA data;

				if( config.get_number( "client-dns-used", &numb1 ) )
					if( numb1 )
						if( config.get_string( "client-dns-suffix", data, 0 ) )
							numb2 = 0;

				config.set_number( "client-dns-suffix-auto", numb2 );

				break;
			}

			case 3: // 3 -> 4
			{
				//
				// update certificate name information
				//

				BDATA path;
				BDATA name;
				BDATA data;

				if( config.get_string( "auth-server-cert", path, 0 ) )
				{
					if( !config.get_binary( "auth-server-cert-data", data ) )
					{
						BDATA path2;
						path2.set( path );
						path2.add( "", 1 );

						file_to_name( path2, name );
						data.file_load( path2.text() );

						config.del( "auth-server-cert" );
						config.set_string( "auth-server-cert-name", name );
						config.set_binary( "auth-server-cert-data", data );
					}
					else
					{
						config.del( "auth-server-cert" );
						config.set_string( "auth-server-cert-name", path );
					}
				}

				if( config.get_string( "auth-client-cert", path, 0 ) )
				{
					if( !config.get_binary( "auth-client-cert-data", data ) )
					{
						BDATA path2;
						path2.set( path );
						path2.add( "", 1 );

						file_to_name( path2, name );
						data.file_load( path2.text() );

						config.del( "auth-client-cert" );
						config.set_string( "auth-client-cert-name", name );
						config.set_binary( "auth-client-cert-data", data );
					}
					else
					{
						config.del( "auth-client-cert" );
						config.set_string( "auth-client-cert-name", path );
					}
				}

				if( config.get_string( "auth-client-key", path, 0 ) )
				{
					if( !config.get_binary( "auth-client-key-data", data ) )
					{
						BDATA path2;
						path2.set( path );
						path2.add( "", 1 );

						file_to_name( path2, name );
						data.file_load( path2.text() );

						config.del( "auth-client-key" );
						config.set_string( "auth-client-key-name", name );
						config.set_binary( "auth-client-key-data", data );
					}
					else
					{
						config.del( "auth-client-key" );
						config.set_string( "auth-client-key-name", path );
					}
				}

				break;
			}
		}

		version++;
	}

	//
	// update to current version
	//

	config.set_number( "version", CONFIG_VERSION );

	return true;
}

_CONFIG_MANAGER::_CONFIG_MANAGER()
{

#ifdef WIN32

	char path_appdata[ MAX_PATH ] = { 0 };

	if( SHGetFolderPath(
			NULL,
			CSIDL_COMMON_APPDATA,
			NULL,
			SHGFP_TYPE_DEFAULT,
			path_appdata ) == S_OK )
	{
		char path_ssoft[] = "\\Shrew Soft VPN";

		BDATA ssoft;
		ssoft.add( path_appdata, strlen( path_appdata ) );
		ssoft.add( path_ssoft, strlen( path_ssoft ) + 1 );

		if( !PathFileExists( ssoft.text() ) )
			CreateDirectory( ssoft.text(), NULL );

		char path_sites[] = "\\Shrew Soft VPN\\sites";

		sites_all.add( path_appdata, strlen( path_appdata ) );
		sites_all.add( path_sites, strlen( path_sites ) + 1 );

		if( !PathFileExists( sites_all.text() ) )
			CreateDirectory( sites_all.text(), NULL );

		char path_certs[] = "\\Shrew Soft VPN\\certs";

		certs_all.add( path_appdata, strlen( path_appdata ) );
		certs_all.add( path_certs, strlen( path_certs ) + 1 );

		if( !PathFileExists( certs_all.text() ) )
			CreateDirectory( certs_all.text(), NULL );
	}

	if( SHGetFolderPath(
			NULL,
			CSIDL_LOCAL_APPDATA,
			NULL,
			SHGFP_TYPE_DEFAULT,
			path_appdata ) == S_OK )
	{
		char path_ssoft[] = "\\Shrew Soft VPN";

		BDATA ssoft;
		ssoft.add( path_appdata, strlen( path_appdata ) );
		ssoft.add( path_ssoft, strlen( path_ssoft ) + 1 );

		if( !PathFileExists( ssoft.text() ) )
			CreateDirectory( ssoft.text(), NULL );

		char path_sites[] = "\\Shrew Soft VPN\\sites";

		sites_user.add( path_appdata, strlen( path_appdata ) );
		sites_user.add( path_sites, strlen( path_sites ) + 1 );

#ifndef OPT_DLLPROJ

		if( !PathFileExists( sites_user.text() ) )
		{
			CreateDirectory( sites_user.text(), NULL );

			// migrate sites from registry

			CONFIG config;
			int	index = 0;

			while( registry_enumerate( config, index ) )
			{
				file_vpn_save( config );
				config.del_all();
			}
		}

#endif

		char path_certs[] = "\\Shrew Soft VPN\\certs";

		certs_user.add( path_appdata, strlen( path_appdata ) );
		certs_user.add( path_certs, strlen( path_certs ) + 1 );

		if( !PathFileExists( certs_user.text() ) )
			CreateDirectory( certs_user.text(), NULL );
	}

#else

	// locate user home directory

	struct passwd * pwd = getpwuid( getuid() );
	if( pwd == NULL )
	{
		printf( "unable to read pwent for %i\n", getuid() );
		exit( -1 );
	}

	// create .ike path

	char path_dotike[] = "/.ike";

	BDATA dotike;

	dotike.add( pwd->pw_dir, strlen( pwd->pw_dir ) );
	dotike.add( path_dotike, strlen( path_dotike ) + 1 );

	struct stat sb;
	memset( &sb, 0, sizeof( sb ) );
	if( stat( dotike.text(), &sb ) )
		mkdir( dotike.text(), S_IRWXU );

	// create sites path

	char path_sites[] = "/.ike/sites";

	sites_user.add( pwd->pw_dir, strlen( pwd->pw_dir ) );
	sites_user.add( path_sites, strlen( path_sites ) + 1 );

	memset( &sb, 0, sizeof( sb ) );
	if( stat( sites_user.text(), &sb ) )
		mkdir( sites_user.text(), S_IRWXU );

	// create certss path

	char path_certs[] = "/.ike/certs";

	certs_user.add( pwd->pw_dir, strlen( pwd->pw_dir ) );
	certs_user.add( path_certs, strlen( path_certs ) + 1 );

	memset( &sb, 0, sizeof( sb ) );
	if( stat( certs_user.text(), &sb ) )
		mkdir( certs_user.text(), S_IRWXU );

	endpwent();

#endif

}
