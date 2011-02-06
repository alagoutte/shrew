
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
#include "openssl/rand.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"

bool _CONFIG_MANAGER::file_enumerate( CONFIG & config, int & index )
{

#ifdef WIN32

	BDATA sites_user_spec;
	sites_user_spec.add( sites_user );
	sites_user_spec.ins( "\\*", 2, sites_user_spec.size() - 1 );

	WIN32_FIND_DATA ffdata;
	int found = 0;
	
	HANDLE hfind = FindFirstFile( sites_user_spec.text(), &ffdata );
	if( hfind == INVALID_HANDLE_VALUE )
		return false;

	while( true )
	{
		bool isdir = false;
		if( ffdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
			isdir = true;

		if( !isdir && ( found >= ( index ) ) )
			break;

		if( FindNextFile( hfind, &ffdata ) == 0 )
			break;

		if( !isdir )
			found++;
	}

	FindClose( hfind );
	if( found < index )
		return false;

	config.set_id( ffdata.cFileName );
	index++;

	return file_vpn_load( config );

#else

	int found = 0;

	DIR * dirp = opendir( sites_user.text() );
	if( dirp == NULL )
		return false;

	dirent * dp = NULL;

	while( found <= index )
	{
		dp = readdir( dirp );
		if( dp == NULL )
			break;

		if( dp->d_type & DT_DIR )
			continue;

		found++;
	}

	closedir( dirp );
	if( dp == NULL )
		return false;

	config.set_id( dp->d_name );
	index++;

	return file_vpn_load( config );

#endif

}

bool _CONFIG_MANAGER::file_enumerate_public( CONFIG & config, int & index )
{

#ifdef WIN32

	BDATA sites_user_spec;
	sites_user_spec.add( sites_all );
	sites_user_spec.ins( "\\*", 2, sites_user_spec.size() - 1 );

	WIN32_FIND_DATA ffdata;
	int found = 0;
	
	HANDLE hfind = FindFirstFile( sites_user_spec.text(), &ffdata );
	if( hfind == INVALID_HANDLE_VALUE )
		return false;

	while( true )
	{
		bool isdir = false;
		if( ffdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
			isdir = true;

		if( !isdir && ( found >= ( index ) ) )
			break;

		if( FindNextFile( hfind, &ffdata ) == 0 )
			break;

		if( !isdir )
			found++;
	}

	FindClose( hfind );
	if( found < index )
		return false;

	config.set_id( ffdata.cFileName );
	config.set_ispublic( true );
	index++;

	return file_vpn_load( config );

#else

	return false;

#endif

}

bool _CONFIG_MANAGER::file_vpn_load( CONFIG & config )
{
	BDATA path;
	if( config.get_ispublic() )
		path.add( sites_all );
	else
		path.add( sites_user );

	path.ins( PATH_DELIM, 1, path.size() - 1 );
	path.ins( config.get_id(), strlen( config.get_id() ), path.size() - 1 );

	return file_vpn_load( config, path.text() );
}

bool _CONFIG_MANAGER::file_vpn_load( CONFIG & config, const char * path, bool save_update )
{

#ifdef WIN32

	FILE * fp;
	if( fopen_s( &fp, path, "r" ) )
		return false;

#else

	FILE * fp = fopen( path, "r" );
	if( fp == NULL )
		return false;

#endif

	while( true )
	{
		char	next;
		char	type;
		BDATA	name;
		BDATA	data;

		//
		// get value type
		//

		type = fgetc( fp );

		if( ( type == ' ' ) ||
			( type == '\r' ) )
			continue;

		if( ( type == '\n' ) ||
			( type == EOF ) )
			break;

		//
		// get delim
		//

		if( fgetc( fp ) != ':' )
			goto parse_fail;

		//
		// get value name
		//

		while( true )
		{
			next = fgetc( fp );

			if( ( next == ':' ) ||
				( next == '\n' ) ||
				( next == EOF ) )
				break;

			name.add( next, 1 );
		}

		if( !name.size() )
			goto parse_fail;

		name.add( "", 1 );

		//
		// check delim
		//

		if( next != ':' )
			goto parse_fail;

		//
		// get value data
		//

		while( true )
		{
			next = fgetc( fp );

			if( next == '\r' )
				continue;

			if( ( next == '\n' ) ||
				( next == EOF ) )
				break;

			data.add( next, 1 );
		}

		data.add( "", 1 );

		switch( type )
		{
			case 's':
			{
				config.add_string( name.text(), data.text(), data.size() );
				break;
			}

			case 'n':
			{
				config.set_number( name.text(), atol( data.text() ) );
				break;
			}

			case 'b':
			{
				BDATA b64;
				b64 = data;
				b64.base64_decode();
				config.set_binary( name.text(), b64 );
				break;
			}
		}
	}

	fclose( fp );

	//
	// automatically update configs
	//

	if( update_config( config ) && save_update )
		file_vpn_save( config, path );

	return true;

	parse_fail:

	fclose( fp );

	return false;
}

bool _CONFIG_MANAGER::file_vpn_save( CONFIG & config )
{
	BDATA path;
	if( config.get_ispublic() )
		path.add( sites_all );
	else
		path.add( sites_user );

	path.ins( "/", 1, path.size() - 1 );
	path.ins( config.get_id(), strlen( config.get_id() ), path.size() - 1 );

	return file_vpn_save( config, path.text() );
}

bool _CONFIG_MANAGER::file_vpn_save( CONFIG & config, const char * path )
{

#ifdef WIN32

	FILE * fp;
	if( fopen_s( &fp, path, "w" ) )
		return false;

#else

	FILE * fp = fopen( path, "w" );
	if( fp == NULL )
		return false;

#endif

	for( long index = 0; index < config.count(); index++ )
	{
		CFGDAT * cfgdat = static_cast<CFGDAT*>( config.get_entry( index ) );
		switch( cfgdat->type )
		{
			case DATA_STRING:
				fprintf( fp, "s:%s:%s\n", cfgdat->key.text(), cfgdat->vval.text() );
				break;

			case DATA_NUMBER:
				fprintf( fp, "n:%s:%li\n", cfgdat->key.text(), cfgdat->nval );
				break;

			case DATA_BINARY:
			{
				BDATA b64;
				b64 = cfgdat->vval;
				b64.base64_encode();
				fprintf( fp, "b:%s:%s\n", cfgdat->key.text(), b64.text() );
				break;
			}
		}
	}

	fclose( fp );

	return true;
}

bool _CONFIG_MANAGER::file_vpn_del( CONFIG & config )
{
	BDATA path;
	if( config.get_ispublic() )
		path.add( sites_all );
	else
		path.add( sites_user );

	path.ins( "/", 1, path.size() - 1 );
	path.ins( config.get_id(), strlen( config.get_id() ), path.size() - 1 );

#ifdef WIN32

	return ( DeleteFile( path.text() ) != 0 );

#else

	return ( unlink( path.text() ) == 0 );

#endif

}

bool read_line_pcf( FILE * fp, BDATA & name, BDATA & data )
{
	char	next;
	BDATA	line;

	name.del();
	data.del();

	//
	// read the next line
	//

	while( true )
	{
		next = fgetc( fp );

		if( next == '\r' )
			continue;

		if( next == '\n' )
			break;

		if( next == EOF )
			break;

		line.add( next, 1 );
	}

	//
	// check for valid line
	//

	if( !line.size() )
	{
		if( next == EOF )
			return false;
		else
		{
			name.add( "", 1 );
			data.add( "", 1 );
			return true;
		}
	}

	//
	// read the name value
	//

	while( line.get( &next, 1 ) )
	{
		if( !name.size() )
			if( ( next == ' ' ) || ( next == '!' ) )
				continue;

		if( next == '=' )
			break;

		name.add( next, 1 );
	}

	//
	// verify the delimiter
	//

	if( next != '=' )
		return true;

	//
	// read the data value
	//

	while( line.get( &next, 1 ) )
	{
		if( !data.size() )
			if( next == ' ' )
				continue;

		data.add( next, 1 );
	}

	//
	// trim the values
	//

	if( name.size() )
		while( name.buff()[ name.size() - 1 ] == ' ' )
			name.size( name.size() -1 );

	if( data.size() )
		while( data.buff()[ data.size() - 1 ] == ' ' )
			data.size( data.size() -1 );

	//
	// null terminate values
	//

	name.add( "", 1 );
	data.add( "", 1 );

	return true;
}

#ifndef OPT_DLLPROJ

bool _CONFIG_MANAGER::file_pcf_load( CONFIG & config, const char * path, bool & need_certs )
{

#ifdef WIN32

	FILE * fp;
	if( fopen_s( &fp, path, "r" ) )
		return false;

#else

	FILE * fp = fopen( path, "r" );
	if( fp == NULL )
		return false;

#endif

	//
	// set some sane defaults
	//

	config.set_number( "version", CONFIG_VERSION );
	config.set_number( "network-ike-port", 500 );
	config.set_number( "network-mtu-size", 1380 );

	config.set_string( "client-auto-mode", "pull", 5 );
	config.set_string( "client-iface", "virtual", 8 );
	config.set_number( "client-addr-auto", 1 );

	config.set_string( "network-natt-mode", "enable", 7 );
	config.set_number( "network-natt-port", 4500 );
	config.set_number( "network-natt-rate", 15 );

	config.set_string( "network-frag-mode", "disable", 8 );
	config.set_number( "network-frag-size", 540 );

	config.set_number( "network-dpd-enable", 1 );
	config.set_number( "network-notify-enable", 1 );
	config.set_number( "client-banner-enable", 1 );

	config.set_string( "auth-method", "mutual-psk-xauth", 17 );
	config.set_string( "ident-server-type", "any", 4 );

	config.set_string( "phase1-exchange", "aggressive", 11 );
	config.set_string( "phase1-cipher", "auto", 5 );
	config.set_string( "phase1-hash", "auto", 5 );
	config.set_number( "phase1-dhgroup", 2 );
	config.set_number( "phase1-life-secs", 86400 );

	config.set_string( "phase2-transform", "auto", 5 );
	config.set_string( "phase2-hmac", "auto", 5 );
	config.set_number( "phase2-pfsgroup", 0 );

	config.set_string( "ipcomp-transform", "disabled", 9 );

	config.set_number( "client-dns-used", 1 );
	config.set_number( "client-dns-auto", 1 );
	config.set_number( "client-dns-suffix-auto", 1 );
	config.set_number( "client-splitdns-used", 1 );
	config.set_number( "client-splitdns-auto", 1 );
	config.set_number( "client-wins-used", 1 );
	config.set_number( "client-wins-auto", 1 );

	config.set_number( "phase2-life-secs", 3600 );
	config.set_number( "phase2-life-kbytes", 0 );

	config.set_number( "policy-nailed", 0 );
	config.set_number( "policy-list-auto", 1 );

	//
	// parse the file contents
	//

	long auth_type = 1;
	bool idtype_set = false;

	BDATA	name;
	BDATA	data;

	while( read_line_pcf( fp, name, data ) )
	{
		//
		// Skip invalid name or value lengths
		//

		if( ( name.size() <= 1 ) || ( data.size() <= 1 ) )
			continue;

		//
		// Convert the appropriate values
		//

		if( !_stricmp( name.text(), "Host" ) && data.size() )
			config.set_string( "network-host", data.text(), data.size() );

		if( !_stricmp( name.text(), "AuthType" ) && data.size() )
		{
			auth_type = atol( data.text() );
			switch( auth_type )
			{
				case 1:
					config.set_string( "auth-method", "mutual-psk-xauth", 17 );
					need_certs = false;
					break;
				case 3:
					config.set_string( "auth-method", "mutual-rsa-xauth", 17 );
					need_certs = true;
					break;
				case 5:
					config.set_string( "auth-method", "hybrid-grp-xauth", 17 );
					need_certs = true;
					break;
				default:
					goto parse_fail;
			}
		}

		if( !_stricmp( name.text(), "GroupName" ) && data.size() )
		{
			idtype_set = true;
			config.set_string( "ident-client-type", "keyid", 6 );
			config.set_string( "ident-client-data", data.text(), data.size() );
		}

		if( !_stricmp( name.text(), "GroupPwd" ) && data.size() )
			config.set_binary( "auth-mutual-psk", data );

		if( !_stricmp( name.text(), "enc_GroupPwd" ) && data.size() )
		{
			data.size( data.size() - 1 );
			if( !data.hex_decode() )
				goto parse_fail;

			//
			// decrypt cisco password
			//

			if( data.size() < 48 )
				goto parse_fail;

			unsigned char key[ 40 ];
			unsigned char one[ 20 ];
			unsigned char two[ 20 ];
			
			data.get( one, 20 );
			data.get( two, 20 );

			one[ 19 ] += 1;

			SHA_CTX ctx;
			SHA1_Init( &ctx );
			SHA1_Update( &ctx, one, 20 );
			SHA1_Final( key, &ctx );

			one[ 19 ] += 2;

			SHA1_Init( &ctx );
			SHA1_Update( &ctx, one, 20 );
			SHA1_Final( key + 20, &ctx );

			size_t pwlen = data.size() - 40;

			SHA1_Init( &ctx );
			SHA1_Update( &ctx, data.buff() + 40, pwlen );
			SHA1_Final( one, &ctx );

			if( memcmp( one, two, 20 ) )
				goto parse_fail;

			BDATA pwd;
			data.get( pwd );

			EVP_CIPHER_CTX ctx_cipher;
			EVP_CIPHER_CTX_init( &ctx_cipher );

			EVP_CipherInit_ex(
				&ctx_cipher,
				EVP_des_ede3_cbc(),
				NULL,
				key,
				data.buff(),
				0 );

			EVP_Cipher(
				&ctx_cipher,
				pwd.buff(),
				pwd.buff(),
				( unsigned int ) pwd.size() );

			pwlen -= pwd.buff()[ pwd.size() - 1 ];
			pwd.size( pwlen );

			config.set_binary( "auth-mutual-psk", pwd );
		}

		if( !_stricmp( name.text(), "DHGroup" ) && data.size() )
		{
			long dh_group = atol( data.text() );
			config.set_number( "phase1-dhgroup", dh_group );
		}

		if( !_stricmp( name.text(), "EnableNat" )  && data.size() )
		{
			long enable_nat = atol( data.text() );
			if( enable_nat )
				config.set_string( "network-natt-mode", "enable", 7 );
			else
				config.set_string( "network-natt-mode", "disable", 8 );
		}

		if( !_stricmp( name.text(), "Username" ) && data.size() )
			config.set_string( "client-saved-username", data.text(), data.size() );

	}

	//
	// add local identity type for pcf
	// files without a GroupName line
	//

	if( !idtype_set )
	{
		switch( auth_type )
		{
			case 1:	// mutual-psk-xauth
				config.set_string( "ident-client-type", "address", 6 );
				break;

			case 3: // mutual-rsa-xauth
			case 5: // hybrid-grp-xauth
				config.set_string( "ident-client-type", "asn1dn", 6 );
				break;

			default:
				goto parse_fail;
		}
	}

	fclose( fp );

	return true;

	parse_fail:

	fclose( fp );

	return false;
}

#endif
