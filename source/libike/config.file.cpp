
/*
 * Copyright (c) 2007
 *      Shrew Soft Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is strictly prohibited. The copywright holder of this
 * software is the sole owner and no other party should have access
 * unless explicit permission was granted by an authorized person.
 *
 * AUTHOR : Matthew Grooms
 *          mgrooms@shrew.net
 *
 */

#include "config.h"
#include "openssl/rand.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"

bool _CONFIG_MANAGER::file_load_vpn( CONFIG * config, char * path )
{
	FILE * fp;
	if( fopen_s( &fp, path, "r" ) )
		return false;

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
				config->add_string( name.text(), data.text(), data.size() );
				break;
			}

			case 'n':
			{
				config->set_number( name.text(), atol( data.text() ) );
				break;
			}

			case 'b':
			{
				BDATA b64;
				b64 = data;
				b64.base64_decode();
				config->set_binary( name.text(), b64 );
				break;
			}
		}
	}

	fclose( fp );

	return true;

	parse_fail:

	fclose( fp );

	return false;
}

bool _CONFIG_MANAGER::file_save_vpn( CONFIG * config, char * path )
{
	FILE * fp;
	if( fopen_s( &fp, path, "w" ) )
		return false;

	for( long index = 0; index < count(); index++ )
	{
		CFGDAT * cfgdat = static_cast<CFGDAT*>( get_entry( index ) );
		switch( cfgdat->type )
		{
			case DATA_STRING:
				fprintf( fp, "s:%s:%s\n", cfgdat->key.text(), cfgdat->vval.text() );
				break;

			case DATA_NUMBER:
				fprintf( fp, "n:%s:%i\n", cfgdat->key.text(), cfgdat->nval );
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

bool _CONFIG_MANAGER::file_load_pcf( CONFIG * config, char * path, bool & need_certs )
{
	FILE * fp;
	if( fopen_s( &fp, path, "r" ) )
		return false;

	//
	// set some sane defaults
	//

	config->set_number( "version", 3 );
	config->set_number( "network-ike-port", 500 );
	config->set_number( "network-mtu-size", 1380 );

	config->set_string( "client-auto-mode", "pull", 5 );
	config->set_string( "client-iface", "virtual", 8 );
	config->set_number( "client-addr-auto", 1 );

	config->set_string( "network-natt-mode", "enable", 7 );
	config->set_number( "network-natt-port", 4500 );
	config->set_number( "network-natt-rate", 15 );

	config->set_string( "network-frag-mode", "disable", 8 );
	config->set_number( "network-frag-size", 540 );

	config->set_number( "network-dpd-enable", 1 );
	config->set_number( "network-notify-enable", 1 );
	config->set_number( "client-banner-enable", 1 );

	config->set_string( "auth-method", "mutual-psk-xauth", 17 );
	config->set_string( "ident-server-type", "any", 4 );

	config->set_string( "phase1-exchange", "aggressive", 11 );
	config->set_string( "phase1-cipher", "auto", 5 );
	config->set_string( "phase1-hash", "auto", 5 );
	config->set_number( "phase1-dhgroup", 2 );
	config->set_number( "phase1-life-secs", 86400 );

	config->set_string( "phase2-transform", "auto", 5 );
	config->set_string( "phase2-hmac", "auto", 5 );
	config->set_number( "phase2-pfsgroup", 0 );

	config->set_string( "ipcomp-transform", "disabled", 9 );

	config->set_number( "client-dns-used", 1 );
	config->set_number( "client-dns-auto", 1 );
	config->set_number( "client-dns-suffix-auto", 1 );
	config->set_number( "client-splitdns-used", 1 );
	config->set_number( "client-splitdns-auto", 1 );
	config->set_number( "client-wins-used", 1 );
	config->set_number( "client-wins-auto", 1 );

	config->set_number( "phase2-life-secs", 3600 );
	config->set_number( "phase2-life-kbytes", 0 );

	config->set_number( "policy-nailed", 0 );
	config->set_number( "policy-list-auto", 1 );

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
			config->set_string( "network-host", data.text(), data.size() );

		if( !_stricmp( name.text(), "AuthType" ) && data.size() )
		{
			auth_type = atol( data.text() );
			switch( auth_type )
			{
				case 1:
					config->set_string( "auth-method", "mutual-psk-xauth", 17 );
					need_certs = false;
					break;
				case 3:
					config->set_string( "auth-method", "mutual-rsa-xauth", 17 );
					need_certs = true;
					break;
				case 5:
					config->set_string( "auth-method", "hybrid-grp-xauth", 17 );
					need_certs = true;
					break;
				default:
					goto parse_fail;
			}
		}

		if( !_stricmp( name.text(), "GroupName" ) && data.size() )
		{
			idtype_set = true;
			config->set_string( "ident-client-type", "keyid", 6 );
			config->set_string( "ident-client-data", data.text(), data.size() );
		}

		if( !_stricmp( name.text(), "GroupPwd" ) && data.size() )
			config->set_binary( "auth-mutual-psk", data );

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
				pwd.size() );

			pwlen -= pwd.buff()[ pwd.size() - 1 ];
			pwd.size( pwlen );

			config->set_binary( "auth-mutual-psk", pwd );
		}

		if( !_stricmp( name.text(), "DHGroup" ) && data.size() )
		{
			long dh_group = atol( data.text() );
			config->set_number( "phase1-dhgroup", dh_group );
		}

		if( !_stricmp( name.text(), "EnableNat" )  && data.size() )
		{
			long enable_nat = atol( data.text() );
			if( enable_nat )
				config->set_string( "network-natt-mode", "enable", 7 );
			else
				config->set_string( "network-natt-mode", "disable", 8 );
		}

		if( !_stricmp( name.text(), "Username" ) && data.size() )
			config->set_string( "client-saved-username", data.text(), data.size() );

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
				config->set_string( "ident-client-type", "address", 6 );
				break;

			case 3: // mutual-rsa-xauth
			case 5: // hybrid-grp-xauth
				config->set_string( "ident-client-type", "asn1dn", 6 );
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
