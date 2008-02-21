
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

//==============================================================================
// helper functions
//

#define DELIM_NEW	','
#define DELIM_OLD	char( 0x255 )

inline char * text_delim( char * text )
{
	char * delim;

	delim = strchr( text, DELIM_NEW );
	if( delim == NULL )
		delim = strchr( text, DELIM_OLD );

	return delim;
}

inline size_t text_length( char * text )
{
	char chrset[] =
	{
		char( DELIM_NEW ),
		char( DELIM_OLD ),
		char( 0x00 )
	};

	return strcspn( text, chrset );
}

//==============================================================================
// configuration classes
//

_CFGDAT::_CFGDAT()
{
	nval = 0;
}

_CONFIG::_CONFIG()
{
}

_CONFIG::~_CONFIG()
{
}

bool _CONFIG::set_id( const char * set_id )
{
	id.del();
	id.set( set_id, strlen( set_id ) + 1 );
	return true;
}

const char * _CONFIG::get_id()
{
	return id.text();
}

_CONFIG & _CONFIG::operator = ( _CONFIG & config )
{
	del_all();
	set_id( config.get_id() );

	for( long index = 0; index < config.count(); index++ )
	{
		CFGDAT * cfgdat = static_cast<CFGDAT*>( config.get_entry( index ) );
		switch( cfgdat->type )
		{
			case DATA_STRING:
				set_string( cfgdat->key.text(), cfgdat->vval.text(), cfgdat->vval.size() );
				break;

			case DATA_NUMBER:
				set_number( cfgdat->key.text(), cfgdat->nval );
				break;

			case DATA_BINARY:
				set_binary( cfgdat->key.text(), cfgdat->vval );
				break;
		}
	}
	
	return *this;
}

CFGDAT * _CONFIG::get_data( long type, const char * key, bool add )
{
	CFGDAT * cfgdat;

	for( long index = 0; index < count(); index++ )
	{
		cfgdat = static_cast<CFGDAT*>( get_entry( index ) );

		if( cfgdat->type != type )
			continue;
		
		if( !strcasecmp( cfgdat->key.text(), key ) )
			return cfgdat;
	}

	if( add )
	{
		cfgdat = new CFGDAT;
		if( cfgdat == NULL )
			return NULL;

		cfgdat->type = type;
		cfgdat->key.set( key, strlen( key ) + 1 );
		add_entry( cfgdat );

		return cfgdat;
	}

	return NULL;
}

void _CONFIG::del( const char * key )
{
	CFGDAT * cfgdat;

	for( long index = 0; index < count(); index++ )
	{
		cfgdat = static_cast<CFGDAT*>( get_entry( index ) );

		if( !strcasecmp( cfgdat->key.text(), key ) )
		{
			del_entry( cfgdat );
			delete cfgdat;
		}
	}
}

void _CONFIG::del_all()
{
	clean();
}

bool _CONFIG::add_string( const char * key, const char * val, size_t size )
{
	CFGDAT * cfgdat = get_data( DATA_STRING, key, true );
	if( !cfgdat )
		return false;

	if( cfgdat->vval.size() )
	{
		cfgdat->vval.set( ",", 1, cfgdat->vval.size() - 1 );
		cfgdat->vval.add( val, size );
		cfgdat->vval.add( "", 1 );
	}
	else
	{
		cfgdat->vval.add( val, size );
		cfgdat->vval.add( "", 1 );
	}

	return true;
}

bool _CONFIG::set_string( const char * key, const char * val, size_t size )
{
	del( key );
	add_string( key, val, size );

	return true;
}

bool _CONFIG::get_string( const char * key, char * val, size_t size, int index )
{
	CFGDAT * cfgdat = get_data( DATA_STRING, key );
	if( !cfgdat )
		return false;

	char * strptr = cfgdat->vval.text();

	for( ; index > 0; index-- )
	{
		char * tmpptr = text_delim( strptr );
		if( tmpptr == NULL )
			return false;

		strptr = tmpptr + 1;
	}

	// calculate final length

	size--;

	size_t clen = text_length( strptr );
	if( clen < size )
		size = clen;

	memcpy( val, strptr, size );
	val[ size ] = 0;

	return true;
}

long _CONFIG::has_string( const char * key, const char * val, size_t size )
{
	CFGDAT * cfgdat = get_data( DATA_STRING, key );
	if( !cfgdat )
		return -1;

	char * oldptr = cfgdat->vval.text();
	char * newptr = cfgdat->vval.text();

	long index = 0;

	while( newptr )
	{
		newptr = text_delim( oldptr );

		if( newptr )
		{
			size_t diff = newptr - oldptr;
			if( diff < size )
				size = diff;
		}

		if( !strncmp( val, oldptr, size ) )
			return index;
		
		oldptr = newptr + 1;
		index++;
	}

	return -1;
}

bool _CONFIG::set_number( const char * key, long val )
{
	CFGDAT * cfgdat = get_data( DATA_NUMBER, key, true );
	if( !cfgdat )
		return false;

	cfgdat->nval = val;

	return true;
}

bool _CONFIG::get_number( const char * key, long * val )
{
	CFGDAT * cfgdat = get_data( DATA_NUMBER, key );
	if( !cfgdat )
		return false;

	*val = cfgdat->nval;

	return true;
}

bool _CONFIG::set_binary( const char * key, BDATA & val )
{
	CFGDAT * cfgdat = get_data( DATA_BINARY, key, true );
	if( !cfgdat )
		return false;

	cfgdat->vval = val;

	return true;
}

bool _CONFIG::get_binary( const char * key, BDATA & val )
{
	CFGDAT * cfgdat = get_data( DATA_BINARY, key );
	if( !cfgdat )
		return false;

	val = cfgdat->vval;

	return true;
}

bool _CONFIG::file_write( const char * path )
{
	FILE * fp = fopen( path, "w" );
	if( fp == NULL )
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

bool _CONFIG::file_read( const char * path )
{
	FILE * fp = fopen( path, "r" );
	if( fp == NULL )
		return false;

	long line = 0;

	while( true )
	{
		int	next;
		int	type;
		BDATA	name;
		BDATA	data;

		//
		// get value type
		//

		type = fgetc( fp );

		if( ( type == ' ' ) ||
			( type == '\t' ) ||
			( type == '\r' ) ||
			( type == '\n' ) )
			continue;

		if( type == EOF )
			break;

		//
		// get delim
		//

		if( fgetc( fp ) != ':' )
		{
			printf( "invalid delimiter \'%c\' between type and name ( line %i )\n",
				next, line );
			goto parse_fail;
		}

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
		{
			printf( "invalid delimiter \'%c\' between name and value ( line %i )\n",
				next, line );
			goto parse_fail;
		}

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

		if( !data.size() )
			goto parse_fail;

		data.add( "", 1 );

		switch( type )
		{
			case 's':
			{
//				printf( "string attribute %s read ( %i bytes )\n",
//					name.text(),
//					data.size() );
				add_string( name.text(), data.text(), data.size() );
				break;
			}

			case 'n':
			{
//				printf( "number attribute %s read ( %i bytes )\n",
//					name.text(),
//					data.size() );
				set_number( name.text(), atol( data.text() ) );
				break;
			}

			case 'b':
			{
//				printf( "binary attribute %s read ( %i bytes )\n",
//					name.text(),
//					data.size() );
				BDATA b64;
				b64 = data;
				b64.base64_decode();
				set_binary( name.text(), b64 );
				break;
			}

			default:
				printf( "invalid value type \'%c\' ( line %i )\n",
					type, line );
				goto parse_fail;
		}

		line++;
	}

	fclose( fp );

	return true;

	parse_fail:

	printf( "parse error in line %i\n", line );

	fclose( fp );

	return false;
}
