
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

/*
  * STRING helper functions
  *
  */

bool cpp_strdup( const char ** new_string, const char * src_string )
{
        // sanity check for pointer

        if( !src_string )
                return false;

        // get string length and allocate storage

        int string_len = strlen( src_string ) + 1;
        char * tmp_string = new char[ string_len ];

        // check for memory allocation error

        if( !tmp_string )
                return false;

        // copy contents ( including null )

        memcpy( tmp_string, src_string, string_len );
        *new_string = tmp_string;

        return true;
}
		
bool cpp_strdel( const char ** del_string )
{
        // sanity check for pointer

        if( !( *del_string ) )
                return false;
 
        // delte the string contents and null pointer

        delete [] *del_string;
        *del_string = 0;
         
        return true;
}

// string duplication up to length chars using c++ add
// for memory allocation

bool cpp_strndup( const char ** new_string, const char * src_string, unsigned long length )
{
        // sanity check for pointer

        if( !src_string )
                return false;

        // calc new string length and allocate storage
 
        unsigned long string_len = strlen( src_string );
        if( length < string_len )
                string_len = length;
        
        char * tmp_string = new char[ string_len + 1 ];   

        // check for memory allocation error

        if( !tmp_string )
                return false;

        // copy contents and null terminate

        memcpy( tmp_string, src_string, string_len );
        tmp_string[ string_len ] = 0;
        *new_string = tmp_string;
 
        return true;
}

/*
 * CONFIG class member functions
 *
 */

_CFGDAT::_CFGDAT()
{
	key = 0;
	bval = 0;
	size = 0;
}

_CONFIG::_CONFIG()
{
	id = 0;
}

_CONFIG::~_CONFIG()
{
	cpp_strdel( &id );
}

bool _CONFIG::set_id( const char * set_id )
{
	cpp_strdel( &id );
	cpp_strdup( &id, set_id );

	return true;
}

const char * _CONFIG::get_id()
{
	return id;
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
				set_string( cfgdat->key, cfgdat->sval, cfgdat->size );
				break;

			case DATA_NUMBER:
				set_number( cfgdat->key, cfgdat->nval );
				break;

			case DATA_BINARY:
				set_binary( cfgdat->key, cfgdat->bval, cfgdat->size );
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
		if( ( cfgdat->type == type ) && !strcasecmp( cfgdat->key, key ) )
			return cfgdat;
	}

	if( add )
	{
		cfgdat = new CFGDAT;
		if( cfgdat )
		{
			cfgdat->type = type;
			cpp_strdup( &cfgdat->key, key );

			add_entry( cfgdat );
			return cfgdat;
		}
	}

	return 0;
}

void _CONFIG::del( const char * key )
{
	CFGDAT * cfgdat;

	for( long index = 0; index < count(); index++ )
	{
		cfgdat = static_cast<CFGDAT*>( get_entry( index ) );
		if( !strcasecmp( cfgdat->key, key ) )
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

bool _CONFIG::add_string( const char * key, const char * val, int size )
{
	CFGDAT * cfgdat = get_data( DATA_STRING, key, true );
	if( !cfgdat )
		return false;

	if( cfgdat->sval )
	{
		long	new_size = cfgdat->size + size + 1;
		char *	new_data = new char[ new_size + 1 ];
		if( !new_data )
			return false;

		memcpy( new_data, cfgdat->sval, cfgdat->size );
		new_data[ cfgdat->size ] = char( 255 );

		memcpy( new_data + cfgdat->size + 1, val, size );
		new_data[ new_size ] = 0;

		cpp_strdel( &cfgdat->sval );

		cfgdat->sval = new_data;
		cfgdat->size = new_size;
	}
	else
	{
		cpp_strndup( &cfgdat->sval, val, size );
		cfgdat->size = size;
	}

	return true;
}

bool _CONFIG::set_string( const char * key, const char * val, int size )
{
	del( key );
	return add_string( key, val, size );
}

long _CONFIG::has_string( const char * key, const char * val, int size )
{
	CFGDAT * cfgdat = get_data( DATA_STRING, key );
	if( !cfgdat )
		return -1;

	const char * oldptr = cfgdat->sval;
	const char * newptr = cfgdat->sval;

	long index = 0;

	while( newptr )
	{
		newptr = strchr( oldptr, char( 255 ) );

		if( newptr )
			if( ( newptr - oldptr ) < size )
				size = newptr - oldptr;

		if( !strncmp( val, oldptr, size ) )
			return index;
		
		oldptr = newptr + 1;
		index++;
	}

	return -1;
}

bool _CONFIG::get_string( const char * key, char * val, int size, int index )
{
	CFGDAT * cfgdat = get_data( DATA_STRING, key );
	if( !cfgdat )
		return false;

	const char * strptr = cfgdat->sval;

	for( ; index > 0; index-- )
	{
		char * tmpptr = strchr( strptr, char( 255 ) );
		if( !tmpptr )
			return false;

		strptr = tmpptr + 1;
	}

	// calculate final length

	size--;

	char chrset[] = { char( 0xff ), char( 0x00 ) };
	int clen = strcspn( strptr, chrset );
	if( clen < size )
		size = clen;

	strncpy( val, strptr, size );
	val[ size ] = 0;

	return true;
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

bool _CONFIG::set_binary( const char * key, char * val, long size )
{
	CFGDAT * cfgdat = get_data( DATA_BINARY, key, true );
	if( !cfgdat )
		return false;

	if( cfgdat->bval )
	{
		delete [] cfgdat->bval;
		cfgdat->size = 0;
	}

	cfgdat->bval = new char[ size ];
	if( cfgdat->bval )
	{
		memcpy( cfgdat->bval, val, size );
		cfgdat->size = size;
	}

	return true;
}

bool _CONFIG::get_binary( const char * key, char * val, long size )
{
	CFGDAT * cfgdat = get_data( DATA_BINARY, key );
	if( !cfgdat )
		return false;

	if( cfgdat->size == size )
	{
		memcpy( val, cfgdat->bval, size );
		cfgdat->size = size;
	}
	else
		return false;

	return true;
}

bool _CONFIG::file_read( char * path )
{
	FILE * fp = fopen( path, "r" );
	if( !fp )
		return false;

	bool fail = false;
	char buff[ 1024 ];

	while( fgets( buff, 1024, fp ) )
	{
		long size = strlen( buff );
		if( size < 4 )
		{
			fail = true;
			break;
		}

		if( buff[ 1 ] != ':' )
		{
			fail = true;
			break;
		}

		char * val = strchr( &buff[ 2 ], ':' );
		if( val == NULL )
		{
			fail = true;
			break;
		}

		*val = '\0';
		val++;

		char * trm = strchr( val, '\n' );
		if( trm != NULL )
			*trm = '\0';

		char * id = &buff[ 2 ];

		if( strlen( id ) <= 0 )
		{
			fail = true;
			break;
		}

		if( strlen( val ) <= 0 )
			continue;

		switch( buff[ 0 ] )
		{
			case 's':
			{
				add_string( id, val, strlen( val ) );
				break;
			}

			case 'n':
			{
				set_number( id, atol( val ) );
				break;
			}
		}
	}

	fclose( fp );

	return !fail;
}

bool _CONFIG::file_write( char * path )
{
	FILE * fp = fopen( path, "w+" );
	if( !fp )
		return false;

	for( long index = 0; index < count(); index++ )
	{
		char buff[ 1024 ];

		CFGDAT * cfgdat = static_cast<CFGDAT*>( get_entry( index ) );
		switch( cfgdat->type )
		{
			case DATA_STRING:
				sprintf( buff, "s:%s:%s\n", cfgdat->key, cfgdat->sval );
				break;

			case DATA_NUMBER:
				sprintf( buff, "n:%s:%li\n", cfgdat->key, cfgdat->nval );
				break;
		}

		fputs( buff, fp );
	}

	fclose( fp );

	return true;
}
