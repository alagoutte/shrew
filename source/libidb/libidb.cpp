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

#include "libidb.h"
#include "base64.h"

//==============================================================================
// basic data class
//

_BDATA & _BDATA::operator =( _BDATA & bdata )
{
	del();
	set( bdata );

	return *this;
}

bool _BDATA::operator ==( _BDATA & bdata )
{
	if( bdata.size() != size() )
		return false;

	return ( memcmp( bdata.buff(), buff(), size() ) == 0 );
}

bool _BDATA::operator !=( _BDATA & bdata )
{
	return !( *this == bdata );
}

_BDATA::_BDATA()
{
	data_buff = NULL;
	data_real = 0;
	data_size = 0;
	data_oset = 0;
}

_BDATA::_BDATA( _BDATA & bdata )
{
	_BDATA();
	*this = bdata;
}

_BDATA::~_BDATA()
{
	del( true );
}

size_t _BDATA::grow( size_t new_real )
{
	if( new_real >= ( 1024 * 1024 ) )
		return data_real;

	if( data_real < new_real )
	{
		unsigned char * new_buff = new unsigned char[ new_real ];
		if( new_buff == NULL )
			return data_real;

		if( data_buff != NULL )
		{
			memcpy( new_buff, data_buff, data_real );
			delete [] data_buff;
		}

		data_buff = new_buff;
		data_real = new_real;
	}

	return data_real;
}

size_t _BDATA::size( size_t new_size )
{
	if( new_size != ~0 )
	{
		if( grow( new_size ) < new_size )
			return data_size;

		data_size = new_size;
	}

	if( data_oset > data_size )
		data_oset = data_size;

	return data_size;
}

size_t _BDATA::oset( size_t new_oset )
{
	if( new_oset != ~0 )
		if( data_size >= new_oset )
			data_oset = new_oset;

	return data_oset;
}

char * _BDATA::text()
{
	return ( char * ) data_buff;
}

unsigned char * _BDATA::buff()
{
	return data_buff;
}

bool _BDATA::hex_encode( bool upper_case )
{
	BDATA	hex_temp;
	size_t	hex_oset = 0;

	while( hex_oset < data_size )
	{
		uint8_t temp1 = data_buff[ hex_oset++ ];
		uint8_t temp2 = temp1 >> 4;
		uint8_t temp3 = temp1 & 0xf;

		if( temp2 <= 9 )
			temp2 += 48;
		else
		{
			if( upper_case )
				temp2 += 55;
			else
				temp2 += 87;
		}

		hex_temp.add( temp2, 1 );

		if( temp3 <= 9 )
			temp3 += 48;
		else
		{
			if( upper_case )
				temp3 += 55;
			else
				temp3 += 87;
		}

		hex_temp.add( temp3, 1 );
	}

	*this = hex_temp;

	return true;
}

bool _BDATA::hex_decode()
{
	BDATA	hex_temp;
	size_t	hex_oset = 0;

	if( size() & 1 )
		return false;

	while( hex_oset < data_size )
	{
		uint8_t temp1 = data_buff[ hex_oset++ ];
		uint8_t temp2 = data_buff[ hex_oset++ ];

		if( ( temp1 >= 48 ) && ( temp1 <= 57 ) )
			temp1 -= 48;
		if( ( temp1 >= 65 ) && ( temp1 <= 70 ) )
			temp1 -= 55;
		if( ( temp1 >= 97 ) && ( temp1 <= 102 ) )
			temp1 -= 87;

		if( ( temp2 >= 48 ) && ( temp2 <= 57 ) )
			temp2 -= 48;
		if( ( temp2 >= 65 ) && ( temp2 <= 70 ) )
			temp2 -= 55;
		if( ( temp2 >= 97 ) && ( temp2 <= 102 ) )
			temp2 -= 87;

		int temp3 = ( temp1 << 4 ) | temp2;

		hex_temp.add( temp3, 1 );
	}

	hex_temp.size( data_size >> 1 );

	*this = hex_temp;

	return true;
}

bool _BDATA::base64_encode()
{
	BDATA	b64_temp;
	size_t	b64_size;

	if( !b64_temp.size( size() * 2 + 2 ) )
		return false;

	b64_size = b64_ntop(
					buff(),
					( long ) size(),
					b64_temp.text(),
					( long ) b64_temp.size() );

	if( b64_size == -1 )
		return false;

	b64_temp.size( b64_size + 1 );
	b64_temp.buff()[ b64_size ] = 0;

	*this = b64_temp;

	return true;
}

bool _BDATA::base64_decode()
{
	BDATA	b64_temp;
	size_t	b64_size;

	if( !b64_temp.size( size() ) )
		return false;

	b64_size = b64_pton(
					text(),
					b64_temp.buff(),
					( long ) b64_temp.size() );

	if( b64_size == -1 )
		return false;

	b64_temp.size( b64_size );

	*this = b64_temp;

	return true;
}

bool _BDATA::set( _BDATA & bdata, size_t oset )
{
	return set( ( char * ) bdata.buff(), bdata.size(), oset );
}

bool _BDATA::set( int value, size_t size, size_t oset )
{
	if( !set( ( void * ) NULL, size ) )
		return false;

	memset( data_buff + oset, value, size );

	return true;
}

bool _BDATA::set( void * buff, size_t size, size_t oset )
{
	size_t new_size = oset + size;

	if( grow( new_size ) < new_size )
		return false;

	if( buff != NULL )
		memcpy( data_buff + oset, buff, size );

	if( data_size < new_size )
		data_size = new_size;

	return true;
}

bool _BDATA::set( char * buff, size_t size, size_t oset )
{
	return set( ( void * ) buff, size, oset );
}

bool _BDATA::set( const char * buff, size_t size, size_t oset )
{
	return set( ( void * ) buff, size, oset );
}

bool _BDATA::ins( _BDATA & bdata, size_t oset )
{
	return ins( bdata.buff(), bdata.size(),	oset );
}

bool _BDATA::ins( int value, size_t size, size_t oset )
{
	if( !ins( ( void * ) NULL, size, oset ) )
		return false;

	memset( data_buff + oset, value, size );

	return true;
}

bool _BDATA::ins( void * buff, size_t size, size_t oset )
{
	size_t new_size = data_size + size;

	if( new_size < ( oset + size ) )
		new_size = ( oset + size );

	if( grow( new_size ) < new_size )
		return false;

	if( oset < data_size )
		memmove(
			data_buff + oset + size,
			data_buff + oset,
			data_size - oset );

	if( buff )
		memcpy(	data_buff + oset, buff, size );

	if( data_size < new_size )
		data_size = new_size;

	return true;
}

bool _BDATA::ins( char * buff, size_t size, size_t oset )
{
	return ins( ( void * ) buff, size, oset );
}

bool _BDATA::ins( const char * buff, size_t size, size_t oset )
{
	return ins( ( void * ) buff, size, oset );
}

bool _BDATA::add( _BDATA & bdata )
{
	return add( bdata.buff(), bdata.size() );
}

bool _BDATA::add( int value, size_t size )
{
	if( !add( ( void * ) NULL, size ) )
		return false;

	memset( data_buff + data_size - size, value, size );

	return true;
}

bool _BDATA::add( void * buff, size_t size )
{
	size_t new_size = data_size + size;

	if( grow( new_size ) < new_size )
		return false;

	if( buff )
		memcpy( data_buff + data_size, buff, size );

	data_size = new_size;

	return true;
}

bool _BDATA::add( char * buff, size_t size )
{
	return add( ( void * ) buff, size );
}

bool _BDATA::add( const char * buff, size_t size )
{
	return add( ( void * ) buff, size );
}

bool _BDATA::get( _BDATA & bdata, size_t size )
{
	size_t left = data_size - data_oset;

	if( size == BDATA_ALL )
		size = left;

	if( size > left )
		return false;

	bdata.size( size );

	return get( bdata.buff(), bdata.size() );
}

bool _BDATA::get( char * buff, size_t size )
{
	return get( ( void * ) buff, size );
}

bool _BDATA::get( void * buff, size_t size )
{
	if( size > ( data_size - data_oset ) )
		return false;

	// copy the user requested data

	if( buff )
		memcpy( buff, data_buff + data_oset, size );

	// set our new offset

	data_oset += size;

	return true;
}

void _BDATA::del( bool null )
{
	if( data_buff )
	{
		if( null )
			memset( data_buff, 0, data_real );

		delete [] data_buff;
	}

	data_buff = NULL;
	data_real = 0;
	data_size = 0;
	data_oset = 0;
}

bool _BDATA::file_load( FILE * fp )
{
	if( fp == NULL )
		return false;

	del();

	while( true )
	{
		int next = fgetc( fp );
		if( next == EOF )
			break;

		add( next, 1 );
	}

	return ( data_size > 0 );
}

bool _BDATA::file_load( const char * path )
{

#ifdef WIN32

	FILE * fp;
	if( fopen_s( &fp, path, "rb" ) )
		return false;

#else

	FILE * fp = fopen( path, "r" );
	if( fp == NULL )
		return false;

#endif

	bool result = file_load( fp );

	fclose( fp );

	return result;
}

bool _BDATA::file_save( FILE * fp )
{
	if( fp == NULL )
		return false;

	size_t count = data_size;
	size_t index = 0;

	for( ; index < count; index++ )
		fputc( data_buff[ index ], fp );

	return true;
}

bool _BDATA::file_save( const char * path )
{

#ifdef WIN32

	FILE * fp;
	if( fopen_s( &fp, path, "wb" ) )
		return false;

#else

	FILE * fp = fopen( path, "w" );
	if( fp == NULL )
		return false;

#endif

	bool result = file_save( fp );

	fclose( fp );

	return result;
}

//==============================================================================
// standard IDB list classes
//

_IDB_ENTRY::_IDB_ENTRY()
{
}

_IDB_ENTRY::~_IDB_ENTRY()
{
}

_IDB_LIST::_IDB_LIST()
{
	entry_list	= NULL;
	entry_max	= 0;
	entry_num	= 0;
}

_IDB_LIST::~_IDB_LIST()
{
	if( entry_list != NULL )
		delete [] entry_list;

	entry_list = NULL;
}

long _IDB_LIST::count()
{
	return entry_num;
}

void _IDB_LIST::clean()
{
	while( count() )
		delete del_entry( 0 );
}

bool _IDB_LIST::grow()
{
	// allocate a new stack of pointers that will
	// be larger that the last by GROW_SIZE

	IDB_ENTRY ** new_entry_list = new IDB_ENTRY * [ entry_max + GROW_SIZE ];

	if( new_entry_list == NULL )
		return false;

	// initialize our new stack of pointers to null and

	memset(
		new_entry_list,
		0,
		( entry_max + GROW_SIZE ) * sizeof( IDB_ENTRY * ) );

	// copy our old pointer stack to our new pointer stack 

	memcpy(
		new_entry_list,
		entry_list,
		entry_max * sizeof( IDB_ENTRY * ) );

	// free our old pointer stack

	if( entry_list != NULL )
		delete [] entry_list;

	//replace it with our new larger pointer stack

	entry_list = new_entry_list;

	// store our new item_capacity

	entry_max += GROW_SIZE;

	return true;
}

bool _IDB_LIST::add_entry( IDB_ENTRY * entry )
{
	// sanity check for valid pointer

	if( entry == NULL )
		return false;

	// make sure we have enough room in our stack,
	// grow if neccesary

	if( entry_num == entry_max )
		if( !grow() )
			return false;

	// store our new string in the next available
	// slot in the stack

	entry_list[ entry_num ] = entry;

	// increment our list count

	entry_num++;

	return true;
}

bool _IDB_LIST::del_entry( IDB_ENTRY * entry )
{
	// sanity check for valid pointer

	if( entry == NULL )
		return false;

	// attempt to match our item to an item
	// in our stack

	long index = 0;
	while( 1 )
	{
		// check for a match
		
		if( entry_list[ index ] == entry )
			break;
	
		// if we have exausted all pointers in our
		// stack then return false
		
		if( index == ( entry_num - 1 ) )
			return false;
			
		index++;		
	}
		
	// copy the trailing pointers in our list
	// to fill the empty slot
	
	int trailing_pointers = entry_num - index - 1;
	if( trailing_pointers )
		memmove(
			&entry_list[ index ],
			&entry_list[ index + 1 ],
			trailing_pointers * sizeof( IDB_ENTRY * ) );
		
	// null previously last used pointer in
	// list and decrement count
	
	entry_list[ entry_num - 1 ] = 0;
	entry_num--;
	
	return true;
}

IDB_ENTRY * _IDB_LIST::del_entry( int index )
{
	// sanity check for valid index
	
	if( ( index >= entry_num ) ||
		( index < 0 ) )
		return NULL;

	// store the item for return

	IDB_ENTRY * entry = entry_list[ index ];

	// copy the trailing pointers in our list
	// to fill the empty slot
	
	int trailing_pointers = entry_num - index - 1;
	if( trailing_pointers )
		memmove(
			&entry_list[ index ],
			&entry_list[ index + 1 ],
			trailing_pointers * sizeof( IDB_ENTRY * ) );
		
	// null previously last used pointer in
	// list and decrement count
	
	entry_list[ entry_num - 1 ] = 0;
	entry_num--;

	return entry;
}

IDB_ENTRY * _IDB_LIST::get_entry( int index )
{
	// sanity check for valid index
	
	if( ( index >= entry_num ) ||
		( index < 0 ) )
		return NULL;

	// return the requested item

	return entry_list[ index ];
}

