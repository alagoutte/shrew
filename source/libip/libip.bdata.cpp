
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

#include "libip.h"

_BDATA::_BDATA()
{
	data_buff = NULL;
	data_size = 0;
	data_oset = 0;
}

_BDATA::~_BDATA()
{
	del( true );
}

bool _BDATA::set( _BDATA & bdata )
{
	return set( ( char * ) bdata.buff(), bdata.size() );
}

bool _BDATA::set( int value, size_t size )
{
	if( !set( ( void * ) NULL, size ) )
		return false;

	memset( data_buff, value, size );

	return true;
}

bool _BDATA::set( char * buff, size_t size )
{
	return set( ( void * ) buff, size );
}

bool _BDATA::set( void * buff, size_t size )
{
	unsigned char * new_buff = new unsigned char[ size ];
	if( !new_buff )
		return false;

	if( buff != NULL )
		memcpy( new_buff, buff, size );

	if( data_buff )
		delete [] data_buff;

	data_buff = new_buff;
	data_size = size;

	return true;
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

bool _BDATA::ins( char * buff, size_t size, size_t oset )
{
	return ins( ( void * ) buff, size );
}

bool _BDATA::ins( void * buff, size_t size, size_t oset )
{
	if( data_size < oset )
		return false;

	size_t	new_size = data_size + size;
	unsigned char * new_buff = new unsigned char[ new_size ];
	if( !new_buff )
		return false;

	memcpy( new_buff + size, data_buff, data_size );

	if( data_size >= oset )
	{
		memcpy(	new_buff, data_buff, oset );

		memcpy(
			new_buff + oset + size,
			data_buff + oset,
			data_size - oset );
	}
	
	if( buff )
		memcpy(	new_buff + oset, buff, size );

	if( data_buff )
		delete [] data_buff;

	data_buff = new_buff;
	data_size = new_size;

	return true;
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

bool _BDATA::add( char * buff, size_t size )
{
	return add( ( void * ) buff, size );
}

bool _BDATA::add( void * buff, size_t size )
{
	size_t	new_size = data_size + size;
	unsigned char * new_buff = new unsigned char[ new_size ];
	if( !new_buff )
		return false;

	memcpy( new_buff, data_buff, data_size );

	if( buff )
		memcpy( new_buff + data_size, buff, size );

	if( data_buff )
		delete [] data_buff;

	data_buff = new_buff;
	data_size = new_size;

	return true;
}

bool _BDATA::get( _BDATA & bdata, size_t size )
{
	if( size == BDATA_ALL )
		size = data_size - data_oset;

	bdata.set( 0, size );

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

bool _BDATA::dec( size_t size )
{
	if( size > data_size )
		return false;

	data_size = size;

	return true;
}

void _BDATA::del( bool null )
{
	if( data_buff )
	{
		if( null )
			memset( data_buff, 0, data_size );

		delete [] data_buff;
	}

	data_buff = NULL;
	data_size = 0;
	data_oset = 0;
}

char * _BDATA::text()
{
	return ( char * ) data_buff;
}

unsigned char * _BDATA::buff()
{
	return data_buff;
}

size_t _BDATA::size()
{
	return data_size;
}

size_t _BDATA::oset()
{
	return data_oset;
}
