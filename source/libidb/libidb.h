
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

#ifndef _IDB_H_
#define _IDB_H_

#include <stdio.h>
#include "export.h"

//==============================================================================
// Basic data class
//==============================================================================

#define BDATA_ALL		~0

typedef class DLX _BDATA
{
	protected:

	unsigned char *	data_buff;
	size_t			data_real;
	size_t			data_size;
	size_t			data_oset;

	size_t			grow( size_t new_size = ~0 );

	public:

	_BDATA &		operator =( _BDATA & bdata );
	bool			operator ==( _BDATA & bdata );
	bool			operator !=( _BDATA & bdata );

	_BDATA();
	_BDATA( _BDATA & bdata );
	virtual ~_BDATA();

	size_t			oset( size_t new_oset = ~0 );
	size_t			size( size_t new_size = ~0 );

	char *			text();
	unsigned char *	buff();

	bool	hex_encode( bool upper_case = false );
	bool	hex_decode();

	bool	base64_encode();
	bool	base64_decode();

	bool set( _BDATA & bdata, size_t oset = 0 );
	bool set( int value, size_t size, size_t oset = 0 );
	bool set( void * buff, size_t size, size_t oset = 0 );
	bool set( char * buff, size_t size, size_t oset = 0 );
	bool set( const char * buff, size_t size, size_t oset = 0 );

	bool ins( _BDATA & bdata, size_t oset = 0 );
	bool ins( int value, size_t size, size_t oset = 0 );
	bool ins( void * buff, size_t size, size_t oset = 0 );
	bool ins( char * buff, size_t size, size_t oset = 0 );
	bool ins( const char * buff, size_t size, size_t oset = 0 );

	bool add( _BDATA & bdata );
	bool add( int value, size_t size );
	bool add( void * buff, size_t size );
	bool add( char * buff, size_t size );
	bool add( const char * buff, size_t size );

	bool get( _BDATA & bdata, size_t size = BDATA_ALL );
	bool get( void * buff, size_t size );
	bool get( char * buff, size_t size );

	void del( bool null = false );

	bool file_load( FILE * fp );
	bool file_load( const char * path );
	bool file_save( FILE * fp );
	bool file_save( const char * path );

}BDATA, *PBDATA;

//==============================================================================
// standard IDB list classes
//==============================================================================

typedef class DLX _IDB_ENTRY
{
	public:

	_IDB_ENTRY();
	virtual ~_IDB_ENTRY();

}IDB_ENTRY;

#define GROW_SIZE	16

typedef class DLX _IDB_LIST
{
	public:

	IDB_ENTRY **	entry_list;
	long			entry_max;
	long			entry_num;

	bool			grow();

	_IDB_LIST();
	virtual ~_IDB_LIST();

	long			count();
	virtual	void	clean();

	bool		add_entry( IDB_ENTRY * entry );
	bool		del_entry( IDB_ENTRY * entry );
	IDB_ENTRY * del_entry( int index );
	IDB_ENTRY * get_entry( int index );

}IDB_LIST;
/*
//==============================================================================
// reference counted IDB classes
//==============================================================================

class _IDB_RC_LIST;

#define IDB_FLAG_DEAD		1
#define IDB_FLAG_IMMEDIATE	2
#define IDB_FLAG_ENDCALLED	4

typedef class DLX _IDB_RC_ENTRY : public IDB_ENTRY
{
	protected:

	long		idb_flags;
	long		idb_refcount;

	inline long chkflags( long flags )
	{
		return ( idb_flags & flags );
	}

	inline long setflags( long flags )
	{
		return idb_flags |= flags;
	}

	inline long clrflags( long flags )
	{
		return idb_flags &= ~flags;
	}

	void callend();

	virtual void beg() = 0;
	virtual void end() = 0;

	public:

	_IDB_RC_ENTRY();
	virtual ~_IDB_RC_ENTRY();

	virtual const char *	name() = 0;
	virtual _IDB_RC_LIST *	list() = 0;

	bool add( bool lock );
	void inc( bool lock );
	bool dec( bool lock, bool setdel = false );

}IDB_RC_ENTRY;

typedef class DLX _IDB_RC_LIST : public IDB_LIST
{
	public:

	_IDB_RC_LIST();
	virtual ~_IDB_RC_LIST();

	virtual	void	clean();

	virtual bool	lock() = 0;
	virtual bool	unlock() = 0;

}IDB_RC_LIST;
*/
#endif
