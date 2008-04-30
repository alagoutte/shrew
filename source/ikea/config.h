
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

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "libidb.h"

#define MAX_CONFSTRING	256

#define DATA_STRING	1
#define DATA_NUMBER	2
#define DATA_BINARY	3

#define CONFIG_OK	0
#define CONFIG_FAILED	1
#define CONFIG_CANCEL	2

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef class _CFGDAT : public IDB_ENTRY
{
	friend class _CONFIG;

	protected:

	BDATA	key;

	long	type;
	BDATA	vval;
	long	nval;

	_CFGDAT();

}CFGDAT;

typedef class DLX _CONFIG : private IDB_LIST
{
	protected:
	
	BDATA		id;
	
	CFGDAT *	get_data( long type, const char * key, bool add = false );
	
	public:
	
	_CONFIG();
	~_CONFIG();
	
	_CONFIG & operator = ( _CONFIG & value );
	
	bool	file_read( const char * path );
	bool	file_write( const char * path );
	
	bool		set_id( const char * id );
	const char *	get_id();
	
	void	del( const char * key );
	void	del_all();
	
	bool	add_string( const char * key, const char * val, size_t size );
	bool	set_string( const char * key, const char * val, size_t size );
	long	has_string( const char * key, const char * val, size_t size );
	bool	get_string( const char * key, char * val, size_t size, int index );

	bool	set_number( const char * key, long val );
	bool	get_number( const char * key, long * val );
	
	bool	set_binary( const char * key, BDATA & val );
	bool	get_binary( const char * key, BDATA & val );
	
}CONFIG;

#endif
