
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

#ifdef WIN32
# include <windows.h>
# include <shlwapi.h>
# include <shlobj.h>
# include <string.h>
#endif

#ifdef UNIX
# ifdef __linux__
#  include <sys/un.h>
#  include <sys/stat.h>
# else
#  include <sys/types.h>
#  include <sys/un.h>
#  include <sys/stat.h>
# endif
# include <unistd.h>
# include <pwd.h>
# include <dirent.h>
# include <string.h>
//# include <sys/socket.h>
# include "compat/winstring.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include "libidb.h"

#ifdef WIN32
# define PATH_DELIM '\\'
#else
# define PATH_DELIM '/'
#endif

#define MAX_CONFSTRING		256

#define CONFIG_VERSION	4

#define DATA_STRING		1
#define DATA_NUMBER		2
#define DATA_BINARY		3

#define CONFIG_OK		0
#define CONFIG_FAILED	1
#define CONFIG_CANCEL	2

typedef class _CFGDAT : public IDB_ENTRY
{
	public:

	BDATA	key;

	long	type;
	BDATA	vval;
	long	nval;

	_CFGDAT();

}CFGDAT;

typedef class DLX _CONFIG : public IDB_LIST
{
	protected:

	BDATA		id;
	bool		ispublic;

	CFGDAT *	get_data( long type, const char * key, bool add = false );

	public:

	_CONFIG();
	~_CONFIG();

	_CONFIG & operator = ( _CONFIG & value );

	bool	set_id( const char * id );
	char *	get_id();

	void	set_ispublic( bool val );
	bool	get_ispublic();

	void	del( const char * key );
	void	del_all();

	bool	add_string( const char * key, const char * val, size_t size );
	bool	add_string( const char * key, BDATA & val );
	bool	set_string( const char * key, const char * val, size_t size );
	bool	set_string( const char * key, BDATA & val );
	bool	get_string( const char * key, char * val, size_t size, int index );
    bool    get_string( const char * key, BDATA & val, int index );
	long	has_string( const char * key, const char * val, size_t size );

	bool	set_number( const char * key, long val );
	bool	get_number( const char * key, long * val );

	bool	set_binary( const char * key, BDATA & val );
	bool	get_binary( const char * key, BDATA & val );

}CONFIG;

typedef class DLX _CONFIG_MANAGER
{
	protected:

	BDATA	sites_all;
	BDATA	certs_all;

	BDATA	sites_user;
	BDATA	certs_user;

	bool update_config( CONFIG & config );

	public:

	_CONFIG_MANAGER();

	bool config_options_load();

	bool file_enumerate( CONFIG & config, int & index );
	bool file_enumerate_public( CONFIG & config, int & index );
	bool file_vpn_load( CONFIG & config );
	bool file_vpn_load( CONFIG & config, const char * path, bool save_update = true );
	bool file_vpn_save( CONFIG & config );
	bool file_vpn_save( CONFIG & config, const char * path );
	bool file_vpn_del( CONFIG & config );

	bool file_pcf_load( CONFIG & config, const char * path, bool & need_certs );

#ifdef WIN32

	bool registry_enumerate( CONFIG & config, int & index );
	bool registry_vpn_load( CONFIG & config );
	bool registry_vpn_save( CONFIG & config );
	bool registry_vpn_del( CONFIG & config );

#endif

}CONFIG_MANAGER;

bool config_cmp_number( CONFIG & config_old, CONFIG & config_new, const char * key );
bool config_cmp_string( CONFIG & config_old, CONFIG & config_new, const char * key );

#endif
