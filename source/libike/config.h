
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

#ifndef _CONFIG_H_
#define _CONFIG_H_

#ifdef WIN32
# include <windows.h>
# include <shlwapi.h>
# include <shlobj.h>
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
# include <pwd.h>
# include <sys/types.h>
# include <dirent.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "libidb.h"

#define MAX_CONFSTRING		256

#define CONFIG_VERSION	3

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

	CFGDAT *	get_data( long type, const char * key, bool add = false );

	public:

	_CONFIG();
	~_CONFIG();

	_CONFIG & operator = ( _CONFIG & value );

	bool	set_id( const char * id );
	char *	get_id();

	void	del( const char * key );
	void	del_all();

	bool	add_string( const char * key, const char * val, size_t size );
	bool	set_string( const char * key, const char * val, size_t size );
	long	has_string( const char * key, const char * val, size_t size );
	bool	get_string( const char * key, char * val, size_t size, int index );
    bool    get_string( const char * key, BDATA & val, int index );

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

	bool registry_enumerate( CONFIG & config, int & index );
	bool registry_vpn_load( CONFIG & config );
	bool registry_vpn_save( CONFIG & config );
	bool registry_vpn_del( CONFIG & config );

	bool file_enumerate( CONFIG & config, int & index );
	bool file_vpn_load( CONFIG & config );
	bool file_vpn_load( CONFIG & config, const char * path );
	bool file_vpn_save( CONFIG & config );
	bool file_vpn_save( CONFIG & config, const char * path );
	bool file_vpn_del( CONFIG & config );

	bool file_pcf_load( CONFIG & config, const char * path, bool & need_certs );

}CONFIG_MANAGER;

bool config_cmp_number( CONFIG & config_old, CONFIG & config_new, const char * key );
bool config_cmp_string( CONFIG & config_old, CONFIG & config_new, const char * key );

#endif
