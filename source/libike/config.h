
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

#include <stdio.h>
#include "libidb.h"

#define MAX_CONFSTRING		256

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

typedef class DLX _CONFIG_MANAGER : public IDB_LIST
{
	public:

	bool config_options_load();

	bool registry_enumerate( CONFIG * config, int * index );
	bool registry_load_vpn( CONFIG * config );
	bool registry_save_vpn( CONFIG * config );
	bool registry_del_vpn( CONFIG * config );

	bool file_enumerate( CONFIG * config, const char * path, int * index );
	bool file_load_vpn( CONFIG * config, const char * path );
	bool file_save_vpn( CONFIG * config, const char * path );
	bool file_load_pcf( CONFIG * config, const char * path, bool & need_certs );
	bool file_del_vpn( CONFIG * config );

}CONFIG_MANAGER;

bool config_cmp_number( CONFIG * config_old, CONFIG * config_new, char * key );
bool config_cmp_string( CONFIG * config_old, CONFIG * config_new, char * key );

#endif
