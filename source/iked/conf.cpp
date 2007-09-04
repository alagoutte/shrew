
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

#include "iked.h"

bool _IKED::conf_load( const char * path, bool trace )
{
	HKEY	key;
	DWORD	result;

	if( RegCreateKeyEx( HKEY_LOCAL_MACHINE, path, 0, 0, 0, KEY_READ, 0, &key, &result ) == ERROR_SUCCESS )
	{
		DWORD	size;
		DWORD	type;
		long	result;

		//
		// install path
		//

		GetCurrentDirectory( MAX_PATH - 1, path_ins );

		size = MAX_PATH - 1;
		type = REG_SZ;

		result = RegQueryValueEx(
					key,
					"path",
					0,
					&type,
					( LPBYTE ) path_ins,
					&size );

		//
		// debug log file
		//

		size = MAX_PATH - 1;
		type = REG_SZ;

		result = RegQueryValueEx(
					key,
					"logfile-iked",
					0,
					&type,
					( LPBYTE ) path_log,
					&size );

		//
		// debug log level
		//

		size = sizeof( level );
		type = REG_DWORD;

		result = RegQueryValueEx(
					key,
					"loglevel",
					0,
					&type,
					( LPBYTE ) &level,
					&size );

		//
		// decoded ike packet dump
		//

		size = sizeof( dump_ike );
		type = REG_DWORD;

		result = RegQueryValueEx(
					key,
					"dump-ike",
					0,
					&type,
					( LPBYTE ) &dump_ike,
					&size );

		//
		// encoded ike packet dump
		//

		size = sizeof( dump_pub );
		type = REG_DWORD;

		result = RegQueryValueEx(
					key,
					"dump-pub",
					0,
					&type,
					( LPBYTE ) &dump_pub,
					&size );

		RegCloseKey( key );
	}

	//
	// set our logfile path
	//

	if( !strlen( path_log ) )
		sprintf_s( path_log, MAX_PATH, "%s/debug/%s", path_ins, "iked.log" );

	if( dump_ike )
		sprintf_s( path_ike, MAX_PATH, "%s/debug/%s", path_ins, "dump-ike.cap" );

	if( dump_pub )
		sprintf_s( path_pub, MAX_PATH, "%s/debug/%s", path_ins, "dump-pub.cap" );


	return true;
}