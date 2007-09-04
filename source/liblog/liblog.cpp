
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

#include "liblog.h"

_LOG::_LOG()
{
	fp = NULL;
}

_LOG::~_LOG()
{
	close();
}

void _LOG::tstamp( char * buff, long size )
{
/*
	time_t		ctime;
	struct tm *	ltime;

	time( &ctime );
    ltime = localtime( &ctime );

	strftime( buff, length, "%y/%m/%d %H:%M:%S ", ltime );
*/
	buff[ 0 ] = 0;
}

bool _LOG::append( char * buff, long size )
{
	lock.lock();

	if( fp != NULL )
	{

#ifdef WIN32

		WriteFile(
			fp,
			buff,
			size,
			( DWORD * ) &size,
			NULL );

#endif

#ifdef UNIX

		fwrite( buff, size, 1, fp );
		fflush( fp );

#endif

	}

	if( log_echo )
		printf( buff );

	lock.unlock();

	return true;
}

bool _LOG::open( char * path, long level, bool echo )
{
	//
	// set the log level
	//

	log_echo = echo;
	log_level = level;

	if( path )
	{
		close();

#ifdef WIN32

		fp = CreateFile(
				path,
				GENERIC_WRITE,
				FILE_SHARE_READ,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				0 );

#endif

#ifdef UNIX

		fp = fopen( path, "w" );

#endif

		if( fp == NULL )
			return false;
	}

	return true;
}

void _LOG::close()
{

	if( fp != NULL )
	{

#ifdef WIN32

		FlushFileBuffers( fp );
		CloseHandle( fp );
#endif

#ifdef UNIX

		fflush( fp );
		fclose( fp );

#endif
		fp = NULL;

	}
}

void _LOG::txt( long level, const char * fmt, ... )
{
	char fbuff[ 128 ];
	tstamp( fbuff, 128 );

	char tbuff[ LOG_MAX_TXT ];
	char bbuff[ LOG_MAX_TXT ];

	if( level > log_level )
		return;

	va_list list;
	va_start( list, fmt );

	long size = 0;

	if( ( fp != NULL ) || log_echo )
	{
		vsprintf_s( tbuff, LOG_MAX_TXT, fmt, list );
		size = sprintf_s( bbuff, LOG_MAX_TXT, "%s%s", fbuff, tbuff );

		if( size != -1 )
			append( bbuff, size );
	}
}

void _LOG::bin( long level, long blevel, void * bin, size_t len, const char * fmt, ... )
{
	//
	// FIXME : Review for buffer overflows
	//

	char fbuff[ 64 ];
	tstamp( fbuff, 64 );

	char tbuff[ LOG_MAX_TXT ];
	char bbuff[ LOG_MAX_BIN ];

	va_list list;
	va_start( list, fmt );

	long size = 0;

	if( ( level <= log_level ) && ( blevel > log_level ) )
	{

		size = vsprintf_s( tbuff, LOG_MAX_TXT, fmt, list ); 

		if( size != -1 )
		{
			size = sprintf_s( bbuff, LOG_MAX_BIN, "%s%s ( %ld bytes )\n", fbuff, tbuff, len );

			append( bbuff, size );
		}
	}

	if( blevel <= log_level )
	{
		size = vsprintf_s( tbuff, LOG_MAX_TXT, fmt, list );
		size = sprintf_s( bbuff, LOG_MAX_TXT, "%s%s ( %ld bytes ) = ", fbuff, tbuff, len );

		char * cdata = ( char * ) bin;
		char * bdata = bbuff + size;

		for( size_t index = 0; index < len; index ++ )
		{
			if( LOG_MAX_BIN - ( bdata - bbuff + size ) <= 8 )
			{
				bdata += sprintf_s( bdata, LOG_MAX_BIN, " ...\n" );
				break;
			}

			if( !( index % 0x20 ) )
				bdata += sprintf_s( bdata, LOG_MAX_BIN, "\n0x :" );

			if( !( index % 0x04 ) )
				bdata += sprintf_s( bdata, LOG_MAX_BIN, " " );

			bdata += sprintf_s( bdata, LOG_MAX_BIN, "%02x", 0xff & cdata[ index ] );
		}

		sprintf_s( bdata, LOG_MAX_BIN, "\n" );
		bdata++;

		size = long( bdata - bbuff );

		append( bbuff, size );

	}

	return;
}
