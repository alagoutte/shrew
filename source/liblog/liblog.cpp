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

bool _LOG::write_buff( char * buff, size_t size )
{
	//
	// build time stamp
	//

	char	tbuff[ LOG_MAX_TXT ];
	size_t	tlen = 0;

	if( !( log_flags & LOGFLAG_SYSTEM ) )
	{
		time_t		ctime;
		struct tm *	ltime;

		time( &ctime );

#ifdef WIN32

		struct tm ltm;
		ltime = &ltm;
		localtime_s( ltime, &ctime );

#endif

#ifdef UNIX

		ltime = localtime( &ctime );

#endif

		tlen = strftime( tbuff, LOG_MAX_TXT, "%y/%m/%d %H:%M:%S ", ltime );
	}

	lock.lock();

	//
	// log buffer to console
	//

	if( log_flags & LOGFLAG_ECHO )
		printf( "%s", buff );

	//
	// log individual lines
	//

	char *	line = buff;
	size_t	oset = 0;
	size_t	llen;

	while( line != NULL && line[ 0 ] )
	{
		char * next = strchr( line, '\n' );

		if( next != NULL )
		{
			if( log_flags & LOGFLAG_SYSTEM )
				next[ 0 ] = 0;

			next++;
			llen = next - line;
		}
		else
			llen = strlen( line );

		if( tlen )
			write_line( tbuff, tlen );

		write_line( line, llen );

		line = next;
	}

	lock.unlock();

	return true;
}

bool _LOG::write_line( char * buff, size_t size )
{
#ifdef WIN32

	DWORD dwsize = ( DWORD ) size;

	if( fp != NULL )
		WriteFile(
			fp,
			buff,
			dwsize,
			&dwsize,
			NULL );

#endif

#ifdef UNIX

	if( log_flags & LOGFLAG_SYSTEM )
		syslog( LOG_NOTICE, "%s", buff );
	else
	{
		if( fp != NULL )
		{
			fwrite( buff, size, 1, fp );
			fflush( fp );
		}
	}
#endif

	return true;
}

bool _LOG::open( char * path, long level, long flags )
{
	//
	// set the log level
	//

	log_flags = flags;
	log_level = level;

#ifdef WIN32

	if( path )
	{
		close();

		fp = CreateFile(
				path,
				GENERIC_WRITE,
				FILE_SHARE_READ,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				0 );

		if( fp == NULL )
			return false;
	}
#endif

#ifdef UNIX

	if( path )
	{
		if( log_flags & LOGFLAG_SYSTEM )
			openlog( path, LOG_NDELAY, LOG_DAEMON );
		else
		{
			fp = fopen( path, "w" );

			if( fp == NULL )
				return false;
		}
	}

#endif

	return true;
}

void _LOG::close()
{

#ifdef WIN32

	if( fp != NULL )
	{
		FlushFileBuffers( fp );
		CloseHandle( fp );
	}
#endif

#ifdef UNIX

	if( log_flags & LOGFLAG_SYSTEM )
		closelog();
	else
	{
		if( fp != NULL )
		{
			fflush( fp );
			fclose( fp );
		}
	}

#endif
	fp = NULL;
}

void _LOG::txt( long level, const char * fmt, ... )
{
	char tbuff[ LOG_MAX_TXT ];
	char fbuff[ LOG_MAX_TXT ];

	if( level > log_level )
		return;

	va_list list;
	va_start( list, fmt );

	if( ( fp != NULL ) || ( log_flags & LOGFLAG_ECHO ) )
	{
		size_t	tsize = LOG_MAX_TXT;
		size_t	tused = 0;

		vsprintf_s( tbuff, LOG_MAX_TXT, fmt, list );
		sprintf_s( fbuff, tsize, "%s", tbuff );

		write_buff( fbuff, tused );
	}
}

void _LOG::bin( long level, long blevel, void * bin, size_t len, const char * fmt, ... )
{
	char tbuff[ LOG_MAX_TXT ];
	char fbuff[ LOG_MAX_BIN ];

	if( level > log_level )
		return;

	va_list list;
	va_start( list, fmt );

	if( ( fp != NULL ) || ( log_flags & LOGFLAG_ECHO ) )
	{
		// tsize = total buffer size - NLx2 - NULL

		size_t	tsize = LOG_MAX_BIN  - 3;
		size_t	tused = 0;

		// add our text label

		vsprintf_s( tbuff, LOG_MAX_TXT, fmt, list ); 
		tused += sprintf_s( fbuff, tsize, "%s ( %ld bytes )", tbuff, len );

		// check binary log level

		if( blevel <= log_level )
		{
			// setup target and source data pointers

			char *	tdata = fbuff;
			char *	sdata = ( char * ) bin;

			// bsize = ( tsize / required chars per line ) * bin bytes per line

			size_t	ssize = ( ( tsize - tused ) / 77 ) * 32;
			size_t	sused = 0;

			if( ssize > len )
				ssize = len;

			// format and log source bytes

			for( ; sused < ssize; sused++ )
			{
				if( !( sused & 0x1F ) )
					tused += sprintf_s( &tdata[ tused ], tsize - tused, "\n0x :" );

				unsigned char bchar = sdata[ sused ];

				if( !( sused & 0x03 ) )
					tused += sprintf_s( &tdata[ tused ], tsize - tused, " %02x", bchar );
				else
					tused += sprintf_s( &tdata[ tused ], tsize - tused, "%02x", bchar );

				assert( tsize > tused );
			}
		}

		// add terminating null and append

		tused += sprintf_s( &fbuff[ tused ], tsize - tused, "\n" );

		write_buff( fbuff, tused );
	}

	return;
}
