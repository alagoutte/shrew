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

#ifndef _LOG_H_
#define _LOG_H_

#ifdef WIN32
# include <windows.h>
# include <stdio.h>
# include <time.h>
#endif

#ifdef UNIX
# include <stdarg.h>
# include <stdio.h>
# include <time.h>
# include <syslog.h>
# include "compat/winstring.h"
#endif

#include "libith.h"
#include "export.h"

#define	LLOG_NONE		0
#define	LLOG_ERROR		1
#define	LLOG_INFO		2
#define	LLOG_DEBUG		3
#define	LLOG_LOUD		4
#define	LLOG_DECODE		5

#define LOG_MAX_TXT		( 1024 * 2 )
#define LOG_MAX_BIN		( 1024 * 8 )

#define LOGFLAG_ECHO		0x01
#define LOGFLAG_SYSTEM		0x02

typedef struct DLX _LOG
{
	private:

#ifdef WIN32

#define snprintf _snprintf
#define vsnprintf _vsnprintf

	HANDLE	fp;

#endif

#ifdef UNIX

	FILE *	fp;

#endif

	ITH_LOCK	lock;

	long		log_level;
	long		log_flags;

	bool	write_buff( char * buff, size_t size );
	bool	write_line( char * buff, size_t size );

	public:

	_LOG();
	~_LOG();

	bool	open( char * path, long level, long flags );
	void	close();

	void	txt( long level, const char * fmt, ... );
	void	bin( long level, long blevel, void * bin, size_t size, const char * fmt, ... );

}LOG, *PLOG;

#endif
