
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

//
// UNIX compatibiliy for MS string functions
//

#ifndef _WINSTRING_H_
#define _WINSTRING_H_

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

inline int vsprintf_s( char * buffer, size_t numberOfElements, const char * format, va_list argptr )
{
	return vsnprintf( buffer, numberOfElements, format, argptr );
}

inline int sprintf_s( char * buffer, size_t sizeOfBuffer, const char * format, ... )
{
	va_list list;
	va_start( list, format );

	return vsnprintf( buffer, sizeOfBuffer, format, list );
}

inline int strcpy_s( char * strDestination, size_t sizeInBytes, const char * strSource )
{
	strncpy( strDestination, strSource, sizeInBytes );

	return 0;
}

inline int strncpy_s( char * strDestination, const char * strSource, size_t sizeInBytes )
{
	strncpy( strDestination, strSource, sizeInBytes );

	return 0;
}

inline int _stricmp( const char * str1, const char * str2 )
{
	return strcasecmp( str1, str2 );
}

#endif
