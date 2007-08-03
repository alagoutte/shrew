
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
	va_list ap;
	va_start( ap, format );
	return snprintf( buffer, sizeOfBuffer, format, ap );
}

inline int strcpy_s( char * strDestination, size_t numberOfElements, const char * strSource )
{
	strncpy( strDestination, strSource, numberOfElements );
}

#endif
