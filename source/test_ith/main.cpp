
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

#ifdef WIN32
# define _CRT_SECURE_NO_DEPRECATE
#endif

#include "time.h"
#include "libith.h"

ITH_TIMER timer;

//
// utility functions
//

char * tstamp( char * str, long len )
{
	time_t		ctime;
	struct tm *	ltime;

	time( &ctime );
	ltime = localtime( &ctime );

	strftime( str, len, "%H:%M:%S", ltime );

	return str;
}

//
// test event class
//

typedef class _EVENT_TEST : public ITH_EVENT
{
	public:

	_EVENT_TEST( long set_id );

	long	id;
	bool	func();

	void	add( ITH_TIMER & add_timer, long add_delay );
	void	end();

}EVENT_TEST;

_EVENT_TEST::_EVENT_TEST( long set_id )
{
	id = set_id;
}

bool _EVENT_TEST::func()
{
	end();
	return false;
}

void _EVENT_TEST::add( ITH_TIMER & add_timer, long add_delay )
{
	delay = add_delay;
	add_timer.add( this );

	char str[ 50 ];
	printf( "%s : event %i added\n", tstamp( str, 50 ), id );
}

void _EVENT_TEST::end()
{
	char str[ 50 ];
	printf( "%s : event %i executed\n", tstamp( str, 50 ), id );
}

//
// test helper thread
//

typedef class _TEST_EXEC : public ITH_EXEC
{
	protected:

	long func( void * arg );

}TEST_EXEC;

long _TEST_EXEC::func( void * arg )
{
	char str[ 50 ];
	printf( "%s : --- THREAD RUN ---\n", tstamp( str, 50 ) );

	Sleep( 1000 );

	EVENT_TEST test1( 1 );
	test1.add( timer, 5000 );

	EVENT_TEST test2( 2 );
	test2.add( timer, 1000 );

	EVENT_TEST test3( 3 );
	test3.add( timer, 8000 );

	Sleep( 11000 );

	timer.end();

	printf( "%s : --- THREAD RUN ---\n", tstamp( str, 50 ) );

	return 0;
}

//
// test program
//

int main( int argc, char * argv[], char * envp[] )
{
	char str[ 50 ];
	printf( "%s : ==== TEST RUN ====\n", tstamp( str, 50 ) );

	TEST_EXEC exec;
	exec.exec( NULL );

	timer.run();

	printf( "%s : ==== TEST END ====\n", tstamp( str, 50 ) );
	printf( "press <Enter> to continue ...\n", tstamp( str, 50 ) );

	getchar();

	return 0;
}

