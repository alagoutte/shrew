
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

#include "libith.h"

//
// thread execution class
//

typedef struct _ITH_PARAM
{
	ITH_EXEC *	exec;
	void *		arg;

}ITH_PARAM;

_ITH_EXEC::_ITH_EXEC()
{
}

#ifdef WIN32

unsigned long __stdcall help( void * arg )
{
	ITH_PARAM * param = ( ITH_PARAM * ) arg;

	long result = param->exec->func( param->arg );

	delete param;

	return result;
}

bool _ITH_EXEC::exec( void * arg )
{
	ITH_PARAM * param = new ITH_PARAM;
	if( param == NULL )
		return false;

	param->exec = this;
	param->arg = arg;

	DWORD tid;

	CreateThread(
		NULL,
		0,
		help,
		param,
		0,
		&tid );

	return true;
}

#endif

#ifdef UNIX

void * help( void * arg )
{
	ITH_PARAM * param = ( ITH_PARAM * ) arg;

	param->exec->func( param->arg );

	delete param;

	return NULL;
}

bool _ITH_EXEC::exec( void * arg )
{
	ITH_PARAM * param = new ITH_PARAM;
	if( param == NULL )
		return false;

	param->exec = this;
	param->arg = arg;

	pthread_create(
		&thread,
		NULL,
		&help,
		param );

	return true;
}

#endif

//
// mutex lock class
//

#ifdef WIN32

_ITH_LOCK::_ITH_LOCK()
{
	memset( name, 0, 20 );
	mutex = CreateMutex( NULL, false, NULL );
}

_ITH_LOCK::~_ITH_LOCK()
{
	CloseHandle( mutex );
}

void _ITH_LOCK::setname( const char * lkname )
{
	strcpy_s( name, 20, lkname );
}

bool _ITH_LOCK::lock()
{
	int result = WaitForSingleObject( mutex, 3000 );

	assert( result != WAIT_FAILED );

	if( result != WAIT_FAILED )
		return true;

	result = GetLastError();

	printf( "XX : mutex lock failed, ERROR CODE %i\n", result );

	return false;
}

bool _ITH_LOCK::unlock()
{
	ReleaseMutex( mutex );

	return true;
}

#endif

#ifdef UNIX

_ITH_LOCK::_ITH_LOCK()
{
	count = 0;
	memset( name, 0, 20 );
	pthread_mutexattr_init( &attr );
	pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_ERRORCHECK );
	pthread_mutex_init( &mutex, &attr );
}

_ITH_LOCK::~_ITH_LOCK()
{
	pthread_mutex_destroy( &mutex );
	pthread_mutexattr_destroy( &attr );
}

void _ITH_LOCK::setname( const char * lkname )
{
	strcpy_s( name, 20, lkname );
}

bool _ITH_LOCK::lock()
{

#ifdef OPT_TIMEDLOCK

        struct timespec ts;
        clock_gettime( CLOCK_REALTIME, &ts );
        ts.tv_sec += 3;

	int result = pthread_mutex_timedlock( &mutex, &ts );

#else

	int result = pthread_mutex_lock( &mutex );

#endif

	switch( result )
	{
		case 0:
			return true;

		case EINVAL:
			printf( "XX : mutex lock failed, invalid parameter\n" );
			break;

		case ETIMEDOUT:
			printf( "XX : mutex lock failed, timeout expired\n" );
			break;

		case EAGAIN:
			printf( "XX : mutex lock failed, recursion error\n" );
			break;

		case EDEADLK:
			printf( "XX : mutex lock failed, mutex already owned\n" );
			break;
	}

	assert( result == 0 );

	return false;
}

bool _ITH_LOCK::unlock()
{

	int result = pthread_mutex_unlock( &mutex );

	switch( result )
	{
		case 0:
			return true;

		case EINVAL:
			printf( "XX : mutex unlock failed, mutex not owned\n" );
			break;
	}

	assert( result == 0 );

	return false;
}

#endif

//
// execution timer class
//

_ITH_TIMER::_ITH_TIMER()
{
	head = NULL;

	stop = false;
	exit = false;
}

_ITH_TIMER::~_ITH_TIMER()
{
}

#ifdef WIN32

void _ITH_TIMER::tval_set( ITH_TIMEVAL & tval, long delay )
{
	SYSTEMTIME stime;
	memset( &stime, 0, sizeof( stime ) );
	GetSystemTime( &stime );

	FILETIME ftime;
	memset( &ftime, 0, sizeof( ftime ) );
	SystemTimeToFileTime( &stime, &ftime );

	memcpy( &tval, &ftime, sizeof( tval ) );

	// ftime expressed as 100 nanosecond units

	ITH_TIMEVAL dval;
	dval.QuadPart = delay;
	dval.QuadPart *= 10000;

	tval.QuadPart += dval.QuadPart;
}

long _ITH_TIMER::tval_cmp( ITH_TIMEVAL & tval1, ITH_TIMEVAL & tval2 )
{
	if( tval1.QuadPart > tval2.QuadPart )
		return 1;

	if( tval1.QuadPart < tval2.QuadPart )
		return -1;

	return 0;
}

#endif

#ifdef UNIX

void _ITH_TIMER::tval_set( ITH_TIMEVAL & tval, long delay )
{
	gettimeofday( &tval, NULL );

	// timeval expressed as seconds and microseconds

	while( delay > 1000 )
	{
		tval.tv_sec++;
		delay -= 1000;
	}

	tval.tv_usec += delay * 1000;

	while( tval.tv_usec > 1000000 )
	{
		tval.tv_sec++;
		tval.tv_usec -= 1000000;
	}
}

long _ITH_TIMER::tval_cmp( ITH_TIMEVAL & tval1, ITH_TIMEVAL & tval2 )
{
	if( tval1.tv_sec > tval2.tv_sec )
		return 1;

	if( tval1.tv_sec < tval2.tv_sec )
		return -1;

	if( tval1.tv_usec > tval2.tv_usec )
		return 1;

	if( tval1.tv_usec < tval2.tv_usec )
		return -1;

	return 0;
}

#endif

long _ITH_TIMER::func( void * arg )
{
	ITH_TIMEVAL current;

	while( !stop )
	{
		ITH_ENTRY * entry = NULL;

		//
		// check if we have an event
		// that needs to be enabled
		//

		tval_set( current );

		lock.lock();

		if( head != NULL )
		{
			if( tval_cmp( head->sched, current ) <= 0 )
			{
				//
				// remove the entry
				//

				entry = head;
				head = entry->next;
			}
		}

		lock.unlock();

		//
		// did we find an active event
		//
		
		if( entry != NULL )
		{
//			printf( "XX : executing event\n" );

			//
			// enable the event and
			// reset if required
			//

			if( entry->event->func() )
				add( entry->event );

			//
			// free the entry
			//

			delete entry;

			continue;
		}

		//
		// sleep for the configured
		// resolution of our timer
		//

		Sleep( tres );
	}

	exit = true;

	return 0;
}

bool _ITH_TIMER::run( long res )
{
	tres = res;

	return exec( NULL );
}

void _ITH_TIMER::end()
{
	stop = true;

	while( !exit )
		Sleep( tres );
}

bool _ITH_TIMER::add( ITH_EVENT * event )
{
	ITH_ENTRY * entry = new ITH_ENTRY;
	if( entry == NULL )
		return false;

	entry->event = event;
	tval_set( entry->sched, event->delay );

	lock.lock();

	ITH_ENTRY * prev = NULL;
	ITH_ENTRY * next = head;

	while( next != NULL )
	{
		if( tval_cmp( entry->sched, next->sched ) <= 0 )
			break;

		if( next == NULL )
			break;

		prev = next;
		next = prev->next;
	}

	entry->next = next;

	if( prev == NULL )
		head = entry;
	else
		prev->next = entry;

	lock.unlock();

	return true;
}

bool _ITH_TIMER::del( ITH_EVENT * event )
{
	ITH_ENTRY * prev = NULL;
	ITH_ENTRY * next = head;

	lock.lock();

	while( next != NULL )
	{
		if( next->event == event )
			break;

		if( next == NULL )
			break;

		prev = next;
		next = prev->next;
	}

	if( next != NULL )
	{
		if( prev == NULL )
			head = next->next;
		else
			prev->next = next->next;

		delete next;
	}

	lock.unlock();

	return ( next != NULL );
}
