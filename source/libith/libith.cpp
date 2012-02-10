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

//==============================================================================
// mutex lock class
//==============================================================================

#ifdef WIN32

_ITH_LOCK::_ITH_LOCK()
{
	memset( obj_name, 0, 20 );
	hmutex = CreateMutex( NULL, false, NULL );
	strcpy_s( obj_name, 20, "unknown" );
}

_ITH_LOCK::~_ITH_LOCK()
{
	CloseHandle( hmutex );
}

void _ITH_LOCK::name( const char * set_name )
{
	strcpy_s( obj_name, 20, set_name );
}

bool _ITH_LOCK::lock()
{
	int result = WaitForSingleObject( hmutex, 3000 );

	assert( result != WAIT_FAILED );

	if( result != WAIT_FAILED )
		return true;

	result = GetLastError();

	printf( "XX : mutex lock failed, ERROR CODE %i\n", result );

	return false;
}

bool _ITH_LOCK::unlock()
{
	ReleaseMutex( hmutex );

	return true;
}

#endif

#ifdef UNIX

_ITH_LOCK::_ITH_LOCK()
{
	memset( obj_name, 0, 20 );
	pthread_mutexattr_init( &attr );
	pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_ERRORCHECK );
	pthread_mutex_init( &mutex, &attr );
}

_ITH_LOCK::~_ITH_LOCK()
{
	pthread_mutex_destroy( &mutex );
	pthread_mutexattr_destroy( &attr );
}

void _ITH_LOCK::name( const char * set_name )
{
	strcpy_s( obj_name, 20, set_name );
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
			printf( "XX : mutex %s lock failed, invalid parameter\n", obj_name  );
			break;

		case ETIMEDOUT:
			printf( "XX : mutex %s lock failed, timeout expired\n", obj_name );
			break;

		case EAGAIN:
			printf( "XX : mutex %s lock failed, recursion error\n", obj_name );
			break;

		case EDEADLK:
			printf( "XX : mutex %s lock failed, mutex already owned\n", obj_name );
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
			printf( "XX : mutex %s unlock failed, mutex not owned\n", obj_name );
			break;
	}

	assert( result == 0 );

	return false;
}

#endif

//==============================================================================
// alertable wait condition
//==============================================================================

#ifdef WIN32

_ITH_COND::_ITH_COND()
{
	hevent = CreateEvent( NULL, TRUE, FALSE, NULL );
}

_ITH_COND::~_ITH_COND()
{
	CloseHandle( hevent );
}

void _ITH_COND::name( const char * set_name )
{
	strcpy_s( obj_name, 20, set_name );
}

bool _ITH_COND::wait( long msecs )
{
	if( msecs < 0 )
		msecs = INFINITE;

	if( WaitForSingleObject( hevent, msecs ) == WAIT_OBJECT_0 )
		return false;

	return true;
}

void _ITH_COND::alert()
{
	SetEvent( hevent );
}

void _ITH_COND::reset()
{
	ResetEvent( hevent );
}

#endif

#ifdef UNIX

_ITH_COND::_ITH_COND()
{
	socketpair( AF_UNIX, SOCK_STREAM, 0, conn_wake );
	fcntl( conn_wake[ 0 ], F_SETFL, O_NONBLOCK );
}

_ITH_COND::~_ITH_COND()
{
	if( conn_wake[ 0 ] != -1 )
	{
		close( conn_wake[ 0 ] );
		conn_wake[ 0 ] = -1;
	}

	if( conn_wake[ 1 ] != -1 )
	{
		close( conn_wake[ 1 ] );
		conn_wake[ 1 ] = -1;
	}

}

void _ITH_COND::name( const char * set_name )
{
	strcpy_s( obj_name, 20, set_name );
}

bool _ITH_COND::wait( long msecs )
{
	// timeval expressed as seconds and microseconds

	timeval	tval;
	timeval * ptval = NULL;

	if( msecs >= 0 )
	{
		tval.tv_sec = msecs / 1000;
		tval.tv_usec = msecs % 1000 * 1000;
		ptval = &tval;
	}

	fd_set fds;
	FD_ZERO( &fds );
	FD_SET( conn_wake[ 0 ], &fds );

	select( conn_wake[ 0 ] + 1, &fds, NULL, NULL, ptval );

	if( FD_ISSET( conn_wake[ 0 ], &fds ) )
		return false;

	return true;
}

void _ITH_COND::alert()
{
	char c = 0;
	long result = send( conn_wake[ 1 ], &c, 1, 0 );
}

void _ITH_COND::reset()
{
	char c = 0;
	long result = recv( conn_wake[ 0 ], &c, 1, 0 );
}

#endif

//==============================================================================
// thread execution class
//==============================================================================

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

	sigset_t signal_mask;
	sigemptyset( &signal_mask );
	sigaddset( &signal_mask, SIGINT );
	sigaddset( &signal_mask, SIGTERM );
	pthread_sigmask( SIG_BLOCK, &signal_mask, NULL );

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

	pthread_detach(
		thread );

	return true;
}

#endif

//==============================================================================
// event execution timer classes
//==============================================================================

_ITH_TIMER::_ITH_TIMER()
{
	head = NULL;

	stop = false;
	exit = false;
}

_ITH_TIMER::~_ITH_TIMER()
{
	while( head != NULL )
	{
		ITH_ENTRY * next = head->next;
		delete head;
		head = next;
	}
}

#ifdef WIN32

void _ITH_TIMER::tval_cur( ITH_TIMEVAL & tval )
{
	SYSTEMTIME stime;
	memset( &stime, 0, sizeof( stime ) );
	GetSystemTime( &stime );

	FILETIME ftime;
	memset( &ftime, 0, sizeof( ftime ) );
	SystemTimeToFileTime( &stime, &ftime );

	memcpy( &tval, &ftime, sizeof( tval ) );
}

void _ITH_TIMER::tval_add( ITH_TIMEVAL & tval, long lval )
{
	// ftime expressed as 100 nanosecond units

	ITH_TIMEVAL dval;
	dval.QuadPart = lval;
	dval.QuadPart *= 10000;

	tval.QuadPart += dval.QuadPart;
}

long _ITH_TIMER::tval_sub( ITH_TIMEVAL & tval1, ITH_TIMEVAL & tval2 )
{
	ITH_TIMEVAL dval;
	dval.QuadPart = tval2.QuadPart - tval1.QuadPart;

	return long( dval.QuadPart / 10000 );
}

bool _ITH_TIMER::wait_time( long msecs )
{
	return cond.wait( msecs );
}

#endif

#ifdef UNIX

void _ITH_TIMER::tval_cur( ITH_TIMEVAL & tval )
{
	gettimeofday( &tval, NULL );
}

void _ITH_TIMER::tval_add( ITH_TIMEVAL & tval, long delay )
{
	// timeval expressed as seconds and microseconds

	tval.tv_sec += delay / 1000;
	tval.tv_usec += delay % 1000 * 1000;
}

long _ITH_TIMER::tval_sub( ITH_TIMEVAL & tval1, ITH_TIMEVAL & tval2 )
{
	long sec = tval2.tv_sec - tval1.tv_sec;
	sec *= 1000;

	long usec = tval2.tv_usec - tval1.tv_usec;
	usec /= 1000;

	return sec + usec;
}

bool _ITH_TIMER::wait_time( long msecs )
{
	return cond.wait( msecs );
}

#endif

void _ITH_TIMER::run()
{
	lock.lock();

	while( !stop )
	{
		//
		// determine the time we must
		// wait before the next event
		// should be executed
		//

		long delay = -1;

		if( head != NULL )
		{
			ITH_TIMEVAL current;
			tval_cur( current );
			delay = tval_sub( current, head->sched );

			if( delay < 0 )
				delay = 0;
		}

		//
		// wait for calculated delay
		//

		lock.unlock();

		bool result = wait_time( delay );

		lock.lock();

		//
		// if the wait returned false,
		// it returned before the time
		// period elapsed
		//

		if( !result )
		{
			cond.reset();
			continue;
		}

		//
		// check if we have an event
		// that needs to be enabled
		//

		if( head != NULL )
		{
			ITH_TIMEVAL current;
			tval_cur( current );

			//
			// make sure the head event
			// is ready to execute
			//

			if( tval_sub( current, head->sched ) > 0 )
				continue;

			ITH_ENTRY * entry = head;
			head = head->next;

			//
			// execute the event
			//

			lock.unlock();

			if( entry->event->func() )
				add( entry->event );

			delete entry;
			lock.lock();
		}
	}

	exit = true;

	lock.unlock();
}

void _ITH_TIMER::end()
{
	stop = true;

	cond.alert();
}

bool _ITH_TIMER::add( ITH_EVENT * event )
{
	ITH_ENTRY * entry = new ITH_ENTRY;
	if( entry == NULL )
		return false;

	entry->event = event;
	tval_cur( entry->sched );
	tval_add( entry->sched, event->delay );

	lock.lock();

	ITH_ENTRY * prev = NULL;
	ITH_ENTRY * next = head;

	while( next != NULL )
	{
		if( tval_sub( next->sched, entry->sched ) <= 0 )
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

	cond.alert();

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

//==============================================================================
// inter process communication classes
//==============================================================================

//
// shared platform functions
//

long _ITH_IPCC::io_send( void *data, size_t size )
{
	char * buff = ( char * ) data;
	size_t sent = 0;
	size_t temp = 0;

	while( size > sent )
	{
		temp = size - sent;
		long result = io_send( buff + sent, temp, temp );

		switch( result )
		{
			case IPCERR_OK:
			case IPCERR_BUFFER:
				break;

			default:
				return result;
		}


		sent += temp;
	}

	return IPCERR_OK;
}

long _ITH_IPCC::io_recv( void *data, size_t size )
{
	char * buff = ( char * ) data;
	size_t rcvd = 0;
	size_t temp = 0;

	while( size > rcvd )
	{
		temp = size - rcvd;
		long result = io_recv( buff + rcvd, temp, temp );

		switch( result )
		{
			case IPCERR_OK:
			case IPCERR_BUFFER:
				break;

			default:
				return result;
		}

		rcvd += temp;
	}

	return IPCERR_OK;
}

#ifdef WIN32

//
// inter process communication client
//

_ITH_IPCC::_ITH_IPCC()
{
	hmutex_recv = CreateMutex( NULL, false, NULL );
	hmutex_send = CreateMutex( NULL, false, NULL );

	hevent_wake = CreateEvent( NULL, true, false, NULL );

	conn = INVALID_HANDLE_VALUE;
}

_ITH_IPCC::~_ITH_IPCC()
{
	detach();

	if( hevent_wake != NULL )
	{
		CloseHandle( hevent_wake );
		hevent_wake = NULL;
	}

	if( hmutex_send != NULL )
	{
		CloseHandle( hmutex_send );
		hmutex_send = NULL;
	}

	if( hmutex_recv != NULL )
	{
		CloseHandle( hmutex_recv );
		hmutex_recv = NULL;
	}
}


void _ITH_IPCC::io_conf( IPCCONN sconn )
{
	conn = sconn;
}

VOID WINAPI io_send_complete( DWORD result, DWORD size, LPOVERLAPPED olapp )
{
	// nothing to do
}

long _ITH_IPCC::io_send( void * data, size_t size, size_t & sent )
{
//	if( conn == INVALID_HANDLE_VALUE )
//		return IPCERR_CLOSED;

	DWORD dwsize = ( DWORD ) sent;

	WaitForSingleObject( hmutex_send, INFINITE );

	// windows does not always set
	// the GetLastError value to
	// success after ReadFileEx but
	// the documentation says you
	// should check it for errors

	SetLastError( ERROR_SUCCESS );

	memset( &olapp_send, 0, sizeof( olapp_send ) );

	long result = WriteFileEx(
					conn,
					data,
					dwsize,
					&olapp_send,
					io_send_complete );

	if( !result )
	{
		result = WaitForSingleObject( hevent_wake, 0 );
//		if( result == WAIT_OBJECT_0 )
//			ResetEvent( hevent_wake );

		ReleaseMutex( hmutex_send );

		if( result == WAIT_OBJECT_0 )
			return IPCERR_WAKEUP;

		return IPCERR_CLOSED;
	}

	result = GetLastError();

	switch( result )
	{
		case ERROR_SUCCESS:

			//
			// wait in an alertable state until
			// the operation completes or until
			// the wake event is signaled
			//

			result = WaitForSingleObjectEx(
				hevent_wake,
				INFINITE,
				true );

			if( result == WAIT_OBJECT_0 )
			{
//				ResetEvent( hevent_wake );

				// cancel the current overlaped
				// request and give it a chance
				// to complete in a wait state

				CancelIo( conn );

				ReleaseMutex( hmutex_recv );

				return IPCERR_WAKEUP;
			}

			GetOverlappedResult(
				conn,
				&olapp_send,
				&dwsize,
				true );

			result = GetLastError();
			break;
	}

	switch( result )
	{
		case ERROR_SUCCESS:
			result = IPCERR_OK;
			break;

		case ERROR_MORE_DATA:
			result = IPCERR_BUFFER;
			break;

		case ERROR_OPERATION_ABORTED:
//			ResetEvent( hevent_wake );
//			result = IPCERR_WAKEUP;
//			break;

		case ERROR_BROKEN_PIPE:
		case ERROR_INVALID_HANDLE:
			result = IPCERR_CLOSED;
			break;

		default:
			result = IPCERR_NODATA;
			break;
	}

	sent = dwsize;

	ReleaseMutex( hmutex_send );

	return result;
}

VOID WINAPI io_recv_complete( DWORD result, DWORD size, LPOVERLAPPED olapp )
{
	// nothing to do
}

long _ITH_IPCC::io_recv( void * data, size_t size, size_t & rcvd )
{
//	if( conn == INVALID_HANDLE_VALUE )
//		return IPCERR_CLOSED;

	DWORD dwsize = ( DWORD ) size;

	WaitForSingleObject( hmutex_recv, INFINITE );

	// windows does not always set
	// the GetLastError value to
	// success after ReadFileEx but
	// the documentation says you
	// should check it for errors

	SetLastError( ERROR_SUCCESS );

	memset( &olapp_recv, 0, sizeof( olapp_recv ) );

	long result = ReadFileEx(
					conn,
					data,
					dwsize,
					&olapp_recv,
					io_recv_complete );

	if( !result )
	{
		result = WaitForSingleObject( hevent_wake, 0 );
		if( result == WAIT_OBJECT_0 )
			ResetEvent( hevent_wake );

		ReleaseMutex( hmutex_recv );

		if( result == WAIT_OBJECT_0 )
			return IPCERR_WAKEUP;

		return IPCERR_CLOSED;
	}

	result = GetLastError();

	switch( result )
	{
		case ERROR_SUCCESS:

			//
			// wait in an alertable state until
			// the operation completes or until
			// the wake event is signaled
			//

			result = WaitForSingleObjectEx(
				hevent_wake,
				INFINITE,
				true );

			if( result == WAIT_OBJECT_0 )
			{
				ResetEvent( hevent_wake );

				// cancel the current overlaped
				// request and give it a chance
				// to complete in a wait state

				CancelIo( conn );

				ReleaseMutex( hmutex_recv );

				return IPCERR_WAKEUP;
			}

			GetOverlappedResult(
				conn,
				&olapp_recv,
				&dwsize,
				true );

			result = GetLastError();
			break;
	}

	switch( result )
	{
		case ERROR_SUCCESS:
			result = IPCERR_OK;
			break;

		case ERROR_MORE_DATA:
			result = IPCERR_BUFFER;
			break;

		case ERROR_OPERATION_ABORTED:
//			ResetEvent( hevent_wake );
//			result = IPCERR_WAKEUP;
//			break;

		case ERROR_BROKEN_PIPE:
		case ERROR_INVALID_HANDLE:
			result = IPCERR_CLOSED;
			break;

		default:
			result = IPCERR_NODATA;
			break;
	}

	rcvd = dwsize;

	ReleaseMutex( hmutex_recv );

	return result;
}

long _ITH_IPCC::attach( const char * path, long timeout )
{
	if( !WaitNamedPipe( path, timeout ) )
		return IPCERR_FAILED;

	conn = CreateFile(
				path,
				GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL,
				OPEN_EXISTING,
				FILE_FLAG_OVERLAPPED,
				NULL );

	if( conn == INVALID_HANDLE_VALUE )
	{
		long result = GetLastError();
		return IPCERR_FAILED;
	}

	return IPCERR_OK;
}

void _ITH_IPCC::wakeup()
{
	if( hevent_wake != NULL )
		SetEvent( hevent_wake );
}

void _ITH_IPCC::detach()
{
	if( conn != INVALID_HANDLE_VALUE )
	{
		CancelIo( conn );
		FlushFileBuffers( conn );

		CloseHandle( conn );
		conn = INVALID_HANDLE_VALUE;
	}
}

//
// inter process communication server
//

_ITH_IPCS::_ITH_IPCS()
{
	hevent_wake = CreateEvent( NULL, true, false, NULL );
	hevent_conn = CreateEvent( NULL, true, false, NULL );

	sid_server = NULL;
	sid_client = NULL;

	acl = NULL;
	psa	= NULL;

	conn = INVALID_HANDLE_VALUE;
}

_ITH_IPCS::~_ITH_IPCS()
{
	done();

	if( hevent_conn != NULL )
	{
		CloseHandle( hevent_conn );
		hevent_conn = NULL;
	}

	if( hevent_wake != NULL )
	{
		CloseHandle( hevent_wake );
		hevent_wake = NULL;
	}
}

long _ITH_IPCS::init( const char * path, bool admin )
{
	// when creating a named pipe with explicit access,
	// you must specify FILE_CREATE_PIPE_INSTANCE for
	// an SID that is appropriate for the account that
	// owns your process. otherwise, after creating the
	// initial pipe instance and assigning the access
	// control, your process will loose its ability to
	// create more than one pipe instance ... really.

	long ea_count = 0;

	// admin sid

	SID_IDENTIFIER_AUTHORITY sia_nt = SECURITY_NT_AUTHORITY;

	if( !AllocateAndInitializeSid(
			&sia_nt,
			2,
			SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0,
			&sid_server ) )
		return IPCERR_FAILED;

	// initialize the explicit access info

	memset( &ea[ 0 ], sizeof( EXPLICIT_ACCESS ), 0 );
	ea[ 0 ].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | FILE_CREATE_PIPE_INSTANCE;
	ea[ 0 ].grfAccessMode = SET_ACCESS;
	ea[ 0 ].grfInheritance= NO_INHERITANCE;
	ea[ 0 ].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[ 0 ].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[ 0 ].Trustee.ptstrName  = ( LPTSTR ) sid_server;

	ea_count++;

	if( !admin )
	{
		// user sid

		if( !AllocateAndInitializeSid(
				&sia_nt,
				2,
				SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_USERS,
				0, 0, 0, 0, 0, 0,
				&sid_client ) )
			return IPCERR_FAILED;

		// initialize the explicit access info

		memset( &ea[ 1 ], sizeof( EXPLICIT_ACCESS ), 0 );
		ea[ 1 ].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
		ea[ 1 ].grfAccessMode = SET_ACCESS;
		ea[ 1 ].grfInheritance= NO_INHERITANCE;
		ea[ 1 ].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[ 1 ].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[ 1 ].Trustee.ptstrName  = ( LPTSTR ) sid_client;

		ea_count++;
	}

	// create a new ACL for the access

	if( SetEntriesInAcl( ea_count, ea, NULL, &acl ) != ERROR_SUCCESS )
		return IPCERR_FAILED;

	// Initialize a security descriptor

	if( !InitializeSecurityDescriptor( &sd, SECURITY_DESCRIPTOR_REVISION ) ) 
		return IPCERR_FAILED;
 
	// Add the ACL to the security descriptor.

	if( !SetSecurityDescriptorDacl(
			&sd,
			TRUE,
			acl,
			FALSE ) )
		return IPCERR_FAILED;

	// Initialize a security attributes structure.

	sa.nLength = sizeof ( SECURITY_ATTRIBUTES );
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = FALSE;

	conn = CreateNamedPipe(
			path,
			FILE_FLAG_FIRST_PIPE_INSTANCE |
			FILE_FLAG_OVERLAPPED |
			PIPE_ACCESS_DUPLEX,
		    PIPE_TYPE_MESSAGE |
			PIPE_READMODE_MESSAGE |
			PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			8192,
			8192,
		    10,
			&sa );

	if( conn == INVALID_HANDLE_VALUE )
		return IPCERR_FAILED;

	return IPCERR_OK;
}

void _ITH_IPCS::done()
{
	if( acl != NULL )
	{
		LocalFree( acl );
		acl = NULL;
	}

	if( sid_client != NULL )
	{
		FreeSid( sid_client );
		sid_client = NULL;
	}

	if( sid_server != NULL )
	{
		FreeSid( sid_server );
		sid_server = NULL;
	}

	if( conn != INVALID_HANDLE_VALUE )
	{
		CloseHandle( conn );
		conn = INVALID_HANDLE_VALUE;
	}
}

long _ITH_IPCS::inbound( const char * path, IPCCONN & ipcconn )
{
	DWORD	dwundef;
	long	result;

	if( conn == INVALID_HANDLE_VALUE )
	{
		conn = CreateNamedPipe(
				path,
				FILE_FLAG_OVERLAPPED |
				PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE |
				PIPE_READMODE_MESSAGE |
				PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				8192,
				8192,
				10,
				&sa );

		if( conn == INVALID_HANDLE_VALUE )
		{
			result = GetLastError();
			return IPCERR_FAILED;
		}
	}

	ipcconn = INVALID_HANDLE_VALUE;

	OVERLAPPED olapp;
	memset( &olapp, 0, sizeof( olapp ) );
	olapp.hEvent = hevent_conn;

	SetLastError( ERROR_SUCCESS );

	result = ConnectNamedPipe( conn, &olapp );
	if( !result )
		result = GetLastError();

	switch( result )
	{
		case ERROR_IO_PENDING:
		{
			HANDLE events[ 2 ] = { hevent_conn, hevent_wake };

			result = WaitForMultipleObjects(
						2,
						events,
						false,
						INFINITE );

			if( result == WAIT_OBJECT_0 + 1 )
			{
				// cancel the current overlaped
				// request and give it a chance
				// to complete in a wait state

				CancelIo( conn );
				SleepEx( 0, true );
			}

			result = GetOverlappedResult(
						conn,
						&olapp,
						&dwundef,
						false );

			result = GetLastError();

			break;
		}
	}

	switch( result )
	{
		case ERROR_SUCCESS:
		case ERROR_PIPE_CONNECTED:
			ipcconn = conn;
			conn = INVALID_HANDLE_VALUE;
			result = IPCERR_OK;
			break;

		case ERROR_OPERATION_ABORTED:
			ResetEvent( hevent_wake );
			result = IPCERR_WAKEUP;
			break;

		case ERROR_GEN_FAILURE:
		case ERROR_BROKEN_PIPE:
		case ERROR_INVALID_HANDLE:
			result = IPCERR_CLOSED;
			break;

		default:
			result = IPCERR_NODATA;
			break;
	}

	return result;
}

void _ITH_IPCS::wakeup()
{
	SetEvent( hevent_wake );
}

#endif

#ifdef UNIX

//
// inter process communication client
//

_ITH_IPCC::_ITH_IPCC()
{
	socketpair( AF_UNIX, SOCK_STREAM, 0, conn_wake );

	conn = -1;
}

_ITH_IPCC::~_ITH_IPCC()
{
	detach();

	if( conn_wake[ 0 ] != -1 )
	{
		close( conn_wake[ 0 ] );
		conn_wake[ 0 ] = -1;
	}

	if( conn_wake[ 1 ] != -1 )
	{
		close( conn_wake[ 1 ] );
		conn_wake[ 1 ] = -1;
	}
}


void _ITH_IPCC::io_conf( IPCCONN sconn )
{
	conn = sconn;
}

long _ITH_IPCC::io_send( void * data, size_t size, size_t & sent )
{
	long result = send( conn, data, size, 0 );
	if( result < 0 )
		return IPCERR_FAILED;

	sent = result;

	return IPCERR_OK;
}

long _ITH_IPCC::io_recv( void * data, size_t size, size_t & rcvd )
{
	fd_set fds;
	FD_ZERO( &fds );
	FD_SET( conn, &fds );
	FD_SET( conn_wake[ 0 ], &fds );

	int max = conn_wake[ 0 ];
	if( max < conn )
		max = conn;

	if( select( max + 1, &fds, NULL, NULL, NULL ) <= 0 )
		return IPCERR_FAILED;

	if( FD_ISSET( conn, &fds ) )
	{
		long result = recv( conn, data, size, 0 );
		if( result < 0 )
			return IPCERR_FAILED;

		if( result == 0 )
			return IPCERR_CLOSED;

		rcvd = result;

		return IPCERR_OK;
	}

	if( FD_ISSET( conn_wake[ 0 ], &fds ) )
	{
		char c;
		recv( conn_wake[ 0 ], &c, 1, 0 );

		return IPCERR_WAKEUP;
	}

	return IPCERR_NODATA;
}

long _ITH_IPCC::attach( const char * path, long timeout )
{
	conn = socket( AF_UNIX, SOCK_STREAM, 0 );
	if( conn == -1 )
		return IPCERR_FAILED;

	if( socketpair( AF_UNIX, SOCK_STREAM, 0, conn_wake ) < 0 )
		return IPCERR_FAILED;

	struct sockaddr_un saddr;
	saddr.sun_family = AF_UNIX;

	long sun_len =  strlen( path ) + sizeof( saddr.sun_family );

#ifndef __linux__
	sun_len += sizeof( saddr.sun_len );
	saddr.sun_len = sun_len;
#endif

	strcpy( saddr.sun_path, path );

	if( connect( conn, ( struct sockaddr * ) &saddr, sun_len ) < 0 )
		return IPCERR_FAILED;

	return IPCERR_OK;
}

void _ITH_IPCC::wakeup()
{
	char c = 0;
	send( conn_wake[ 1 ], &c, 1, 0 );
}

void _ITH_IPCC::detach()
{
	if( conn != -1 )
		close( conn );
}

//
// inter process communication server
//

_ITH_IPCS::_ITH_IPCS()
{
	conn = -1;

	socketpair( AF_UNIX, SOCK_STREAM, 0, conn_wake );
}

_ITH_IPCS::~_ITH_IPCS()
{
	done();

	if( conn_wake[ 0 ] != -1 )
	{
		close( conn_wake[ 0 ] );
		conn_wake[ 0 ] = -1;
	}

	if( conn_wake[ 1 ] != -1 )
	{
		close( conn_wake[ 1 ] );
		conn_wake[ 1 ] = -1;
	}
}

long _ITH_IPCS::init( const char * path, bool admin )
{
	unlink( path );

	conn = socket( AF_UNIX, SOCK_STREAM, 0 );
	if( conn == -1 )
		return IPCERR_FAILED;

	struct sockaddr_un saddr;
	saddr.sun_family = AF_UNIX;

	long sun_len =  strlen( path ) + sizeof( saddr.sun_family );

#ifndef __linux__
        sun_len += sizeof( saddr.sun_len );
        saddr.sun_len = sun_len;
#endif

	strcpy( saddr.sun_path, path );

	if( bind( conn, ( struct sockaddr * ) &saddr, sun_len ) < 0 )
		return IPCERR_FAILED;

	if( !admin )
		if( chmod( path, S_IRWXU | S_IRWXG | S_IRWXO ) < 0 )
			return IPCERR_FAILED;

	if( listen( conn, 5 ) < 0 )
		return IPCERR_FAILED;

	return IPCERR_OK;
}

void _ITH_IPCS::done()
{
	if( conn != -1 )
		close( conn );
}

long _ITH_IPCS::inbound( const char * path, IPCCONN & ipcconn )
{
	fd_set fds;
	FD_ZERO( &fds );
	FD_SET( conn, &fds );
	FD_SET( conn_wake[ 0 ], &fds );

	int max = conn_wake[ 0 ];
	if( max < conn )
		max = conn;

	if( select( max + 1, &fds, NULL, NULL, NULL ) <= 0 )
		return IPCERR_FAILED;

	if( FD_ISSET( conn, &fds ) )
	{
		ipcconn = accept( conn, NULL, NULL );
		if( ipcconn < 0 )
			return IPCERR_FAILED;

		return IPCERR_OK;
	}

	if( FD_ISSET( conn_wake[ 0 ], &fds ) )
	{
		char c;
		recv( conn_wake[ 0 ], &c, 1, 0 );

		return IPCERR_WAKEUP;
	}

	return IPCERR_NODATA;
}

void _ITH_IPCS::wakeup()
{
	char c = 0;
	send( conn_wake[ 1 ], &c, 1, 0 );
}

#endif
