
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

//==============================================================================
// inter process communication classes
//==============================================================================

#ifdef WIN32

//
// inter process communication client
//

_ITH_IPCC::_ITH_IPCC()
{
	hmutex_recv = CreateMutex( NULL, false, NULL );
	hmutex_send = CreateMutex( NULL, false, NULL );

	hevent_wake = CreateEvent( NULL, true, false, NULL );
	hevent_send = CreateEvent( NULL, true, false, NULL );

	conn = INVALID_HANDLE_VALUE;
}

_ITH_IPCC::~_ITH_IPCC()
{
	detach();
}


void _ITH_IPCC::io_conf( IPCCONN sconn )
{
	conn = sconn;
}

VOID WINAPI io_recv_complete( DWORD result, DWORD size, LPOVERLAPPED olapp )
{
	// we do nothing here as the
	// WaitForSingleObjectEx call
	// will wake on io completion
}

long _ITH_IPCC::io_recv( void * data, size_t & size )
{
	DWORD dwsize = ( DWORD ) size;

	OVERLAPPED olapp;
	memset( &olapp, 0, sizeof( olapp ) );

	WaitForSingleObject( hmutex_recv, INFINITE );

	// windows does not always set
	// the GetLastError value to
	// success after ReadFileEx but
	// the documentation says you
	// should check it for errors

	SetLastError( ERROR_SUCCESS );

	long result = ReadFileEx(
					conn,
					data,
					dwsize,
					&olapp,
					io_recv_complete );

	if( !result )
	{
		ReleaseMutex( hmutex_recv );
		return IPCERR_CLOSED;
	}

	result = GetLastError();

	switch( result )
	{
		case ERROR_SUCCESS:

			result = WaitForSingleObjectEx(
						hevent_wake,
						INFINITE,
						true );

			if( result == WAIT_OBJECT_0 )
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
						&dwsize,
						true );

			result = GetLastError();

			break;
	}

	size = dwsize;

	switch( result )
	{
		case ERROR_SUCCESS:
			result = IPCERR_OK;
			break;

		case ERROR_MORE_DATA:
			result = IPCERR_BUFFER;
			break;

		case ERROR_OPERATION_ABORTED:
			ResetEvent( hevent_wake );
			result = IPCERR_WAKEUP;
			break;

		case ERROR_BROKEN_PIPE:
		case ERROR_INVALID_HANDLE:
			result = IPCERR_CLOSED;
			break;

		default:
			result = IPCERR_NODATA;
			break;
	}

	ReleaseMutex( hmutex_recv );

	return result;
}

long _ITH_IPCC::io_send( void * data, size_t & size )
{
	OVERLAPPED olapp;
	memset( &olapp, 0, sizeof( olapp ) );
	olapp.hEvent = hevent_send;

	WaitForSingleObject( hmutex_send, INFINITE );

	DWORD dwsize = ( DWORD ) size;

	long result = WriteFile(
					conn,
					data,
					dwsize,
					&dwsize,
					&olapp );

	if( !result && ( GetLastError() == ERROR_IO_PENDING ) )
	{
		WaitForSingleObjectEx(
			hevent_send,
			INFINITE,
			true );

		result = GetOverlappedResult(
					conn,
					&olapp,
					&dwsize,
					true );
	}

	size = dwsize;

	if( !result )
	{
		result = GetLastError();

		switch( result )
		{
			case ERROR_MORE_DATA:
				ReleaseMutex( hmutex_send );
				return IPCERR_BUFFER;

			case ERROR_BROKEN_PIPE:
				conn = INVALID_HANDLE_VALUE;
				ReleaseMutex( hmutex_send );
				return IPCERR_CLOSED;
		}
	}

	ReleaseMutex( hmutex_send );
	return IPCERR_OK;
}

long _ITH_IPCC::attach( char * path, long timeout )
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
	}

	if( hevent_send != NULL )
	{
		CloseHandle( hevent_send );
		hevent_send = NULL;
	}

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

	if( conn != INVALID_HANDLE_VALUE )
	{
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

	sid		= NULL;
	acl		= NULL;
	psa		= NULL;

	conn	= INVALID_HANDLE_VALUE;
}

_ITH_IPCS::~_ITH_IPCS()
{
	done();
}

long _ITH_IPCS::init( char * path, bool admin )
{
	// create the well-known world sid

	SID_IDENTIFIER_AUTHORITY basesid = SECURITY_NT_AUTHORITY;

	if( admin )
	{
		// domain admin sid

		if( !AllocateAndInitializeSid(
				&basesid,
				1,
				SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_ADMINS,
				0, 0, 0, 0, 0, 0,
				&sid ) )
			return IPCERR_FAILED;
	}
	else
	{
		// domain user sid

		if( !AllocateAndInitializeSid(
				&basesid,
				1,
				SECURITY_WORLD_RID,
				0,
				0, 0, 0, 0, 0, 0,
				&sid ) )
			return IPCERR_FAILED;
	}

	// initialize the explicit access info

	memset( &ea, sizeof( ea ), 0 );
	ea.grfAccessPermissions = KEY_READ | KEY_WRITE;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance= NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.ptstrName  = ( LPTSTR ) sid;

	if( admin )
		ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	else
		ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

	// create a new ACL that contains the new ACEs.

	if( SetEntriesInAcl( 1, &ea, NULL, &acl ) != ERROR_SUCCESS )
		return IPCERR_FAILED;

	// Initialize a security descriptor

	if( !InitializeSecurityDescriptor( &sd, SECURITY_DESCRIPTOR_REVISION ) ) 
		return IPCERR_FAILED;
 
	// Add the ACL to the security descriptor.

	if( !SetSecurityDescriptorDacl(
			&sd,
			TRUE,		// bDaclPresent flag
			acl,
			FALSE ) )	// not a default DACL
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
			NULL );
//			&sa );

	if( conn == INVALID_HANDLE_VALUE )
		return IPCERR_FAILED;

	return IPCERR_OK;
}

void _ITH_IPCS::done()
{
	if( acl != NULL )
		LocalFree( acl );

	if( sid != NULL )
		FreeSid( sid );

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

	if( conn != INVALID_HANDLE_VALUE )
		CloseHandle( conn );

	conn = INVALID_HANDLE_VALUE;
}

long _ITH_IPCS::inbound( char * path, IPCCONN & ipcconn )
{
	DWORD dwundef;

	if( conn == INVALID_HANDLE_VALUE )
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
				NULL );
//				&sa );

	ipcconn = INVALID_HANDLE_VALUE;

	OVERLAPPED olapp;
	memset( &olapp, 0, sizeof( olapp ) );
	olapp.hEvent = hevent_conn;

	SetLastError( ERROR_SUCCESS );

	ConnectNamedPipe( conn, &olapp );

	long result = GetLastError();

	switch( result )
	{
		case ERROR_IO_PENDING:
		{
			HANDLE events[ 2 ];
			events[ 0 ] = hevent_conn;
			events[ 1 ] = hevent_wake;

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
						true );

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

		case ERROR_BROKEN_PIPE:
		case ERROR_INVALID_HANDLE:
			result = IPCERR_CLOSED;
			break;

		default:
			result = IPCERR_NODATA;
			break;
	}

	return IPCERR_OK;
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
	sock = -1;
}

_ITH_IPCC::~_ITH_IPCC()
{
	detach();
}


void _ITH_IPCC::io_conf( IPCCONN sconn )
{
	conn = sconn;
}

long _ITH_IPCC::io_recv( void * data, size_t & size )
{
	long result = recv( sock, data, size, 0 );
	if( result < 0 )
		return IPCERR_FAILED;

	size = result;

	return IPCERR_OK;
}

long _ITH_IPCC::io_send( void * data, size_t & size )
{
	long result = send( sock, data, size, 0 );
	if( result < 0 )
		return IKEI_FAILED;

	size = result;

	return IPCERR_OK;
}

long _ITH_IPCC::attach( char * path, long timeout )
{
	sock = socket( AF_UNIX, SOCK_STREAM, 0 );
	if( sock == -1 )
		return IPCERR_FAILED;

	struct sockaddr_un saddr;
	saddr.sun_family = AF_UNIX;

	long sun_len =  strlen( path ) + sizeof( saddr.sun_family );

#ifndef __linux__
	sun_len += sizeof( saddr.sun_len );
	saddr.sun_len = sun_len;
#endif

	strcpy( saddr.sun_path, path );

	if( connect( sock, ( struct sockaddr * ) &saddr, sun_len ) < 0 )
		return IPCERR_FAILED;

	return IPCERR_OK;
}

void _ITH_IPCC::wakeup()
{
}

void _ITH_IPCC::detach()
{
	if( sock != -1 )
	{
		close( sock );
		sock = -1;
	}
}

//
// inter process communication server
//

_ITH_IPCS::_ITH_IPCS()
{
	sock = -1;
}

_ITH_IPCS::~_ITH_IPCS()
{
	done();
}

long _ITH_IPCS::init( char * path, bool admin )
{
	unlink( IKEI_SOCK_NAME );

	sock = socket( AF_UNIX, SOCK_STREAM, 0 );
	if( sock == -1 )
		return IPCERR_FAILED;

	struct sockaddr_un saddr;
	saddr.sun_family = AF_UNIX;

	long sun_len =  strlen( path ) + sizeof( saddr.sun_family );

#ifndef __linux__
        sun_len += sizeof( saddr.sun_len );
        saddr.sun_len = sun_len;
#endif

	strcpy( saddr.sun_path, path );

	if( bind( sock, ( struct sockaddr * ) &saddr, sun_len ) < 0 )
		return IPCERR_FAILED;

	if( chmod( IKEI_SOCK_NAME, S_IRWXU | S_IRWXG | S_IRWXO ) < 0 )
		return IPCERR_FAILED;

	if( listen( sock, 5 ) < 0 )
		return IPCERR_FAILED;

	return IPCERR_OK;
}

void _ITH_IPCS::done()
{
	if( sock != -1 )
		close( sock );
}

long _ITH_IPCS::inbound( char * path, IPCCONN & ipcconn )
{
	fd_set fdset;
	FD_ZERO( &fdset );
	FD_SET( sock, &fdset );

	if( select( sock + 1, &fdset, NULL, NULL, NULL ) <= 0 )
		return IPCERR_FAILED;

	int csock = accept( sock, NULL, NULL );
	if( csock < 0 )
		return IPCERR_FAILED;

	ipcconn = csock;

	return IPCERR_OK;
}

void _ITH_IPCS::wakeup()
{
}

#endif
