
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

#ifndef _LIBITH_H_
#define _LIBITH_H_

#ifdef WIN32
# include <windows.h>
# include <assert.h>
# include <aclapi.h>
#endif

#ifdef UNIX
# ifdef __linux__
#  include <time.h>
#  include <errno.h>
#  include <assert.h>
#  include <unistd.h>
#  include <signal.h>
#  include <pthread.h>
#  include <fcntl.h>
#  include <sys/time.h>
#  include <sys/un.h>
#  include <sys/stat.h>
#  include <sys/socket.h>
# else
#  include <errno.h>
#  include <unistd.h>
#  include <signal.h>
#  include <assert.h>
#  include <pthread.h>
#  include <fcntl.h>
#  include <sys/time.h>
#  include <sys/types.h>
#  include <sys/un.h>
#  include <sys/stat.h>
#  include <sys/socket.h>
# endif
# include "compat/winstring.h"
#endif

#include <stdio.h>
#include "export.h"

//
// Win32 specific
//

#ifdef WIN32

typedef LARGE_INTEGER ITH_TIMEVAL;

#endif

//
// Unix specific
//

#ifdef UNIX

typedef timeval ITH_TIMEVAL; 
#define Sleep( T ) usleep( T * 1000 )

#endif

//==============================================================================
// mutex lock class
//==============================================================================

typedef class DLX _ITH_LOCK
{
	private:

#ifdef WIN32

	HANDLE	hmutex;

#endif

#ifdef UNIX

	pthread_mutex_t mutex;
	pthread_mutexattr_t attr;

#endif

	char	obj_name[ 20 ];

	public:

	_ITH_LOCK();
	~_ITH_LOCK();

	void	name( const char * set_name );

	bool	lock();
	bool	unlock();

}ITH_LOCK;

//==============================================================================
// alertable wait condition
//==============================================================================

typedef class DLX _ITH_COND
{
	private:

#ifdef WIN32

	HANDLE	hevent;

#endif

#ifdef UNIX

	int	conn_wake[ 2 ];

#endif

	char	obj_name[ 20 ];

	public:

	_ITH_COND();
	~_ITH_COND();

	void	name( const char * set_name );

	bool	wait( long msecs );

	void	alert();
	void	reset();

}ITH_COND;

//==============================================================================
// thread execution class
//==============================================================================

typedef class DLX _ITH_EXEC
{

#ifdef UNIX

	pthread_t thread;

#endif

	public:

	_ITH_EXEC();

	bool			exec( void * arg );
	virtual long	func( void * arg ) = 0;

}ITH_EXEC;

//==============================================================================
// event execution timer classes
//==============================================================================

typedef class DLX _ITH_EVENT
{
	public:

	long delay;

	virtual	bool func() = 0;

}ITH_EVENT;

typedef struct _ITH_ENRTY
{
	_ITH_ENRTY * next;
	_ITH_EVENT * event;

	ITH_TIMEVAL	sched;

}ITH_ENTRY;

typedef class DLX _ITH_TIMER
{
	private:

	ITH_ENTRY *	head;
	ITH_LOCK	lock;
	ITH_COND	cond;

	bool	stop;
	bool	exit;

	void	tval_cur( ITH_TIMEVAL & tval );
	void	tval_add( ITH_TIMEVAL & tval, long lval = 0 );
	long	tval_sub( ITH_TIMEVAL & tval1, ITH_TIMEVAL & tval2 );

	bool	wait_time( long msecs );

	public:

	_ITH_TIMER();
	virtual	~_ITH_TIMER();

	void	run();
	void	end();

	bool	add( ITH_EVENT * event );
	bool	del( ITH_EVENT * event );

}ITH_TIMER;

//==============================================================================
// inter process communication classes
//==============================================================================

#ifdef WIN32

#define IPCCONN			HANDLE

#endif

#ifdef UNIX

#define IPCCONN			int

#endif

#define IPCTYPE_SYSIPC	1
#define IPCTYPE_SOCKET	2

#define IPCERR_OK		1
#define IPCERR_FAILED	2
#define IPCERR_BUFFER	3
#define IPCERR_WAKEUP	4
#define IPCERR_CLOSED	5
#define IPCERR_NODATA	6

typedef class DLX _ITH_IPCC
{
	protected:

#ifdef WIN32

	HANDLE	hmutex_send;
	HANDLE	hmutex_recv;

	HANDLE	hevent_wake;

	OVERLAPPED olapp_send;
	OVERLAPPED olapp_recv;

#endif

#ifdef UNIX

	int		conn_wake[ 2 ];

#endif
	protected:

	IPCCONN		conn;

	void	io_conf( IPCCONN sconn );

	long	io_send( void * data, size_t size );
	long	io_send( void * data, size_t size, size_t & sent );

	long	io_recv( void * data, size_t size );
	long	io_recv( void * data, size_t size, size_t & rcvd );

	public:

	_ITH_IPCC();
	~_ITH_IPCC();

	long	attach( const char * path, long timeout );
	void	wakeup();
	void	detach();

}ITH_IPCC;

typedef class DLX _ITH_IPCS
{
	private:

#ifdef WIN32

	HANDLE		hevent_conn;
	HANDLE		hevent_wake;

	PSID		sid_server;
	PSID		sid_client;
	PACL		acl;

	EXPLICIT_ACCESS			ea[ 2 ];
	SECURITY_DESCRIPTOR		sd;
	SECURITY_ATTRIBUTES		sa;
	PSECURITY_ATTRIBUTES	psa;

#endif

#ifdef UNIX

	int		conn_wake[ 2 ];

#endif

	protected:

	IPCCONN		conn;

	public:

	_ITH_IPCS();
	~_ITH_IPCS();

	long	init( const char * path, bool admin );
	void	done();

	long	inbound( const char * path, IPCCONN & ipcconn );
	void	wakeup();

}ITH_IPCS;

#endif
