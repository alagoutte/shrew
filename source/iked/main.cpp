
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

#include "iked.h"

IKED iked;

#ifdef WIN32

//
// win32 service specific section
//

#define SERVICE_NAME	"iked"
#define SERVICE_DESC	"ShrewSoft IKE Daemon"
#define INSTALL_HKEY	"SOFTWARE\\ShrewSoft\\vpn"

SERVICE_STATUS_HANDLE	service_handle;
SERVICE_STATUS			service_status;

void service_add( char * path )
{
	char prog[ MAX_PATH ];
	sprintf_s( prog, MAX_PATH, "%s -service", path );

	SC_HANDLE hmngr = NULL;
	SC_HANDLE hsrvc = NULL;

	hmngr = OpenSCManager(
				NULL,
				NULL,
				SC_MANAGER_ALL_ACCESS );

	if( hmngr == NULL )
	{
		printf( "!! : unable to open service manager\n" );
		exit( 1 );
	}
	
	hsrvc = CreateService(
				hmngr,
				SERVICE_NAME,
				SERVICE_DESC,
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS,
				SERVICE_AUTO_START,
				SERVICE_ERROR_NORMAL,
				prog,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL );

	if( hsrvc != NULL )
		printf( "ii : service has been registered\n" );
	else
		printf( "!! : unable to register service\n" );
}

void service_del( char * path )
{
	SC_HANDLE hmngr = NULL;
	SC_HANDLE hsrvc = NULL;

	hmngr = OpenSCManager(
				NULL,
				NULL,
				SC_MANAGER_ALL_ACCESS );

	if( hmngr == NULL )
	{
		printf( "!! : unable to open service manager\n" );
		exit( 1 );
	}

	hsrvc = OpenService(
				hmngr,
				SERVICE_NAME,
				SERVICE_ALL_ACCESS );

	if( hmngr == NULL )
	{
		printf( "!! : unable to open service\n" );
		exit( 1 );
	}

	if( DeleteService( hsrvc ) )
		printf( "ii : service has been deregistered\n" );
	else
		printf( "!! : unable to deregister service\n" );
}

DWORD __stdcall service_ctrl( DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext ) 
{
	switch( dwControl )
	{
		case SERVICE_CONTROL_STOP: 

			//
			// stop daemon operation
			//

			iked.halt( true );

			break;

		case SERVICE_CONTROL_INTERROGATE:

			//
			// send service status update
			//

			break;

		case SERVICE_CONTROL_POWEREVENT:

			//
			// power event notifications
			//

			if( dwEventType == PBT_APMSUSPEND )
			{
				iked.log.txt( LLOG_DEBUG,
					"ii : SERVICE_CONTROL_POWEREVENT -> PBT_APMSUSPEND\n" );

				iked.halt( false );
			}

			if( dwEventType == PBT_APMRESUMEAUTOMATIC )
				iked.log.txt( LLOG_DEBUG,
					"ii : SERVICE_CONTROL_POWEREVENT -> PBT_APMRESUMEAUTOMATIC\n" );

			if( dwEventType == PBT_APMRESUMESUSPEND )
				iked.log.txt( LLOG_DEBUG,
					"ii : SERVICE_CONTROL_POWEREVENT -> PBT_APMRESUMESUSPEND\n" );

			break;

		default:

			//
			// unknown service opcode
			//

			printf( "ii : unknown service opcode\n" );
		    return ERROR_CALL_NOT_IMPLEMENTED;
	} 

	//
	// send service status update
	//

	if( !SetServiceStatus( service_handle, &service_status ) )
		printf( "ii : unable to update service status" );

    return NO_ERROR;
}

VOID __stdcall service_main( DWORD argc, LPTSTR * argv ) 
{
	//
	// Register service control handler
	//

	service_status.dwServiceType        = SERVICE_WIN32;
	service_status.dwCurrentState       = SERVICE_START_PENDING;
	service_status.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT;
	service_status.dwWin32ExitCode      = 0;
	service_status.dwServiceSpecificExitCode = 0;
	service_status.dwCheckPoint         = 0;
	service_status.dwWaitHint           = 0;
 
    service_handle = RegisterServiceCtrlHandlerEx(
						SERVICE_NAME,
						service_ctrl,
						NULL );
 
	if( service_handle == NULL )
	{ 
		printf( "ii : unable to register service control handler\n" );
		return; 
	} 

	if( iked.init( 0 ) != LIBIKE_OK )
	{ 
		//
		// daemon initialization failed
		//

		service_status.dwCurrentState	= SERVICE_STOPPED;
		service_status.dwCheckPoint		= 0;
		service_status.dwWaitHint		= 0;
		service_status.dwWin32ExitCode	= -1;
		service_status.dwServiceSpecificExitCode = 0;

		SetServiceStatus( service_handle, &service_status ); 

		printf( "ii : service failed to start\n" );

		return; 
	}

	//
	// daemon initialized
	//

	service_status.dwCurrentState	= SERVICE_RUNNING;
	service_status.dwCheckPoint		= 0; 
	service_status.dwWaitHint		= 0; 

	SetServiceStatus( service_handle, &service_status );

	printf( "ii : service started\n" );

	//
	// run daemon main loop
	//

	iked.loop();

	//
	// notify service has stopped
	//

	service_status.dwWin32ExitCode	= 0;
	service_status.dwCurrentState	= SERVICE_STOPPED;
	service_status.dwCheckPoint		= 0;
	service_status.dwWaitHint		= 0;

	SetServiceStatus( service_handle, &service_status );
}

#endif

#ifdef UNIX

//
// unix daemon specific section
//

void daemon_stop( int sig_num )
{
	//
	// stop daemon operation
	//

	iked.halt( true );
}

bool daemon_pidfile_create( char * path_pid )
{
	if( !path_pid[ 0 ] )
		return false;

	//
	// read the pid file
	//

	pid_t pid = -1;

	FILE * fp = fopen( path_pid, "r" );
	if( fp != NULL )
	{
		fscanf( fp, "%d", &pid );
		fclose( fp );
	}

	if( getpgid( pid ) != -1 )
	{
		printf( "process already running as pid %d\n", pid );
		return false;
	}

	fp = fopen( path_pid, "w" );
	if( fp != NULL )
	{
		fprintf( fp, "%d", getpid() );
		fclose( fp );
		return true;
	}

	printf( "unable to open pid file path \'%s\'\n", path_pid );
	return false;
}

void daemon_pidfile_remove( char * path_pid )
{
	if( !path_pid[ 0 ] )
		return;

	unlink( path_pid );
}

#endif

int main( int argc, char * argv[], char * envp[] )
{

#ifdef WIN32

	//
	// initialize winsock
	//

	WORD	reqver;
	WSADATA	wsadata;
	memset( &wsadata, 0, sizeof( wsadata ) );

	reqver = MAKEWORD( 1, 1 );
	if( WSAStartup( reqver, &wsadata ) )
	{
		printf( "wsastartup failed\n" );
		return false;
	}

	//
	// check command line parameters
	//

	bool service = false;

	for( long count = 1; count < argc; count++ )
	{
		if( !strcmp( argv[ count ], "-service" ) )
			service = true;

		if( !strcmp( argv[ count ], "-register" ) )
		{
			service_add( argv[ 0 ] );
			return 0;
		}

		if( !strcmp( argv[ count ], "-deregister" ) )
		{
			service_del( argv[ 0 ] );
			return 0;
		}
	}

	//
	// are we running as a service
	// or a foreground application
	//

	if( service )
	{
		//
		// running as a service
		//

		SERVICE_TABLE_ENTRY	ste[ 2 ];
		
		ste[ 0 ].lpServiceName = SERVICE_NAME;
		ste[ 0 ].lpServiceProc = service_main;
		ste[ 1 ].lpServiceName = NULL;
		ste[ 1 ].lpServiceProc = NULL;
		
		if( !StartServiceCtrlDispatcher( ste ) )
			printf( "ii : StartServiceCtrlDispatcher error = %d\n", GetLastError() );
	}
	else
	{
		//
		// running as an application
		//

		if( iked.init( 0 ) != LIBIKE_OK )
			return false;

		//
		// run daemon main loop
		//

		iked.loop();
	}

	//
	// release winsock
	//

	WSACleanup(); 

#endif

#ifdef UNIX

	//
	// check that we are root
	//

	if( getuid() )
	{
		printf( "you must be root to run this program !!!\n" );
		return LIBIKE_FAILED;
	}

	//
	// check command line parameters
	//

	char path_conf[ MAX_PATH ] = { 0 };
	char path_log[ MAX_PATH ] = { 0 };
	char path_pid[ MAX_PATH ] = { 0 };
	bool service = true;
	long debuglevel = 0;

	for( long argi = 1; argi < argc; argi++ )
	{
		if( !strcmp( argv[ argi ], "-F" ) )
		{
			service = false;
			continue;
		}

		if( !strcmp( argv[ argi ], "-p" ) )
		{
			if( ( argc - argi ) < 2 )
			{
				printf( "you must specify a path following the -p option\n" );
				return -1;
			}

			strncpy( path_pid, argv[ ++argi ], MAX_PATH );

			continue;
		}

		if( !strcmp( argv[ argi ], "-f" ) )
		{
			if( ( argc - argi ) < 2 )
			{
				printf( "you must specify a path following the -f option\n" );
				return -1;
			}

			strncpy( path_conf, argv[ ++argi ], MAX_PATH );

			continue;
		}

		if( !strcmp( argv[ argi ], "-l" ) )
		{
			if( ( argc - argi ) < 2 )
			{
				printf( "you must specify a path following the -l option\n" );
				return -1;
			}

			strncpy( path_log, argv[ ++argi ], MAX_PATH );

			continue;
		}

		if( !strcmp( argv[ argi ], "-d" ) )
		{
			if( ( argc - argi ) < 2 )
			{
				printf( "you must specify a debug level between 0 and 6 following the -d option\n" );
				return -1;
			}

			debuglevel = atol( argv[ ++argi ] );
			if ( ( debuglevel < 0 ) || (debuglevel > 6) )
			{
				printf( "you must specify a debug level between 0 and 6 following the -d option\n" );
				return -1;
			}

			continue;
		}

		printf( "invalid option %s specified\n", argv[ argi ] );
		return -1;
	}

	//
	// setup stop signal
	//

	signal( SIGINT, daemon_stop );
	signal( SIGTERM, daemon_stop );
	signal( SIGPIPE, SIG_IGN );

	//
	// set config and log file paths
	//

	iked.set_files( path_conf, path_log );

	//
	// initialize
	//

	if( iked.init( debuglevel ) != LIBIKE_OK )
		return -1;

	//
	// are we running as a deamon
	//

	if( service )
		daemon( 0, 0 );

	//
	// create our pid file
	//

	if( path_pid[ 0 ] )
		if( !daemon_pidfile_create( path_pid ) )
			return -1;

	//
	// run daemon main loop
	//

	iked.loop();

	//
	// remove our pidfile
	//

	if( path_pid[ 0 ] )
		daemon_pidfile_remove( path_pid );

#endif

	return 0;
}

