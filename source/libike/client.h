
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

#ifndef _CLIENT_H_
#define _CLIENT_H_

#ifdef WIN32
# include <winsock2.h>
# include <windows.h>
# include <shlobj.h>
#else
# include <unistd.h>
# include <signal.h>
# include <netdb.h>
# include <netinet/in.h>
#endif

# include <string.h>

#include "libike.h"
#include "config.h"
#include "export.h"
#include "version.h"

enum OPT_RESULT
{
	OPT_RESULT_SUCCESS,
	OPT_RESULT_SYNTAX_ERROR,
	OPT_RESULT_RESUME_ERROR
};

enum CLIENT_STATE
{
	CLIENT_STATE_DISCONNECTED,
	CLIENT_STATE_CONNECTING,
	CLIENT_STATE_CONNECTED,
	CLIENT_STATE_DISCONNECTING
};

typedef class DLX _CLIENT : public ITH_EXEC
{
	protected:

	ITH_COND		connecting;
	CONFIG_MANAGER	manager;

	BDATA site_name;

	IKE_PEER		peer;
	IKE_XCONF       xconf;
	IKE_PROPOSAL    proposal_isakmp;
	IKE_PROPOSAL    proposal_esp;
	IKE_PROPOSAL    proposal_ipcomp;
	IKEI			ikei;
	IKEI_STATS		stats;

	BDATA	fpath;
	BDATA	fpass;
	BDATA	username;
	BDATA	password;
	bool	autoconnect;
	bool	suspended;
	
	virtual const char * app_name() = 0;

	virtual bool	get_username() = 0;
	virtual bool	get_password() = 0;
	virtual bool	get_filepass( BDATA & path ) = 0;

	virtual bool	set_stats() = 0;
	virtual bool	set_status( long status, BDATA * text ) = 0;

	bool	run_init();
	bool	run_loop();

	long	func( void * );

	CONFIG			config;
	CLIENT_STATE	cstate;

	public:

	_CLIENT();
	virtual ~_CLIENT();

	OPT_RESULT	read_opts( int argc, char ** argv );
	void		show_help();

	bool		config_load();
	bool		config_save();

	CLIENT_STATE	state();

	bool		auto_connect();
	bool		user_credentials();

	bool		vpn_connect( bool wait_input );
	bool		vpn_disconnect();

	bool		vpn_suspend();
	bool		vpn_resume();

	virtual bool	log( long code, const char * format, ... ) = 0;

}CLIENT;

#endif
