
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

#ifndef _IKEC_H_
#define _IKEC_H_

#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <stdarg.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "libike.h"
#include "config.h"
#include "version.h"

enum IKEC_STATE
{
	IKEC_STATE_DISCONNECTED,
	IKEC_STATE_CONNECTING,
	IKEC_STATE_CONNECTED,
	IKEC_STATE_DISCONNECTING
};

typedef class _IKEC : public ITH_EXEC
{
	protected:

	ITH_COND	connecting;

	IKE_PEER	peer;
	IKE_XCONF       xconf;
	IKE_PROPOSAL    proposal_isakmp;
	IKE_PROPOSAL    proposal_esp;
	IKE_PROPOSAL    proposal_ipcomp;
	IKEI		ikei;
	IKEI_STATS	stats;

	BDATA	sites;
	BDATA	fspec;
	BDATA	fpath;
	BDATA	fpass;
	BDATA	username;
	BDATA	password;

	virtual bool	get_username() = 0;
	virtual bool	get_password() = 0;
	virtual bool	get_filepass( BDATA & path ) = 0;

	virtual bool	set_state() = 0;
	virtual bool	set_stats() = 0;
	virtual bool	set_status( long & status, BDATA & text ) = 0;

	long	func( void * );

	CONFIG		config;
	IKEC_STATE	cstate;

	public:

	_IKEC();
	virtual ~_IKEC();

	bool		opts( int argc, char ** argv );
	bool		load( BDATA & name );
	bool		save( BDATA & name );

	IKEC_STATE	state();
	bool		connect( bool wait_input );
	bool		disconnect();

	virtual bool	log( long code, const char * format, ... ) = 0;

}IKEC;

#endif
