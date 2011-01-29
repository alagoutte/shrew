
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

#ifndef _LIBIKED_H_
#define _LIBIKED_H_

#ifdef WIN32
# include <winsock2.h>
# include <aclapi.h>
#endif

#ifdef UNIX
# include <pwd.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# ifdef __linux__
#  include <sys/un.h>
#  include <sys/stat.h>
# else
#  include <sys/types.h>
#  include <sys/un.h>
#  include <sys/stat.h>
# endif
#endif

#include <assert.h>
#include <string.h>
#include <time.h>
#include "libidb.h"
#include "libith.h"
#include "ike.h"
#include "export.h"

#ifdef WIN32
# define IKEI_PIPE_NAME				"\\\\.\\pipe\\ikedi"
#else
# define IKEI_PIPE_NAME				"/var/run/ikedi"
#endif

#define IKEI_MSGID_RESULT			1
#define IKEI_MSGID_ENABLE			2
#define IKEI_MSGID_SUSPEND			3
#define IKEI_MSGID_STATUS			4
#define IKEI_MSGID_PEER				5
#define IKEI_MSGID_PROPOSAL			6
#define IKEI_MSGID_CLIENT			7
#define IKEI_MSGID_NETWORK			8
#define IKEI_MSGID_CFGSTR			9
#define IKEI_MSGID_STATS			10

#define IKEI_RESULT_OK				0
#define IKEI_RESULT_FAILED			1
#define IKEI_RESULT_PASSWD			2

#define CFGSTR_CRED_XAUTH_USER		1
#define CFGSTR_CRED_XAUTH_PASS		2
#define CFGSTR_CRED_FILE_PASS		3
#define CFGSTR_CRED_PSK				4
#define CFGSTR_CRED_RSA_LKEY		5
#define CFGSTR_CRED_RSA_LCRT		6
#define CFGSTR_CRED_RSA_RCRT		7
#define CFGSTR_CRED_LID				8
#define CFGSTR_CRED_RID				9
#define CFGSTR_SPLIT_DOMAIN			10

#define STATUS_DISCONNECTED			1
#define STATUS_CONNECTING			2
#define STATUS_CONNECTED			3
#define STATUS_DISCONNECTING		4
#define STATUS_BANNER				5
#define STATUS_INFO					6
#define STATUS_WARN					7
#define STATUS_FAIL					8

typedef struct _IKEI_HEADER
{
	long		type;
	size_t		size;

}IKEI_HEADER;

typedef struct _IKEI_BASIC
{
	long		value;
	size_t		bsize;

}IKEI_BASIC;

typedef struct _IKEI_STATS
{
	IKE_SADDR	peer;

	long	sa_good;
	long	sa_fail;
	long	sa_dead;

	long	natt;
	bool	frag;
	bool	dpd;

}IKEI_STATS;

typedef class DLX _IKEI_MSG : public BDATA
{
	private:

	void	init( long type );

	long	get_basic( long * value, BDATA * bdata = NULL );
	long	set_basic( long value, BDATA * bdata = NULL );

	long	get_struct( long * value, void * sdata, size_t ssize );
	long	set_struct( long value, void * sdata, size_t ssize );

	public:

	IKEI_HEADER	header;

	long	get_result( long * msgres );
	long	set_result( long msgres );

	long	get_status( long * status, BDATA * str );
	long	set_status( long status, BDATA * str );
	long	set_status( long status, const char * str );

	long	get_stats( IKEI_STATS * stats );
	long	set_stats( IKEI_STATS * stats );

	long	get_enable( long * enable );
	long	set_enable( long enable );

	long	get_suspend( long * suspend );
	long	set_suspend( long suspend );

	long	get_peer( IKE_PEER * peer );
	long	set_peer( IKE_PEER * peer );

	long	get_proposal( IKE_PROPOSAL * proposal );
	long	set_proposal( IKE_PROPOSAL * proposal );

	long	get_client( IKE_XCONF * xconf );
	long	set_client( IKE_XCONF * xconf );

	long	get_network( long * type, IKE_PH2ID * ph2id );
	long	set_network( long type, IKE_PH2ID * ph2id );

	long	get_cfgstr( long * type, BDATA * str );
	long	set_cfgstr( long type, BDATA * str );

}IKEI_MSG;

typedef class DLX _IKEI : private _ITH_IPCC
{
	friend class _IKES;

	public:

	long	attach( long timeout );
	void	wakeup();
	void	detach();

	long	recv_message( IKEI_MSG & msg );
	long	send_message( IKEI_MSG & msg );
	long	send_message( IKEI_MSG & msg, long * rslt );

}IKEI;

typedef class DLX _IKES : private _ITH_IPCS
{
	public:

	long	init();
	void	done();

	long	inbound( IKEI ** ikei );
	void	wakeup();

}IKES;


#endif
