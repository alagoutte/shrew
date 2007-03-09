
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

#include <winsock2.h>
#include <aclapi.h>

#endif

#ifdef UNIX

#include <sys/un.h>
#include <sys/stat.h>

#endif

#include <assert.h>
#include <string.h>
#include <time.h>
#include "ike.h"
#include "export.h"

#define IKEI_EVENT_NAME				"ikedi"
#define IKEI_PIPE_NAME				"\\\\.\\pipe\\ikedi"
#define IKEI_SOCK_NAME				"/var/run/ikedi"
#define IKEI_MAX_BDATA				2048

#define IKEI_MSGID_RESULT			1
#define IKEI_MSGID_ENABLE			2
#define IKEI_MSGID_STATUS			3
#define IKEI_MSGID_PEER				4
#define IKEI_MSGID_PROPOSAL			5
#define IKEI_MSGID_CLIENT			6
#define IKEI_MSGID_NETWORK			7
#define IKEI_MSGID_CFGSTR			8
#define IKEI_MSGID_STATS			9

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

#define STATUS_ENABLED				1
#define STATUS_DISABLED				2
#define STATUS_BANNER				3
#define STATUS_INFO					4
#define STATUS_WARN					5
#define STATUS_FAIL					6

#define IKEI_OK						1
#define IKEI_PASSWD					2
#define IKEI_FAILED					3
#define IKEI_NODATA					4

typedef struct _IKEI_MSG
{
	long		peer;
	long		type;
	long		size;

}IKEI_MSG, *pIKEI_MSG;

typedef struct _IKEI_MSG_BASIC
{
	IKEI_MSG	msg;
	long		value;
	long		bsize;

}IKEI_MSG_BASIC;

typedef struct _IKEI_STATS
{
	long	sa_good;
	long	sa_fail;
	long	sa_dead;

	bool	natt;
	bool	frag;
	bool	dpd;

}IKEI_STATS;

typedef class DLX _IKEI
{
	friend class _IKES;

	protected:

#ifdef WIN32

	HANDLE		hpipe;
	OVERLAPPED	olapp;
	bool		wait;

#endif

#ifdef UNIX

	int		sock;

#endif

	IKEI_MSG	tmsg;

	long	wait_msg( IKEI_MSG & msg, long timeout );
	long	recv_msg( void * data, unsigned long & size, bool wait = false );
	long	send_msg( void * data, unsigned long size );
	long	peek_msg( void * data, unsigned long size );

	long	recv_basic( long type, long * value, void * bdata, long * bsize, bool wait = false );
	long	send_basic( long type, long value, void * bdata, long bsize );
	long	send_bidir( long type, long value, void * bdata, long bsize, long * msgres );

	public:

	_IKEI();
	~_IKEI();

	long	attach( long timeout );
	void	detach();

	long	next_msg( IKEI_MSG & msg );

	long	send_msg_result( long msgres );

	long	recv_msg_status( long * status, char * str, long & len );
	long	send_msg_status( long status, char * str, long * msgres = NULL );

	long	recv_msg_stats( IKEI_STATS * stats );
	long	send_msg_stats( IKEI_STATS * stats, long * msgres = NULL );

	long	recv_msg_enable( long * enable );
	long	send_msg_enable( long enable );

	long	recv_msg_peer( IKE_PEER * peer );
	long	send_msg_peer( IKE_PEER * peer, long * msgres = NULL );

	long	recv_msg_proposal( IKE_PROPOSAL * proposal );
	long	send_msg_proposal( IKE_PROPOSAL * proposal, long * msgres = NULL );

	long	recv_msg_client( IKE_XCONF * xconf );
	long	send_msg_client( IKE_XCONF * xconf, long * msgres = NULL );

	long	recv_msg_network( IKE_PH2ID * ph2id, long * type );
	long	recv_msg_network( IKE_PH2ID * ph2id, long type, long * msgres = NULL );

	long	recv_msg_cfgstr( long * type, char * str, long * len );
	long	send_msg_cfgstr( long type, char * str, long len, long * msgres = NULL );

}IKEI;

typedef class DLX _IKES
{
	private:

#ifdef WIN32

	HANDLE		hsrvc;
	HANDLE		hpipe;
	OVERLAPPED	olapp;

#endif

#ifdef UNIX

	int		sock;

#endif

	public:

	_IKES();
	~_IKES();

	bool	init();
	IKEI *	inbound();

}IKES;


#endif
