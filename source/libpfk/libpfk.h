
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

#ifndef _LIBPFK_H_
#define _LIBPFK_H_

#ifdef WIN32
# include <winsock2.h>
# include <windows.h>
# include <process.h>
# include <stdlib.h>
# include "inttypes.h"
# include "pfkeyv2.h"
# include "ipsec.h"
#endif

#ifdef UNIX
# ifdef __linux__
#  include <unistd.h>
#  include <string.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <inttypes.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <linux/pfkeyv2.h>
#  include <linux/ipsec.h>
#  include <linux/udp.h>
# else
#  include <unistd.h>
#  include <string.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <sys/socket.h>
#  include <net/pfkeyv2.h>
#  include <netinet/in.h>
#  include <netinet/udp.h>
#  ifdef OPT_NETIPSEC
#   include <netipsec/ipsec.h>
#  else
#   include <netinet6/ipsec.h>
#  endif
# endif
#endif

//
// Win32 specific
//

#ifdef WIN32

#define PFKI_EVENT_NAME			"pfki"
#define PFKI_PIPE_NAME			"\\\\.\\pipe\\pfki"
#define getpid	_getpid

#endif

//
// Unix specific
//

#ifdef UNIX

#define PFKEY_BUFFSIZE			128 * 1024

#ifndef SADB_X_EALG_AESCBC
# define SADB_X_EALG_AESCBC 12
#endif

#ifndef __FreeBSD__

// Linux and NetBSD compat

#define PFKEY_SOFT_LIFETIME_RATE	80

#define PFKEY_UNUNIT64(a)		((a) << 3)
#define PFKEY_UNIT64(a)			((a) >> 3)

#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))
#define PFKEY_EXTLEN(msg) \
        PFKEY_UNUNIT64(((struct sadb_ext *)(msg))->sadb_ext_len)
#define PFKEY_ADDR_PREFIX(ext) \
        (((struct sadb_address *)(ext))->sadb_address_prefixlen)
#define PFKEY_ADDR_PROTO(ext) \
        (((struct sadb_address *)(ext))->sadb_address_proto)
#define PFKEY_ADDR_SADDR(ext) \
        ((struct sockaddr *)((caddr_t)(ext) + sizeof(struct sadb_address)))

#endif

#endif

#include <stdio.h>
#include "export.h"

#define PFKI_MAX_XFORMS		4
#define PFKI_MAX_KEYLEN		32

#define NAME_MSGTYPE		1
#define NAME_SATYPE			2
#define NAME_SAENCR			3
#define NAME_SACOMP			4
#define NAME_SAAUTH			5
#define NAME_SPTYPE			6
#define NAME_SPDIR			7
#define NAME_SPMODE			8
#define NAME_SPLEVEL		9
#define NAME_NTTYPE			10

#define PFKI_WINDSIZE		4

#define PFKI_OK				1
#define PFKI_FAILED			2
#define PFKI_NODATA			3

typedef struct _PFKI_SA
{
	u_int32_t	spi;
	u_int8_t	replay;
	u_int8_t	state;
	u_int8_t	auth;
	u_int8_t	encrypt;
	u_int32_t	flags;

}PFKI_SA;

typedef struct _PFKI_SA2
{
	u_int8_t	mode;
	u_int32_t	sequence;
	u_int32_t	reqid;

}PFKI_SA2;

typedef struct _PFKI_ADDR
{
	u_int8_t proto;
	u_int8_t prefix;
	
	union
	{
		sockaddr	saddr;
		sockaddr_in	saddr4;
	};

}PFKI_ADDR;

typedef struct _PFKI_LTIME
{
	u_int32_t	allocations;
	u_int64_t	bytes;
	u_int64_t	addtime;
	u_int64_t	usetime;

}PFKI_LTIME;

typedef struct _PFKI_KEY
{
	u_int8_t	keydata[ PFKI_MAX_KEYLEN ];
	u_int16_t	length;

}PFKI_KEY;

typedef struct _PFKI_RANGE
{
	u_int32_t	min;
	u_int32_t	max;

}PFKI_RANGE;

typedef struct _PFKI_SP
{
	u_int16_t	type;
	u_int32_t	id;
	u_int8_t	dir;
	u_int8_t	prot;
	u_int16_t	port;

}PFKI_SP;

typedef struct _PFKI_NATT
{
	u_int8_t	type;
	u_int16_t	port_src;
	u_int16_t	port_dst;
	u_int16_t	fraglen;

}PFKI_NATT;

typedef struct _PFKI_SAINFO
{
	u_int8_t	satype;
	u_int32_t	seq;
	u_int32_t	pid;
	u_int8_t	error;

	PFKI_SA		sa;
	PFKI_SA2	sa2;
	PFKI_ADDR	paddr_src;
	PFKI_ADDR	paddr_dst;
	PFKI_LTIME	ltime_curr;
	PFKI_LTIME	ltime_hard;
	PFKI_LTIME	ltime_soft;
	PFKI_KEY	ekey;
	PFKI_KEY	akey;
	PFKI_NATT	natt;
	PFKI_RANGE	range;

}PFKI_SAINFO;

typedef struct _PFKI_XFORM
{
	u_int16_t	proto;
	u_int8_t	mode;
	u_int8_t	level;
	u_int16_t	reqid;

	sockaddr	saddr_src;
	sockaddr	saddr_dst;

}PFKI_XFORM;

typedef struct _PFKI_SPINFO
{
	u_int32_t	seq;
	u_int32_t	pid;
	u_int8_t	error;

	PFKI_SP		sp;
	PFKI_ADDR	paddr_src;
	PFKI_ADDR	paddr_dst;

	PFKI_XFORM	xforms[ PFKI_MAX_XFORMS ];

}PFKI_SPINFO;

typedef class DLX _PFKI_MSG
{
	friend class _PFKI;

	private:

	unsigned char *	msg_buff;
	long			msg_size;

	bool append( long size );

	public:

	_PFKI_MSG();
	~_PFKI_MSG();

	sadb_msg *	hdr;

	void reset();
	bool local();

}PFKI_MSG;

typedef class DLX _PFKI
{
	friend class _PFKS;

	private:

#ifdef WIN32

	HANDLE		hpipe;
	OVERLAPPED	olapp;
	sadb_msg	tmsg;
	bool		wait;

#endif

#ifdef UNIX

	int		sock;

#endif

	bool sockaddr_len( int safam, int & salen );

	long wait_msg();
	long send_msg( PFKI_MSG & msg );
	long recv_msg( PFKI_MSG & msg, bool peek = false );

	long buff_get_ext( PFKI_MSG & msg, sadb_ext ** ext, long type );
	long buff_add_ext( PFKI_MSG & msg, sadb_ext ** ext, long xlen, bool unit64 = true );

	long buff_get_address( sadb_address * ext, PFKI_ADDR & addr );
	long buff_set_address( sadb_address * ext, PFKI_ADDR & addr );

	long buff_get_ipsec( sadb_x_policy * ext, PFKI_SPINFO & spinfo );
	long buff_add_ipsec( PFKI_MSG & msg, PFKI_SPINFO & spinfo );

	long buff_get_key( sadb_key * ext, PFKI_KEY & key );
	long buff_set_key( sadb_key * ext, PFKI_KEY & key );

	long send_sainfo( u_int8_t sadb_msg_type, PFKI_SAINFO & sainfo, bool serv );
	long send_spinfo( u_int8_t sadb_msg_type, PFKI_SPINFO & spinfo, bool serv );

	public:

	_PFKI();
	~_PFKI();

	// extention functions

	long	read_sa( PFKI_MSG & msg, PFKI_SA & sa );
	long	read_sa2( PFKI_MSG & msg, PFKI_SA2 & sa2 );
	long	read_range( PFKI_MSG & msg, PFKI_RANGE & range );
	long	read_ltime_curr( PFKI_MSG & msg, PFKI_LTIME & ltime );
	long	read_ltime_hard( PFKI_MSG & msg, PFKI_LTIME & ltime );
	long	read_ltime_soft( PFKI_MSG & msg, PFKI_LTIME & ltime );
	long	read_key_a( PFKI_MSG & msg, PFKI_KEY & akey );
	long	read_key_e( PFKI_MSG & msg, PFKI_KEY & ekey );
	long	read_address_src( PFKI_MSG & msg, PFKI_ADDR & addr );
	long	read_address_dst( PFKI_MSG & msg, PFKI_ADDR & addr );
	long	read_natt( PFKI_MSG & msg, PFKI_NATT & natt );
	long	read_policy( PFKI_MSG & msg, PFKI_SPINFO & spinfo );

	long	open();
	void	close();

	char *	name( long type, long value );

	long	next_msg( PFKI_MSG & msg );

	// client functions

	long	send_register( u_int8_t satype );
	long	send_flush();
	long	send_dump();
	long	send_add( PFKI_SAINFO & sainfo );
	long	send_get( PFKI_SAINFO & sainfo );
	long	send_del( PFKI_SAINFO & sainfo );
	long	send_getspi( PFKI_SAINFO & sainfo );
	long	send_update( PFKI_SAINFO & sainfo );

	long	send_spflush();
	long	send_spdump();
	long	send_spadd( PFKI_SPINFO & spinfo );
	long	send_spdel( PFKI_SPINFO & spinfo );

	// server functions

	long	serv_dump( PFKI_SAINFO & sainfo );
	long	serv_add( PFKI_SAINFO & sainfo );
	long	serv_get( PFKI_SAINFO & sainfo );
	long	serv_del( PFKI_SAINFO & sainfo );
	long	serv_acquire( PFKI_SPINFO & spinfo );
	long	serv_getspi( PFKI_SAINFO & sainfo );
	long	serv_update( PFKI_SAINFO & sainfo );

	long	serv_spdump( PFKI_SPINFO & spinfo );
	long	serv_spadd( PFKI_SPINFO & spinfo );
	long	serv_spdel( PFKI_SPINFO & spinfo );

}PFKI;

#ifdef WIN32

typedef class DLX _PFKS
{
	private:

	HANDLE	hsrvc;
	HANDLE	hpipe;

	public:

	_PFKS();
	~_PFKS();

	bool	init();
	PFKI *	accept();

}PFKS;

#endif

#endif
