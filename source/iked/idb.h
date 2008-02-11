
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

#ifndef _IDB_H_
#define _IDB_H_

#include "libip.h"
#include "libpfk.h"
#include "crypto.h"

//
// forward delare some class types
//

typedef class _IKED_XAUTH IKED_XAUTH;
typedef class _IKED_XCONF IKED_XCONF;

typedef class _IDB_TUNNEL IDB_TUNNEL;
typedef class _IDB_XCH IDB_XCH;
typedef class _IDB_PH1 IDB_PH1;
typedef class _IDB_PH2 IDB_PH2;
typedef class _IDB_CFG IDB_CFG;

enum XCH_STATUS
{
	XCH_STATUS_ANY,
	XCH_STATUS_PENDING,
	XCH_STATUS_LARVAL,
	XCH_STATUS_MATURE,
	XCH_STATUS_EXPIRING,
	XCH_STATUS_DEAD
};

enum XCH_ERRORCODE
{
	XCH_NORMAL,
	XCH_FAILED_CLIENT,
	XCH_FAILED_NETWORK,
	XCH_FAILED_TIMEOUT,
	XCH_FAILED_PENDING,
	XCH_FAILED_EXPIRED,
	XCH_FAILED_FLUSHED,
	XCH_FAILED_USERREQ,
	XCH_FAILED_MSG_FORMAT,
	XCH_FAILED_MSG_CRYPTO,
	XCH_FAILED_MSG_AUTH,
	XCH_FAILED_USER_AUTH,
	XCH_FAILED_PEER_AUTH,
	XCH_FAILED_PEER_DEAD,
	XCH_FAILED_PEER_DELETE,
	XCH_FAILED_IKECONFIG,
	XCH_FAILED_DHCPCONFIG
};

//
// XXX : these need to move back
//       into iked.h
//

#pragma pack( 1 )

typedef struct _IKE_HEADER
{
	IKE_COOKIES	cookies;

	uint8_t		payload;	// initial payload
	uint8_t		version;	// isakmp version
	uint8_t		exchange;	// exchange type
	uint8_t		flags;		// flags
	uint32_t	msgid;		// message id
	uint32_t	length;		// message length

}IKE_HEADER;

typedef struct _IKE_PAYLOAD
{
	uint8_t		next;		// next payload
	uint8_t		reserved;	// reserved
	uint16_t	length;		// payload size

}IKE_PAYLOAD;

#pragma pack()

typedef struct _PLD_DATA
{
	size_t	oset;
	size_t	size;

}PLD_DATA;

typedef class _PACKET_IKE : public _PACKET
{
	protected:

	PLD_DATA	pld_stack[ 8 ];
	long		pld_depth;

	IKE_HEADER	header;

	public:

	unsigned char	notify;

	_PACKET_IKE();
	~_PACKET_IKE();

	void	reset();

	void	set_msgid( uint32_t msgid );
	void	get_msgid( uint32_t & msgid );

	bool	add_payload( bool encap, uint8_t next );
	bool	get_payload( bool encap, uint8_t & next );
	void	end_payload( bool decap, bool write = true );

	size_t	get_payload_left();

	bool	write( IKE_COOKIES & cookies,
					uint8_t payload,
					uint8_t exchange,
					uint8_t flags );

	bool	read( IKE_COOKIES & cookies,
					uint8_t & payload,
					uint8_t & exchange,
					uint8_t & flags );

	bool	done();

}PACKET_IKE;

//
// IKE list classes
//

typedef struct _IKE_PENTRY
{
	bool			pnext;
	IKE_PROPOSAL	proposal;

}IKE_PENTRY;

typedef class _IKE_PLIST
{
	private:

	LIST	prop_list;

	public:

	_IKE_PLIST();
	~_IKE_PLIST();

	long	count();
	void	clean();

	bool	add( IKE_PROPOSAL * proposal, bool pnext );
	bool	get( IKE_PROPOSAL ** proposal, long pindex, uint8_t proto = 0 );

	bool	nextb( long & bindex, long & pindex, long & pcount );
	bool	nextp( IKE_PROPOSAL ** proposal, long & pindex, long & tindex, long & tcount );
	bool	nextt( IKE_PROPOSAL ** proposal, long & tindex );

}IKE_PLIST;

typedef class _IKE_CLIST
{
	private:

	LIST	list_certs;

	public:

	BDATA name;

	_IKE_CLIST();
	~_IKE_CLIST();

	long	count();

	bool	add( BDATA & cert );
	bool	get( BDATA & cert, long index );

}IKE_CLIST;

typedef class _IKE_ILIST
{
	private:

	LIST	list_ph2id;

	public:

	BDATA name;

	_IKE_ILIST();
	~_IKE_ILIST();

	long	count();

	bool	add( IKE_PH2ID & ph2id );
	bool	get( IKE_PH2ID & ph2id, long index );

}IKE_ILIST;

typedef class _IKE_NLIST
{
	private:
	
	LIST	list_notify;

	public:

	~_IKE_NLIST();

	long	count();

	bool	add( IKE_NOTIFY & notify );
	bool	get( IKE_NOTIFY & notify, long index );

}IKE_NLIST;

typedef class _IKE_DLIST
{
	private:
	
	LIST	list_suffix;

	public:

	~_IKE_DLIST();

	long	count();

	bool	add( BDATA & suffix );
	bool	get( BDATA & suffix, long index );

}IKE_DLIST;

//
// IKE internal database types
//

#define IDB_FLAG_DEAD		1
#define IDB_FLAG_ENDED		2
#define IDB_FLAG_NOEND		4

typedef class _IDB
{
	protected:

	long		idb_flags;
	long		idb_refcount;

	inline long chkflags( long flags )
	{
		return ( idb_flags & flags );
	}
	
	inline long setflags( long flags )
	{
		return idb_flags |= flags;
	}

	inline long clrflags( long flags )
	{
		return idb_flags &= ~flags;
	}

	virtual void beg() = 0;
	virtual void end() = 0;

	public:

	_IDB();
	virtual ~_IDB();

	// implemented by sub classes

	virtual char *	name() = 0;
	virtual LIST *	list() = 0;

	bool add( bool lock );
	bool inc( bool lock );
	bool dec( bool lock, bool setdel = false );

}IDB;

typedef struct _IDB_NETMAP
{
	IKE_ILIST *	ilist;
	long		mode;
	BDATA		group;

}IDB_NETMAP;

typedef class _IDB_PEER : public IKE_PEER, public IDB
{
	private:
	
	LIST	netmaps;

	virtual void	beg();
	virtual void	end();

	public:

	BDATA		fpass;
	BDATA		cert_l;
	BDATA		cert_r;
	BDATA		psk;
	BDATA		iddata_l;
	BDATA		iddata_r;
	EVP_PKEY *	key;

	BDATA			xauth_group;
	IKED_XAUTH *	xauth_source;
	IKED_XCONF *	xconf_source;

	IKE_PLIST		prop_list;

	virtual	char *	name();
	virtual LIST *	list();

	_IDB_PEER( IKE_PEER * set_peer );
	virtual ~_IDB_PEER();

	bool netmap_add( IKE_ILIST * ilist, long	mode, BDATA * group );
	bool netmap_del( IDB_NETMAP * netmap );
	bool netmap_get( IDB_NETMAP ** netmap, long index );

}IDB_PEER;

typedef class _ITH_EVENT_TUNDHCP : public ITH_EVENT
{
	public:

	IDB_TUNNEL *	tunnel;

	time_t	lease;
	time_t	renew;
	time_t	retry;

	bool	func();

}ITH_EVENT_TUNDHCP;

typedef class _IDB_TUNNEL : public IDB
{
	public:

	IDB_PEER *	peer;

	IKE_XAUTH	xauth;
	IKE_XCONF	xconf;
	IKEI_STATS	stats;

	XCH_ERRORCODE	close;

#ifdef WIN32
	IKE_NSCFG	nscfg;
#endif

	IKE_SADDR	saddr_l;
	IKE_SADDR	saddr_r;

	bool		force_all;
	IKE_ILIST	idlist_incl;
	IKE_ILIST	idlist_excl;
	IKE_DLIST	dlist;

	BDATA		banner;

	long		tunnelid;
	long		tstate;
	long		lstate;
	long		natt_v;

	uint32_t	dhcp_xid;
	SOCKET		dhcp_sock;

	ITH_EVENT_TUNDHCP	event_dhcp;

	virtual	char *	name();
	virtual LIST *	list();

	virtual void	beg();
	virtual void	end();

	_IDB_TUNNEL( IDB_PEER * set_peer, IKE_SADDR * set_saddr_l, IKE_SADDR * set_saddr_r );
	virtual ~_IDB_TUNNEL();

}IDB_TUNNEL;

typedef class _IDB_POLICY : public PFKI_SPINFO, public IDB
{
	public:

	bool	route;

	virtual	char *	name();
	virtual LIST *	list();

	virtual void	beg();
	virtual void	end();

	_IDB_POLICY( PFKI_SPINFO * spinfo );
	virtual ~_IDB_POLICY();

}IDB_POLICY;

//
// generic event class
//

typedef class _ITH_EVENT_RESEND : public ITH_EVENT, IPQUEUE
{
	public:

	IDB_XCH *	xch;
	IPQUEUE		ipqueue;
	long		attempt;

	virtual ~_ITH_EVENT_RESEND();

	bool	func();

}ITH_EVENT_RESEND;

//
// generic exchange handle class
//

typedef class _IDB_XCH : public _IDB
{
	public:

	IDB_TUNNEL *	tunnel;

	ITH_LOCK		lock;
	XCH_STATUS		xch_status;
	XCH_ERRORCODE	xch_errorcode;
	uint16_t		xch_notifycode;

	bool			initiator;
	unsigned char	exchange;

	uint32_t	msgid;
	long		lstate;
	long		xstate;

	DH *		dh;
	long		dh_size;

	BDATA		nonce_l;
	BDATA		nonce_r;

	BDATA		xl;
	BDATA		xr;

	IKE_PLIST	plist_l;
	IKE_PLIST	plist_r;

	long		hash_size;
	BDATA		hash_l;
	BDATA		hash_r;

	BDATA		hda;		// hash data accumulator
	BDATA		iv;

	ITH_EVENT_RESEND	event_resend;

	IKE_NLIST	nlist;

	_IDB_XCH();
	virtual ~_IDB_XCH();

	XCH_STATUS	status();
	XCH_STATUS	status( XCH_STATUS status, XCH_ERRORCODE errorcode, uint16_t notifycode );

	bool	resend_queue( PACKET_IP & packet );
	bool	resend_sched();
	void	resend_clear() ;

}IDB_XCH;

//
// phase1 event classes
//

typedef class _ITH_EVENT_PH1DPD : public ITH_EVENT
{
	public:

	IDB_PH1 *	ph1;

	bool	func();

}ITH_EVENT_PH1DPD;

typedef class _ITH_EVENT_PH1NATT : public ITH_EVENT
{
	public:

	IDB_PH1 *	ph1;

	bool	func();

}ITH_EVENT_PH1NATT;

typedef class _ITH_EVENT_PH1SOFT : public ITH_EVENT
{
	public:

	IDB_PH1 *	ph1;

	bool	func();

}ITH_EVENT_PH1SOFT;

typedef class _ITH_EVENT_PH1HARD : public ITH_EVENT
{
	public:

	IDB_PH1 *	ph1;

	bool	func();

}ITH_EVENT_PH1HARD;

//
// phase1 handle class
//

typedef class _IDB_PH1 : public IDB_XCH
{
	virtual void	beg();
	virtual void	end();

	public:

	const EVP_CIPHER *	evp_cipher;
	const EVP_MD *		evp_hash;

	IKE_COOKIES	cookies;

	IKE_PH1ID	ph1id_l;
	IKE_PH1ID	ph1id_r;

	bool	xauth_l;	// local will support xauth
	bool	xauth_r;	// remote will support xauth

	bool	unity_l;	// local is cisco unity compatible
	bool	unity_r;	// remote is cisco unity compatible

	bool	netsc_l;	// local is netscreen compatible
	bool	netsc_r;	// remote is netscreen compatible

	bool	zwall_l;	// local is zywall compatible
	bool	zwall_r;	// remote is zywall compatible

	bool	swind_l;	// local is sidewinder compatible
	bool	swind_r;	// remote is sidewinder compatible

	bool	chkpt_l;	// local is checkpoint compatible
	bool	chkpt_r;	// remote is checkpoint compatible

	bool	natt_l;		// local will support natt
	bool	natt_r;		// remote will support natt
	long	natt_v;		// version negotiated
	uint8_t	natt_p;		// payload identifier

	bool	dpd_l;		// local will support dead peer detect
	bool	dpd_r;		// remote will support dead peer detect

	bool	frag_l;		// local will support fragmentation
	bool	frag_r;		// remote will support fragmentation

	bool	natted_l;	// local address is natted
	bool	natted_r;	// remote address is natted

	uint32_t	dpd_req;	// last dpd request sequence
	uint32_t	dpd_res;	// last dpd response sequence

	uint8_t		ctype_l;	// local certificate type
	uint8_t		ctype_r;	// remote certificate type

	uint16_t	auth_id;	// selected authentication type

	LIST	frags;

	BDATA	key;

	BDATA	idi;
	BDATA	idr;

	BDATA	natd_ls;
	BDATA	natd_ld;
	BDATA	natd_rs;
	BDATA	natd_rd;

	IKE_CLIST	certs_r;
	BDATA		sign_r;

	BDATA	skeyid;
	BDATA	skeyid_d;
	BDATA	skeyid_a;
	BDATA	skeyid_e;

	ITH_EVENT_PH1DPD	event_dpd;
	ITH_EVENT_PH1NATT	event_natt;
	ITH_EVENT_PH1SOFT	event_soft;
	ITH_EVENT_PH1HARD	event_hard;

	// sub class functions

	virtual	char *	name();
	virtual LIST *	list();

	// class functions

	_IDB_PH1( IDB_TUNNEL * set_tunnel, bool set_initiator, IKE_COOKIES * set_cookies );
	virtual ~_IDB_PH1();

	bool	setup_dhgrp( IKE_PROPOSAL * proposal );
	bool	setup_xform( IKE_PROPOSAL * proposal );

	void	clean();

	bool	frag_add( unsigned char * data, unsigned long size, long index, bool last );
	bool	frag_get( PACKET_IKE & packet );

}IDB_PH1;

//
// phase2 event classes
//

typedef class _ITH_EVENT_PH2SOFT : public ITH_EVENT
{
	public:

	IDB_PH2 *	ph2;
	long		diff;

	bool	func();

}ITH_EVENT_PH2SOFT;

typedef class _ITH_EVENT_PH2HARD : public ITH_EVENT
{
	public:

	IDB_PH2 *	ph2;

	bool	func();

}ITH_EVENT_PH2HARD;

//
// phase2 handle class
//

typedef class _IDB_PH2 : public IDB_XCH
{
	public:

	uint32_t	seqid_in;
	uint32_t	seqid_out;
	long		spicount;

	long		dhgr_id;

	IKE_PH2ID	ph2id_ls;
	IKE_PH2ID	ph2id_ld;
	IKE_PH2ID	ph2id_rs;
	IKE_PH2ID	ph2id_rd;

	ITH_EVENT_PH2SOFT	event_soft;
	ITH_EVENT_PH2HARD	event_hard;

	// sub class functions

	virtual	char *	name();
	virtual LIST *	list();

	virtual void	beg();
	virtual void	end();

	// class functions

	_IDB_PH2( IDB_TUNNEL * set_tunnel, bool set_initiator, uint32_t set_msgid, uint32_t set_seqid_in );
	virtual ~_IDB_PH2();

	bool	setup_dhgrp();
	bool	setup_xform();

	void	clean();

}IDB_PH2;

//
// config handle class
//

typedef class _IDB_CFG : public IDB_XCH
{
	protected:

	LIST	attrs;

	public:

	// sub class functions

	virtual	char *	name();
	virtual LIST *	list();

	virtual void	beg();
	virtual void	end();

	// class functions

	_IDB_CFG( IDB_TUNNEL * tunnel, bool set_initiator, unsigned long set_msgid );
	virtual ~_IDB_CFG();

	BDATA		hash;

	uint8_t		mtype;
	uint16_t	ident;

	IKE_ATTR *	attr_get( long index );
	bool		attr_has( unsigned short atype );
	bool		attr_add_b( unsigned short atype, unsigned short adata );
	bool		attr_add_v( unsigned short atype, void * vdata, size_t size );

	long		attr_count();						// get attribute count
	void		attr_reset();						// reset attribute list

	bool	setup();
	void	clean();

}IDB_CFG;

//
// informational handle class
//

typedef class _IDB_INF : public IDB_XCH
{
	public:

	// sub class functions

	virtual	char *	name();
	virtual LIST *	list();

	virtual void	beg();
	virtual void	end();

	// class functions

	_IDB_INF();
	virtual ~_IDB_INF();

}IDB_INF;

#endif
