
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

#include "ipsec.h"
#include "crypto.h"
#include "libip.h"

//
// forward delare some class types

typedef class _IKED_XAUTH IKED_XAUTH;
typedef class _IKED_XCONF IKED_XCONF;

typedef class _IDB_XCH IDB_XCH;
typedef class _IDB_PH1 IDB_PH1;
typedef class _IDB_PH2 IDB_PH2;
typedef class _IDB_CFG IDB_CFG;

//
// XXX : these need to move back
//       into iked.h
//

typedef struct _IKE_PAYLOAD
{
	long	oset;
	long	size;

}IKE_PAYLOAD;

typedef class _PACKET_IKE : public _PACKET
{
	protected:

	IKE_PAYLOAD		pld_stack[ 8 ];
	long			pld_depth;

	uint32_t		pkt_msgid;

	public:

	_PACKET_IKE();
	~_PACKET_IKE();

	unsigned char	notify;

	void	reset();

	void	set_msgid( uint32_t msgid );
	void	get_msgid( uint32_t & msgid );

	bool	add_payload( bool encap, uint8_t next_payload );
	bool	get_payload( bool encap, uint8_t & next_payload );
	void	end_payload( bool decap, bool write = true );

	bool	chk_payload( long & bytes_left );

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

typedef class _IDB
{
	public:

	long		refid;
	long		refcount;
	long		lstate;
	uint32_t	msgid;

	_IDB::_IDB()
	{
		refid = 0;
		refcount = 0;

		lstate = 0;

		msgid = 0;
	}

	virtual bool add( bool lock ) = 0;
	virtual bool inc( bool lock ) = 0;
	virtual bool dec( bool lock ) = 0;

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

	_IDB_PEER( IKE_PEER * set_peer );
	virtual ~_IDB_PEER();

	virtual bool add( bool lock );
	virtual bool inc( bool lock );
	virtual bool dec( bool lock );
	virtual void end( bool lock );

	bool netmap_add( IKE_ILIST * ilist, long	mode, BDATA * group );
	bool netmap_del( IDB_NETMAP * netmap );
	bool netmap_get( IDB_NETMAP ** netmap, long index );

}IDB_PEER;

typedef class _IDB_TUNNEL : public IDB
{
	public:

	IDB_PEER *	peer;

	IKE_XAUTH	xauth;
	IKE_XCONF	xconf;
	IKEI_STATS	stats;

	IKE_SADDR	saddr_l;
	IKE_SADDR	saddr_r;

	bool		force_all;
	IKE_ILIST	idlist_incl;
	IKE_ILIST	idlist_excl;
	IKE_DLIST	dlist;

	BDATA		banner;

	long		state;
	long		close;
	long		natt_v;

	_IDB_TUNNEL( IDB_PEER * set_peer, IKE_SADDR * set_saddr_l, IKE_SADDR * set_saddr_r );
	virtual ~_IDB_TUNNEL();

	virtual bool add( bool lock );
	virtual bool inc( bool lock );
	virtual bool dec( bool lock );
	virtual void end( bool lock );

}IDB_TUNNEL;

typedef class _IDB_POLICY : public PFKI_SPINFO, public IDB
{
	public:

	bool	route;

	_IDB_POLICY( PFKI_SPINFO * spinfo );

	virtual bool add( bool lock );
	virtual bool inc( bool lock );
	virtual bool dec( bool lock );

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

typedef class _IDB_XCH : public IDB
{
	public:

	IDB_TUNNEL *	tunnel;

	bool			initiator;
	unsigned char	exchange;

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
	public:

	const EVP_CIPHER *	evp_cipher;
	const EVP_MD *		evp_hash;

	IKE_COOKIES	cookies;

	IKE_PH1ID	ph1id_l;
	IKE_PH1ID	ph1id_r;

	bool	xauth_l;	// local will support xauth
	bool	xauth_r;	// remote will support xauth

	bool	natt_l;		// local will support natt
	bool	natt_r;		// remote will support natt
	long	natt_v;		// version negotiated

	bool	dpd_l;		// local will support dead peer detect
	bool	dpd_r;		// remote will support dead peer detect

	bool	frag_l;		// local will support fragmentation
	bool	frag_r;		// remote will support fragmentation

	bool	natted_l;	// local address is natted
	bool	natted_r;	// remote address is natted

	uint32_t	dpd_req;	// last dpd request sequence
	uint32_t	dpd_res;	// last dpd response sequence

	uint8_t	ctype_l;	// local certificate type
	uint8_t	ctype_r;	// remote certificate type

	LIST	frags;

	BDATA	key;

	BDATA	idi;
	BDATA	idr;

	BDATA	natd_ls;
	BDATA	natd_ld;
	BDATA	natd_rs;
	BDATA	natd_rd;

	BDATA	cert_r;
	BDATA	sign_r;

	BDATA	skeyid;
	BDATA	skeyid_d;
	BDATA	skeyid_a;
	BDATA	skeyid_e;

	ITH_EVENT_PH1DPD	event_dpd;
	ITH_EVENT_PH1NATT	event_natt;
	ITH_EVENT_PH1HARD	event_hard;

	_IDB_PH1( IDB_TUNNEL * set_tunnel, bool set_initiator, IKE_COOKIES * set_cookies );
	virtual ~_IDB_PH1();

	virtual bool add( bool lock );
	virtual bool inc( bool lock );
	virtual bool dec( bool lock );

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

	_IDB_PH2( IDB_TUNNEL * set_tunnel, bool set_initiator, uint32_t set_msgid, uint32_t set_seqid_in );
	virtual ~_IDB_PH2();

	virtual bool add( bool lock );
	virtual bool inc( bool lock );
	virtual bool dec( bool lock );

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

	_IDB_CFG( IDB_TUNNEL * tunnel, bool set_initiator, unsigned long set_msgid );
	virtual ~_IDB_CFG();

	virtual bool add( bool lock );
	virtual bool inc( bool lock );
	virtual bool dec( bool lock );

	BDATA		hash;

	uint8_t		mtype;
	uint16_t	ident;

	IKE_ATTR *	attr_get( long index );
	bool		attr_has( unsigned short atype );
	bool		attr_add_b( unsigned short atype, unsigned short adata );
	bool		attr_add_v( unsigned short atype, void * vdata, unsigned long size );

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

	_IDB_INF();
	virtual ~_IDB_INF();

	virtual bool add( bool lock );
	virtual bool inc( bool lock );
	virtual bool dec( bool lock );

}IDB_INF;

#endif
