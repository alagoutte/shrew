
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

#ifndef _IKE_IDB_H_
#define _IKE_IDB_H_

#ifdef OPT_DTP
# include "libdtp.h"
#endif

//==============================================================================
// general classes
//==============================================================================

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

	void		set_msgid( uint32_t msgid );
	uint32_t	get_msgid();

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

#ifdef UNIX

typedef struct _SOCK_INFO : public IDB_ENTRY
{
	int         sock;
	IKE_SADDR   saddr;
	bool        natt;

}SOCK_INFO;

typedef struct _VNET_ADAPTER
{
	int fn;
	char    name[ IFNAMSIZ ];

}VNET_ADAPTER;

#endif

//==============================================================================
// basic data list
//

typedef class _IDB_ENTRY_BDATA : public IDB_ENTRY, public BDATA
{
}IDB_ENTRY_BDATA;

typedef class _IDB_LIST_BDATA : public IDB_LIST
{
	public:

	BDATA name;

	virtual ~_IDB_LIST_BDATA();

	bool	add( BDATA & bdata );
	bool	get( BDATA & bdata, long index );

}IDB_LIST_BDATA;

//==============================================================================
// ike proposal list
//

typedef class _IDB_ENTRY_PROPOSAL : public IDB_ENTRY, public IKE_PROPOSAL
{
	public:

	bool	pnext;

}IDB_ENTRY_PROPOSAL;

typedef class _IDB_LIST_PROPOSAL : public IDB_LIST
{
	public:

	virtual ~_IDB_LIST_PROPOSAL();

	bool	add( IKE_PROPOSAL * proposal, bool pnext );
	bool	get( IKE_PROPOSAL ** proposal, long pindex, uint8_t proto = 0 );

	bool	nextb( long & bindex, long & pindex, long & pcount );
	bool	nextp( IKE_PROPOSAL ** proposal, long & pindex, long & tindex, long & tcount );
	bool	nextt( IKE_PROPOSAL ** proposal, long & tindex );

}IDB_LIST_PROPOSAL;

//==============================================================================
// ike notification list
//

typedef class _IDB_ENTRY_NOTIFY : public IDB_ENTRY, public IKE_NOTIFY
{
}IDB_ENTRY_NOTIFY;

typedef class _IDB_LIST_NOTIFY : public IDB_LIST
{
	public:

	virtual ~_IDB_LIST_NOTIFY();

	bool	add( IKE_NOTIFY & notify );
	bool	get( IKE_NOTIFY & notify, long index );

}IDB_LIST_NOTIFY;

//==============================================================================
// certificate list
//

typedef class _IDB_ENTRY_CERT : public IDB_ENTRY
{
	public:

	uint8_t	type;
	BDATA	data;

}IDB_ENTRY_CERT;

typedef class _IDB_LIST_CERT : public IDB_LIST
{
	public:

	virtual ~_IDB_LIST_CERT();

	bool	add( uint8_t & type, BDATA & data );
	bool	get( uint8_t & type, BDATA & data, long index );

}IDB_LIST_CERT;

//==============================================================================
// phase2 ID list
//

typedef class _IDB_ENTRY_PH2ID : public IDB_ENTRY, public IKE_PH2ID
{
}IDB_ENTRY_PH2ID;

typedef class _IDB_LIST_PH2ID : public IDB_LIST, public IDB_ENTRY
{
	public:

	BDATA name;

	virtual ~_IDB_LIST_PH2ID();

	bool	add( IKE_PH2ID & ph2id );
	bool	get( IKE_PH2ID & ph2id, long index );

}IDB_LIST_PH2ID;

//==============================================================================
// network map list ( list of phase2 ID lists )
//

typedef class _IDB_ENTRY_NETMAP : public IDB_ENTRY
{
	public:

	IDB_LIST_PH2ID *	idlist;
	long				mode;
	BDATA				group;

}IDB_ENTRY_NETMAP;

typedef class _IDB_LIST_NETMAP : public IDB_LIST
{
	public:

	BDATA name;

	virtual ~_IDB_LIST_NETMAP();

	bool	add( IDB_LIST_PH2ID * idlist, long mode, BDATA * group );
	bool	del( IDB_ENTRY_NETMAP * netmap );
	bool	get( IDB_ENTRY_NETMAP ** netmap, long index );

}IDB_LIST_NETMAP;

//==============================================================================
// domain name list
//

typedef IDB_ENTRY_BDATA IDB_ENTRY_DOMAIN;
typedef IDB_LIST_BDATA IDB_LIST_DOMAIN ;

//==============================================================================
// reference counted IDB derived classes
//==============================================================================

enum XCH_STATUS
{
	XCH_STATUS_ANY,
	XCH_STATUS_PENDING,
	XCH_STATUS_LARVAL,
	XCH_STATUS_MATURE,
	XCH_STATUS_EXPIRING,
	XCH_STATUS_EXPIRED,
	XCH_STATUS_DEAD
};

enum XCH_ERRORCODE
{
	XCH_NORMAL,
	XCH_FAILED_CLIENT,
	XCH_FAILED_NETWORK,
	XCH_FAILED_ADAPTER,
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

typedef struct _VENDOPTS
{
	union
	{
		struct
		{
			unsigned long xauth	:1;
			unsigned long frag	:1;
			unsigned long dpdv1	:1;
			unsigned long hbeat	:1;
			unsigned long natt	:1;

			unsigned long ssoft	:1;
			unsigned long kame	:1;
			unsigned long unity	:1;
			unsigned long netsc	:1;
			unsigned long zwall	:1;
			unsigned long swind	:1;
			unsigned long swall	:1;
			unsigned long chkpt	:1;

		}flag;

		unsigned long flags;
	};

}VENDOPTS;

typedef class _IKED_XAUTH IKED_XAUTH;
typedef class _IKED_XCONF IKED_XCONF;

typedef class _IDB_TUNNEL IDB_TUNNEL;
typedef class _IDB_XCH IDB_XCH;
typedef class _IDB_PH1 IDB_PH1;
typedef class _IDB_PH2 IDB_PH2;
typedef class _IDB_CFG IDB_CFG;

//==============================================================================
// tunnel event classes
//

typedef class _ITH_EVENT_TUNDHCP : public ITH_EVENT
{
	public:

	IDB_TUNNEL *	tunnel;

	time_t	lease;
	time_t	renew;
	long	retry;

	bool	func();

}ITH_EVENT_TUNDHCP;

typedef class _ITH_EVENT_TUNDPD : public ITH_EVENT
{
	public:

	IDB_TUNNEL *	tunnel;

	uint32_t	sequence;
	uint32_t	attempt;

	void	next();

	bool	func();

}ITH_EVENT_TUNDPD;

typedef class _ITH_EVENT_TUNNATT : public ITH_EVENT
{
	public:

	IDB_TUNNEL *	tunnel;

	bool	func();

}ITH_EVENT_TUNNATT;

typedef class _ITH_EVENT_TUNSTATS : public ITH_EVENT
{
	public:

	IDB_TUNNEL *	tunnel;

	bool	func();

}ITH_EVENT_TUNSTATS;

//==============================================================================
// exchange event classes
//

typedef class _ITH_EVENT_RESEND : public ITH_EVENT, public IPQUEUE
{
	public:

	IDB_XCH *	xch;
	IPQUEUE		ipqueue;
	long		attempt;

	bool	func();

}ITH_EVENT_RESEND;

//==============================================================================
// phase1 event classes
//

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

typedef class _ITH_EVENT_PH1DEAD : public ITH_EVENT
{
	public:

	IDB_PH1 *	ph1;

	bool	func();

}ITH_EVENT_PH1DEAD;

//==============================================================================
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

//==============================================================================
// ike internal data classes
//

class _IKED_RC_LIST;

#define ENTRY_FLAG_DEAD			1
#define ENTRY_FLAG_IMMEDIATE	2
#define ENTRY_FLAG_ENDCALLED	4

typedef class _IKED_RC_ENTRY : public IDB_ENTRY
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

	void callend();

	virtual void beg() = 0;
	virtual void end() = 0;

	public:

	_IKED_RC_ENTRY();
	virtual ~_IKED_RC_ENTRY();

	virtual const char *	name() = 0;
	virtual _IKED_RC_LIST *	list() = 0;

	bool add( bool lock );
	void inc( bool lock );
	bool dec( bool lock, bool setdel = false );

}IKED_RC_ENTRY;

typedef class _IKED_RC_LIST : public IDB_LIST
{
	public:

	_IKED_RC_LIST();
	virtual ~_IKED_RC_LIST();

	virtual	void	clean();

	bool	lock();
	bool	unlock();

}IKED_RC_LIST;

typedef class _IDB_PEER : public IKED_RC_ENTRY, public IKE_PEER
{
	private:

	virtual void	beg();
	virtual void	end();

	public:

	BDATA		iddata_l;
	BDATA		iddata_r;

	BDATA		cert_l;
	BDATA		cert_r;
	BDATA		cert_k;
	BDATA		psk;

	BDATA			xauth_group;
	IKED_XAUTH *	xauth_source;
	IKED_XCONF *	xconf_source;

	IDB_LIST_PROPOSAL	proposals;
	IDB_LIST_NETMAP		netmaps;

	virtual	const char *	name();
	virtual IKED_RC_LIST *	list();

	_IDB_PEER( IKE_PEER * set_peer );
	virtual ~_IDB_PEER();

}IDB_PEER;

typedef class _IDB_LIST_PEER : public IKED_RC_LIST
{
	public:

	IDB_PEER * get( int index );

	bool find(
			bool lock,
			IDB_PEER ** peer,
			IKE_SADDR * saddr );

}IDB_LIST_PEER;

typedef class _IDB_TUNNEL : public IKED_RC_ENTRY
{
	public:

	long		tunnelid;
	long		tstate;
	long		lstate;
	long		natt_version;
	bool		suspended;

	IDB_PEER *	peer;
	IKEI *		ikei;

#ifdef OPT_DTP
	DTPI *		dtpi;
#endif

	VNET_ADAPTER * adapter;

	IKE_SADDR	saddr_l;
	IKE_SADDR	saddr_r;

	//
	// FIXME : move client stuff into class
	//

	IKEI_STATS		stats;
	IKE_XAUTH		xauth;
	IKE_XCONF		xconf;
	IDB_LIST_DOMAIN	domains;
	BDATA			banner;
	XCH_ERRORCODE	close;

#ifdef WIN32
	IKE_NSCFG		nscfg;
#endif

	bool			force_all;
	IDB_LIST_PH2ID	idlist_incl;
	IDB_LIST_PH2ID	idlist_excl;

	//
	// FIXME : move DHCP stuff into class
	//

	uint32_t	dhcp_xid;
	uint8_t		dhcp_hwtype;
	uint8_t		dhcp_hwaddr[ 6 ];
	SOCKET		dhcp_sock;

	ITH_EVENT_TUNDHCP	event_dhcp;
	ITH_EVENT_TUNDPD	event_dpd;
	ITH_EVENT_TUNNATT	event_natt;
	ITH_EVENT_TUNSTATS	event_stats;

	virtual	const char *	name();
	virtual IKED_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	_IDB_TUNNEL( IDB_PEER * set_peer, IKE_XCONF * set_xconf, IKE_SADDR * set_saddr_l, IKE_SADDR * set_saddr_r );
	virtual ~_IDB_TUNNEL();

}IDB_TUNNEL;

typedef class _IDB_LIST_TUNNEL : public IKED_RC_LIST
{
	public:

	IDB_TUNNEL * get( int index );

	bool find(
			bool lock,
			IDB_TUNNEL ** tunnel,
			long * tunnelid,
			IKE_SADDR * saddr,
			bool port,
			bool suspended );

}IDB_LIST_TUNNEL;

typedef class _IDB_POLICY : public IKED_RC_ENTRY, public PFKI_SPINFO
{
	public:

	IPROUTE_ENTRY	route_entry;
	long			flags;

	virtual	const char *	name();
	virtual IKED_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	_IDB_POLICY( PFKI_SPINFO * spinfo );
	virtual ~_IDB_POLICY();

}IDB_POLICY;

typedef class _IDB_LIST_POLICY : public IKED_RC_LIST
{
	public:

	IDB_POLICY * get( int index );

	bool find(
			bool lock,
			IDB_POLICY ** policy,
			long dir,
			u_int16_t type,
			u_int32_t * seq,
			u_int32_t * plcyid,
			IKE_SADDR * src,
			IKE_SADDR * dst,
			IKE_PH2ID * ids,
			IKE_PH2ID * idd );

	void	flush();

}IDB_LIST_POLICY;

//==============================================================================
// ike generic exchange handle class
//

typedef class _IDB_XCH : public IKED_RC_ENTRY
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

	BDATA		hash_l;
	BDATA		hash_r;

	BDATA		hda;		// hash data accumulator
	BDATA		iv;

	IDB_LIST_NOTIFY		notifications;

	ITH_EVENT_RESEND	event_resend;

	_IDB_XCH();
	virtual ~_IDB_XCH();

	XCH_STATUS	status();
	XCH_STATUS	status( XCH_STATUS status, XCH_ERRORCODE errorcode, uint16_t notifycode );

	void	new_msgid();
	bool	new_msgiv( IDB_PH1 * ph1 );

	bool	resend();
	bool	resend_queue( PACKET_IP & packet );
	void	resend_purge();
	bool	resend_sched( bool lock );
	void	resend_clear( bool lock, bool purge );

}IDB_XCH;

//==============================================================================
// ike generic sa exchange handle class
//

typedef class _IDB_XCH_SA : public IDB_XCH
{
	public:

	DH *		dh;
	long		dh_size;

	BDATA		xl;
	BDATA		xr;

	BDATA		nonce_l;
	BDATA		nonce_r;

	IDB_LIST_PROPOSAL	plist_l;
	IDB_LIST_PROPOSAL	plist_r;

	_IDB_XCH_SA();
	virtual ~_IDB_XCH_SA();

}IDB_XCH_SA;

//==============================================================================
// ike phase1 exchange handle class
//

typedef class _IDB_PH1 : public IDB_XCH_SA
{
	virtual void	beg();
	virtual void	end();

	public:

	const EVP_CIPHER *	evp_cipher;
	const EVP_MD *		evp_hash;
	long				hash_size;

	IKE_COOKIES	cookies;

	IKE_PH1ID	ph1id_l;
	IKE_PH1ID	ph1id_r;

	VENDOPTS	vendopts_l;
	VENDOPTS	vendopts_r;

	long	natt_version;	// version negotiated
	uint8_t	natt_pldtype;	// payload identifier

	uint16_t	auth_id;	// selected authentication type

	IDB_LIST	frags;

	BDATA	key;

	BDATA	idi;
	BDATA	idr;

	IDB_LIST_BDATA	natd_hash_l;
	IDB_LIST_BDATA	natd_hash_r;

	IDB_LIST_CERT	creqs_r;
	IDB_LIST_CERT	certs_r;
	BDATA			sign_r;

	BDATA	skeyid;
	BDATA	skeyid_d;
	BDATA	skeyid_a;
	BDATA	skeyid_e;

	ITH_EVENT_PH1SOFT	event_soft;
	ITH_EVENT_PH1HARD	event_hard;
	ITH_EVENT_PH1DEAD	event_dead;

	// sub class functions

	virtual	const char *	name();
	virtual IKED_RC_LIST *	list();

	// class functions

	_IDB_PH1( IDB_TUNNEL * set_tunnel, bool set_initiator, IKE_COOKIES * set_cookies );
	virtual ~_IDB_PH1();

	bool	setup_dhgrp( IKE_PROPOSAL * proposal );
	bool	setup_xform( IKE_PROPOSAL * proposal );

	void	clean();

	//
	// FIXME : fragments should be IDB list
	//

	bool	frag_add( unsigned char * data, unsigned long size, long index, bool last );
	bool	frag_get( PACKET_IKE & packet );

}IDB_PH1;

typedef class _IDB_LIST_PH1 : public IKED_RC_LIST
{
	public:

	IDB_PH1 * get( int index );

	bool find(
			bool lock,
			IDB_PH1 ** ph1,
			IDB_TUNNEL * tunnel,
			XCH_STATUS min,
			XCH_STATUS max,
			IKE_COOKIES * cookies );
	
}IDB_LIST_PH1;

//==============================================================================
// ike phase2 exchange handle class
//

typedef class _IDB_PH2 : public IDB_XCH_SA
{
	public:

	IKE_COOKIES	cookies;
	uint32_t	seqid_in;
	uint32_t	seqid_out;
	uint32_t	plcyid_in;
	uint32_t	plcyid_out;

	bool		nailed;
	long		spicount;
	long		dhgr_id;

	IKE_PH2ID	ph2id_ls;
	IKE_PH2ID	ph2id_ld;
	IKE_PH2ID	ph2id_rs;
	IKE_PH2ID	ph2id_rd;

	ITH_EVENT_PH2SOFT	event_soft;
	ITH_EVENT_PH2HARD	event_hard;

	// sub class functions

	virtual	const char *	name();
	virtual IKED_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	// class functions

	_IDB_PH2( IDB_TUNNEL * set_tunnel, bool set_initiator, uint32_t set_msgid, uint32_t set_seqid_in );
	virtual ~_IDB_PH2();

	bool	setup_dhgrp();
	bool	setup_xform();

	void	clean();

}IDB_PH2;

typedef class _IDB_LIST_PH2 : public IKED_RC_LIST
{
	public:

	IDB_PH2	* get( int index );

	bool find(
			bool lock,
			IDB_PH2 ** ph2,
			IDB_TUNNEL * tunnel,
			XCH_STATUS min,
			XCH_STATUS max,
			u_int32_t * seqid,
			uint32_t * msgid,
			IKE_SPI * spi_l,
			IKE_SPI * spi_r );

	void	flush();

}IDB_LIST_PH2;

//==============================================================================
// ike configuraion exchange handle class
//

typedef class _IDB_CFG : public IDB_XCH
{
	protected:

	IDB_LIST	attrs;

	public:

	// this should never be accessed
	// directly, only for comparison

	IDB_PH1 *	ph1ref;

	// sub class functions

	virtual	const char *	name();
	virtual IKED_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	// class functions

	_IDB_CFG( IDB_PH1 * set_ph1ref, bool set_initiator );
	virtual ~_IDB_CFG();

	BDATA		hash;

	uint8_t		mtype;
	uint16_t	ident;

	//
	// FIXME : attributes should be IDB list
	//

	IKE_ATTR *	attr_get( long index );
	bool		attr_has( unsigned short atype );
	bool		attr_add_b( unsigned short atype, unsigned short adata );
	bool		attr_add_v( unsigned short atype, const void * vdata, size_t size );

	long		attr_count();						// get attribute count
	void		attr_reset();						// reset attribute list

	bool	setup();
	void	clean();

}IDB_CFG;

typedef class _IDB_LIST_CFG : public IKED_RC_LIST
{
	public:

	IDB_CFG * get( int index );

	bool find(
			bool lock,
			IDB_CFG ** cfg,
			IDB_PH1 * ph1 );

}IDB_LIST_CFG;

//==============================================================================
// ike informational exchange handle class
//

typedef class _IDB_INF : public IDB_XCH
{
	public:

	// sub class functions

	virtual	const char *	name();
	virtual IKED_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	// class functions

	_IDB_INF();
	virtual ~_IDB_INF();

}IDB_INF;

typedef IKED_RC_LIST IDB_LIST_INF;

#endif /// _IKE_IDB_H_
