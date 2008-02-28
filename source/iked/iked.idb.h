
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

//==============================================================================
// standard IDB derived classes
//==============================================================================

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

	bool	add( BDATA & cert );
	bool	get( BDATA & cert, long index );

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

	bool	add( IKE_NOTIFY & notify );
	bool	get( IKE_NOTIFY & notify, long index );

}IDB_LIST_NOTIFY;

//==============================================================================
// certificate list
//

typedef IDB_ENTRY_BDATA IDB_ENTRY_CERT;

typedef class _IDB_LIST_CERT : public IDB_LIST_BDATA
{
	public:

	BDATA name;

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

typedef class _IDB_LIST_IKED : public IDB_RC_LIST
{
	protected:

	virtual ITH_LOCK	* rc_lock();
	virtual LOG			* rc_log();

}IDB_LIST_IKED;

typedef class _IDB_PEER : public IDB_RC_ENTRY, public IKE_PEER
{
	private:

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

	IDB_LIST_PROPOSAL	proposals;
	IDB_LIST_NETMAP		netmaps;

	virtual	char *			name();
	virtual IDB_RC_LIST *	list();

	_IDB_PEER( IKE_PEER * set_peer );
	virtual ~_IDB_PEER();

}IDB_PEER;

typedef class _IDB_LIST_PEER : public IDB_LIST_IKED
{
	public:

	IDB_PEER * get( int index );

	bool find(
			bool lock,
			IDB_PEER ** peer,
			IKE_SADDR * saddr );

}IDB_LIST_PEER;

typedef class _IDB_TUNNEL : public IDB_RC_ENTRY
{
	public:

	long		tunnelid;
	long		tstate;
	long		lstate;

	IDB_PEER *	peer;

	IKE_SADDR	saddr_l;
	IKE_SADDR	saddr_r;

	long			natt_version;

	IKE_XAUTH		xauth;
	IKE_XCONF		xconf;
	IDB_LIST_DOMAIN	domains;
	BDATA			banner;
	IKEI_STATS		stats;
	XCH_ERRORCODE	close;

#ifdef WIN32
	IKE_NSCFG		nscfg;
#endif

	bool			force_all;
	IDB_LIST_PH2ID	idlist_incl;
	IDB_LIST_PH2ID	idlist_excl;

	//
	// FIXME : move DHCP state into config handle
	//

	uint32_t	dhcp_xid;
	uint8_t		dhcp_hwtype;
	uint8_t		dhcp_hwaddr[ 5 ];
	SOCKET		dhcp_sock;

	ITH_EVENT_TUNDHCP	event_dhcp;

	virtual	char *			name();
	virtual IDB_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	_IDB_TUNNEL( IDB_PEER * set_peer, IKE_SADDR * set_saddr_l, IKE_SADDR * set_saddr_r );
	virtual ~_IDB_TUNNEL();

}IDB_TUNNEL;

typedef class _IDB_LIST_TUNNEL : public IDB_LIST_IKED
{
	public:

	IDB_TUNNEL * get( int index );

	bool find(
			bool lock,
			IDB_TUNNEL ** tunnel,
			long * tunnelid,
			IKE_SADDR * saddr,
			bool port );

}IDB_LIST_TUNNEL;

typedef class _IDB_POLICY : public IDB_RC_ENTRY, public PFKI_SPINFO
{
	public:

	bool		route;
	bool		nailed;

	virtual	char *			name();
	virtual IDB_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	_IDB_POLICY( PFKI_SPINFO * spinfo );
	virtual ~_IDB_POLICY();

}IDB_POLICY;

typedef class _IDB_LIST_POLICY : public IDB_LIST_IKED
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

typedef class _IDB_XCH : public IDB_RC_ENTRY
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

	long		hash_size;
	BDATA		hash_l;
	BDATA		hash_r;

	BDATA		hda;		// hash data accumulator
	BDATA		iv;

	//
	// FIXME : only use lists in classes that need them
	//

	IDB_LIST_PROPOSAL	plist_l;
	IDB_LIST_PROPOSAL	plist_r;
	IDB_LIST_NOTIFY		notifications;

	ITH_EVENT_RESEND	event_resend;

	_IDB_XCH();
	virtual ~_IDB_XCH();

	XCH_STATUS	status();
	XCH_STATUS	status( XCH_STATUS status, XCH_ERRORCODE errorcode, uint16_t notifycode );

	bool	resend_queue( PACKET_IP & packet );
	bool	resend_sched();
	void	resend_clear() ;

}IDB_XCH;

//==============================================================================
// ike phase1 exchange handle class
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

	VENDOPTS	vendopts_l;
	VENDOPTS	vendopts_r;

	long	natt_version;	// version negotiated
	uint8_t	natt_pldtype;	// payload identifier

	bool	natted_l;	// local address is natted
	bool	natted_r;	// remote address is natted

	//
	// FIXME : dpd sequences should be in tunnel
	//

	uint32_t	dpd_req;	// last dpd request sequence
	uint32_t	dpd_res;	// last dpd response sequence

	uint8_t		ctype_l;	// local certificate type
	uint8_t		ctype_r;	// remote certificate type

	uint16_t	auth_id;	// selected authentication type

	IDB_LIST	frags;

	BDATA	key;

	BDATA	idi;
	BDATA	idr;

	BDATA	natd_ls;
	BDATA	natd_ld;
	BDATA	natd_rs;
	BDATA	natd_rd;

	IDB_LIST_CERT	certs_r;
	BDATA			sign_r;

	BDATA	skeyid;
	BDATA	skeyid_d;
	BDATA	skeyid_a;
	BDATA	skeyid_e;

	ITH_EVENT_PH1DPD	event_dpd;
	ITH_EVENT_PH1NATT	event_natt;
	ITH_EVENT_PH1SOFT	event_soft;
	ITH_EVENT_PH1HARD	event_hard;

	// sub class functions

	virtual	char *			name();
	virtual IDB_RC_LIST *	list();

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

typedef class _IDB_LIST_PH1 : public IDB_LIST_IKED
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

typedef class _IDB_PH2 : public IDB_XCH
{
	public:

	uint32_t	seqid_in;
	uint32_t	seqid_out;
	uint32_t	nailed_plcyid;
	long		spicount;

	long		dhgr_id;

	IKE_PH2ID	ph2id_ls;
	IKE_PH2ID	ph2id_ld;
	IKE_PH2ID	ph2id_rs;
	IKE_PH2ID	ph2id_rd;

	ITH_EVENT_PH2SOFT	event_soft;
	ITH_EVENT_PH2HARD	event_hard;

	// sub class functions

	virtual	char *			name();
	virtual IDB_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	// class functions

	_IDB_PH2( IDB_TUNNEL * set_tunnel, bool set_initiator, uint32_t set_msgid, uint32_t set_seqid_in );
	virtual ~_IDB_PH2();

	bool	setup_dhgrp();
	bool	setup_xform();

	void	clean();

}IDB_PH2;

typedef class _IDB_LIST_PH2 : public IDB_LIST_IKED
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

	// sub class functions

	virtual	char *			name();
	virtual IDB_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	// class functions

	_IDB_CFG( IDB_TUNNEL * tunnel, bool set_initiator, unsigned long set_msgid );
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
	bool		attr_add_v( unsigned short atype, void * vdata, size_t size );

	long		attr_count();						// get attribute count
	void		attr_reset();						// reset attribute list

	bool	setup();
	void	clean();

}IDB_CFG;

typedef class _IDB_LIST_CFG : public IDB_LIST_IKED
{
	public:

	IDB_CFG * get( int index );

	bool find(
			bool lock,
			IDB_CFG ** cfg,
			IDB_TUNNEL * tunnel,
			unsigned long msgid );

}IDB_LIST_CFG;

//==============================================================================
// ike informational exchange handle class
//

typedef class _IDB_INF : public IDB_XCH
{
	public:

	// sub class functions

	virtual	char *			name();
	virtual IDB_RC_LIST *	list();

	virtual void	beg();
	virtual void	end();

	// class functions

	_IDB_INF();
	virtual ~_IDB_INF();

}IDB_INF;

typedef IDB_LIST_IKED IDB_LIST_INF;

#endif /// _IKE_IDB_H_
