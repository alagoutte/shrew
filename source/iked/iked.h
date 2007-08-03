
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

#ifndef _IKED_H_
#define _IKED_H_

#ifdef WIN32
# include <winsock2.h>
# include <windows.h>
# include <shlwapi.h>
# include <time.h>
# include <assert.h>
# include <string.h>
# include "libvflt.h"
# include "libvnet.h"
# include "ipsec.h"
#endif

#ifdef UNIX
# ifdef __linux__
#  include <signal.h>
#  include <pwd.h>
#  include <grp.h>
#  include <netdb.h>
#  include <net/if.h>
#  include <sys/ioctl.h>
#  include <linux/udp.h>
# else
#  include <signal.h>
#  include <pwd.h>
#  include <grp.h>
#  include <netdb.h>
#  include <sys/ioctl.h>
#  include <sys/param.h>
#  include <sys/socket.h>
#  include <net/if.h>
# endif
# ifdef __FreeBSD__
#  include <sys/linker.h>
# endif
# include "conf.parse.hpp"
#endif

#ifdef OPT_LDAP
#include <ldap.h>
#endif

#include "version.h"
#include "liblog.h"
#include "libike.h"
#include "libith.h"
#include "libpfk.h"
#include "libike.h"
#include "ike.h"
#include "idb.h"
#include "xauth.h"
#include "xconf.h"
#include "crypto.h"

#ifdef OPT_DTP
#include "libdtp.h"
#endif


//
// Win32 specific
//

#ifdef WIN32

#define PATH_CONF		"SOFTWARE\\ShrewSoft\\vpn"

#define SET_SALEN( A, B )

#endif

//
// Unix specific
//

#ifdef UNIX

#ifdef __FreeBSD__
# define PATH_CONF		"/usr/local/etc/iked.conf"
#else
# define PATH_CONF		"/etc/iked.conf"
#endif

#ifdef __linux__
#define SET_SALEN( A, B )
#else
#define SET_SALEN( A, B ) ((sockaddr*)(A))->sa_len = B
#endif

#define PATH_DEBUG		"/var/log"
#define MAX_PATH		1024

// Conf parser definition

#define YY_DECL										\
	yy::conf_parser::token_type						\
	yylex( yy::conf_parser::semantic_type * yylval,	\
	yy::conf_parser::location_type * yylloc,		\
	IKED & iked )

YY_DECL;

#endif

//
// IKED constants
//

#define	VEND_XAUTH		{ 0x09, 0x00, 0x26, 0x89, 0xDF, 0xD6, 0xB7, 0x12 }
#define	VEND_UNITY		{ 0x12, 0xf5, 0xf2, 0x8c, 0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc, 0x01, 0x00 }
#define VEND_FRAG		{ 0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7, 0xde, 0x7f, 0x00, 0xd6, 0xc2, 0xd3, 0x80, 0x00, 0x00, 0x00 }
#define	VEND_NATT_V02	{ 0x90, 0xcb, 0x80, 0x91, 0x3e, 0xbb, 0x69, 0x6e, 0x08, 0x63, 0x81, 0xb5, 0xec, 0x42, 0x7b, 0x1f }
#define	VEND_NATT_RFC	{ 0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f }
#define VEND_KAME		{ 0x70, 0x03, 0xcb, 0xc1, 0x09, 0x7d, 0xbe, 0x9c, 0x26, 0x00, 0xba, 0x69, 0x83, 0xbc, 0x8b, 0x35 }
#define VEND_DPD1		{ 0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00 }

#define LIBIKE_IKE_PORT			500		// default isakmp port
#define LIBIKE_NATT_PORT		4500	// default nat-t port

#define LIBIKE_MAX_TEXTADDR		24		// max text address length
#define LIBIKE_MAX_TEXTP1ID		128		// max text phase1 id length
#define LIBIKE_MAX_TEXTP2ID		50		// max text phase2 id length
#define LIBIKE_MAX_TEXTSPI		64		// max text phase2 id length
#define LIBIKE_MAX_VARID		512		// max variable id length
#define LIBIKE_MAX_DHGRP		512		// max dh group size

#define LIBIKE_OK				0
#define LIBIKE_FAILED			-1
#define LIBIKE_SOCKET			-2
#define LIBIKE_NODATA			-3
#define LIBIKE_HOSTNAME			-4
#define LIBIKE_HOSTPORT			-5
#define LIBIKE_MEMORY			-6
#define LIBIKE_ENCODE			-7
#define LIBIKE_DECODE			-8

#define LTIME_OBEY				1
#define LTIME_CLAIM				2
#define LTIME_STRICT			3
#define LTIME_EXACT				4

#define NAME_INITIATOR			1
#define NAME_EXCHANGE			2
#define NAME_PROTOCOL			3
#define NAME_XFORM_ISAKMP		4
#define NAME_XFORM_AH			5
#define NAME_XFORM_ESP			6
#define NAME_XFORM_IPCOMP		7
#define NAME_PAYLOAD			8
#define NAME_CIPHER				9
#define NAME_MAUTH				10
#define NAME_PAUTH				11
#define NAME_HASH				12
#define NAME_CERT				13
#define NAME_GROUP				14
#define NAME_ENCAP				15
#define NAME_IDENT				16
#define NAME_NOTIFY				17

#define XSTATE_SENT_SA			0x000000001
#define XSTATE_SENT_KE			0x000000002
#define XSTATE_SENT_NO			0x000000004
#define XSTATE_SENT_ID			0x000000008
#define XSTATE_SENT_CT			0x000000010
#define XSTATE_SENT_CR			0x000000020
#define XSTATE_SENT_SI			0x000000040
#define XSTATE_SENT_HA			0x000000080
#define XSTATE_RECV_SA			0x000000100
#define XSTATE_RECV_KE			0x000000200
#define XSTATE_RECV_NO			0x000000400
#define XSTATE_RECV_ID			0x000000800
#define XSTATE_RECV_SI			0x000001000
#define XSTATE_RECV_CT			0x000002000
#define XSTATE_RECV_CR			0x000004000
#define XSTATE_RECV_NDL			0x000008000
#define XSTATE_RECV_NDR			0x000010000
#define XSTATE_RECV_IDL			0x000020000
#define XSTATE_RECV_IDR			0x000040000
#define XSTATE_RECV_HA			0x000080000
#define XSTATE_RECV_LP			0x000100000
#define XSTATE_SENT_LP			0x000200000

#define LSTATE_PENDING			0x000000001		// pending phase1 negotiation
#define LSTATE_HASSPI			0x000000002		// pfkey spi obtained
#define LSTATE_CHKPROP			0x000000004		// proposal verified
#define LSTATE_CHKHASH			0x000000008		// hash verified
#define LSTATE_CHKIDS			0x000000010		// identity verified
#define LSTATE_GENNATD			0x000000020		// natt discovery generated
#define LSTATE_CHKNATD			0x000000040		// natt discovery verified
#define LSTATE_HASNATP			0x000000080		// natt ports floated
#define LSTATE_HASKEYS			0x000000100		// keys generated
#define LSTATE_CLAIMLT			0x000000200		// claim reponder lifetime
#define LSTATE_MATURE			0x000000400		// mature and usable
#define LSTATE_EXPIRE			0x000000800		// lifetime expired
#define LSTATE_NOTIFY			0x000001000		// skip peer notify
#define LSTATE_DELETE			0x000002000		// ready for delete

#define TSTATE_INITIALIZED		0x00000001
#define TSTATE_RECV_XAUTH		0x00000002
#define TSTATE_SENT_XAUTH		0x00000004
#define TSTATE_RECV_XRSLT		0x00000008
#define TSTATE_SENT_XRSLT		0x00000010
#define TSTATE_SENT_CONFIG		0x00000020
#define TSTATE_RECV_CONFIG		0x00000040
#define TSTATE_VNET_ENABLE		0x00000080
#define TSTATE_DELETE			0x00000100

#define DSTATE_ACTIVE			0
#define DSTATE_TERMINATE		1
#define DSTATE_INACTIVE			2

#define RLEVEL_DAEMON			2

#define TERM_CLIENT				1
#define TERM_SOCKET				2
#define TERM_EXPIRE				3
#define TERM_BADMSG				4
#define TERM_USER_AUTH			5
#define TERM_PEER_AUTH			6
#define TERM_USER_CLOSE			7
#define TERM_PEER_CLOSE			8
#define TERM_PEER_DEAD			9

#define FILE_OK					0
#define FILE_FAIL				1
#define FILE_PASS				2

//
// IKED main classes and structures
//

#ifdef UNIX

typedef struct _SOCK_INFO
{
	int			sock;
	IKE_SADDR	saddr;

}SOCK_INFO;

typedef struct _VNET_ADAPTER
{
	FILE *	fp;
	char	name[ IFNAMSIZ ];

}VNET_ADAPTER;

#endif

typedef class _ITH_ADMIN : public _ITH_EXEC
{
	virtual long func( void * arg );

}ITH_ADMIN;

typedef class _ITH_NWORK : public _ITH_EXEC
{
	virtual long func( void * arg );

}ITH_NWORK;

typedef class _ITH_PFKEY : public _ITH_EXEC
{
	virtual long func( void * arg );

}ITH_PFKEY;

typedef class _IKED
{
	friend class _ITH_ADMIN;
	friend class _ITH_NWORK;
	friend class _ITH_PFKEY;

	friend class _IDB_PEER;
	friend class _IDB_POLICY;
	friend class _IDB_TUNNEL;
	friend class _IDB_XCH;
	friend class _IDB_PH1;
	friend class _IDB_PH2;
	friend class _IDB_CFG;
	friend class _IDB_INF;

	friend class _ITH_EVENT_RESEND;

	friend class _ITH_EVENT_PH1DPD;
	friend class _ITH_EVENT_PH1NATT;
	friend class _ITH_EVENT_PH1HARD;

	friend class _ITH_EVENT_PH2SOFT;
	friend class _ITH_EVENT_PH2HARD;

	friend class _IKED_XAUTH_SYSTEM;
	friend class _IKED_XAUTH_LDAP;

	friend class _IKED_XCONF;
	friend class _IKED_XCONF_LOCAL;

#ifdef UNIX

	friend class yy::conf_parser;

#endif

	private:

	char	path_ins[ MAX_PATH ];	// install path
	char	path_log[ MAX_PATH ];	// logfile path
	char	path_ike[ MAX_PATH ];	// debug output path
	char	path_pub[ MAX_PATH ];	// debug output path

	long	level;				// logfile level

	long	state;				// daemon run state
	long	refcount;			// reference count
	long	tunnelid;			// next tunnel id
	short	policyid;			// next request id

	long	retry_count;		// packet retry count
	long	retry_delay;		// packet retry delay
	
	PFKI		pfki;			// pfkey interface
	IKES		ikes;			// ike service interface
	IPROUTE		iproute;		// ip route config interface
	IPFRAG		ipfrag;			// ip fragment handling interface

	ITH_ADMIN	ith_admin;		// admin thread
	ITH_NWORK	ith_nwork;		// network thread
	ITH_PFKEY	ith_pfkey;		// pfkey thread

	ITH_TIMER	ith_timer;		// execution timer

	short	ident;				// ip identity

	LIST	list_socket;		// socket list
	LIST	list_netgrp;		// net groups list
	LIST	list_peer;			// ipsec peer list
	LIST	list_tunnel;		// ipsec tunnel list
	LIST	list_policy;		// ipsec policy list
	LIST	list_phase1;		// phase 1 exchanges
	LIST	list_phase2;		// phase 2 exchanges
	LIST	list_config;		// config exchanges

	long	sock_ike_open;
	long	sock_natt_open;

	bool	conf_fail;

	// known vendor ids

	BDATA	vend_xauth;
	BDATA	vend_unity;
	BDATA	vend_frag;
	BDATA	vend_natt_v02;
	BDATA	vend_natt_rfc;
	BDATA	vend_dpd1;
	BDATA	vend_kame;

	long	dump_ike;			// packet dump decoded traffic
	long	dump_pub;			// packet dump encoded traffic

	PCAP_DUMP	pcap_ike;
	PCAP_DUMP	pcap_pub;
	PCAP_DUMP	pcap_frg;
	PCAP_DUMP	pcap_prv;

	// locking functions

	ITH_LOCK	lock_sdb;
	ITH_LOCK	lock_net;

	// xauth and xconf classes

	_IKED_XAUTH_LOCAL	xauth_local;
	_IKED_XCONF_LOCAL	xconf_local;

#ifdef OPT_LDAP
	IKED_XAUTH_LDAP		xauth_ldap;
#endif

	// id name helper functions

	char *	find_name( long type, long id );

	// random helper functions

	bool	rand_bytes( void * buff, long size );

	// network helper functions

	long	socket_init();
	void	socket_done();
	long	socket_create( IKE_SADDR & saddr, bool encap );
	long	socket_locate( IKE_SADDR & saddr );
	long	socket_select( unsigned long timeout );

	long	header( PACKET_IP & packet, ETH_HEADER & ethhdr );
	long	recv_ip( PACKET_IP & packet, ETH_HEADER * ethhdr = NULL );
	long	send_ip( PACKET_IP & packet, ETH_HEADER * ethhdr = NULL );

	bool	vnet_init();
	bool	vnet_get( VNET_ADAPTER ** adapter );
	bool	vnet_rel( VNET_ADAPTER * adapter );
	bool	vnet_set( VNET_ADAPTER * adapter, bool enable );
	bool	vnet_setup(	VNET_ADAPTER * adapter, IKE_XCONF & xconf );

	void	text_addr( char * text, in_addr & addr );
	void	text_mask( char * text, in_addr & addr );
	void	text_addr( char * text, sockaddr * saddr, bool port );
	void	text_addr( char * text, IKE_SADDR * iaddr, bool port );
	void	text_addr( char * text, PFKI_ADDR * paddr, bool port, bool netmask );

	void	text_ph1id( char * text, IKE_PH1ID * ph1id );
	void	text_ph2id( char * text, IKE_PH2ID * ph2id );

	bool	find_addr_r( sockaddr_in & raddr, unsigned short rport, char * rname );
	bool	find_addr_l( IKE_SADDR & saddr_r, IKE_SADDR & addr_l, unsigned short lport );

	// config file loader

	bool	conf_load( char * path, bool trace = false );

	// x.509 certificate helper functions

	bool	cert_2_bdata( BDATA & cert, X509 * x509 );
	bool	bdata_2_cert( X509 ** x509, BDATA & cert );

	void	load_path( char * file, char * fpath );

	long	cert_load_pem( BDATA & cert, char * file, bool ca, BDATA & pass );
	long	cert_load_p12( BDATA & cert, char * file, bool ca, BDATA & pass );
	long	cert_save( char * file, BDATA & cert );
	bool	cert_desc( BDATA & cert, BDATA & text );
	bool	cert_subj( BDATA & cert, BDATA & subj );
	bool	asn1_text( BDATA & asn1, BDATA & text );
	bool	text_asn1( BDATA & text, BDATA & asn1 );
	bool	cert_verify( BDATA & cert, BDATA & ca );

	long	prvkey_rsa_load_pem( char * file, EVP_PKEY ** evp_pkey, BDATA & pass );
	long	prvkey_rsa_load_p12( char * file, EVP_PKEY ** evp_pkey, BDATA & pass );
	bool	pubkey_rsa_read( BDATA & cert, EVP_PKEY ** evp_pkey );
	bool	prvkey_rsa_encrypt( EVP_PKEY * evp_pkey, BDATA & data );
	bool	pubkey_rsa_decrypt( EVP_PKEY * evp_pkey, BDATA & sign );

	// id helper functions

	bool	gen_ph1id_l( IDB_PH1 * ph1, IKE_PH1ID & ph1id );
	bool	gen_ph1id_r( IDB_PH1 * ph1, IKE_PH1ID & ph1id );

	bool	cmp_ph1id( IKE_PH1ID & idt, IKE_PH1ID & ids, bool natt );
	bool	cmp_ph2id( IKE_PH2ID & idt, IKE_PH2ID & ids, bool exact );

	// ike security db functions

	bool	get_peer( bool lock, IDB_PEER ** peer, IKE_SADDR * saddr );
	bool	get_policy( bool lock, IDB_POLICY ** policy, long dir, u_int16_t type, u_int32_t * plcyid, IKE_SADDR * src, IKE_SADDR * dst, IKE_PH2ID * ids, IKE_PH2ID * idd );
	bool	get_tunnel( bool lock, IDB_TUNNEL ** tunnel, long * tunnelid, IKE_SADDR * saddr, bool port );
	bool	get_phase1( bool lock, IDB_PH1 ** ph1, IDB_TUNNEL * tunnel, long state, long nostate, IKE_COOKIES * cookies );
	bool	get_phase2( bool lock, IDB_PH2 ** ph2, IDB_TUNNEL * tunnel, long state, long nostate, u_int32_t * seqid, uint32_t * msgid, IKE_SPI * spi_l, IKE_SPI * spi_r );
	bool	get_config( bool lock, IDB_CFG ** cfg, IDB_TUNNEL * tunnel, unsigned long msgid );

	// ike packet handler functions

	long	packet_ike_encap( PACKET_IKE & packet_ike, PACKET_IP & packet_ip, IKE_SADDR & src, IKE_SADDR & dst, long natt );
	long	packet_ike_send( IDB_PH1 * ph1, IDB_XCH * xch, PACKET_IKE & packet, bool retry );
	long	packet_ike_xmit( IDB_PH1 * ph1, IDB_XCH * xch, PACKET_IKE & packet, bool retry );
	long	packet_ike_encrypt( IDB_PH1 * ph1, PACKET_IKE & packet, BDATA * iv );
	long	packet_ike_decrypt( IDB_PH1 * ph1, PACKET_IKE & packet, BDATA * iv );

	// ike exchange handler functions

	long	process_phase1_recv( IDB_PH1 * ph1, PACKET_IKE & packet, unsigned char payload );
	long	process_phase1_send( IDB_PH1 * ph1 );

	long	process_phase2_recv( IDB_PH1 * ph1, PACKET_IKE & packet, unsigned char payload );
	long	process_phase2_send( IDB_PH1 * ph1, IDB_PH2 * ph2 );

	long	process_config_recv( IDB_PH1 * ph1, PACKET_IKE & packet, unsigned char payload );
	long	process_config_send( IDB_PH1 * ph1, IDB_CFG * cfg );

	long	process_inform_recv( IDB_PH1 * ph1, PACKET_IKE & packet, unsigned char payload );
	long	process_inform_send( IDB_PH1 * ph1, IDB_XCH * inform );

	// policy helper functions

	bool	policy_get_addrs( PFKI_SPINFO * spinfo, IKE_SADDR & src, IKE_SADDR & dst );
	bool	policy_cmp_prots( PFKI_SPINFO * spinfo1, PFKI_SPINFO * spinfo2 );

	bool	policy_list_create( IDB_TUNNEL * tunnel, bool initiator );
	bool	policy_list_remove( IDB_TUNNEL * tunnel, bool initiator );

	bool	policy_create( IDB_TUNNEL * tunnel, u_int16_t type, IKE_PH2ID & id1, IKE_PH2ID & id2 );
	bool	policy_remove( IDB_TUNNEL * tunnel, u_int16_t type, IKE_PH2ID & id1, IKE_PH2ID & id2 );

	// proposal helper functions

	long	phase1_gen_prop( IDB_PH1 * ph1 );
	long	phase1_sel_prop( IDB_PH1 * ph1 );
	bool	phase1_cmp_prop( IKE_PROPOSAL * proposal1, IKE_PROPOSAL * proposal2, bool initiator, long life_check );

	long	phase2_gen_prop( IDB_PH2 * ph2, IDB_POLICY * policy );
	long	phase2_sel_prop( IDB_PH2 * ph2 );
	bool	phase2_cmp_prop( IKE_PROPOSAL * proposal1, IKE_PROPOSAL * proposal2, bool initiator, long life_check );

	// phase1 exchange helper functions

	long	phase1_gen_keys( IDB_PH1 * ph1 );
	long	phase1_gen_hash_i( IDB_PH1 * ph1, BDATA & hash );
	long	phase1_gen_hash_r( IDB_PH1 * ph1, BDATA & hash );
	bool	phase1_chk_port( IDB_PH1 * ph1, IKE_SADDR * saddr_r, IKE_SADDR * saddr_l );
	long	phase1_add_vend( IDB_PH1 * ph1, PACKET_IKE & packet );
	long	phase1_chk_vend( IDB_PH1 * ph1, BDATA & vend );
	long	phase1_chk_hash( IDB_PH1 * ph1 );
	long	phase1_chk_sign( IDB_PH1 * ph1 );
	long	phase1_gen_natd( IDB_PH1 * ph1 );
	bool	phase1_chk_natd( IDB_PH1 * ph1 );
	long	phase1_chk_idr( IDB_PH1 * ph1 );

	// phase2 exchange helper functions

	long	phase2_gen_hash_i( IDB_PH1 * ph1, IDB_PH2 * ph2, BDATA & hash );
	long	phase2_gen_hash_r( IDB_PH1 * ph1, IDB_PH2 * ph2, BDATA & hash );
	long	phase2_gen_hash_p( IDB_PH1 * ph1, IDB_PH2 * ph2, BDATA & hash );
	long	phase2_chk_hash_i( IDB_PH1 * ph1, IDB_PH2 * ph2 );
	long	phase2_chk_hash_r( IDB_PH1 * ph1, IDB_PH2 * ph2 );
	long	phase2_chk_hash_p( IDB_PH1 * ph1, IDB_PH2 * ph2 );
	long	phase2_chk_params( IDB_PH1 * ph1, IDB_PH2 * ph2, PACKET_IKE & packet );
	long	phase2_gen_keys( IDB_PH1 * ph1, IDB_PH2 * ph2 );
	long	phase2_gen_keys( IDB_PH1 * ph1, IDB_PH2 * ph2, long dir, IKE_PROPOSAL * proposal, BDATA & shared );
	long	phase2_gen_iv( IDB_PH1 * ph1, unsigned long msgid, BDATA & iv );

	// config exchange helper functions

	long	config_xconf_set( IDB_CFG * cfg, long & setmask, long nullmask );
	long	config_xconf_get( IDB_CFG * cfg, long & getmask, long readmask );

	long	config_chk_hash( IDB_PH1 * ph1, IDB_CFG * cfg, unsigned long msgid );
	long	config_message_send( IDB_PH1 * ph1, IDB_CFG * cfg );

	// informational exchange helper functions

	long	inform_get_spi( char * text, IDB_PH1 * ph1, IKE_NOTIFY * notify );
	long	inform_chk_hash( IDB_PH1 * ph1, IDB_XCH * inform );
	long	inform_gen_hash( IDB_PH1 * ph1, IDB_XCH * inform );
	long	inform_chk_notify( IDB_PH1 * ph1, IKE_NOTIFY * notify, bool secure );
	long	inform_chk_delete( IDB_PH1 * ph1, IKE_NOTIFY * notify, bool secure );
	long	inform_new_notify( IDB_PH1 * ph1, IDB_PH2 * ph2, unsigned short code, BDATA * data = NULL );
	long	inform_new_delete( IDB_PH1 * ph1, IDB_PH2 * ph2 );
	long	inform_gen_iv( IDB_PH1 * ph1, unsigned long msgid, BDATA & iv );

	//
	// isakmp payload handler functions
	//

	long	payload_add_frag( PACKET_IKE & packet, unsigned char & index, unsigned char * data, long & size, long max );
	long	payload_get_frag( PACKET_IKE & packet, IDB_PH1 * ph1, bool & complete );

	long	payload_add_attr( PACKET_IKE & packet, IKE_ATTR & attrib  );
	long	payload_get_attr( PACKET_IKE & packet, IKE_ATTR & attrib );

	long	payload_add_sa( PACKET_IKE & packet, IKE_PLIST & plist, uint8_t next );
	long	payload_get_sa( PACKET_IKE & packet, IKE_PLIST & plist );

	long	payload_add_xform( PACKET_IKE & packet, IKE_PROPOSAL * proposal, uint8_t next );
	long	payload_get_xform( PACKET_IKE & packet, IKE_PROPOSAL * proposal );

	long	payload_add_kex( PACKET_IKE & packet, BDATA & gx, uint8_t next );
	long	payload_get_kex( PACKET_IKE & packet, BDATA & gx );

	long	payload_add_nonce( PACKET_IKE & packet, BDATA & nonce, uint8_t next );
	long	payload_get_nonce( PACKET_IKE & packet, BDATA & nonce );

	long	payload_add_ph1id( PACKET_IKE & packet, IKE_PH1ID & ph1id, uint8_t next );
	long	payload_get_ph1id( PACKET_IKE & packet, IKE_PH1ID & ph1id );

	long	payload_add_ph2id( PACKET_IKE & packet, IKE_PH2ID & ph2id, uint8_t next );
	long	payload_get_ph2id( PACKET_IKE & packet, IKE_PH2ID & ph2id );

	long	payload_add_hash( PACKET_IKE & packet, BDATA & hash, uint8_t next );
	long	payload_get_hash( PACKET_IKE & packet, BDATA & hash, long size );

	long	payload_add_cert( PACKET_IKE & packet, uint8_t type, BDATA & cert, uint8_t next );
	long	payload_get_cert( PACKET_IKE & packet, uint8_t & type, BDATA & cert );

	long	payload_add_creq( PACKET_IKE & packet, uint8_t type, uint8_t next );
	long	payload_get_creq( PACKET_IKE & packet, uint8_t & type );

	long	payload_add_sign( PACKET_IKE & packet, BDATA & sign, uint8_t next );
	long	payload_get_sign( PACKET_IKE & packet, BDATA & sign );

	long	payload_add_vend( PACKET_IKE & packet, BDATA & vend, uint8_t next );
	long	payload_get_vend( PACKET_IKE & packet, BDATA & vend );

	long	payload_add_cfglist( PACKET_IKE & packet, IDB_CFG * cfg, uint8_t next );
	long	payload_get_cfglist( PACKET_IKE & packet, IDB_CFG * cfg );

	long	payload_add_natd( PACKET_IKE & packet, BDATA & natd, uint8_t next );
	long	payload_get_natd( PACKET_IKE & packet, BDATA & natd, long size );

	long	payload_add_notify( PACKET_IKE & packet, IKE_NOTIFY * notify, uint8_t next );
	long	payload_get_notify( PACKET_IKE & packet, IKE_NOTIFY * notify );

	long	payload_add_delete( PACKET_IKE & packet, IKE_NOTIFY * notify, uint8_t next );
	long	payload_get_delete( PACKET_IKE & packet, IKE_NOTIFY * notify );

	//
	// main ike process handlers
	//

	long	process_ike_send();
	long	process_ike_recv( PACKET_IKE & packet, IKE_SADDR & saddr_src, IKE_SADDR & saddr_dst );

	//
	// pfkey process handlers
	//

	bool	paddr_ph2id( PFKI_ADDR & paddr, IKE_PH2ID & ph2id );
	bool	ph2id_paddr( IKE_PH2ID & ph2id, PFKI_ADDR & paddr );

	long	pfkey_recv_spinfo( PFKI_MSG & msg );
	long	pfkey_recv_acquire( PFKI_MSG & msg );
	long	pfkey_recv_getspi( PFKI_MSG & msg );
	long	pfkey_recv_spdel( PFKI_MSG & msg );

	long	pfkey_send_getspi( IDB_POLICY * policy, IDB_PH2 * ph2 );
	long	pfkey_send_update( IDB_PH2 * ph2, IKE_PROPOSAL * proposal, BDATA & ekey, BDATA & akey, long dir );
	long	pfkey_send_delete( IDB_PH2 * ph2 );
	long	pfkey_send_spadd( PFKI_SPINFO * spinfo );
	long	pfkey_send_spdel( PFKI_SPINFO * spinfo );

	//
	// admiministrative interface handlers
	//

	void	attach_ike_admin();

	//
	// execution thread loops
	//

	long	loop_ike_admin( IKEI * ikei );
	long	loop_ike_nwork();
	long	loop_ike_pfkey();

	public:

	_IKED();
	~_IKED();

	LOG	log;	// generic log object

	long	init( long setlevel );
	long	halt();
	void	loop();

}IKED;

//
// global iked object
//

extern IKED iked;

//
// generic utility classes and functions
//

bool cmp_ikeaddr( IKE_SADDR & addr1, IKE_SADDR & addr2, bool port );

bool has_sockaddr( sockaddr * saddr1 );
bool cmp_sockaddr( sockaddr & saddr1, sockaddr & saddr2, bool port );
bool cpy_sockaddr( sockaddr & saddr1, sockaddr & saddr2, bool port );
bool get_sockport( sockaddr & saddr, u_int16_t & port );
bool set_sockport( sockaddr & saddr, u_int16_t port );

#endif
