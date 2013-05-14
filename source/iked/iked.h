
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
#  include <sys/ioctl.h>
#  include <linux/if.h>
#  include <linux/if_tun.h>
#  include <linux/if_ether.h>
# else
#  include <signal.h>
#  include <pwd.h>
#  include <grp.h>
#  include <netdb.h>
#  include <sys/ioctl.h>
#  include <sys/param.h>
#  include <sys/socket.h>
#  include <net/if.h>
#  ifndef __APPLE__
#   include <net/if_tap.h>
#  else
#   include <sys/sysctl.h>
#   include "compat/tun_ioctls.h"
#  endif
# endif
# ifdef __FreeBSD__
#  include <sys/linker.h>
# endif
# include "compat/winstring.h"
# ifndef SOCKET
#  define SOCKET int
# endif
# ifndef INVALID_SOCKET
#  define INVALID_SOCKET -1
# endif
#endif

#ifdef OPT_LDAP
# include <ldap.h>
#endif

#include "version.h"
#include "libip.h"
#include "liblog.h"
#include "libith.h"
#include "libpfk.h"
#include "libike.h"
#include "libidb.h"
#include "crypto.h"
#include "ike.h"
#include "iked.idb.h"
#include "xauth.h"
#include "xconf.h"

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

#ifndef PATH_CONF
#define PATH_CONF		"/etc/iked.conf"
#endif

#ifdef __linux__
#define SET_SALEN( A, B )
#else
#define SET_SALEN( A, B ) ((sockaddr*)(A))->sa_len = B
#endif

#define PATH_DEBUG		"/var/log"
#define MAX_PATH		1024

namespace yy{ class conf_parser; };

#endif

//
// IKED constants
//

// Netscreen-01 299ee8289f40a8973bc78687e2e7226b532c3b76
// Netscreen-02 3a15e1f3cf2a63582e3ac82d1c64cbe3b6d779e7
// Netscreen-03 47d2b126bfcd83489760e2cf8c5d4d5a03497c15
// Netscreen-04 4a4340b543e02b84c88a8b96a8af9ebe77d9accc
// Netscreen-05 64405f46f03b7660a23be116a1975058e69e8387
// Netscreen-06 699369228741c6d4ca094c93e242c9de19e7b7c6
// Netscreen-07 8c0dc6cf62a0ef1b5c6eabd1b67ba69866adf16a
// Netscreen-08 92d27a9ecb31d99246986d3453d0c3d57a222a61
// Netscreen-09 9b096d9ac3275a7d6fe8b91c583111b09efed1a0
// Netscreen-10 bf03746108d746c904f1f3547de24f78479fed12
// Netscreen-11 c2e80500f4cc5fbf5daaeed3bb59abaeee56c652
// Netscreen-12 c8660a62b03b1b6130bf781608d32a6a8d0fb89f
// Netscreen-13 f885da40b1e7a9abd17655ec5bbec0f21f0ed52e
// Netscreen-14 2a2bcac19b8e91b426107807e02e7249569d6fd3
// Netscreen-15 166f932d55eb64d8e4df4fd37e2313f0d0fd8451
// Netscreen-16 a35bfd05ca1ac0b3d2f24e9e82bfcbff9c9e52b5

#define	VEND_XAUTH		{ 0x09, 0x00, 0x26, 0x89, 0xDF, 0xD6, 0xB7, 0x12 }
#define VEND_FRAG		{ 0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7, 0xde, 0x7f, 0x00, 0xd6, 0xc2, 0xd3, 0x80, 0x00, 0x00, 0x00 }
#define VEND_DPD1		{ 0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00 }
#define	VEND_DPD1_NG	{ 0x3b, 0x90, 0x31, 0xdc, 0xe4, 0xfc, 0xf8, 0x8b, 0x48, 0x9a, 0x92, 0x39, 0x63, 0xdd, 0x0c, 0x49 }
#define VEND_HBEAT		{ 0x48, 0x65, 0x61, 0x72, 0x74, 0x42, 0x65, 0x61, 0x74, 0x5f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x38, 0x6b, 0x01, 0x00 }
#define	VEND_NATT_V00	{ 0x44, 0x85, 0x15, 0x2d, 0x18, 0xb6, 0xbb, 0xcd, 0x0b, 0xe8, 0xa8, 0x46, 0x95, 0x79, 0xdd, 0xcc }
#define	VEND_NATT_V01	{ 0x16, 0xf6, 0xca, 0x16, 0xe4, 0xa4, 0x06, 0x6d, 0x83, 0x82, 0x1a, 0x0f, 0x0a, 0xea, 0xa8, 0x62 }
#define	VEND_NATT_V02	{ 0x90, 0xcb, 0x80, 0x91, 0x3e, 0xbb, 0x69, 0x6e, 0x08, 0x63, 0x81, 0xb5, 0xec, 0x42, 0x7b, 0x1f }
#define VEND_NATT_V03	{ 0x7d, 0x94, 0x19, 0xa6, 0x53, 0x10, 0xca, 0x6f, 0x2c, 0x17, 0x9d, 0x92, 0x15, 0x52, 0x9d, 0x56 }
#define	VEND_NATT_RFC	{ 0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f }

#define VEND_SSOFT		{ 0xf1, 0x4b, 0x94, 0xb7, 0xbf, 0xf1, 0xfe, 0xf0, 0x27, 0x73, 0xb8, 0xc4, 0x9f, 0xed, 0xed, 0x26 }
#define VEND_KAME		{ 0x70, 0x03, 0xcb, 0xc1, 0x09, 0x7d, 0xbe, 0x9c, 0x26, 0x00, 0xba, 0x69, 0x83, 0xbc, 0x8b, 0x35 }
#define	VEND_UNITY		{ 0x12, 0xf5, 0xf2, 0x8c, 0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc }
#define VEND_NETSC		{ 0x16, 0x6f, 0x93, 0x2d, 0x55, 0xeb, 0x64, 0xd8, 0xe4, 0xdf, 0x4f, 0xd3, 0x7e, 0x23, 0x13, 0xf0, 0xd0, 0xfd, 0x84, 0x51 }
#define VEND_ZWALL		{ 0x62, 0x50, 0x27, 0x74, 0x9d, 0x5a, 0xb9, 0x7f, 0x56, 0x16, 0xc1, 0x60, 0x27, 0x65, 0xcf, 0x48, 0x0a, 0x3b, 0x7d, 0x0b }
#define VEND_SWIND		{ 0x84, 0x04, 0xad, 0xf9, 0xcd, 0xa0, 0x57, 0x60, 0xb2, 0xca, 0x29, 0x2e, 0x4b, 0xff, 0x53, 0x7b }
#define VEND_SWALL		{ 0x40, 0x4B, 0xF4, 0x39, 0x52, 0x2C, 0xA3, 0xF6 }
#define VEND_CHKPT		{ 0xf4, 0xed, 0x19, 0xe0, 0xc1, 0x14, 0xeb, 0x51, 0x6f, 0xaa, 0xac, 0x0e, 0xe3, 0x7d, 0xaf, 0x28, 0x07, 0xb4, 0x38, 0x1f }

#define UNITY_FWTYPE	{ 0x80, 0x01, 0x00, 0x01, 0x80, 0x02, 0x00, 0x01, 0x80, 0x03, 0x00, 0x02 };

#define LIBIKE_IKE_PORT			500		// default isakmp port
#define LIBIKE_NATT_PORT		4500	// default nat-t port

#define LIBIKE_MAX_TEXTPROT		5		// max text protocol length
#define LIBIKE_MAX_TEXTADDR		24		// max text address length
#define LIBIKE_MAX_TEXTPORT		6		// max text port length
#define LIBIKE_MAX_TEXTP1ID		256		// max text phase1 id length
#define LIBIKE_MAX_TEXTP2ID		64		// max text phase2 id length
#define LIBIKE_MAX_TEXTSPI		64		// max text phase2 id length
#define LIBIKE_MAX_VARID		512		// max variable id length
#define LIBIKE_MAX_DHGRP		1024	// max dh group size

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

#define XSTATE_SENT_SA			0x00000001
#define XSTATE_SENT_KE			0x00000002
#define XSTATE_SENT_NO			0x00000004
#define XSTATE_SENT_ID			0x00000008
#define XSTATE_SENT_CT			0x00000010
#define XSTATE_SENT_CR			0x00000020
#define XSTATE_SENT_SI			0x00000040
#define XSTATE_SENT_HA			0x00000080
#define XSTATE_RECV_SA			0x00000100
#define XSTATE_RECV_KE			0x00000200
#define XSTATE_RECV_NO			0x00000400
#define XSTATE_RECV_ID			0x00000800
#define XSTATE_RECV_SI			0x00001000
#define XSTATE_RECV_CT			0x00002000
#define XSTATE_RECV_CR			0x00004000
#define XSTATE_RECV_ND			0x00008000
#define XSTATE_RECV_IDL			0x00010000
#define XSTATE_RECV_IDR			0x00020000
#define XSTATE_RECV_HA			0x00040000
#define XSTATE_RECV_LP			0x00080000
#define XSTATE_SENT_LP			0x00100000

#define CSTATE_RECV_XUSER		0x00000001
#define CSTATE_SENT_XUSER		0x00000002
#define CSTATE_RECV_XPASS		0x00000004
#define CSTATE_SENT_XPASS		0x00000008
#define CSTATE_RECV_XRSLT		0x00000010
#define CSTATE_SENT_XRSLT		0x00000020
#define CSTATE_RECV_XCONF		0x00000040
#define CSTATE_SENT_XCONF		0x00000080
#define CSTATE_RECV_ACK			0x00000100
#define CSTATE_SENT_ACK			0x00000200
#define CSTATE_USE_PASSCODE		0x80000000

#define LSTATE_CHKPROP			0x00000001		// proposal verified
#define LSTATE_CHKHASH			0x00000002		// hash verified
#define LSTATE_CHKIDS			0x00000004		// identity verified
#define LSTATE_GENNATD			0x00000008		// natt discovery generated
#define LSTATE_HASKEYS			0x00000010		// keys generated
#define LSTATE_CLAIMLT			0x00000020		// claim reponder lifetime

#define TSTATE_NATT_FLOAT		0x00000001
#define TSTATE_INITIALIZED		0x00000002
#define TSTATE_VNET_CONFIG		0x00000004
#define TSTATE_VNET_ENABLE		0x00000008
#define TSTATE_POLICY_INIT		0x00000010

#define PFLAG_ROUTED			0x00000001
#define PFLAG_NAILED			0x00000002		// negotiate persistent SAs
#define PFLAG_INITIAL			0x00000004		// negotiate an initial SA

#define RLEVEL_DAEMON			2

#define FILE_OK					0
#define FILE_PATH				1
#define FILE_FAIL				2

//
// IKED main classes and structures
//

typedef class _IKED_EXEC : public _ITH_EXEC
{
	public:

	virtual long func( void * arg );
	virtual long iked_func( void * arg ) = 0;

}IKED_EXEC;

typedef class _ITH_IKES : public _IKED_EXEC
{
	virtual long iked_func( void * arg );

}ITH_IKES;

typedef class _ITH_IKEC : public _IKED_EXEC
{
	virtual long iked_func( void * arg );

}ITH_IKEC;

typedef class _ITH_NWORK : public _IKED_EXEC
{
	virtual long iked_func( void * arg );

}ITH_NWORK;

typedef class _ITH_PFKEY : public _IKED_EXEC
{
	virtual long iked_func( void * arg );

}ITH_PFKEY;

typedef class _IKED
{
	friend class _ITH_IKES;
	friend class _ITH_IKEC;
	friend class _ITH_NWORK;
	friend class _ITH_PFKEY;

	friend class _IDB_PEER;
	friend class _IDB_TUNNEL;
	friend class _IDB_POLICY;
	friend class _IDB_XCH;
	friend class _IDB_PH1;
	friend class _IDB_PH2;
	friend class _IDB_CFG;
	friend class _IDB_INF;

	friend class _IKED_RC_LIST;
	friend class _IDB_LIST_IKED;
	friend class _IDB_LIST_PEER;
	friend class _IDB_LIST_TUNNEL;
	friend class _IDB_LIST_POLICY;
	friend class _IDB_LIST_PH1;
	friend class _IDB_LIST_PH2;
	friend class _IDB_LIST_CFG;

	friend class _ITH_EVENT_TUNDHCP;
	friend class _ITH_EVENT_TUNDPD;
	friend class _ITH_EVENT_TUNNATT;
	friend class _ITH_EVENT_TUNSTATS;

	friend class _ITH_EVENT_RESEND;

	friend class _ITH_EVENT_PH1SOFT;
	friend class _ITH_EVENT_PH1HARD;
	friend class _ITH_EVENT_PH1DEAD;

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

	char	path_ins[ MAX_PATH ];		// install path
	char	path_conf[ MAX_PATH ];		// configuration file
	char	path_log[ MAX_PATH ];		// logfile path
	char	path_decrypt[ MAX_PATH ];	// decrypted pcap path
	char	path_encrypt[ MAX_PATH ];	// encrypted pcap path
	char	path_dhcp[ MAX_PATH ];		// dhcp seed
	
	long	level;				// logging level
	long	logflags;			// logging options

	long	peercount;			// peer reference count
	long	loopcount;			// loop reference count

	long	tunnelid;			// next tunnel id
	short	policyid;			// next request id
	long	dnsgrpid;			// next dns group id

	long	retry_count;		// packet retry count
	long	retry_delay;		// packet retry delay
	
	PFKI		pfki;			// pfkey interface
	IKES		ikes;			// ike service interface
	IPROUTE		iproute;		// ip route config interface
	IPFRAG		ipfrag;			// ip fragment handling interface

	ITH_IKES	ith_ikes;		// server ipc thread
	ITH_IKEC	ith_ikec;		// client ipc thread
	ITH_NWORK	ith_nwork;		// network thread
	ITH_PFKEY	ith_pfkey;		// pfkey thread

	ITH_TIMER	ith_timer;		// execution timer

	short	ident;				// ip identity

	ITH_COND	cond_idb;		// idb null reference condition
	ITH_COND	cond_run;		// daemon null reference condition

	ITH_LOCK	lock_run;
	ITH_LOCK	lock_net;
	ITH_LOCK	lock_idb;

#ifdef UNIX

	IDB_LIST	list_socket;		// socket list
	int			wake_socket[2];		// wakeup socket

#endif

	IDB_LIST			idb_list_netgrp;
	IDB_LIST_PEER		idb_list_peer;
	IDB_LIST_TUNNEL		idb_list_tunnel;
	IDB_LIST_POLICY		idb_list_policy;
	IDB_LIST_PH1		idb_list_ph1;
	IDB_LIST_PH2		idb_list_ph2;
	IDB_LIST_CFG		idb_list_cfg;

	long	sock_ike_open;
	long	sock_natt_open;

	bool	conf_fail;

	// known vendor ids

	BDATA	vend_xauth;
	BDATA	vend_frag;
	BDATA	vend_dpd1;
	BDATA	vend_dpd1_ng;
	BDATA	vend_hbeat;
	BDATA	vend_natt_v00;
	BDATA	vend_natt_v01;
	BDATA	vend_natt_v02;
	BDATA	vend_natt_v03;
	BDATA	vend_natt_rfc;

	BDATA	vend_ssoft;
	BDATA	vend_kame;
	BDATA	vend_unity;
	BDATA	vend_netsc;
	BDATA	vend_zwall;
	BDATA	vend_swind;
	BDATA	vend_chkpt;

	BDATA	unity_fwtype;

	long	dump_decrypt;		// packet dump decoded traffic
	long	dump_encrypt;		// packet dump encoded traffic

	PCAP_DUMP	pcap_decrypt;
	PCAP_DUMP	pcap_encrypt;

	// xauth and xconf classes

	_IKED_XAUTH_LOCAL	xauth_local;
	_IKED_XCONF_LOCAL	xconf_local;

	uint8_t	dhcp_seed[ 6 ];		// DHCP MAC seed value

#ifdef OPT_LDAP

	IKED_XAUTH_LDAP		xauth_ldap;

#endif

	// id name helper functions

	const char *	find_name( long type, long id );

	// random helper functions

	bool	rand_bytes( void * buff, long size );

	// network helper functions

	long	socket_init();
	void	socket_done();
	long	socket_create( IKE_SADDR & saddr, bool natt );
	void	socket_wakeup();
	long	socket_lookup_addr( IKE_SADDR & saddr_l, IKE_SADDR & saddr_r );
	long	socket_lookup_port( IKE_SADDR & saddr_l, bool natt );

#ifdef WIN32

	long	tunnel_filter_add( IDB_TUNNEL * tunnel, bool natt );
	long	tunnel_filter_del( IDB_TUNNEL * tunnel );

#endif

	long	header( PACKET_IP & packet, ETH_HEADER & ethhdr );
	long	recv_ip( PACKET_IP & packet, ETH_HEADER * ethhdr = NULL );
	long	send_ip( PACKET_IP & packet, ETH_HEADER * ethhdr = NULL );

	bool	vnet_init();
	bool	vnet_get( VNET_ADAPTER ** adapter );
	bool	vnet_rel( VNET_ADAPTER * adapter );

	bool	client_net_config( IDB_TUNNEL * tunnel );
	bool	client_net_revert( IDB_TUNNEL * tunnel );

	bool	client_dns_config( IDB_TUNNEL * tunnel );
	bool	client_dns_revert( IDB_TUNNEL * tunnel );

#ifdef OPT_DTP

	bool	dnsproxy_check( IKEI * ikei );
	bool	dnsproxy_setup( IDB_TUNNEL * tunnel );
	void	dnsproxy_cleanup( IDB_TUNNEL * tunnel );

#endif

	void	text_prot( char * text, int prot );
	void	text_addr( char * text, in_addr & addr );
	void	text_mask( char * text, in_addr & addr );
	void	text_port( char * text, int port );
	void	text_addr( char * text, sockaddr * saddr, bool port );
	void	text_addr( char * text, IKE_SADDR * iaddr, bool port );
	void	text_addr( char * text, PFKI_ADDR * paddr, bool port, bool netmask );

	void	text_ph1id( char * text, IKE_PH1ID * ph1id );
	void	text_ph2id( char * text, IKE_PH2ID * ph2id );

	// config file loader

	bool	conf_load( const char * path, bool trace = false );

	// x.509 certificate helper functions

	long	cert_load( BDATA & cert, char * fpath, bool ca, BDATA & pass );
	long	cert_load( BDATA & cert, BDATA & input, bool ca, BDATA & pass );
	bool	cert_desc( BDATA & cert, BDATA & text );
	bool	cert_subj( BDATA & cert, BDATA & subj );
	bool	asn1_text( BDATA & asn1, BDATA & text );
	bool	text_asn1( BDATA & text, BDATA & asn1 );
	bool	cert_verify( IDB_LIST_CERT & certs, BDATA & ca, BDATA & cert );

	long	prvkey_rsa_load( BDATA & prvkey, char * fpath, BDATA & pass );
	long	prvkey_rsa_load( BDATA & prvkey, BDATA & input, BDATA & pass );
	bool	pubkey_rsa_read( BDATA & cert, BDATA & pubkey );
	bool	prvkey_rsa_encrypt( BDATA & prvkey, BDATA & hash, BDATA & sign );
	bool	pubkey_rsa_decrypt( BDATA & pubkey, BDATA & sign, BDATA & hash );

	// id helper functions

	bool	gen_ph1id_l( IDB_PH1 * ph1, IKE_PH1ID & ph1id );
	bool	gen_ph1id_r( IDB_PH1 * ph1, IKE_PH1ID & ph1id );

	bool	cmp_ph1id( IKE_PH1ID & idt, IKE_PH1ID & ids, bool natt );
	bool	cmp_ph2id( IKE_PH2ID & idt, IKE_PH2ID & ids, bool exact );

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

	// dhcp over ipsec helper functions

	long	socket_dhcp_create( IDB_TUNNEL * tunnel );
	long	socket_dhcp_remove( IDB_TUNNEL * tunnel );

	long	socket_dhcp_send( IDB_TUNNEL * tunnel, PACKET & packet );
	long	socket_dhcp_recv( IDB_TUNNEL * tunnel, PACKET & packet );

	long	process_dhcp_send( IDB_TUNNEL * tunnel );
	long	process_dhcp_recv( IDB_TUNNEL * tunnel );

	// policy helper functions

	bool	policy_get_addrs( PFKI_SPINFO * spinfo, IKE_SADDR & src, IKE_SADDR & dst );
	bool	policy_cmp_prots( PFKI_SPINFO * spinfo1, PFKI_SPINFO * spinfo2 );

	bool	policy_dhcp_create( IDB_TUNNEL * tunnel );
	bool	policy_dhcp_remove( IDB_TUNNEL * tunnel );

	bool	policy_list_create( IDB_TUNNEL * tunnel, bool initiator );
	bool	policy_list_remove( IDB_TUNNEL * tunnel, bool initiator );

	bool	policy_create( IDB_TUNNEL * tunnel, u_int16_t type, u_int8_t level, IKE_PH2ID & id1, IKE_PH2ID & id2, bool route );
	bool	policy_remove( IDB_TUNNEL * tunnel, u_int16_t type, u_int8_t level, IKE_PH2ID & id1, IKE_PH2ID & id2, bool route );

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
	long	phase1_add_vend( IDB_PH1 * ph1, PACKET_IKE & packet, uint8_t next );
	long	phase1_chk_vend( IDB_PH1 * ph1, BDATA & vend );
	long	phase1_chk_hash( IDB_PH1 * ph1 );
	long	phase1_chk_sign( IDB_PH1 * ph1 );
	long	phase1_gen_natd( IDB_PH1 * ph1 );
	bool	phase1_add_natd( IDB_PH1 * ph1, PACKET_IKE & packet, uint8_t next );
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

	// config exchange helper functions

	bool	config_client_xauth_recv( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_client_xauth_send( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_client_xconf_pull_recv( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_client_xconf_pull_send( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_client_xconf_push_recv( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_client_xconf_push_send( IDB_CFG * cfg, IDB_PH1 * ph1 );

	bool	config_server_xauth_recv( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_server_xauth_send( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_server_xconf_pull_recv( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_server_xconf_pull_send( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_server_xconf_push_recv( IDB_CFG * cfg, IDB_PH1 * ph1 );
	bool	config_server_xconf_push_send( IDB_CFG * cfg, IDB_PH1 * ph1 );

	long	config_xconf_set( IDB_CFG * cfg, long setbits, long setmask, VENDOPTS vendopts );
	long	config_xconf_get( IDB_CFG * cfg, long & getbits, long getmask, VENDOPTS vendopts );

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

	long	payload_add_frag( PACKET_IKE & packet, unsigned char & index, unsigned char * data, size_t & size, size_t max );
	long	payload_get_frag( PACKET_IKE & packet, IDB_PH1 * ph1, bool & complete );

	long	payload_add_attr( PACKET_IKE & packet, IKE_ATTR & attrib  );
	long	payload_get_attr( PACKET_IKE & packet, IKE_ATTR & attrib );

	long	payload_add_sa( PACKET_IKE & packet, IDB_LIST_PROPOSAL & plist, uint8_t next );
	long	payload_get_sa( PACKET_IKE & packet, IDB_LIST_PROPOSAL & plist );

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
	long	payload_get_creq( PACKET_IKE & packet, uint8_t & type, BDATA & dn );

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

	long	pfkey_init_phase2( bool nail, u_int16_t plcytype, u_int32_t plcyid, u_int32_t seq );

	long	pfkey_recv_spadd( PFKI_MSG & msg );
	long	pfkey_recv_spnew( PFKI_MSG & msg );
	long	pfkey_recv_acquire( PFKI_MSG & msg );
	long	pfkey_recv_getspi( PFKI_MSG & msg );
	long	pfkey_recv_flush( PFKI_MSG & msg );
	long	pfkey_recv_spdel( PFKI_MSG & msg );
	long	pfkey_recv_spflush( PFKI_MSG & msg );

	long	pfkey_send_getspi( IDB_POLICY * policy, IDB_PH2 * ph2 );
	long	pfkey_send_update( IDB_PH2 * ph2, IKE_PROPOSAL * proposal, BDATA & ekey, BDATA & akey, long dir );
	long	pfkey_send_delete( IDB_PH2 * ph2 );
	long	pfkey_send_spadd( PFKI_SPINFO * spinfo );
	long	pfkey_send_spdel( PFKI_SPINFO * spinfo );

	//
	// execution thread loops
	//

	void	loop_ref_inc( const char * name );
	void	loop_ref_dec( const char * name );

	long	loop_ipc_server();
	long	loop_ipc_client( IKEI * ikei );

	long	loop_ike_nwork();
	long	loop_ike_pfkey();

	public:

	_IKED();
	~_IKED();

	LOG	log;	// generic log object

	void	set_files( char * set_path_conf, const char * set_path_log );

	long	init( long setlevel );
	long	halt( bool terminate );
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
