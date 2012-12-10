
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

#ifndef _IKE_H_
#define _IKE_H_

#include "libidb.h"
#include "inttypes.h"

#define CONF_STRLEN					256

//
// IPSEC DOI - RFC 2407
//

// ipsec situations

#define ISAKMP_SIT_IDENT_ONLY		0x1		// identity only
#define ISAKMP_SIT_SECRECY			0x2		// labled secrecy
#define ISAKMP_SIT_INTEGRITY		0x4		// labled integrity

// ipsec security protocols

#define	ISAKMP_PROTO_ISAKMP			1
#define	ISAKMP_PROTO_IPSEC_AH		2
#define	ISAKMP_PROTO_IPSEC_ESP		3
#define	ISAKMP_PROTO_IPCOMP			4

// ipsec isakmp transforms

#define ISAKMP_KEY_IKE				1

// ipsec ah transforms

#define ISAKMP_AH_MD5				2
#define ISAKMP_AH_SHA				3
#define ISAKMP_AH_DES				4
#define ISAKMP_AH_SHA256			5
#define ISAKMP_AH_SHA384			6
#define ISAKMP_AH_SHA512			7

// ipsec esp transforms

#define ISAKMP_ESP_DES_IV64			1
#define ISAKMP_ESP_DES				2
#define ISAKMP_ESP_3DES				3
#define ISAKMP_ESP_RC5				4
#define ISAKMP_ESP_IDEA				5
#define ISAKMP_ESP_CAST				6
#define ISAKMP_ESP_BLOWFISH			7
#define ISAKMP_ESP_3IDEA			8
#define ISAKMP_ESP_DES_IV32			9
#define ISAKMP_ESP_RC4				10
#define ISAKMP_ESP_NULL				11
#define ISAKMP_ESP_AES				12

// ipsec ipcomp transforms

#define ISAKMP_IPCOMP_NONE			0
#define ISAKMP_IPCOMP_OUI			1
#define ISAKMP_IPCOMP_DEFLATE		2
#define ISAKMP_IPCOMP_LZS			3

// ipsec sa attributes

#define ISAKMP_ATTR_LIFE_TYPE			1	// basic
#define ISAKMP_ATTR_LIFE_DURATION		2	// variable
#define ISAKMP_ATTR_GROUP_DESC			3	// basic
#define ISAKMP_ATTR_ENCAP_MODE			4	// basic
#define ISAKMP_ATTR_AUTH_ALGORITHM		5	// basic
#define ISAKMP_ATTR_KEY_LEGTH			6	// basic
#define ISAKMP_ATTR_KEY_ROUNDS			7	// basic
#define ISAKMP_ATTR_CMPR_DICT_SIZE		8	// basic
#define ISAKMP_ATTR_CMPR_ALGORITHM		9	// variable

// life type values

#define ISAKMP_LIFETYPE_SECONDS			1
#define ISAKMP_LIFETYPE_KBYTES			2

// encapsulation mode values

#define ISAKMP_ENCAP_TUNNEL					1
#define ISAKMP_ENCAP_TRANSPORT				2
#define ISAKMP_ENCAP_RFC_UDP_TUNNEL			3
#define ISAKMP_ENCAP_RFC_UDP_TRANSPORT		4
#define ISAKMP_ENCAP_VXX_UDP_TUNNEL			61443
#define ISAKMP_ENCAP_VXX_UDP_TRANSPORT		61444

// authentication algorithm values

#define ISAKMP_AUTH_HMAC_MD5			1
#define ISAKMP_AUTH_HMAC_SHA1			2
#define ISAKMP_AUTH_DES_MAC				3
#define ISAKMP_AUTH_KPDK				4
#define ISAKMP_AUTH_HMAC_SHA2_256		5
#define	ISAKMP_AUTH_HMAC_SHA2_384		6
#define	ISAKMP_AUTH_HMAC_SHA2_512		7

// identification types

#define ISAKMP_ID_NONE					0
#define ISAKMP_ID_IPV4_ADDR				1
#define ISAKMP_ID_FQDN					2
#define ISAKMP_ID_USER_FQDN				3
#define ISAKMP_ID_IPV4_ADDR_SUBNET		4
#define ISAKMP_ID_IPV6_ADDR				5
#define ISAKMP_ID_IPV6_ADDR_SUBNET		6
#define ISAKMP_ID_IPV4_ADDR_RANGE		7
#define ISAKMP_ID_IPV6_ADDR_RANGE		8
#define ISAKMP_ID_ASN1_DN				9
#define ISAKMP_ID_ASN1_GN				10
#define ISAKMP_ID_KEY_ID				11

//
// ISAKMP - RFC 2408
//

// version 1.0 values

#define ISAKMP_MAJOR					1
#define ISAKMP_MINOR					0
#define ISAKMP_VERSION					ISAKMP_MAJOR << 4 | ISAKMP_MINOR

// payload types

#define ISAKMP_PAYLOAD_NONE				0	// no more payloads
#define ISAKMP_PAYLOAD_SA				1	// security association
#define ISAKMP_PAYLOAD_PROPOSAL			2	// proposal
#define ISAKMP_PAYLOAD_TRANSFORM		3	// transform
#define ISAKMP_PAYLOAD_KEX				4	// key exchange
#define ISAKMP_PAYLOAD_IDENT			5	// identificaion
#define ISAKMP_PAYLOAD_CERT				6	// certificate
#define ISAKMP_PAYLOAD_CERT_REQ			7	// certificate request
#define ISAKMP_PAYLOAD_HASH				8	// hash
#define ISAKMP_PAYLOAD_SIGNATURE		9	// signature
#define ISAKMP_PAYLOAD_NONCE			10	// noonce
#define ISAKMP_PAYLOAD_NOTIFY			11	// notification
#define ISAKMP_PAYLOAD_DELETE			12	// delete
#define ISAKMP_PAYLOAD_VEND				13	// vendor id
#define ISAKMP_PAYLOAD_ATTRIB			14  // mode config attibutes
#define ISAKMP_PAYLOAD_NAT_RFC_DISC		20  // nat discovery
#define ISAKMP_PAYLOAD_NAT_RFC_ORIG		21  // nat original address
#define ISAKMP_PAYLOAD_NAT_VXX_DISC		130 // nat discovery
#define ISAKMP_PAYLOAD_NAT_VXX_ORIG		131 // nat original address
#define ISAKMP_PAYLOAD_FRAGMENT			132	// fragmentation payload

// exchange types

#define ISAKMP_EXCH_BASE				1	// base
#define ISAKMP_EXCH_IDENT_PROTECT		2	// identity protection ( main )
#define ISAKMP_EXCH_AUTHENTICATION		3	// authentication only
#define ISAKMP_EXCH_AGGRESSIVE			4	// aggressive mode
#define ISAKMP_EXCH_INFORMATIONAL		5	// informational
#define ISAKMP_EXCH_CONFIG				6	// isakmp config

// certificate types

#define ISAKMP_CERT_NONE			0
#define ISAKMP_CERT_PKCS7			1
#define ISAKMP_CERT_PGP				2
#define ISAKMP_CERT_DNS_SIGNED		3
#define ISAKMP_CERT_X509_SIG		4
#define ISAKMP_CERT_X509_KEX		5
#define ISAKMP_CERT_KERBEROS		6
#define ISAKMP_CERT_CRL				7
#define ISAKMP_CERT_ARL				8
#define ISAKMP_CERT_SPKI			9
#define ISAKMP_CERT_X509_ATTR		10
#define	ISAKMP_CERT_RSA_PLAIN		11

// isakmp doi types

#define ISAKMP_DOI_GENERIC			0
#define ISAKMP_DOI_IPSEC			1

// isakmp flags

#define ISAKMP_FLAGS_OFFSET			19

#define ISAKMP_FLAG_ENCRYPT			0x01	// payload is encrypted
#define ISAKMP_FLAG_COMMIT			0x02	// synchronous exchange
#define ISAKMP_FLAG_AUTH_ONLY		0x04	// authentication only

// notify types

#define ISAKMP_N_INVALID_PAYLOAD_TYPE			1
#define ISAKMP_N_DOI_NOT_SUPPORTED				2
#define ISAKMP_N_SITUATION_NOT_SUPPORTED		3
#define ISAKMP_N_INVALID_COOKIE					4
#define ISAKMP_N_INVALID_MAJOR_VERSION			5
#define ISAKMP_N_INVALID_MINOR_VERSION			6
#define ISAKMP_N_INVALID_EXCHANGE_TYPE			7
#define ISAKMP_N_INVALID_FLAGS					8
#define ISAKMP_N_INVALID_MESSAGE_ID				9
#define ISAKMP_N_INVALID_PROTOCOL_ID			10
#define ISAKMP_N_INVALID_SPI					11
#define ISAKMP_N_INVALID_TRANSFORM_ID			12
#define ISAKMP_N_ATTRIBUTES_NOT_SUPPORTED		13
#define ISAKMP_N_NO_PROPOSAL_CHOSEN				14
#define ISAKMP_N_BAD_PROPOSAL_SYNTAX			15
#define ISAKMP_N_PAYLOAD_MALFORMED				16
#define ISAKMP_N_INVALID_KEY_INFORMATION		17
#define ISAKMP_N_INVALID_ID_INFORMATION			18
#define ISAKMP_N_INVALID_CERT_ENCODING			19
#define ISAKMP_N_INVALID_CERTIFICATE			20
#define ISAKMP_N_CERT_TYPE_UNSUPPORTED			21
#define ISAKMP_N_INVALID_CERT_AUTHORITY			22
#define ISAKMP_N_INVALID_HASH_INFORMATION		23
#define ISAKMP_N_AUTHENTICATION_FAILED			24
#define ISAKMP_N_INVALID_SIGNATURE				25
#define ISAKMP_N_ADDRESS_NOTIFICATION			26
#define ISAKMP_N_NOTIFY_SA_LIFETIME				27
#define ISAKMP_N_CERTIFICATE_UNAVAILABLE		28
#define ISAKMP_N_UNSUPPORTED_EXCHANGE_TYPE		29
#define ISAKMP_N_UNEQUAL_PAYLOAD_LENGTHS		30

//
// IKE - RFC 2409
//

// echange types

#define ISAKMP_EXCH_QUICK					32		// quick
#define ISAKMP_EXCH_NEW_GROUP				33		// new group

// notification types

#define ISAKMP_N_RESPONDER_LIFETIME			24576
#define ISAKMP_N_REPLAY_STATUS				24577
#define ISAKMP_N_INITIAL_CONTACT			24578

//
// attribute types
//

#define BASIC						0x8000

#define IKE_ATTR_TRANSFORM			1	// basic
#define IKE_ATTR_HASH				2	// basic
#define IKE_ATTR_AUTH_METHOD		3	// basic
#define IKE_ATTR_GROUP_DESC			4	// basic
#define IKE_ATTR_GROUP_TYPE			5	// basic
#define IKE_ATTR_GROUP_PRIME		6	// variable
#define IKE_ATTR_GROUP_GENERATOR_1	7	// variable
#define IKE_ATTR_GROUP_GENERATOR_2	8	// variable
#define IKE_ATTR_GROUP_CURVE_A		9	// variable
#define IKE_ATTR_GROUP_CURVE_B		10	// variable
#define IKE_ATTR_LIFE_TYPE			11	// basic
#define IKE_ATTR_LIFE_DURATION		12	// variable
#define IKE_ATTR_PRF				13	// basic
#define IKE_ATTR_KEY_LENGTH			14	// basic
#define IKE_ATTR_FIELD_SIZE			15	// basic
#define IKE_ATTR_GROUP_ORDER		16	// variable

#define IKE_CIPHER_DES				1
#define IKE_CIPHER_IDEA				2
#define IKE_CIPHER_BLOWFISH			3
#define IKE_CIPHER_RC5_R16_B64		4
#define IKE_CIPHER_3DES				5
#define IKE_CIPHER_CAST				6
#define IKE_CIPHER_AES				7

#define IKE_HASH_MD5				1
#define IKE_HASH_SHA1				2
#define IKE_HASH_TIGER				3
#define	IKE_HASH_SHA2_256			4
#define IKE_HASH_SHA2_384			5
#define IKE_HASH_SHA2_512			6

#define IKE_AUTH_PRESHARED_KEY		1
#define IKE_AUTH_SIG_DSA			2
#define IKE_AUTH_SIG_RSA			3
#define IKE_AUTH_SIG_RSA_ENCRYPT	4
#define IKE_AUTH_SIG_RSA_REVISED	5

#define IKE_GRP_GROUP1				1	// oakley modp 768
#define IKE_GRP_GROUP2				2	// oakley modp 1024
#define IKE_GRP_GROUP3				3	// oakley ecn  155
#define IKE_GRP_GROUP4				4	// oakley ecn  185
#define IKE_GRP_GROUP5				5	// oakley modp 1536
#define IKE_GRP_GROUP14				14	// oakley modp 2048
#define IKE_GRP_GROUP15				15	// oakley modp 3072
#define IKE_GRP_GROUP16				16	// oakley modp 4096
#define IKE_GRP_GROUP17				17	// oakley modp 6144
#define IKE_GRP_GROUP18				18	// oakley modp 8192

#define IKE_GRP_TYPE_MODP			1
#define IKE_GRP_TYPE_ECP			2
#define IKE_GRP_TYPE_EC2N			3

#define IKE_LIFE_TYPE_SECONDS		1
#define IKE_LIFE_TYPE_KBYTES		2

//
// IKE protocol extensions
//

// ike fragmentation

#define IKE_FRAG_FLAG_LAST			0x01

// cisco high availability

#define ISAKMP_N_UNITY_LOAD_BALANCE	40501
#define ISAKMP_N_UNITY_GROUP_HASH	40503

// dead peer detection

#define ISAKMP_N_DPD_R_U_THERE		36136
#define ISAKMP_N_DPD_R_U_THERE_ACK	36137

// configuration exchange types

#define ISAKMP_CFG_REQUEST			1
#define ISAKMP_CFG_REPLY			2
#define ISAKMP_CFG_SET				3
#define ISAKMP_CFG_ACK				4

// configuration attributes

#define INTERNAL_IP4_ADDRESS		1	// variable   0 or 4 octets 
#define INTERNAL_IP4_NETMASK		2	// variable   0 or 4 octets
#define INTERNAL_IP4_DNS			3	// variable   0 or 4 octets
#define INTERNAL_IP4_NBNS			4	// variable   0 or 4 octets
#define INTERNAL_ADDRESS_EXPIRY		5	// variable   0 or 4 octets
#define INTERNAL_IP4_DHCP			6	// variable   0 or 4 octets
#define APPLICATION_VERSION			7	// variable   0 or more 
#define INTERNAL_IP6_ADDRESS		8	// variable   0 or 16 octets 
#define INTERNAL_IP6_NETMASK		9	// variable   0 or 16 octets 
#define INTERNAL_IP6_DNS			10	// variable   0 or 16 octets 
#define INTERNAL_IP6_NBNS			11	// variable   0 or 16 octets 
#define INTERNAL_IP6_DHCP			12	// variable   0 or 16 octets 
#define INTERNAL_IP4_SUBNET			13	// variable   0 or 8 octets 
#define SUPPORTED_ATTRIBUTES		14	// variable   0 or multiples of 2 
#define INTERNAL_IP6_SUBNET			15	// variable   0 or 17 octets

// extended authentication modes

#define XAUTH_AUTH_INIT_PSK			65001
#define XAUTH_AUTH_RESP_PSK			65002
#define XAUTH_AUTH_INIT_DSS			65003
#define XAUTH_AUTH_RESP_DSS			65004
#define XAUTH_AUTH_INIT_RSA			65005
#define XAUTH_AUTH_RESP_RSA			65006
#define XAUTH_AUTH_INIT_RSA_ENC		65007
#define XAUTH_AUTH_RESP_RSA_ENC		65008
#define XAUTH_AUTH_INIT_RSA_REV		65009
#define XAUTH_AUTH_RESP_RSA_REV		65010

// hybrid authentication modes

#define HYBRID_AUTH_INIT_RSA		64221
#define HYBRID_AUTH_RESP_RSA		64222
#define HYBRID_AUTH_INIT_DSS		64223
#define HYBRID_AUTH_RESP_DSS		64224

// extended authentication types

#define XAUTH_TYPE_GENERIC			0
#define XAUTH_TYPE_RADIUS_CHAP		1
#define XAUTH_TYPE_OTP				2
#define XAUTH_TYPE_SKEY				3

// extended authentication attributes

#define XAUTH_TYPE					16520	// basic
#define XAUTH_USER_NAME				16521	// variable
#define XAUTH_USER_PASSWORD			16522	// variable
#define XAUTH_PASSCODE				16523	// variable
#define XAUTH_MESSAGE				16524	// variable
#define XAUTH_CHALLENGE				16525	// variable
#define XAUTH_DOMAIN				16526	// variable
#define XAUTH_STATUS				16527	// basic
#define XAUTH_NEXT_PIN				16528	// variable
#define XAUTH_ANSWER				16529	// variable

// unity configuration attributes

#ifdef WIN32
#define UNITY_APP_VERSION_STRING	"Cisco Systems VPN Client 4.8.01.0300:WinNT"
#else
#define UNITY_APP_VERSION_STRING	"Cisco Systems VPN Client 4.8.01 (0640):Linux"
#endif

#define UNITY_BANNER				28672	// variable
#define UNITY_SAVE_PASSWD			28673	// basic
#define UNITY_DEF_DOMAIN			28674	// variable
#define UNITY_SPLIT_DOMAIN			28675	// variable
#define UNITY_SPLIT_INCLUDE			28676	// variable
#define UNITY_NATT_PORT				28677	// basic
#define UNITY_SPLIT_EXCLUDE			28678	// variable
#define UNITY_PFS					28679	// basic
#define UNITY_FW_TYPE				28680	// variable
#define UNITY_BACKUP_SERVERS		28681	// variable
#define UNITY_DDNS_HOSTNAME			28682	// variable

// checkpoint extended authentication attributes

#define	CHKPT_TYPE					13
#define CHKPT_USER_NAME				14
#define CHKPT_USER_PASSWORD			15
#define CHKPT_MESSAGE				17
#define CHKPT_CHALLENGE				18
#define CHKPT_STATUS				20

// checkpoint configuration attributes

#define CHKPT_DEF_DOMAIN			16387
#define CHKPT_MAC_ADDRESS			16388
#define CHKPT_MARCIPAN_REASON_CODE	16389
#define CHKPT_UNKNOWN1				16400
#define CHKPT_UNKNOWN2				16401
#define CHKPT_UNKNOWN3				16402

//
// implementation specific constants
//

#define ISAKMP_COOKIE_SIZE				8
#define ISAKMP_SPI_SIZE					4
#define ISAKMP_CPI_SIZE					2
#define ISAKMP_NONCE_SIZE				20
#define ISAKMP_NONCE_MIN				4
#define ISAKMP_NONCE_MAX				252

#define ISAKMP_CERT_MAX					( 1024 * 32 )
#define ISAKMP_CREQ_MAX					( 1024 * 4 )
#define ISAKMP_SIGN_MAX					( 1024 * 4 )

//
// ipsec config constants
//

#define	IPSEC_CONTACT_SERVER	1
#define	IPSEC_CONTACT_CLIENT	2
#define	IPSEC_CONTACT_INIT		3
#define	IPSEC_CONTACT_RESP		4
#define	IPSEC_CONTACT_BOTH		5

#define IPSEC_NATT_DISABLE		0
#define IPSEC_NATT_ENABLE		1
#define IPSEC_NATT_FORCE_DRAFT	2
#define IPSEC_NATT_FORCE_RFC	3
#define IPSEC_NATT_FORCE_CISCO	4

#define IPSEC_FRAG_DISABLE		0
#define IPSEC_FRAG_ENABLE		1
#define IPSEC_FRAG_FORCE		2

#define IPSEC_DPD_DISABLE		0
#define IPSEC_DPD_ENABLE		1
#define IPSEC_DPD_FORCE			2

#define IPSEC_NATT_NONE			0
#define IPSEC_NATT_CISCO		1
#define IPSEC_NATT_V00			2
#define IPSEC_NATT_V01			3
#define IPSEC_NATT_V02			4
#define IPSEC_NATT_V03			5
#define IPSEC_NATT_RFC			255

#define IPSEC_OPTS_SPLITNET		0x0001
#define IPSEC_OPTS_BANNER		0x0002
#define IPSEC_OPTS_PFS			0x0004
#define IPSEC_OPTS_ADDR			0x0008
#define IPSEC_OPTS_MASK			0x0010
#define IPSEC_OPTS_NBNS			0x0020
#define IPSEC_OPTS_DNSS			0x0040
#define IPSEC_OPTS_DOMAIN		0x0080
#define IPSEC_OPTS_SPLITDNS		0x0100
#define IPSEC_OPTS_SAVEPW		0x0200
#define IPSEC_OPTS_CISCO_UDP	0x0400
#define IPSEC_OPTS_CISCO_GRP	0x0800
#define IPSEC_OPTS_VEND_CHKPT	0x1000

#define IPSEC_DNSS_MAX			8
#define IPSEC_NBNS_MAX			4

#define CONFIG_MODE_NONE		0
#define CONFIG_MODE_PULL		1
#define CONFIG_MODE_PUSH		2
#define CONFIG_MODE_DHCP		3

#define POLICY_MODE_DISABLE		0
#define POLICY_MODE_COMPAT		1
#define POLICY_MODE_CONFIG		2

#define POLICY_LEVEL_AUTO		0
#define POLICY_LEVEL_USE		1
#define POLICY_LEVEL_REQUIRE	2
#define POLICY_LEVEL_UNIQUE		3
#define POLICY_LEVEL_SHARED		4

//
// IKE structures and classes
//

typedef struct _IKE_SADDR
{
	union
	{
		sockaddr		saddr;
		sockaddr_in		saddr4;
	};

}IKE_SADDR;

typedef struct _IKE_ATTR : public IDB_ENTRY
{
	bool		basic;
	uint16_t	atype;
	uint16_t	bdata;
	BDATA		vdata;

}IKE_ATTR;

typedef struct _IKE_COOKIES
{
	unsigned char i[ ISAKMP_COOKIE_SIZE ];
	unsigned char r[ ISAKMP_COOKIE_SIZE ];

}IKE_COOKIES;

typedef struct _IKE_PH1ID
{
	uint8_t		type;
	in_addr		addr;
	BDATA		varid;

}IKE_PH1ID;

typedef struct _IKE_PH2ID
{
	uint8_t		prot;
	uint16_t	port;
	uint8_t		type;

	in_addr		addr1;
	in_addr		addr2;

}IKE_PH2ID;

typedef struct _IKE_SPI
{
	union
	{
		IKE_COOKIES	cookies;	// isakmp cookies
		uint32_t	spi;		// esp/ah spi
		uint16_t	cpi;		// ipcomp cpi
	};

	uint8_t size;

}IKE_SPI;

typedef struct _IKE_PROPOSAL
{
	uint8_t		pnumb;
	uint8_t		tnumb;

	uint8_t		proto;
	uint8_t		xform;
	uint16_t	encap;
	uint16_t	reqid;

	IKE_SPI		spi;

	uint16_t	ciph_id;
	uint16_t	ciph_kl;
	uint16_t	hash_id;
	uint16_t	dhgr_id;
	uint16_t	auth_id;
	uint32_t	life_sec;
	uint32_t	life_kbs;

}IKE_PROPOSAL;

typedef struct _IKE_PEER
{
	IKE_SADDR		saddr;

	unsigned char	contact;
	unsigned char	exchange;
	bool			notify;
	bool			nailed;
	long			natt_mode;
	unsigned short	natt_port;
	long			natt_rate;
	long			frag_ike_mode;
	size_t			frag_ike_size;
	long			frag_esp_mode;
	size_t			frag_esp_size;
	long			dpd_mode;
	long			dpd_delay;
	long			dpd_retry;
	long			life_check;

	unsigned char	idtype_l;
	unsigned char	idtype_r;

	long			plcy_mode;
	long			plcy_level;
	long			xconf_mode;

}IKE_PEER;

typedef struct _IKE_XAUTH
{
	uint16_t	type;
	BDATA		user;
	BDATA		pass;
	BDATA		hash;

	BDATA	context;

}IKE_XAUTH;

typedef struct _IKE_NSCFG
{
	bool		dnss_from_dhcp;					// dns server list obtained from dhcp
	in_addr		dnss_list[ IPSEC_DNSS_MAX ];	// dns server list
	uint32_t	dnss_count;						// dns server count
	uint32_t	dnss_nodyn;						// dns dynamic update disabled
	char		dnss_suffix[ CONF_STRLEN ];

	in_addr		nbns_list[ IPSEC_NBNS_MAX ];	// wins server list
	uint32_t	nbns_count;						// wins server count
	uint32_t	nbns_nopts;						// wins options
	uint32_t	nbns_ntype;						// wins node type

}IKE_NSCFG;


typedef struct _IKE_XCONF
{
	long		opts;		// enabled options
	long		rqst;		// request options

	in_addr		addr;		// network address
	in_addr		mask;		// network mask
	in_addr		dhcp;		// dhcp servers

	uint32_t	expi;		// address expires
	uint32_t	vmtu;		// adapter mtu
	uint16_t	dhgr;		// pfs dh group
	uint16_t	svpw;		// save password

	IKE_NSCFG	nscfg;		// name service config

}IKE_XCONF;

typedef struct _IKE_NOTIFY
{
	uint8_t		type;
	uint32_t	doi;
	uint8_t		proto;
	uint16_t	code;

	IKE_SPI		spi;
	BDATA		data;

}IKE_NOTIFY;

typedef struct _IKE_FRAG : public IDB_ENTRY
{
	public:

	long	index;
	bool	last;
	BDATA	data;

}IKE_FRAG;

#pragma pack( 1 )

typedef struct _IKE_SUBNET
{
	in_addr addr;
	in_addr mask;

}IKE_SUBNET;

typedef struct _IKE_UNITY_NET
{
	in_addr		addr;
	in_addr		mask;
	uint8_t		prot;
	uint8_t		pad;
	uint16_t	port_loc;
	uint16_t	port_rmt;

}IKE_UNITY_NET;

#pragma pack()

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

#endif
