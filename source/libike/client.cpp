
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

#include "client.h"

//==============================================================================
// Base IKEC class
//==============================================================================

bool _CLIENT::run_init()
{
	memset( &peer, 0, sizeof( peer ) );
	memset( &xconf, 0, sizeof( xconf ) );

	//
	// load the config into ipsecc
	//

	long	numb;
	char	text[ MAX_CONFSTRING ];
	BDATA	btext;

	//
	// ---------- PEER CONFIG ----------
	//

	// default values

	peer.contact = IPSEC_CONTACT_CLIENT;
	peer.plcy_mode = POLICY_MODE_CONFIG;
	peer.notify = true;

	// netowrk host

	if( !config.get_string( "network-host", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : network-host undefined\n" );
		return false;
	}

	char * host = text;
	while( host && * host == ' ' )
		host++;

	if( inet_addr( host ) != INADDR_NONE )
	{
		peer.saddr.saddr4.sin_family = AF_INET;
		peer.saddr.saddr4.sin_addr.s_addr = inet_addr( host );
	}
	else
	{
		struct hostent * hp = gethostbyname( host );
		if( !hp )
		{
			log( STATUS_FAIL, "config error : cannot resolve address for host %s\n", host );
			return false;
		}

		peer.saddr.saddr4.sin_family = hp->h_addrtype;
		memcpy( &peer.saddr.saddr4.sin_addr, hp->h_addr, hp->h_length );
	}

	// network port

	if( !config.get_number( "network-ike-port", &numb ) )
	{
		log( STATUS_FAIL, "config error : network-ike-port undefined\n" );
		return false;
	}

	peer.saddr.saddr4.sin_port = htons( ( unsigned short ) numb );

	// client auto config mode

	peer.xconf_mode = CONFIG_MODE_NONE;

	if( config.get_string( "client-auto-mode", text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "push", text ) )
			peer.xconf_mode = CONFIG_MODE_PUSH;

		if( !strcmp( "pull", text ) )
			peer.xconf_mode = CONFIG_MODE_PULL;

		if( !strcmp( "dhcp", text ) )
			peer.xconf_mode = CONFIG_MODE_DHCP;
	}

	// nat-t enable

	peer.natt_mode = IPSEC_NATT_DISABLE;
	peer.natt_port = htons( 4500 );
	peer.natt_rate = 30;

#ifdef OPT_NATT

	if( config.get_string( "network-natt-mode", text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "enable", text ) )
		{
			peer.natt_mode = IPSEC_NATT_ENABLE;
			xconf.rqst |= IPSEC_OPTS_CISCO_UDP;
		}

		if( !strcmp( "force", text ) )
			peer.natt_mode = IPSEC_NATT_FORCE_RFC;

		if( !strcmp( "force-draft", text ) )
			peer.natt_mode = IPSEC_NATT_FORCE_DRAFT;

		if( !strcmp( "force-rfc", text ) )
			peer.natt_mode = IPSEC_NATT_FORCE_RFC;

		if( !strcmp( "force-cisco-udp", text ) )
		{
			peer.natt_mode = IPSEC_NATT_FORCE_CISCO;
			peer.natt_port = htons( 10000 );
			xconf.rqst |= IPSEC_OPTS_CISCO_UDP;
		}

		// nat-t udp port

		if( config.get_number( "network-natt-port", &numb ) )
			peer.natt_port = htons( ( unsigned short ) numb );

		// nat-t keep-alive rate

		if( config.get_number( "network-natt-rate", &numb ) )
			peer.natt_rate = numb;
	}

#endif

	// ike fragmentation enable

	peer.frag_esp_mode = IPSEC_FRAG_DISABLE;
	peer.frag_ike_mode = IPSEC_FRAG_DISABLE;

	if( config.get_string( "network-frag-mode", text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "enable", text ) )
			peer.frag_ike_mode = IPSEC_FRAG_ENABLE;

		if( !strcmp( "force", text ) )
			peer.frag_ike_mode = IPSEC_FRAG_FORCE;

		// ike fragmentation size

		peer.frag_ike_size = 520;
		if( !config.get_number( "network-frag-size", &numb ) )
			peer.frag_ike_size = numb;
	}

	// dpd enable

	peer.dpd_mode = IPSEC_DPD_DISABLE;
	peer.dpd_delay = 15;
	peer.dpd_retry = 5;

	numb = 0;
	config.get_number( "network-dpd-enable", &numb );
	if( numb == 1 )
		peer.dpd_mode = IPSEC_DPD_ENABLE;

	// isakmp notify

	numb = 0;
	config.get_number( "network-notify-enable", &numb );
	if( numb )
		peer.notify = true;

	// request motd banner

	numb = 0;
	config.get_number( "client-banner-enable", &numb );
	if( numb )
		xconf.rqst |= IPSEC_OPTS_BANNER;

	//
	// ---------- IDENTITY CONFIG ----------
	//

	// client identification type

	peer.idtype_l = 255;

	if( !config.get_string( "ident-client-type", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : ident-client-type undefined\n" );
		return false;
	}

	if( !strcmp( "none", text ) )
		peer.idtype_l = ISAKMP_ID_NONE;

	if( !strcmp( "asn1dn", text ) )
		peer.idtype_l = ISAKMP_ID_ASN1_DN;

	if( !strcmp( "keyid", text ) )
		peer.idtype_l = ISAKMP_ID_KEY_ID;

	if( !strcmp( "fqdn", text ) )
		peer.idtype_l = ISAKMP_ID_FQDN;

	if( !strcmp( "ufqdn", text ) )
		peer.idtype_l = ISAKMP_ID_USER_FQDN;

	if( !strcmp( "address", text ) )
		peer.idtype_l = ISAKMP_ID_IPV4_ADDR;

	if( peer.idtype_l == 255 )
	{
		log( STATUS_FAIL, "config error : ident-client-type is invalid\n" );
		return false;
	}

	// server identification type

	peer.idtype_r = 255;

	if( !config.get_string( "ident-server-type", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : ident-server-idtype undefined\n" );
		return false;
	}

	if( !strcmp( "any", text ) )
		peer.idtype_r = ISAKMP_ID_NONE;

	if( !strcmp( "asn1dn", text ) )
		peer.idtype_r = ISAKMP_ID_ASN1_DN;

	if( !strcmp( "keyid", text ) )
		peer.idtype_r = ISAKMP_ID_KEY_ID;

	if( !strcmp( "fqdn", text ) )
		peer.idtype_r = ISAKMP_ID_FQDN;

	if( !strcmp( "ufqdn", text ) )
		peer.idtype_r = ISAKMP_ID_USER_FQDN;

	if( !strcmp( "address", text ) )
		peer.idtype_r = ISAKMP_ID_IPV4_ADDR;

	if( peer.idtype_r == 255 )
	{
		log( STATUS_FAIL, "config error : ident-server-type is invalid\n" );
		return false;
	}

	//
	// ---------- IKSAMP PROPOSAL ----------
	//

	// phase1 exchange mode

	if( !config.get_string( "phase1-exchange", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : phase1-exchange undefined\n" );
		return false;
	}

	if( !strcmp( "main", text ) )
		peer.exchange = ISAKMP_EXCH_IDENT_PROTECT;

	if( !strcmp( "aggressive", text ) )
		peer.exchange = ISAKMP_EXCH_AGGRESSIVE;

	if( !peer.exchange )
	{
		log( STATUS_FAIL, "config error : phase1-exchange is invalid\n" );
		return false;
	}

	memset( &proposal_isakmp, 0, sizeof( proposal_isakmp ) );

	// defaults

	proposal_isakmp.proto	= ISAKMP_PROTO_ISAKMP;
	proposal_isakmp.xform	= ISAKMP_KEY_IKE;

	// phase1 cipher type

	if( !config.get_string( "phase1-cipher", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : phase1-cipher undefined\n" );
		return false;
	}

	if( !strcmp( "auto", text ) )
		proposal_isakmp.ciph_id = 0;

	if( !strcmp( "aes", text ) )
		proposal_isakmp.ciph_id = IKE_CIPHER_AES;

	if( !strcmp( "blowfish", text ) )
		proposal_isakmp.ciph_id = IKE_CIPHER_BLOWFISH;

	if( !strcmp( "3des", text ) )
		proposal_isakmp.ciph_id = IKE_CIPHER_3DES;

	if( !strcmp( "cast", text ) )
		proposal_isakmp.ciph_id = IKE_CIPHER_CAST;

	if( !strcmp( "des", text ) )
		proposal_isakmp.ciph_id = IKE_CIPHER_DES;

	// phase1 cipher keylength

	if( ( proposal_isakmp.ciph_id == IKE_CIPHER_AES ) ||
		( proposal_isakmp.ciph_id == IKE_CIPHER_BLOWFISH ) )
	{
		if( !config.get_number( "phase1-keylen", &numb ) )
		{
			log( STATUS_FAIL, "config error : phase1-keylen undefined\n" );
			return false;
		}

		proposal_isakmp.ciph_kl = ( unsigned short ) numb;
	}
	
	// phase1 hash type

	if( !config.get_string( "phase1-hash", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : phase1-hash undefined\n" );
		return false;
	}

	if( !strcmp( "auto", text ) )
		proposal_isakmp.hash_id = 0;

	if( !strcmp( "md5", text ) )
		proposal_isakmp.hash_id = IKE_HASH_MD5;

	if( !strcmp( "sha1", text ) )
		proposal_isakmp.hash_id = IKE_HASH_SHA1;

	if( !strcmp( "sha2-256", text ) )
		proposal_isakmp.hash_id = IKE_HASH_SHA2_256;

	if( !strcmp( "sha2-384", text ) )
		proposal_isakmp.hash_id = IKE_HASH_SHA2_384;

	if( !strcmp( "sha2-512", text ) )
		proposal_isakmp.hash_id = IKE_HASH_SHA2_512;

	// phase1 dh group description

	if( !config.get_number( "phase1-dhgroup", &numb ) )
	{
		log( STATUS_FAIL, "config error : phase1-dhgroup undefined\n" );
		return false;
	}

	proposal_isakmp.dhgr_id = ( unsigned short ) numb;

	// phase1 authentication mode

	if( !config.get_string( "auth-method", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : auth-method undefined\n" );
		return false;
	}

	if( !strcmp( "hybrid-rsa-xauth", text ) )
		proposal_isakmp.auth_id = HYBRID_AUTH_INIT_RSA;

	if( !strcmp( "hybrid-grp-xauth", text ) )
	{
		proposal_isakmp.auth_id = HYBRID_AUTH_INIT_RSA;
		xconf.opts |= IPSEC_OPTS_CISCO_GRP;
	}

	if( !strcmp( "mutual-rsa-xauth", text ) )
		proposal_isakmp.auth_id = XAUTH_AUTH_INIT_RSA;

	if( !strcmp( "mutual-psk-xauth", text ) )
		proposal_isakmp.auth_id = XAUTH_AUTH_INIT_PSK;

	if( !strcmp( "mutual-rsa", text ) )
		proposal_isakmp.auth_id = IKE_AUTH_SIG_RSA;

	if( !strcmp( "mutual-psk", text ) )
		proposal_isakmp.auth_id = IKE_AUTH_PRESHARED_KEY;

	// phase1 lifetime

	if( config.get_number( "phase1-life-secs", &numb ) )
		proposal_isakmp.life_sec	= numb;

	if( config.get_number( "phase1-life-kbytes", &numb ) )
		proposal_isakmp.life_kbs	= numb;

	//
	// ---------- ESP PROPOSAL ----------
	//

	memset( &proposal_esp, 0, sizeof( proposal_esp ) );

	// defaults

	proposal_esp.proto = ISAKMP_PROTO_IPSEC_ESP;
	proposal_esp.encap = 1;

	// phase2 transform type

	if( !config.get_string( "phase2-transform", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : phase2-transform undefined\n" );
		return false;
	}

	if( !strcmp( "auto", text ) )
		proposal_esp.xform = 0;

	if( !strcmp( "esp-aes", text ) )
		proposal_esp.xform = ISAKMP_ESP_AES;

	if( !strcmp( "esp-blowfish", text ) )
		proposal_esp.xform = ISAKMP_ESP_BLOWFISH;

	if( !strcmp( "esp-3des", text ) )
		proposal_esp.xform = ISAKMP_ESP_3DES;

	if( !strcmp( "esp-cast", text ) )
		proposal_esp.xform = ISAKMP_ESP_CAST;

	if( !strcmp( "esp-des", text ) )
		proposal_esp.xform = ISAKMP_ESP_DES;

	// phase2 transform keylength

	if( ( proposal_esp.xform == ISAKMP_ESP_AES ) ||
		( proposal_esp.xform == ISAKMP_ESP_BLOWFISH ) )
	{
		if( !config.get_number( "phase2-keylen", &numb ) )
		{
			log( STATUS_FAIL, "config error : phase2-keylen undefined\n" );
			return false;
		}

		proposal_esp.ciph_kl = ( unsigned short ) numb;
	}

	// phase2 hmac type

	if( !config.get_string( "phase2-hmac", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : phase2-hmac undefined\n" );
		return false;
	}

	if( !strcmp( "auto", text ) )
		proposal_esp.hash_id = 0;

	if( !strcmp( "md5", text ) )
		proposal_esp.hash_id = ISAKMP_AUTH_HMAC_MD5;

	if( !strcmp( "sha1", text ) )
		proposal_esp.hash_id = ISAKMP_AUTH_HMAC_SHA1;

	if( !strcmp( "sha2-256", text ) )
		proposal_esp.hash_id = ISAKMP_AUTH_HMAC_SHA2_256;

	if( !strcmp( "sha2-384", text ) )
		proposal_esp.hash_id = ISAKMP_AUTH_HMAC_SHA2_384;

	if( !strcmp( "sha2-512", text ) )
		proposal_esp.hash_id = ISAKMP_AUTH_HMAC_SHA2_512;

	// phase2 pfs group description

	proposal_esp.dhgr_id = 0;

	if( config.get_number( "phase2-pfsgroup", &numb ) )
	{
		if( !numb )
			xconf.rqst |= IPSEC_OPTS_PFS;

		if( ( numb == IKE_GRP_GROUP1 ) ||
			( numb == IKE_GRP_GROUP2 ) ||
			( numb == IKE_GRP_GROUP5 ) ||
			( numb == IKE_GRP_GROUP14 ) ||
			( numb == IKE_GRP_GROUP15 ) ||
			( numb == IKE_GRP_GROUP16 ) ||
			( numb == IKE_GRP_GROUP17 ) ||
			( numb == IKE_GRP_GROUP18 ) )
			proposal_esp.dhgr_id = ( unsigned short ) numb;
	}

	// phase2 lifetimes

	if( config.get_number( "phase2-life-secs", &numb ) )
		proposal_esp.life_sec = numb;

	if( config.get_number( "phase2-life-kbytes", &numb ) )
		proposal_esp.life_kbs = numb;

	//
	// ---------- IPCOMP PROPOSAL ----------
	//

	memset( &proposal_ipcomp, 0, sizeof( proposal_ipcomp ) );

	// defaults

	proposal_ipcomp.proto = ISAKMP_PROTO_IPCOMP;
	proposal_ipcomp.encap = 0;

	// ipcomp transform type

	if( !config.get_string( "ipcomp-transform", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : ipcomp-transform undefined\n" );
		return false;
	}

	if( !strcmp( "none", text ) )
		proposal_ipcomp.xform = ISAKMP_IPCOMP_NONE;

	if( !strcmp( "deflate", text ) )
		proposal_ipcomp.xform = ISAKMP_IPCOMP_DEFLATE;

	if( !strcmp( "lzs", text ) )
		proposal_ipcomp.xform = ISAKMP_IPCOMP_LZS;

	if( config.get_number( "phase2-life-secs", &numb ) )
		proposal_ipcomp.life_sec = numb;

	if( config.get_number( "phase2-life-kbytes", &numb ) )
		proposal_ipcomp.life_kbs = numb;

	//
	// ---------- CLIENT CONFIG ----------
	//

	// unity save password option

	if( ( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_PSK ) ||
	    ( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_RSA ) ||
	    ( proposal_isakmp.auth_id == HYBRID_AUTH_INIT_RSA ) )
		if( ( peer.xconf_mode == CONFIG_MODE_PULL ) ||
		    ( peer.xconf_mode == CONFIG_MODE_PUSH ) )
			xconf.rqst |= IPSEC_OPTS_SAVEPW;

	// network interface type

	if( !config.get_string( "client-iface", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : client-iface undefined\n" );
		return false;
	}

	if( !strcmp( "virtual", text ) || !strcmp( "random", text ) )
	{
		xconf.opts |= ( IPSEC_OPTS_ADDR | IPSEC_OPTS_MASK );

		// virtual adapter with assgined address

		if( !strcmp( "virtual", text ) )
		{
			numb = 1;
			config.get_number( "client-addr-auto", &numb );

			if( numb )
			{
				// auto address configuration

				xconf.rqst |= ( IPSEC_OPTS_ADDR | IPSEC_OPTS_MASK );
			}
			else
			{
				// static address configuration

				if( !config.get_string( "client-ip-addr", text, MAX_CONFSTRING, 0 ) )
				{
					log( STATUS_FAIL, "config error : client-ip-addr undefined\n" );
					return false;
				}

				xconf.addr.s_addr = inet_addr( text );

				if( !config.get_string( "client-ip-mask", text, MAX_CONFSTRING, 0 ) )
				{
					log( STATUS_FAIL, "config error : client-ip-mask undefined\n" );
					return false;
				}

				xconf.mask.s_addr = inet_addr( text );
			}
		}

		// virtual adapter with randomized address

		if( !strcmp( "random", text ) )
		{
			// random address configuration

			if( !config.get_string( "client-ip-addr", text, MAX_CONFSTRING, 0 ) )
			{
				log( STATUS_FAIL, "config error : client-ip-addr undefined\n" );
				return false;
			}

			xconf.addr.s_addr = inet_addr( text );

			if( !config.get_string( "client-ip-mask", text, MAX_CONFSTRING, 0 ) )
			{
				log( STATUS_FAIL, "config error : client-ip-mask undefined\n" );
				return false;
			}

			xconf.mask.s_addr = inet_addr( text );

			// randomize address

			uint32_t addr = rand();
			addr &= ~xconf.mask.s_addr;
			xconf.addr.s_addr |= addr;
		}

		// adapter mtu

		xconf.vmtu = 1500;
		if( config.get_number( "network-mtu-size", &numb ) )
			xconf.vmtu = numb;
	}

	// enable wins options

	if( config.get_number( "client-wins-used", &numb ) )
	{
		if( numb )
		{
			// netbios name server address

			numb = 0;
			config.get_number( "client-wins-auto", &numb );

			if( numb )
			{
				// auto server configuration
				
				xconf.rqst |= IPSEC_OPTS_NBNS;
			}
			else
			{
				// static server configuration

				for( long index = 0; index < IPSEC_NBNS_MAX; index++ )
				{
					if( !config.get_string( "client-wins-addr", text, MAX_CONFSTRING, index ) )
						break;

					xconf.nscfg.nbns_list[ index ].s_addr = inet_addr( text );
					xconf.nscfg.nbns_count++;
				}

				if( !xconf.nscfg.nbns_count )
				{
					log( STATUS_FAIL, "config error : client-wins-addr undefined\n" );
					return false;
				}

				xconf.opts |= IPSEC_OPTS_NBNS;
			}
		}
	}

	// enable dns options

	if( config.get_number( "client-dns-used", &numb ) )
	{
		if( numb )
		{
			numb = 0;
			config.get_number( "client-dns-auto", &numb );

			if( numb )
			{
				// auto server configuration

				xconf.rqst |= IPSEC_OPTS_DNSS;
			}
			else
			{
				// dns server addresses

				for( long index = 0; index < IPSEC_DNSS_MAX; index++ )
				{
					if( !config.get_string( "client-dns-addr", text, MAX_CONFSTRING, index ) )
						break;

					xconf.nscfg.dnss_list[ index ].s_addr = inet_addr( text );
					xconf.nscfg.dnss_count++;
				}

				if( !xconf.nscfg.dnss_count )
				{
					log( STATUS_FAIL, "config error : client-dns-addr undefined\n" );
					return false;
				}

				xconf.opts |= IPSEC_OPTS_DNSS;
			}

			numb = 0;
			config.get_number( "client-dns-suffix-auto", &numb );

			if( numb )
			{
				// auto domain configuration

				xconf.rqst |= IPSEC_OPTS_DOMAIN;
			}
			else
			{
				// static domain configuration

				if( config.get_string( "client-dns-suffix", text, MAX_CONFSTRING, 0 ) )
				{
					strncpy_s( xconf.nscfg.dnss_suffix, text, CONF_STRLEN );

					xconf.opts |= IPSEC_OPTS_DOMAIN;
				}
			}
		}
	}

	// policy type

	peer.plcy_level = POLICY_LEVEL_AUTO;

	if( config.get_string( "policy-level", text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "use", text ) )
			peer.plcy_level = POLICY_LEVEL_USE;

		if( !strcmp( "require", text ) )
			peer.plcy_level = POLICY_LEVEL_REQUIRE;

		if( !strcmp( "unique", text ) )
			peer.plcy_level = POLICY_LEVEL_UNIQUE;

		if( !strcmp( "shared", text ) )
			peer.plcy_level = POLICY_LEVEL_SHARED;
	}

	// nailed policy enable

	numb = 0;
	config.get_number( "policy-nailed", &numb );
	if( numb )
		peer.nailed = true;

	// auto policy enable

	numb = 0;
	config.get_number( "policy-list-auto", &numb );
	if( numb )
	{
		// automatic policy config

		xconf.rqst |= IPSEC_OPTS_SPLITNET;

	}
	else
	{
		// static policy config

		xconf.opts |= IPSEC_OPTS_SPLITNET;
	}

	// vendor compatibility options

	numb = 0;
	config.get_number( "vendor-chkpt-enable", &numb );
	if( numb )
		xconf.opts |= IPSEC_OPTS_VEND_CHKPT;

	//
	// ---------- CONNECT TO IKED ----------
	//

	long	result;
	long	msgres;

	if( ikei.attach( 3000 ) != IPCERR_OK )
	{
		log( STATUS_FAIL, "failed to attach to key daemon\n" );
		return false;
	}

	log( STATUS_INFO, "attached to key daemon ...\n" );

	//
	// send the peer configuration message
	//

	IKEI_MSG msg;

	msg.set_peer( &peer );
	result = ikei.send_message( msg, &msgres );

	if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
	{
		log( STATUS_FAIL, "peer config failed\n" );
		goto config_failed;
	}

	log( STATUS_INFO, "peer configured\n" );

	//
	// send proposal config messages
	//

	msg.set_proposal( &proposal_isakmp );
	result = ikei.send_message( msg, &msgres );

	if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
	{
		log( STATUS_FAIL, "isakmp proposal config failed\n" );
		goto config_failed;
	}

	log( STATUS_INFO, "iskamp proposal configured\n" );

	msg.set_proposal( &proposal_esp );
	result = ikei.send_message( msg, &msgres );

	if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
	{
		log( STATUS_FAIL, "esp proposal config failed\n" );
		goto config_failed;
	}

	log( STATUS_INFO, "esp proposal configured\n" );

	if( proposal_ipcomp.xform )
	{
		msg.set_proposal( &proposal_ipcomp );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
		{
			log( STATUS_FAIL, "ipcomp proposal config failed\n" );
			goto config_failed;
		}

		log( STATUS_INFO, "ipcomp proposal configured\n" );
	}

	//
	// send the client configuration message
	//

	msg.set_client( &xconf );
	result = ikei.send_message( msg, &msgres );

	if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
	{
		log( STATUS_FAIL, "client config failed\n" );
		goto config_failed;
	}

	log( STATUS_INFO, "client configured\n" );

	//
	// verify and send our xauth info
	//

	if( ( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_PSK ) ||
		( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == HYBRID_AUTH_INIT_RSA ) )
	{
		get_username();

		msg.set_cfgstr( CFGSTR_CRED_XAUTH_USER, &username );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
		{
			log( STATUS_FAIL, "xauth username config failed\n" );
			goto config_failed;
		}

		get_password();

		msg.set_cfgstr( CFGSTR_CRED_XAUTH_PASS, &password );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
		{
			log( STATUS_FAIL, "xauth password config failed\n" );
			goto config_failed;
		}
	}

	//
	// verify and send our identity info
	//

	// client id data

	if( config.get_string( "ident-client-data", btext, 0 ) )
	{
		msg.set_cfgstr( CFGSTR_CRED_LID, &btext );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
		{
			log( STATUS_FAIL, "local id config failed\n" );
			goto config_failed;
		}
	}

	log( STATUS_INFO, "local id configured\n" );

	// server id data

	if( config.get_string( "ident-server-data", btext, 0 ) )
	{
		msg.set_cfgstr( CFGSTR_CRED_RID, &btext );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
		{
			log( STATUS_FAIL, "remote id config failed\n" );
			goto config_failed;
		}
	}

	log( STATUS_INFO, "remote id configured\n" );

	//
	// verify and send our peer authentication info
	//

	if( ( proposal_isakmp.auth_id == HYBRID_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == IKE_AUTH_SIG_RSA ) )
	{
		BDATA name;

		// server certificate

		if( !config.get_string( "auth-server-cert-name", name, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-server-cert-name undefined\n" );
			goto config_failed;
		}

		if( !config.get_binary( "auth-server-cert-data", btext ) )
		{
			log( STATUS_FAIL, "config error : auth-server-cert-data undefined\n" );
			goto config_failed;
		}

		server_cert_rety:

		msg.set_cfgstr( CFGSTR_CRED_RSA_RCRT, &btext );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres == IKEI_RESULT_FAILED ) )
		{
			log( STATUS_FAIL, "server cert config failed\n" );
			goto config_failed;
		}

		if( msgres == IKEI_RESULT_PASSWD )
		{
			if( !get_filepass( name ) )
			{
				log( STATUS_FAIL, "server cert file requires password\n" );
				goto config_failed;
			}

			msg.set_cfgstr( CFGSTR_CRED_FILE_PASS, &fpass );
			result = ikei.send_message( msg, &msgres );

			goto server_cert_rety;
		}

		log( STATUS_INFO, "server cert configured\n" );
	}

	if( ( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == IKE_AUTH_SIG_RSA ) )
	{
		BDATA name;

		// client certificate

		if( !config.get_string( "auth-client-cert-name", name, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-client-cert-name undefined\n" );
			goto config_failed;
		}

		if( !config.get_binary( "auth-client-cert-data", btext ) )
		{
			log( STATUS_FAIL, "config error : auth-client-cert-data undefined\n" );
			goto config_failed;
		}

		client_cert_rety:

		msg.set_cfgstr( CFGSTR_CRED_RSA_LCRT, &btext );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres == IKEI_RESULT_FAILED ) )
		{
			log( STATUS_FAIL, "client cert config failed\n" );
			goto config_failed;
		}

		if( msgres == IKEI_RESULT_PASSWD )
		{
			if( !get_filepass( name ) )
			{
				log( STATUS_FAIL, "client cert file requires password\n" );
				goto config_failed;
			}

			msg.set_cfgstr( CFGSTR_CRED_FILE_PASS, &fpass );
			result = ikei.send_message( msg, &msgres );

			goto client_cert_rety;
		}

		log( STATUS_INFO, "client cert configured\n" );

		// client private key

		if( !config.get_string( "auth-client-cert-name", name, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-client-cert-name undefined\n" );
			goto config_failed;
		}

		if( !config.get_binary( "auth-client-key-data", btext ) )
		{
			log( STATUS_FAIL, "config error : auth-client-key-data undefined\n" );
			goto config_failed;
		}

		client_pkey_rety:

		msg.set_cfgstr( CFGSTR_CRED_RSA_LKEY, &btext );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres == IKEI_RESULT_FAILED ) )
		{
			log( STATUS_FAIL, "client key config failed\n" );
			goto config_failed;
		}

		if( msgres == IKEI_RESULT_PASSWD )
		{
			if( !get_filepass( name ) )
			{
				log( STATUS_FAIL, "client key file requires password\n" );
				goto config_failed;
			}

			msg.set_cfgstr( CFGSTR_CRED_FILE_PASS, &fpass );
			result = ikei.send_message( msg, &msgres );

			goto client_pkey_rety;
		}

		log( STATUS_INFO, "client key configured\n" );
	}

	if( ( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_PSK ) ||
		( proposal_isakmp.auth_id == IKE_AUTH_PRESHARED_KEY ) ||
		( xconf.opts & IPSEC_OPTS_CISCO_GRP ) )
	{
		// mutual preshared key

		BDATA psk;

		if( !config.get_binary( "auth-mutual-psk", psk ) )
		{
			log( STATUS_FAIL, "config error : auth-mutual-psk undefined\n" );
			goto config_failed;
		}

		msg.set_cfgstr( CFGSTR_CRED_PSK, &psk );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres == IKEI_RESULT_FAILED ) )
		{
			log( STATUS_FAIL, "pre-shared key config failed\n" );
			goto config_failed;
		}

		log( STATUS_INFO, "pre-shared key configured\n" );
	}

	//
	// define our splitdns domains
	//

	if(  ( xconf.opts & IPSEC_OPTS_SPLITDNS ) &&
		!( xconf.rqst & IPSEC_OPTS_SPLITDNS ) )
	{
		long index = 0;
		while( config.get_string( "client-splitdns-list", btext, index++ ) )
		{
			msg.set_cfgstr( CFGSTR_SPLIT_DOMAIN, &btext );
			result = ikei.send_message( msg, &msgres );

			if( ( result != IPCERR_OK ) || ( msgres == IKEI_RESULT_FAILED ) )
			{
				log( STATUS_FAIL, "split domain name config failed\n" );
				goto config_failed;
			}
		}
	}

	//
	// define our manual remote id list
	//

	if( !( xconf.rqst & IPSEC_OPTS_SPLITNET ) )
	{
		long index = 0;

		while( config.get_string( "policy-list-exclude", text, MAX_CONFSTRING, index ) )
		{
			char * split = strchr( text, '/' ) + 2;
			unsigned long addr = inet_addr( text );
			unsigned long mask = inet_addr( split );

			IKE_PH2ID ph2id;
			memset( &ph2id, 0, sizeof( ph2id ) );

			ph2id.type = ISAKMP_ID_IPV4_ADDR_SUBNET;
			ph2id.addr1.s_addr = addr;
			ph2id.addr2.s_addr = mask;

			msg.set_network( UNITY_SPLIT_EXCLUDE, &ph2id );
			result = ikei.send_message( msg, &msgres );

			if( ( result != IPCERR_OK ) || ( msgres == IKEI_RESULT_FAILED ) )
			{
				log( STATUS_FAIL, "policy include config failed\n" );
				goto config_failed;
			}

			index++;
		}

		index = 0;

		while( config.get_string( "policy-list-include", text, MAX_CONFSTRING, index ) )
		{
			char * split = strchr( text, '/' ) + 2;
			unsigned long addr = inet_addr( text );
			unsigned long mask = inet_addr( split );

			IKE_PH2ID ph2id;
			memset( &ph2id, 0, sizeof( ph2id ) );

			ph2id.type = ISAKMP_ID_IPV4_ADDR_SUBNET;
			ph2id.addr1.s_addr = addr;
			ph2id.addr2.s_addr = mask;

			msg.set_network( UNITY_SPLIT_INCLUDE, &ph2id );
			result = ikei.send_message( msg, &msgres );

			if( ( result != IPCERR_OK ) || ( msgres == IKEI_RESULT_FAILED ) )
			{
				log( STATUS_FAIL, "policy include config failed\n" );
				goto config_failed;
			}

			index++;
		}
	}

	//
	// ---------- ENABLE TUNNEL ----------
	//

	msg.set_enable( true );
	if( ikei.send_message( msg ) != IPCERR_OK )
	{
		log( STATUS_FAIL, "send enable failed\n" );
		goto config_failed;
	}

	//
	// no more user input past this point
	//

	connecting.alert();

	return true;

	config_failed:

	ikei.detach();

	log( STATUS_INFO, "detached from key daemon\n" );

	return false;
}

bool _CLIENT::run_loop()
{
	IKEI_MSG msg;

	//
	// ---------- FEEDBACK LOOP ----------
	//

	long status;
	long result;
	BDATA btext;

	while( true )
	{
		//
		// get the next message
		//

		result = ikei.recv_message( msg );

		if( result == IPCERR_NODATA )
			continue;

		if( ( result == IPCERR_FAILED ) || ( result == IPCERR_CLOSED ) )
		{
			if( cstate != CLIENT_STATE_DISCONNECTED )
			{
				log( STATUS_FAIL, "key daemon attachment error\n" );
				cstate = CLIENT_STATE_DISCONNECTED;
				set_status( STATUS_DISCONNECTED, NULL );
			}

			break;
		}

		//
		// check for user cancelation
		//

		if( result == IPCERR_WAKEUP )
		{
			msg.set_enable( false );
			if( ikei.send_message( msg ) != IPCERR_OK )
				break;

			continue;
		}

		//
		// evaluate the message
		//

		switch( msg.header.type )
		{
			//
			// status message
			//

			case IKEI_MSGID_STATUS:
			{
				if( msg.get_status( &status, &btext ) != IPCERR_OK )
					break;

				switch( status )
				{
					case STATUS_DISCONNECTED:
						cstate = CLIENT_STATE_DISCONNECTED;
						break;

					case STATUS_CONNECTING:
						cstate = CLIENT_STATE_CONNECTING;
						break;

					case STATUS_CONNECTED:
						cstate = CLIENT_STATE_CONNECTED;
						break;

					case STATUS_DISCONNECTING:
						cstate = CLIENT_STATE_DISCONNECTING;
						break;
				}

				set_status( status, &btext );

				break;
			}

			//
			// statistics message
			//

			case IKEI_MSGID_STATS:
			{
				if( msg.get_stats( &stats ) != IPCERR_OK )
					break;

				set_stats();

				break;
			}
		}
	}

	ikei.detach();

	log( STATUS_INFO, "detached from key daemon\n" );

	return true;
}


long _CLIENT::func( void * arg )
{
	if( arg == ( void * ) 1 )
		if( !run_init() )
			return -1;

	if( !run_loop() )
		return -1;

	return 0;
}

_CLIENT::_CLIENT()
{
	memset( &stats, 0, sizeof( stats ) );

	cstate = CLIENT_STATE_DISCONNECTED;
	autoconnect = false;
	suspended = false;
}

_CLIENT::~_CLIENT()
{
}

CLIENT_STATE _CLIENT::state()
{
	return cstate;
}

OPT_RESULT _CLIENT::read_opts( int argc, char ** argv )
{
	site_name.del();

	// read our command line args

	bool syntax_error = false;

	for( int argi = 1; argi < argc; argi++ )
	{
		// remote site name

		if( !strcmp( argv[ argi ], "-r" ) )
		{
			if( ++argi >= argc )
				return OPT_RESULT_SYNTAX_ERROR;

			site_name.set(
				argv[ argi ], strlen( argv[ argi ] ) + 1 );

			continue;
		}

#ifdef WIN32

		if( !strcmp( argv[ argi ], "-s" ) )
		{
			// this takes a few trys some times,
			// i have no idea why. we wait up to
			// 10 seconds for the file.

			int i = 0;
			for( ; i < 20; i++ )
			{
				// read suspended site name from the
				// control file under windows temp

				char temp_path[ MAX_PATH ] = { 0 };
				char file_path[ MAX_PATH ] = { 0 };

				if( SHGetFolderPath(
						NULL,
						CSIDL_COMMON_APPDATA,
						NULL,
						SHGFP_TYPE_DEFAULT,
						temp_path ) == S_OK )
				{
					sprintf_s( file_path, "%s\\Shrew Soft VPN\\sscp-login-info", temp_path );
					if( site_name.file_load( file_path ) )
					{
						site_name.add( "", 1 );
						DeleteFile( file_path );
						break;
					}
				}

				Sleep( 500 );
			}

			if( i >= 20 )
				return OPT_RESULT_RESUME_ERROR;

			suspended = true;
			continue;
		}
#endif

		// remote site username

		if( !strcmp( argv[ argi ], "-u" ) )
		{
			if( ++argi >= argc )
				return OPT_RESULT_SYNTAX_ERROR;

			username.set(
				argv[ argi ], strlen( argv[ argi ] ) );

			continue;
		}

		// remote site password

		if( !strcmp( argv[ argi ], "-p" ) )
		{
			if( ++argi >= argc )
				return OPT_RESULT_SYNTAX_ERROR;

			password.set(
				argv[ argi ], strlen( argv[ argi ] ) );

			continue;
		}

		// auto connect

		if( !strcmp( argv[ argi ], "-a" ) )
		{
			autoconnect = true;
			continue;
		}

		// syntax error

		return OPT_RESULT_SYNTAX_ERROR;
	}

	// make sure we have a site name

	if( !site_name.size() )
		return OPT_RESULT_SYNTAX_ERROR;

	return OPT_RESULT_SUCCESS;
}

void _CLIENT::show_help()
{
	log( STATUS_FAIL,
		"invalid parameters specified ...\n" );

	log( STATUS_INFO,
		"%s -r \"name\" [ -u <user> ][ -p <pass> ][ -a ]\n"
		" -r\tsite configuration path\n"
		" -u\tconnection user name\n"
		" -p\tconnection user password\n"
		" -a\tauto connect\n",
		app_name() );
}

bool _CLIENT::config_load()
{
	if( !site_name.size() )
		return false;
	
	config.set_id( site_name.text() );

	bool loaded = manager.file_vpn_load( config );
	if( !loaded )
	{
		config.set_ispublic( true );
		loaded = manager.file_vpn_load( config );
	}

	if( !loaded )
	{
		log( STATUS_FAIL, "failed to load \'%s\'\n",
			site_name.text() );

		return false;
	}

	log( STATUS_INFO, "config loaded for site \'%s\'\n",
		site_name.text() );

	return true;
}

bool _CLIENT::auto_connect()
{
	return autoconnect;
}

bool _CLIENT::user_credentials()
{
	char text[ MAX_CONFSTRING ];

	if( config.get_string( "auth-method", text, MAX_CONFSTRING, 0 ) )
		if( !strcmp( "hybrid-rsa-xauth", text ) ||
			!strcmp( "hybrid-grp-xauth", text ) ||
			!strcmp( "mutual-rsa-xauth", text ) ||
			!strcmp( "mutual-psk-xauth", text ) )
			return true;

	return false;
}

bool _CLIENT::vpn_connect( bool wait_input )
{
	if( cstate != CLIENT_STATE_DISCONNECTED )
	{
		log( STATUS_FAIL,
			"tunnel connected! try disconnecting first\n" );

		return false;
	}

	if( config.get_id() == NULL )
	{
		log( STATUS_FAIL,
			"no site configuration loaded\n" );

		return false;
	}

	connecting.reset();

	exec( ( void * ) 1 );

	if( wait_input )
		connecting.wait( -1 );

	return true;
}

bool _CLIENT::vpn_disconnect()
{
	if( cstate == CLIENT_STATE_DISCONNECTED )
	{
		log( STATUS_FAIL,
			"tunnel disconnected! try connecting first\n" );

		return false;
	}

	if( config.get_id() == NULL )
	{
		log( STATUS_FAIL,
			"no site configuration loaded\n" );

		return false;
	}
	
	ikei.wakeup();

	return true;
}

bool _CLIENT::vpn_suspend()
{
	IKEI_MSG msg;
	msg.set_suspend( 1 );
	if( ikei.send_message( msg ) != IPCERR_OK )
		return false;

	return true;
}

bool _CLIENT::vpn_resume()
{
	if( ikei.attach( 3000 ) != IPCERR_OK )
	{
		log( STATUS_FAIL, "failed to attach to key daemon\n" );
		return false;
	}

	log( STATUS_INFO, "attached to key daemon ...\n" );

	IKEI_MSG msg;
	msg.set_suspend( 0 );
	if( ikei.send_message( msg ) != IPCERR_OK )
	{
		log( STATUS_INFO, "failed to resume vpn connection\n" );
		return false;
	}

	cstate = CLIENT_STATE_CONNECTED;
	set_status( STATUS_CONNECTED, NULL );

	exec( ( void * ) 0 );

	return true;
}
