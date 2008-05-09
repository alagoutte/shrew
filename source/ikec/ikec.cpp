
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

#include "ikec.h"

_IKEC::_IKEC()
{
	active = false;
	cancel = false;
}

_IKEC::~_IKEC()
{
}

char * _IKEC::file_spec( char * name )
{
	if( name != NULL )
	{
		strncpy( fspec, name, 254 );
		snprintf( fpath, 1023,
			"%s/%s", sites, name );
	}

	return fspec;
}

char * _IKEC::file_path()
{
	return fpath;
}

char * _IKEC::site_path()
{
	return sites;
}

bool _IKEC::init( root * setr )
{
	// store our root window

	r = setr;

	// locate user home directory

	struct passwd * pwd = getpwuid( getuid() );
	if( pwd == NULL )
	{
		printf( "unable to read pwent for %i\n", getuid() );
		return false;
	}

	// create site path

	snprintf( sites, 1023, "%s/.ike/sites", pwd->pw_dir );
	endpwent();

	return true;
}

bool _IKEC::log( long code, const char * format, ... )
{
	char buff[ 1024 ];
	memset( buff, 0, sizeof( buff ) );
	va_list list;
	va_start( list, format );
	vsprintf( buff, format, list );

	QApplication::postEvent( r, new StatusEvent( buff, code ) );

	return true;
}

void _IKEC::run()
{
	//
	// load the config into ipsecc
	//

	long	numb;
	char	text[ MAX_CONFSTRING ];
	BDATA	btext;

	//
	// ---------- PEER CONFIG ----------
	//

	memset( &peer, 0, sizeof( peer ) );

	// default values

	peer.contact = IPSEC_CONTACT_CLIENT;
	peer.notify = true;

	// netowrk host

	if( !config.get_string( "network-host", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : network-host undefined\n" );
		return;
	}

	char * host = text;
	while( host && * host == ' ' )
		host++;

	if( isdigit( host[ 0 ] ) )
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
			return;
		}

		peer.saddr.saddr4.sin_family = hp->h_addrtype;
		memcpy( &peer.saddr.saddr4.sin_addr, hp->h_addr, hp->h_length );
	}

	// network port

	if( !config.get_number( "network-ike-port", &numb ) )
	{
		log( STATUS_FAIL, "config error : network-ike-port undefined\n" );
		return;
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
			peer.natt_mode = IPSEC_NATT_ENABLE;

		if( !strcmp( "force", text ) )
			peer.natt_mode = IPSEC_NATT_FORCE_RFC;

		if( !strcmp( "force-draft", text ) )
			peer.natt_mode = IPSEC_NATT_FORCE_DRAFT;

		if( !strcmp( "force-rfc", text ) )
			peer.natt_mode = IPSEC_NATT_FORCE_RFC;

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
	peer.dpd_rate = 30;

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
		log( STATUS_FAIL, "config error : auth-client-type undefined\n" );
		return;
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
		return;
	}

	// server identification type

	peer.idtype_r = 255;

	if( !config.get_string( "ident-server-type", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : auth-server-idtype undefined\n" );
		return;
	}

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
		return;
	}

	//
	// ---------- IKSAMP PROPOSAL ----------
	//

	// phase1 exchange mode

	if( !config.get_string( "phase1-exchange", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : phase1-exchange undefined\n" );
		return;
	}

	if( !strcmp( "main", text ) )
		peer.exchange = ISAKMP_EXCH_IDENT_PROTECT;

	if( !strcmp( "aggressive", text ) )
		peer.exchange = ISAKMP_EXCH_AGGRESSIVE;

	if( !peer.exchange )
	{
		log( STATUS_FAIL, "config error : phase1-exchange is invalid\n" );
		return;
	}

	memset( &proposal_isakmp, 0, sizeof( proposal_isakmp ) );

	// defaults

	proposal_isakmp.proto	= ISAKMP_PROTO_ISAKMP;
	proposal_isakmp.xform	= ISAKMP_KEY_IKE;

	// phase1 cipher type

	if( !config.get_string( "phase1-cipher", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : phase1-cipher undefined\n" );
		return;
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
			return;
		}

		proposal_isakmp.ciph_kl = ( unsigned short ) numb;
	}
	
	// phase1 hash type

	if( !config.get_string( "phase1-hash", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : phase1-hash undefined\n" );
		return;
	}

	if( !strcmp( "auto", text ) )
		proposal_isakmp.hash_id = 0;

	if( !strcmp( "md5", text ) )
		proposal_isakmp.hash_id = IKE_HASH_MD5;

	if( !strcmp( "sha1", text ) )
		proposal_isakmp.hash_id = IKE_HASH_SHA1;

	// phase1 dh group description

	if( !config.get_number( "phase1-dhgroup", &numb ) )
	{
		log( STATUS_FAIL, "config error : phase1-dhgroup undefined\n" );
		return;
	}

	proposal_isakmp.dhgr_id = ( unsigned short ) numb;

	// phase1 authentication mode

	if( !config.get_string( "auth-method", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : auth-method undefined\n" );
		return;
	}

	if( !strcmp( "hybrid-rsa-xauth", text ) )
		proposal_isakmp.auth_id = HYBRID_AUTH_INIT_RSA;

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
		return;
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
			return;
		}

		proposal_esp.ciph_kl = ( unsigned short ) numb;
	}

	// phase2 hmac type

	if( !config.get_string( "phase2-hmac", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : phase2-hmac undefined\n" );
		return;
	}

	if( !strcmp( "auto", text ) )
		proposal_esp.hash_id = 0;

	if( !strcmp( "md5", text ) )
		proposal_esp.hash_id = ISAKMP_AUTH_HMAC_MD5;

	if( !strcmp( "sha1", text ) )
		proposal_esp.hash_id = ISAKMP_AUTH_HMAC_SHA;

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
			( numb == IKE_GRP_GROUP16 ) )
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
		return;
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
		return;
	}

	if( !strcmp( "virtual", text ) )
	{
		xconf.opts |= ( IPSEC_OPTS_ADDR | IPSEC_OPTS_MASK );
		xconf.rqst |= ( IPSEC_OPTS_ADDR | IPSEC_OPTS_MASK );

		peer.plcy_mode = POLICY_MODE_CONFIG;

		// ip address and netmask

		if( config.get_number( "client-addr-auto", &numb ) )
		{
			if( !numb )
			{
				if( !config.get_string( "client-ip-addr", text, MAX_CONFSTRING, 0 ) )
				{
					log( STATUS_FAIL, "config error : client-ip-addr undefined\n" );
					return;
				}

				xconf.addr.s_addr = inet_addr( text );

				if( !config.get_string( "client-ip-mask", text, MAX_CONFSTRING, 0 ) )
				{
					log( STATUS_FAIL, "config error : client-ip-mask undefined\n" );
					return;
				}

				xconf.mask.s_addr = inet_addr( text );

				xconf.rqst &= ~( IPSEC_OPTS_ADDR | IPSEC_OPTS_MASK );
			}
		}

		// adapter mtu

		xconf.vmtu = 1500;
		if( config.get_number( "network-mtu-size", &numb ) )
			xconf.vmtu = numb;
	}

	// enable wins options

	if( config.get_number( "client-wins-enable", &numb ) )
	{
		if( numb )
		{
			xconf.opts |= IPSEC_OPTS_NBNS;
			xconf.rqst |= IPSEC_OPTS_NBNS;

			// netbios name server address

			numb = 0;
			config.get_number( "client-wins-auto", &numb );

			if( !numb )
			{
				if( !config.get_string( "client-wins-addr", text, MAX_CONFSTRING, 0 ) )
				{
					log( STATUS_FAIL, "config error : client-wins-addr undefined\n" );
					return;
				}

				xconf.nscfg.nbns_list[ 0 ].s_addr = inet_addr( text );
				xconf.nscfg.nbns_count = 1;
				xconf.rqst &= ~IPSEC_OPTS_NBNS;
			}
		}
	}

	// enable dns options

	if( config.get_number( "client-dns-used", &numb ) )
	{
		if( numb )
		{
			xconf.opts |= ( IPSEC_OPTS_DNSS | IPSEC_OPTS_DOMAIN );
			xconf.rqst |= ( IPSEC_OPTS_DNSS | IPSEC_OPTS_DOMAIN );

			numb = 0;
			config.get_number( "client-dns-auto", &numb );

			if( !numb )
			{
				// dns server address

				if( !config.get_string( "client-dns-addr", text, MAX_CONFSTRING, 0 ) )
				{
					log( STATUS_FAIL, "config error : client-dns-addr undefined\n" );
					return;
				}

				xconf.nscfg.dnss_list[ 0 ].s_addr = inet_addr( text );
				xconf.nscfg.dnss_count = 1;
				xconf.rqst &= ~IPSEC_OPTS_DNSS;

				// domain name suffix

				if( !config.get_string( "client-dns-suffix", text, MAX_CONFSTRING, 0 ) )
				{
					xconf.opts &= ~IPSEC_OPTS_DOMAIN;
					xconf.rqst &= ~IPSEC_OPTS_DOMAIN;
				}
				else
					strncpy( xconf.nscfg.suffix, text, CONF_STRLEN );
			}
		}
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
		xconf.rqst |= IPSEC_OPTS_SPLITNET;

		peer.plcy_mode = POLICY_MODE_CONFIG;
	}
	else
	{
		peer.plcy_mode = POLICY_MODE_COMPAT;
	}

	//
	// ---------- CONNECT TO IKED ----------
	//

	IKEI	ikei;
	long	result;
	long	msgres;

	if( ikei.attach( 3000 ) != IPCERR_OK )
	{
		log( STATUS_FAIL, "failed to attach to key daemon ...\n" );
		return;
	}

	log( STATUS_INFO, "attached to key daemon ...\n" );

	//
	// ---------- UPDATE STATE ----------
	//

	active = true;
	cancel = false;

	QApplication::postEvent( r, new RunningEvent( true, host ) );

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
		BDATA user;
		user.set( ikec.username.ascii(), ikec.username.length() );

		msg.set_cfgstr( CFGSTR_CRED_XAUTH_USER, &user );
		result = ikei.send_message( msg, &msgres );

		if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
		{
			log( STATUS_FAIL, "xauth username config failed\n" );
			goto config_failed;
		}

		BDATA pass;
		pass.set( ikec.password.ascii(), ikec.password.length() );

		msg.set_cfgstr( CFGSTR_CRED_XAUTH_PASS, &pass );
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

	config.get_string( "ident-client-data", btext, 0 );
	msg.set_cfgstr( CFGSTR_CRED_LID, &btext );
	result = ikei.send_message( msg, &msgres );

	if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
	{
		log( STATUS_FAIL, "local id config failed\n" );
		goto config_failed;
	}

	log( STATUS_INFO, "local id configured\n" );

	// server id data

	config.get_string( "ident-server-data", btext, 0 );
	msg.set_cfgstr( CFGSTR_CRED_RID, &btext );
	result = ikei.send_message( msg, &msgres );

	if( ( result != IPCERR_OK ) || ( msgres != IKEI_RESULT_OK ) )
	{
		log( STATUS_FAIL, "remote id config failed\n" );
		goto config_failed;
	}

	log( STATUS_INFO, "remote id configured\n" );

	//
	// verify and send our peer authentication info
	//

	if( ( proposal_isakmp.auth_id == HYBRID_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == IKE_AUTH_SIG_RSA ) )
	{
		// server certificate

		if( !config.get_string( "auth-server-cert", btext, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-server-cert undefined\n" );
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
			FilePassData PassData;
			PassData.filepath = text;
			QApplication::postEvent( r, new FilePassEvent( &PassData ) );
			while( PassData.result == -1 )
				msleep( 10 );

			if( PassData.result == QDialog::Rejected )
			{
				log( STATUS_FAIL, "server cert file requires password\n" );
				goto config_failed;
			}

			BDATA fpass;
			fpass.set( PassData.password.ascii(), PassData.password.length() );

			msg.set_cfgstr( CFGSTR_CRED_FILE_PASS, &fpass );
			result = ikei.send_message( msg, &msgres );

			goto server_cert_rety;
		}

		log( STATUS_INFO, "server cert configured\n" );
	}

	if( ( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == IKE_AUTH_SIG_RSA ) )
	{
		// client certificate

		if( !config.get_string( "auth-client-cert", btext, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-client-cert undefined\n" );
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
			FilePassData PassData;
			PassData.filepath = text;
			QApplication::postEvent( r, new FilePassEvent( &PassData ) );
			while( PassData.result == -1 )
				msleep( 10 );

			if( PassData.result == QDialog::Rejected )
			{
				log( STATUS_FAIL, "client cert file requires password\n" );
				goto config_failed;
			}

			BDATA fpass;
			fpass.set( PassData.password.ascii(), PassData.password.length() );

			msg.set_cfgstr( CFGSTR_CRED_FILE_PASS, &fpass );
			result = ikei.send_message( msg, &msgres );

			goto client_cert_rety;
		}

		log( STATUS_INFO, "client cert configured\n" );

		// client private key

		if( !config.get_string( "auth-client-key", btext, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-client-key undefined\n" );
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
			FilePassData PassData;
			PassData.filepath = text;
			QApplication::postEvent( r, new FilePassEvent( &PassData ) );
			while( PassData.result == -1 )
				msleep( 10 );

			if( PassData.result == QDialog::Rejected )
			{
				log( STATUS_FAIL, "client key file requires password\n" );
				goto config_failed;
			}

			BDATA fpass;
			fpass.set( PassData.password.ascii(), PassData.password.length() );

			msg.set_cfgstr( CFGSTR_CRED_FILE_PASS, &fpass );
			result = ikei.send_message( msg, &msgres );

			goto client_pkey_rety;
		}

		log( STATUS_INFO, "client key configured\n" );
	}

	if( ( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_PSK ) ||
		( proposal_isakmp.auth_id == IKE_AUTH_PRESHARED_KEY ) )
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
	// ---------- FEEDBACK LOOP ----------
	//

	long status;

	while( true )
	{
		//
		// get the next message
		//

		result = ikei.recv_message( msg );

		if( result == IPCERR_NODATA )
			continue;

		if( ( result == IPCERR_FAILED ) ||
		    ( result == IPCERR_CLOSED ) )
			break;

		//
		// check for user cancelation
		//

		if( result == IPCERR_WAKEUP )
		{
			msg.set_enable( true );
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
			// enable message
			//

			case IKEI_MSGID_ENABLE:
			
				if( msg.get_enable( &msgres ) != IPCERR_OK )
					break;

				QApplication::postEvent( r, new EnableEvent( msgres ) );

				break;

			//
			// status message
			//

			case IKEI_MSGID_STATUS:
			{
				if( msg.get_status( &status, &btext ) != IPCERR_OK )
					break;

				log( status, btext.text(), btext.size() );

				break;
			}

			//
			// statistics message
			//

			case IKEI_MSGID_STATS:
			{
				IKEI_STATS stats;

				if( msg.get_stats( &stats ) != IPCERR_OK )
					break;

				QApplication::postEvent( r, new StatsEvent( stats ) );

				break;
			}
		}
	}

	config_failed:

	ikei.detach();

	log( STATUS_INFO, "detached from key daemon ...\n" );

	//
	// ---------- UPDATE STATE ----------
	//

	active = false;
	cancel = false;

	QApplication::postEvent( r, new RunningEvent( false, "" ) );

	return;
}
