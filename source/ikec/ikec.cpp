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

bool _IKEC::log( long code, char * format, ... )
{
	char buff[ 1024 ];
	memset( buff, 0, sizeof( buff ) );
	va_list list;
	va_start( list, format );
	vsprintf( buff, format, list );

	r->textBrowserStatus->append( buff );

	return true;
}

void _IKEC::run()
{
	//
	// load the config into ipsecc
	//

	log( STATUS_INFO, "configuring client settings ...\n" );

	char text[ MAX_CONFSTRING ];
	long numb;

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

	r->textLabelRemoteValue->setText( host );

	// network port

	if( !config.get_number( "network-ike-port", &numb ) )
	{
		log( STATUS_FAIL, "config error : network-ike-port undefined\n" );
		return;
	}

	peer.saddr.saddr4.sin_port = htons( ( unsigned short ) numb );

	// client auto config mode

	peer.xconf_mode = CONFIG_MODE_PULL;

	if( config.get_string( "client-auto-mode", text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "push", text ) )
			peer.xconf_mode = CONFIG_MODE_PUSH;
	}

	// nat-t enable

	peer.natt_mode = IPSEC_NATT_DISABLE;

	if( config.get_string( "network-natt-mode", text, MAX_CONFSTRING, 0 ) )
	{
		if( !strcmp( "enable", text ) )
			peer.natt_mode = IPSEC_NATT_ENABLE;

		if( !strcmp( "force", text ) )
			peer.natt_mode = IPSEC_NATT_FORCE;

		// nat-t udp port

		peer.natt_port = htons( 4500 );
		if( config.get_number( "network-natt-port", &numb ) )
			peer.natt_port = htons( ( unsigned short ) numb );

		// nat-t keep-alive rate

		peer.natt_rate = 30;
		if( config.get_number( "network-natt-rate", &numb ) )
			peer.natt_rate = numb;
	}

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
	peer.dpd_rate = 15;

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

	if( !config.get_string( "ident-client-type", text, MAX_CONFSTRING, 0 ) )
	{
		log( STATUS_FAIL, "config error : auth-client-type undefined\n" );
		return;
	}

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

	if( !peer.idtype_l )
	{
		log( STATUS_FAIL, "config error : ident-client-type is invalid\n" );
		return;
	}

	// server identification type

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

	if( !peer.idtype_r )
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

		// enable wins options

		numb = 0;
		if( config.get_number( "client-wins-used", &numb ) )
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

					xconf.nbns.s_addr = inet_addr( text );
					xconf.rqst &= ~IPSEC_OPTS_NBNS;
				}
			}
		}
	}

	// enable dns options

	if( config.get_number( "client-dns-enable", &numb ) )
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

				xconf.dnss.s_addr = inet_addr( text );
				xconf.rqst &= ~IPSEC_OPTS_DNSS;

				// domain name suffix

				if( config.get_string( "client-dns-suffix", text, MAX_CONFSTRING, 0 ) )
				{
					strncpy( xconf.suffix, text, CONF_STRLEN );
					xconf.rqst &= ~IPSEC_OPTS_DOMAIN;
				}
			}
		}
	}

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
	// ---------- UPLOAD CONFIG ----------
	//

	IKEI	ikei;
	long	result;
	long	msgres;

	result = ikei.attach( 10000 );

	if( result != IKEI_OK )
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

	QApplication::postEvent( r, new QCustomEvent( EVENT_CONNECTING ) );

	//
	// send the peer configuration message
	//

	result = ikei.send_msg_peer( &peer, &msgres );

	if( ( result != IKEI_OK ) || ( msgres != IKEI_OK ) )
	{
		log( STATUS_FAIL, "peer config failed\n" );
		goto config_failed;
	}

	log( STATUS_INFO, "peer configured\n" );

	//
	// send proposal config messages
	//

	result = ikei.send_msg_proposal( &proposal_isakmp, &msgres );

	if( ( result != IKEI_OK ) || ( msgres != IKEI_OK ) )
	{
		log( STATUS_FAIL, "isakmp proposal config failed\n" );
		goto config_failed;
	}

	log( STATUS_INFO, "iskamp proposal configured\n" );

	result = ikei.send_msg_proposal( &proposal_esp, &msgres );

	if( ( result != IKEI_OK ) || ( msgres != IKEI_OK ) )
	{
		log( STATUS_FAIL, "esp proposal config failed\n" );
		goto config_failed;
	}

	log( STATUS_INFO, "esp proposal configured\n" );

	if( proposal_ipcomp.xform )
	{
		result = ikei.send_msg_proposal( &proposal_ipcomp, &msgres );

		if( ( result != IKEI_OK ) || ( msgres != IKEI_OK ) )
		{
			log( STATUS_FAIL, "ipcomp proposal config failed\n" );
			goto config_failed;
		}

		log( STATUS_INFO, "ipcomp proposal configured\n" );
	}

	//
	// send the client configuration message
	//

	result = ikei.send_msg_client( &xconf, &msgres );

	if( ( result != IKEI_OK ) || ( msgres != IKEI_OK ) )
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
		r->lineEditUsername->text().ascii();

		ikei.send_msg_cfgstr( CFGSTR_CRED_XAUTH_USER,
			( char * ) r->lineEditUsername->text().ascii(),
			r->lineEditUsername->text().length() );

		ikei.send_msg_cfgstr( CFGSTR_CRED_XAUTH_PASS,
			( char * ) r->lineEditPassword->text().ascii(),
			r->lineEditPassword->text().length() );
	}

	//
	// verify and send our identity info
	//

	// client id data

	if( !config.get_string( "ident-client-data", text, MAX_CONFSTRING, 0 ) )
	{
		
		if( ( peer.idtype_l == ISAKMP_ID_KEY_ID ) ||
			( peer.idtype_l == ISAKMP_ID_FQDN ) ||
			( peer.idtype_l == ISAKMP_ID_USER_FQDN ) )
		{
			log( STATUS_FAIL, "config error : ident-client-data undefined\n" );
			goto config_failed;
		}
	}
	else
	{
		result = ikei.send_msg_cfgstr( CFGSTR_CRED_LID, text, strlen( text ), &msgres );

		if( ( result != IKEI_OK ) || ( msgres != IKEI_OK ) )
		{
			log( STATUS_FAIL, "local id config failed\n" );
			goto config_failed;
		}

		log( STATUS_INFO, "local id configured\n" );
	}

	// server id data

	if( !config.get_string( "ident-server-data", text, MAX_CONFSTRING, 0 ) )
	{
		if( ( peer.idtype_r == ISAKMP_ID_KEY_ID ) ||
			( peer.idtype_r == ISAKMP_ID_FQDN ) ||
			( peer.idtype_r == ISAKMP_ID_USER_FQDN ) )
		{
			log( STATUS_FAIL, "config error : ident-server-data undefined\n" );
			goto config_failed;
		}
	}
	else
	{
		result = ikei.send_msg_cfgstr( CFGSTR_CRED_RID, text, strlen( text ), &msgres );

		if( ( result != IKEI_OK ) || ( msgres != IKEI_OK ) )
		{
			log( STATUS_FAIL, "remote id config failed\n" );
			goto config_failed;
		}

		log( STATUS_INFO, "remote id configured\n" );
	}

	//
	// verify and send our peer authentication info
	//

	if( ( proposal_isakmp.auth_id == HYBRID_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == IKE_AUTH_SIG_RSA ) )
	{
		// server certificate

		if( !config.get_string( "auth-server-cert", text, MAX_CONFSTRING, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-server-cert undefined\n" );
			goto config_failed;
		}

		server_cert_rety:

		result = ikei.send_msg_cfgstr( CFGSTR_CRED_RSA_RCRT, text, strlen( text ), &msgres );

		if( ( result == IKEI_FAILED ) || ( msgres == IKEI_FAILED ) )
		{
			log( STATUS_FAIL, "server cert config failed\n" );
			goto config_failed;
		}

		if( msgres == IKEI_PASSWD )
		{
/*			if( !DialogBoxParam(
					hinst,
					( LPCTSTR ) IDD_FILEPASS,
					hw_main,
					( DLGPROC ) dproc_filepass,
					( long ) text ) )
			{
				log( STATUS_FAIL, "server cert file requires password\n" );
				goto config_failed;
			}

			ikei.send_msg_cfgstr( CFGSTR_CRED_FILE_PASS, filepass, strlen( filepass ) );
			goto server_cert_rety;
*/		}

		log( STATUS_INFO, "server cert configured\n" );
	}

	if( ( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_RSA ) ||
		( proposal_isakmp.auth_id == IKE_AUTH_SIG_RSA ) )
	{
		// client certificate

		if( !config.get_string( "auth-client-cert", text, MAX_CONFSTRING, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-client-cert undefined\n" );
			goto config_failed;
		}

		client_cert_rety:

		result = ikei.send_msg_cfgstr( CFGSTR_CRED_RSA_LCRT, text, strlen( text ), &msgres );

		if( ( result == IKEI_FAILED ) || ( msgres == IKEI_FAILED ) )
		{
			log( STATUS_FAIL, "client cert config failed\n" );
			goto config_failed;
		}

		if( msgres == IKEI_PASSWD )
		{
/*			if( !DialogBoxParam(
					hinst,
					( LPCTSTR ) IDD_FILEPASS,
					hw_main,
					( DLGPROC ) dproc_filepass,
					( long ) text ) )
			{
				log( STATUS_FAIL, "client cert file requires password\n" );
				goto config_failed;
			}

			ikei.send_msg_cfgstr( CFGSTR_CRED_FILE_PASS, filepass, strlen( filepass ) );
			goto client_cert_rety;
*/		}

		log( STATUS_INFO, "client cert configured\n" );

		// client private key

		if( !config.get_string( "auth-client-key", text, MAX_CONFSTRING, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-client-key undefined\n" );
			goto config_failed;
		}

		client_pkey_rety:

		result = ikei.send_msg_cfgstr( CFGSTR_CRED_RSA_LKEY, text, strlen( text ), &msgres );

		if( ( result == IKEI_FAILED ) || ( msgres == IKEI_FAILED ) )
		{
			log( STATUS_FAIL, "client key config failed\n" );
			goto config_failed;
		}

		if( msgres == IKEI_PASSWD )
		{
/*			if( !DialogBoxParam(
					hinst,
					( LPCTSTR ) IDD_FILEPASS,
					hw_main,
					( DLGPROC ) dproc_filepass,
					( long ) text ) )
			{
				log( STATUS_FAIL, "client key file requires password\n" );
				goto client_pkey_rety;
			}
*/		}

		log( STATUS_INFO, "client key configured\n" );
	}

	if( ( proposal_isakmp.auth_id == XAUTH_AUTH_INIT_PSK ) ||
		( proposal_isakmp.auth_id == IKE_AUTH_PRESHARED_KEY ) )
	{
		// mutual preshared key

		if( !config.get_string( "auth-mutual-psk", text, MAX_CONFSTRING, 0 ) )
		{
			log( STATUS_FAIL, "config error : auth-mutual-psk undefined\n" );
			goto config_failed;
		}

		result = ikei.send_msg_cfgstr( CFGSTR_CRED_PSK, text, strlen( text ), &msgres );
		if( ( result != IKEI_OK ) || ( msgres != IKEI_OK ) )
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
		while( config.get_string( "client-splitdns-list", text, MAX_CONFSTRING, index++ ) )
			ikei.send_msg_cfgstr( CFGSTR_SPLIT_DOMAIN, text, strlen( text ) );
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

			ikei.recv_msg_network( &ph2id, UNITY_SPLIT_EXCLUDE );

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

			ikei.recv_msg_network( &ph2id, UNITY_SPLIT_INCLUDE );

			index++;
		}
	}

	//
	// ---------- ENABLE TUNNEL ----------
	//

	if( !ikei.send_msg_enable( true ) )
		return;

	//
	// ---------- FEEDBACK LOOP ----------
	//

	long status;

	while( true )
	{
		//
		// check for user cancelation
		//

		if( cancel == true )
			if( !ikei.send_msg_enable( false ) )
				break;

		//
		// get the next message
		//

		IKEI_MSG msg;
		result = ikei.next_msg( msg );

		if( result == IKEI_NODATA )
			continue;

		if( result == IKEI_FAILED )
			break;

		//
		// evaluate the message
		//

		switch( msg.type )
		{
			case IKEI_MSGID_ENABLE:
			
				result = ikei.recv_msg_enable( &msgres );
				if( result != IKEI_OK )
					break;

				if( msgres )
					log( STATUS_WARN, "bringing up tunnel ...\n" );
				else
					log( STATUS_WARN, "bringing down tunnel ...\n" );

				break;

			case IKEI_MSGID_STATS:
			{
				IKEI_STATS stats;

				result = ikei.recv_msg_stats( &stats );
				if( result != IKEI_OK )
					break;

				QString n;

				n.setNum( stats.sa_good );
				r->textLabelEstablishedValue->setText( n );

				n.setNum( stats.sa_dead );
				r->textLabelExpiredValue->setText( n );

				n.setNum( stats.sa_fail );
				r->textLabelFailedValue->setText( n );

				if( stats.natt )
					r->textLabelTransportValue->setText( "NAT-T / IKE | ESP" );
				else
					r->textLabelTransportValue->setText( "IKE | ESP" );

				if( stats.frag )
					r->textLabelFragValue->setText( "Enabled" );
				else
					r->textLabelFragValue->setText( "Disabled" );

				if( stats.dpd )
					r->textLabelDPDValue->setText( "Enabled" );
				else
					r->textLabelDPDValue->setText( "Disabled" );

				break;
			}

			//
			// status message
			//

			case IKEI_MSGID_STATUS:
			{
				char	txtmsg[ IKEI_MAX_BDATA + 1 ] = { 0 };
				long	txtlen = IKEI_MAX_BDATA;

				result = ikei.recv_msg_status( &status, txtmsg, txtlen );
				if( result != IKEI_OK )
					break;

				switch( status )
				{
					case STATUS_BANNER:

						ikec.banner = txtmsg;
						QApplication::postEvent( r, new QCustomEvent( EVENT_BANNER ) );

						break;

					case STATUS_ENABLED:

						QApplication::postEvent( r, new QCustomEvent( EVENT_CONNECTED ) );

						log( status, txtmsg );

						break;

					case STATUS_DISABLED:
					case STATUS_INFO:
					case STATUS_WARN:
					case STATUS_FAIL:

						log( status, txtmsg );

						break;

					default:

						log( STATUS_FAIL, "!!! unknown status message !!!\n" );
				}

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

	QApplication::postEvent( r, new QCustomEvent( EVENT_DISCONNECTED ) );

	return;
}
