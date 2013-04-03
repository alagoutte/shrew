
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

%{

#include <cstdlib>
#include <errno.h>
#include <limits.h>
#include <string>
#include "iked.h"
#include "conf.parse.hpp"

#define YY_DECL                                     \
    yy::conf_parser::token_type                     \
    yylex( yy::conf_parser::semantic_type * yylval, \
    yy::conf_parser::location_type * yylloc,        \
    IKED & iked )

YY_DECL;


#define yyterminate() return token::END

int yy_first_time = 1;

%}

%option noyywrap nounput batch debug

/*
 * TYPES
 *
 */

nl	\n
ws	[ \t]+
semic	\;
bcb	\{
ecb	\}
quoted	\"[^"]*\"
number	[0-9]+
label   [0-9A-Za-z_\-]+
network	[0-9\.]+"/"[0-9]+
address	[0-9\.]+
comment	\#.*

/*
 * SECTIONS
 *
 */

%s SEC_ROOT
%s SEC_DAEMON
%s SEC_NETGROUP
%s SEC_XA_LDAP
%s SEC_XC_LOCAL
%s SEC_PEER
%s SEC_PLCY
%s SEC_PROP

%{
#define YY_USER_ACTION  yylloc->columns( yyleng );
%}

%%

%{
	yylloc->step();
%}

%{

typedef yy::conf_parser::token token;

if( yy_first_time )
{
	BEGIN SEC_ROOT;
	yy_first_time = 0;
}

%}

<SEC_ROOT>daemon		{ BEGIN SEC_DAEMON; return( token::DAEMON ); }
<SEC_DAEMON>{bcb}		{ return( token::BCB ); }
<SEC_DAEMON>socket		{ return( token::SOCK ); }
<SEC_DAEMON>ike			{ return( token::IKE ); }
<SEC_DAEMON>natt		{ return( token::NATT ); }
<SEC_DAEMON>syslog		{ return( token::SYSLOG ); }
<SEC_DAEMON>none		{ return( token::LL_NONE ); }
<SEC_DAEMON>error		{ return( token::LL_ERROR ); }
<SEC_DAEMON>info		{ return( token::LL_INFO ); }
<SEC_DAEMON>debug		{ return( token::LL_DEBUG ); }
<SEC_DAEMON>loud		{ return( token::LL_LOUD ); }
<SEC_DAEMON>decode		{ return( token::LL_DECODE ); }
<SEC_DAEMON>log_level		{ return( token::LOG_LEVEL ); }
<SEC_DAEMON>log_file		{ return( token::LOG_FILE ); }
<SEC_DAEMON>dhcp_file		{ return( token::DHCP_FILE ); }
<SEC_DAEMON>pcap_decrypt	{ return( token::PCAP_DECRYPT ); }
<SEC_DAEMON>pcap_encrypt	{ return( token::PCAP_ENCRYPT ); }
<SEC_DAEMON>retry_delay		{ return( token::RETRY_DELAY ); }
<SEC_DAEMON>retry_count		{ return( token::RETRY_COUNT ); }
<SEC_DAEMON>{ecb}		{ BEGIN SEC_ROOT; return( token::ECB ); }

<SEC_ROOT>netgroup		{ BEGIN SEC_NETGROUP; return( token::NETGROUP ); }
<SEC_NETGROUP>{bcb}		{ return( token::BCB ); }
<SEC_NETGROUP>{ecb}		{ BEGIN SEC_ROOT; return( token::ECB ); }

<SEC_ROOT>xauth_ldap		{ BEGIN SEC_XA_LDAP; return( token::XAUTH_LDAP ); }
<SEC_XA_LDAP>{bcb}		{ return( token::BCB ); }
<SEC_XA_LDAP>version		{ return( token::LD_VERSION ); }
<SEC_XA_LDAP>url		{ return( token::LD_URL ); }
<SEC_XA_LDAP>base		{ return( token::LD_BASE ); }
<SEC_XA_LDAP>subtree		{ return( token::LD_SUBTREE ); }
<SEC_XA_LDAP>enable		{ return( token::ENABLE ); }
<SEC_XA_LDAP>disable		{ return( token::DISABLE ); }
<SEC_XA_LDAP>bind_dn		{ return( token::LD_BIND_DN ); }
<SEC_XA_LDAP>bind_pw		{ return( token::LD_BIND_PW ); }
<SEC_XA_LDAP>attr_user		{ return( token::LD_ATTR_USER ); }
<SEC_XA_LDAP>attr_group		{ return( token::LD_ATTR_GROUP ); }
<SEC_XA_LDAP>attr_member	{ return( token::LD_ATTR_MEMBER ); }
<SEC_XA_LDAP>{ecb}		{ BEGIN SEC_ROOT; return( token::ECB ); }

<SEC_ROOT>xconf_local		{ BEGIN SEC_XC_LOCAL; return( token::XCONF_LOCAL ); }
<SEC_XC_LOCAL>{bcb}		{ return( token::BCB ); }
<SEC_XC_LOCAL>network4		{ return( token::NETWORK4 ); }
<SEC_XC_LOCAL>dnss4		{ return( token::DNSS4 ); }
<SEC_XC_LOCAL>nbns4		{ return( token::NBNS4 ); }
<SEC_XC_LOCAL>dns_suffix	{ return( token::DNS_SUFFIX ); }
<SEC_XC_LOCAL>dns_list		{ return( token::DNS_LIST ); }
<SEC_XC_LOCAL>banner		{ return( token::BANNER ); }
<SEC_XC_LOCAL>pfs_group		{ return( token::PFS_GROUP ); }
<SEC_XC_LOCAL>{ecb}		{ BEGIN SEC_ROOT; return( token::ECB ); }

<SEC_ROOT>peer			{ BEGIN SEC_PEER; return( token::PEER ); }
<SEC_PEER>{bcb}			{ return( token::BCB ); }
<SEC_PEER>contact		{ return( token::CONTACT ); }
<SEC_PEER>initiator		{ return( token::INITIATOR ); }
<SEC_PEER>responder		{ return( token::RESPONDER ); }
<SEC_PEER>exchange		{ return( token::EXCHANGE ); }
<SEC_PEER>main			{ return( token::MAIN ); }
<SEC_PEER>aggressive		{ return( token::AGGRESSIVE ); }
<SEC_PEER>enable		{ return( token::ENABLE ); }
<SEC_PEER>disable		{ return( token::DISABLE ); }
<SEC_PEER>force			{ return( token::FORCE ); }
<SEC_PEER>draft			{ return( token::DRAFT ); }
<SEC_PEER>rfc			{ return( token::RFC ); }
<SEC_PEER>natt_mode		{ return( token::NATT_MODE ); }
<SEC_PEER>natt_rate		{ return( token::NATT_RATE ); }
<SEC_PEER>dpd_mode		{ return( token::DPD_MODE ); }
<SEC_PEER>dpd_delay		{ return( token::DPD_DELAY ); }
<SEC_PEER>dpd_retry		{ return( token::DPD_RETRY ); }
<SEC_PEER>frag_ike_mode		{ return( token::FRAG_IKE_MODE ); }
<SEC_PEER>frag_ike_size		{ return( token::FRAG_IKE_SIZE ); }
<SEC_PEER>frag_esp_mode		{ return( token::FRAG_ESP_MODE ); }
<SEC_PEER>frag_esp_size		{ return( token::FRAG_ESP_SIZE ); }
<SEC_PEER>peerid		{ return( token::PEERID ); }
<SEC_PEER>local			{ return( token::LOCAL ); }
<SEC_PEER>remote		{ return( token::REMOTE ); }
<SEC_PEER>address		{ return( token::ADDR ); }
<SEC_PEER>fqdn			{ return( token::FQDN ); }
<SEC_PEER>ufqdn			{ return( token::UFQDN ); }
<SEC_PEER>keyid			{ return( token::KEYID ); }
<SEC_PEER>asn1dn		{ return( token::ASN1DN ); }
<SEC_PEER>authdata		{ return( token::AUTHDATA ); }
<SEC_PEER>psk			{ return( token::PSK ); }
<SEC_PEER>ca			{ return( token::CA ); }
<SEC_PEER>cert			{ return( token::CERT ); }
<SEC_PEER>pkey			{ return( token::PKEY ); }
<SEC_PEER>life_check		{ return( token::LIFE_CHECK ); }
<SEC_PEER>obey			{ return( token::OBEY ); }
<SEC_PEER>claim			{ return( token::CLAIM ); }
<SEC_PEER>strict		{ return( token::STRICT ); }
<SEC_PEER>exact			{ return( token::EXACT ); }
<SEC_PEER>xauth_source		{ return( token::XAUTH_SOURCE ); }
<SEC_PEER>xconf_source		{ return( token::XCONF_SOURCE ); }
<SEC_PEER>pull			{ return( token::PULL ); }
<SEC_PEER>push			{ return( token::PUSH ); }
<SEC_PEER>system		{ return( token::LOCAL ); }
<SEC_PEER>ldap			{ return( token::LDAP ); }
<SEC_PEER>plcy_mode		{ return( token::PLCY_MODE ); }
<SEC_PEER>config		{ return( token::CONFIG ); }
<SEC_PEER>compat		{ return( token::COMPAT ); }
<SEC_PEER>plcy_list		{ BEGIN SEC_PLCY; return( token::PLCY_LIST ); }
<SEC_PEER>proposal		{ BEGIN SEC_PROP; return( token::PROPOSAL ); }
<SEC_PEER>{ecb}			{ BEGIN SEC_ROOT; return( token::ECB ); }

<SEC_PLCY>{bcb}			{ return( token::BCB ); }
<SEC_PLCY>include		{ return( token::INCLUDE ); }
<SEC_PLCY>exclude		{ return( token::EXCLUDE ); }
<SEC_PLCY>{ecb}			{ BEGIN SEC_PEER; return( token::ECB ); }

<SEC_PROP>{bcb}			{ return( token::BCB ); }
<SEC_PROP>isakmp		{ return( token::ISAKMP ); }
<SEC_PROP>ah			{ return( token::AH ); }
<SEC_PROP>esp			{ return( token::ESP ); }
<SEC_PROP>ipcomp		{ return( token::IPCOMP ); }
<SEC_PROP>auth			{ return( token::AUTH ); }
<SEC_PROP>hybrid_xauth_rsa	{ return( token::HYB_XA_RSA ); }
<SEC_PROP>mutual_xauth_rsa	{ return( token::MUT_XA_RSA ); }
<SEC_PROP>mutual_xauth_psk	{ return( token::MUT_XA_PSK ); }
<SEC_PROP>mutual_rsa		{ return( token::MUT_RSA ); }
<SEC_PROP>mutual_psk		{ return( token::MUT_PSK ); }
<SEC_PROP>ciph			{ return( token::CIPH ); }
<SEC_PROP>klen			{ return( token::KLEN ); }
<SEC_PROP>hash			{ return( token::HASH ); }
<SEC_PROP>hmac			{ return( token::MSGA ); }
<SEC_PROP>dhgr			{ return( token::DHGR ); }
<SEC_PROP>comp			{ return( token::COMP ); }
<SEC_PROP>aes			{ return( token::ALG_AES ); }
<SEC_PROP>blowfish		{ return( token::ALG_BLOWFISH ); }
<SEC_PROP>3des			{ return( token::ALG_3DES ); }
<SEC_PROP>cast			{ return( token::ALG_CAST ); }
<SEC_PROP>des			{ return( token::ALG_DES ); }
<SEC_PROP>md5			{ return( token::ALG_MD5 ); }
<SEC_PROP>sha1			{ return( token::ALG_SHA1 ); }
<SEC_PROP>sha2_256		{ return( token::ALG_SHA2_256 ); }
<SEC_PROP>sha2_384		{ return( token::ALG_SHA2_384 ); }
<SEC_PROP>sha2_512		{ return( token::ALG_SHA2_512 ); }
<SEC_PROP>deflate		{ return( token::ALG_DEFLATE ); }
<SEC_PROP>lzs			{ return( token::ALG_LZS ); }
<SEC_PROP>life_sec		{ return( token::LIFE_SEC ); }
<SEC_PROP>life_kbs		{ return( token::LIFE_KBS ); }
<SEC_PROP>{ecb}			{ BEGIN SEC_PEER; return( token::ECB ); }

{ws}+		;
{comment}	;
{nl}+		yylloc->lines( yyleng );
{semic}		return( token::EOS );

{quoted} {

	int len = strlen( yytext );
	if( len < 3 )
		return token::SEQ;

	yylval->bval = new BDATA;
	yylval->bval->set( yytext + 1, len - 2 );
	yylval->bval->add( 0, 1 );

	return token::QUOTED;
}

{number} {

	yylval->ival = strtol( yytext, NULL, 10 );

	return token::NUMBER;
}

{label} {

	yylval->bval = new BDATA;
	yylval->bval->set( yytext, strlen( yytext ) );
	yylval->bval->add( 0, 1 );

	return token::LABEL;
}

{network} {

	yylval->bval = new BDATA;
	yylval->bval->set( yytext, strlen( yytext ) );
	yylval->bval->add( 0, 1 );

	return token::NETWORK;
}

{address} {

	yylval->bval = new BDATA;
	yylval->bval->set( yytext, strlen( yytext ) );
	yylval->bval->add( 0, 1 );

	return token::ADDRESS;
}

<<EOF>> {
	yyterminate();
}

.	return token::SEQ;

%%

/*
 * PROGRAM
 *
 */

bool _IKED::conf_load( const char * path, bool trace )
{
	//
	// set some defaults
	//

	level = LOG_DEBUG;

	if( path_conf[ 0 ] == 0 )
		snprintf( path_conf, MAX_PATH, "%s/iked.conf", path );

	if( path_log[ 0 ] == 0 )
		snprintf( path_log, MAX_PATH, "%s/iked.log", PATH_DEBUG );

	snprintf( path_dhcp, MAX_PATH, "%s/iked.dhcp", path );

	//
	// open file and run parser
	//
	
	yy_flex_debug = trace;
	if( !( yyin = fopen( path_conf, "r" ) ) )
	{
		log.txt( LLOG_ERROR, "!! : unable to open %s\n", path_conf );
		return false;
	}

	log.txt( LOG_INFO, "ii : reading config %s\n", path_conf );

	yy::conf_parser parser( *this );
	parser.set_debug_level( trace );

	parser.parse();
 
	fclose( yyin );

	return !conf_fail;
}
