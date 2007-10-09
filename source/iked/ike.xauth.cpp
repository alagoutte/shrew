
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

#include "iked.h"

//
// XAUTH - BASE CLASS
//

_IKED_XAUTH::~_IKED_XAUTH()
{
}

//
// XAUTH - LOCAL ACCOUNT DB
//

static const char * iked_xauth_local_name = "local";

_IKED_XAUTH_LOCAL::_IKED_XAUTH_LOCAL()
{
}

_IKED_XAUTH_LOCAL::~_IKED_XAUTH_LOCAL()
{
}

const char * _IKED_XAUTH_LOCAL::name()
{
	return iked_xauth_local_name;
}

bool _IKED_XAUTH_LOCAL::auth_pwd( IKE_XAUTH & xauth )
{
	//
	// null terminate username and password
	//

	xauth.user.add( 0, 1 );
	xauth.pass.add( 0, 1 );

	const char * usr = ( const char * ) xauth.user.buff();
	const char * pwd = ( const char * ) xauth.pass.buff();

#ifdef UNIX

	struct passwd * pw = getpwnam( usr );

	if( pw == NULL )
		return false;

	if( pw->pw_uid == 0 )
		return false;

#ifdef OPT_SHADOW

	struct spwd * spw = getspnam( usr );

	if( spw == NULL )
		return false;

	char * syscryptpwd = spw->sp_pwdp;

#else

	char * syscryptpwd = pw->pw_passwd;

#endif

	char * cryptpwd = crypt( pwd, syscryptpwd ); 
	if( cryptpwd == NULL )
		return false;

	if( !strcmp( cryptpwd, syscryptpwd ) )
		return true;

#endif

	return false;
}

bool _IKED_XAUTH_LOCAL::auth_grp( IKE_XAUTH & xauth, BDATA & group )
{

#ifdef UNIX

	const char * usr = ( const char * ) xauth.user.buff();
	const char * grp = ( const char * ) group.buff();

	struct group * gr = getgrnam( grp );
	if( gr == NULL )
		return false;

	char * member;
	int index = 0;
	while( ( member = gr->gr_mem[ index++ ] ) != NULL )
		if( !strcmp( member, usr ) )
			return true;

#endif

	return false;
}

//
// XAUTH - LDAP ACCOUNT DB
//

#ifdef OPT_LDAP

static const char * iked_xauth_ldap_name = "ldap";

_IKED_XAUTH_LDAP::_IKED_XAUTH_LDAP()
{
	//
	// set ldap defaults
	//

	version = 3;
	subtree = false;
	attr_user.set( "cn", strlen( "cn" ) + 1 );
	attr_group.set( "cn", strlen( "cn" ) + 1 );
	attr_member.set( "member", strlen( "member" ) + 1 );
}

_IKED_XAUTH_LDAP::~_IKED_XAUTH_LDAP()
{
}

const char * _IKED_XAUTH_LDAP::name()
{
	return iked_xauth_ldap_name;
}

bool _IKED_XAUTH_LDAP::open_conn( LDAP ** ld )
{
	// initialize the ldap handle

	int res = ldap_initialize( ld, url.text() );
	if( res != LDAP_SUCCESS )
	{
		iked.log.txt( LLOG_ERROR,
			"!! : xauth ldap initialize failed ( %s )\n",
			ldap_err2string( res ) );

		return false;
	}

	// initialize the protocol version

	ldap_set_option( *ld,
		LDAP_OPT_PROTOCOL_VERSION,
		&version );

	//
	// attempt to bind to the ldap server.
    // default to anonymous bind unless a
	// user dn and password has been
	// specified in our configuration
    //

	if( bind_dn.size() && bind_pw.size() )
	{
		struct berval cred;
		cred.bv_val = bind_pw.text();
		cred.bv_len = bind_pw.size() - 1;

		res = ldap_sasl_bind_s(	*ld,
				bind_dn.text(), NULL, &cred,
				NULL, NULL, NULL );
	}
	else
	{
		res = ldap_sasl_bind_s( *ld,
				NULL, NULL, NULL,
				NULL, NULL, NULL );
	}
	
	if( res != LDAP_SUCCESS )
	{
		iked.log.txt( LLOG_ERROR,
			"!! : xauth ldap search bind failed ( %s )\n",
			ldap_err2string( res ) );

		ldap_unbind_ext_s( *ld, NULL, NULL );

		return false;
	}

	return true;
}

bool _IKED_XAUTH_LDAP::auth_pwd( IKE_XAUTH & xauth )
{
	bool result = false;

	LDAP *	ld = NULL;
	BDATA	filter;
	char *	atlist[ 1 ] = { NULL };
	char *	userdn = NULL;
	int		scope = LDAP_SCOPE_ONELEVEL;
	int	ecount = 0;

	LDAPMessage * lr = NULL;
	LDAPMessage * le = NULL;

	// open an ldap connection

	if( !open_conn( &ld ) )
		return false;

	// build an ldap user search filter

	filter.add( attr_user.buff(), attr_user.size() - 1 );
	filter.add( "=", 1 );
	filter.add( xauth.user.buff(), xauth.user.size() - 1 );
	filter.add( 0, 1 );
	
	// attempt to locate the user dn

	if( subtree )
		scope = LDAP_SCOPE_SUBTREE;

	struct timeval timeout;
	timeout.tv_sec = 15;
	timeout.tv_usec = 0;

	int res = ldap_search_ext_s( ld,
				base.text(),
				scope,
				filter.text(),
				atlist,
				0,
				NULL,
				NULL,
				&timeout,
				2,
				&lr );

	if( res != LDAP_SUCCESS )
	{
		iked.log.txt( LLOG_ERROR,
			"!! : xauth ldap user search failed ( %s )\n",
			ldap_err2string( res ) );

		goto ldap_pwd_end;
	}

	// check the number of ldap entries returned

	ecount = ldap_count_entries(ld, lr);
	if( ecount < 1 )
		goto ldap_pwd_end;

	if( ecount > 1 )
	{
		iked.log.txt( LLOG_ERROR,
			"!! : warning, ldap return multiple results for user %s\n",
			xauth.user.buff() );
	}

	// obtain the first result entry

	le = ldap_first_entry( ld, lr );

	if( le == NULL )
	{
		iked.log.txt( LLOG_ERROR,
			"!! : xauth ldap unable to read result entry" );

		goto ldap_pwd_end;
	}

	// obtain the result entry dn

	userdn = ldap_get_dn( ld, le );

	if( userdn == NULL )
	{
		iked.log.txt( LLOG_ERROR,
			"!! : xauth ldap unable to read result dn" );

		goto ldap_pwd_end;
	}

	// cache the user dn in the xauth state

	xauth.context.set( userdn, strlen( userdn ) + 1 );

	//
	// finally, use the dn and the xauth
	// password to check the users given
	// credentials by attempting to bind
	// to the ldap server
	//

	struct berval cred;
	cred.bv_val = ( char * ) xauth.pass.buff();
	cred.bv_len = xauth.pass.size() - 1;

	res = ldap_sasl_bind_s(
			ld,
			userdn,
			NULL,
			&cred,
			NULL,
			NULL,
			NULL);

	if( res == LDAP_SUCCESS )
		result = true;

ldap_pwd_end:

	// free ldap resources

	if( userdn != NULL )
		ldap_memfree( userdn );

	if( lr != NULL )
		ldap_msgfree( lr );

	ldap_unbind_ext_s( ld, NULL, NULL );

	return result;
}

bool _IKED_XAUTH_LDAP::auth_grp( IKE_XAUTH & xauth, BDATA & group )
{
	bool result = false;

	LDAP *	ld = NULL;
	BDATA	filter;
	char *	atlist[ 1 ] = { NULL };
	int		scope = LDAP_SCOPE_ONELEVEL;
	int	ecount = 0;

	LDAPMessage * lr = NULL;

	// open an ldap connection

	if( !open_conn( &ld ) )
		return false;

	// build an ldap group search filter

	filter.add( "(&(", 3 );
	filter.add( attr_group.buff(), attr_group.size() - 1 );
	filter.add( "=", 1 );
	filter.add( group.buff(), group.size() - 1 );
	filter.add( ")(", 2 );
	filter.add( attr_member.buff(), attr_member.size() - 1 );
	filter.add( "=", 1 );
	filter.add( xauth.context.buff(), xauth.context.size() - 1 );
	filter.add( "))", 2 );
	filter.add( 0, 1 );

	// attempt to locate the group dn

	if( subtree )
		scope = LDAP_SCOPE_SUBTREE;

	struct timeval timeout;
	timeout.tv_sec = 15;
	timeout.tv_usec = 0;

	int res = ldap_search_ext_s( ld,
				base.text(),
				scope,
				filter.text(),
				atlist,
				0,
				NULL,
				NULL,
				&timeout,
				2,
				&lr );

	if( res != LDAP_SUCCESS )
	{
		iked.log.txt( LLOG_ERROR,
			"!! : xauth ldap group search failed ( %s )\n",
			ldap_err2string( res ) );

		goto ldap_grp_end;
	}

	// check the number of ldap entries returned

	ecount = ldap_count_entries( ld, lr );
	if( ecount < 1 )
		goto ldap_grp_end;

	if( ecount > 1 )
	{
		iked.log.txt( LLOG_ERROR,
			"!! : warning, ldap return multiple results for group %s\n",
			group.buff() );
	}

	// found a valid group membership

	result = true;

ldap_grp_end:

	// free ldap resources

	if( lr != NULL )
		ldap_msgfree( lr );

	ldap_unbind_ext_s( ld, NULL, NULL );

	return result;
}

#endif
