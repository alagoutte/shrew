
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

//
// XAUTH abstract class
//

typedef class _IKED_XAUTH
{
	public:

	virtual ~_IKED_XAUTH();

	virtual const char * name() = 0;

	virtual bool	auth_pwd( IKE_XAUTH & xauth ) = 0;
	virtual bool	auth_grp( IKE_XAUTH & xauth, BDATA & group ) = 0;

}IKED_XAUTH;

//
// XAUTH functional classes
//

typedef class _IKED_XAUTH_LOCAL : public _IKED_XAUTH
{
	public:

	_IKED_XAUTH_LOCAL();
	virtual ~_IKED_XAUTH_LOCAL();

	virtual const char * name();

	virtual bool	auth_pwd( IKE_XAUTH & xauth );
	virtual bool	auth_grp( IKE_XAUTH & xauth, BDATA & group );

}IKED_XAUTH_LOCAL;

#ifdef OPT_LDAP

typedef class _IKED_XAUTH_LDAP : public _IKED_XAUTH
{
	protected:

	bool	open_conn( LDAP ** ld );

	public:

	long	version;
	BDATA	url;
	BDATA	base;
	bool	subtree;
	BDATA	bind_dn;
	BDATA	bind_pw;
	BDATA	attr_user;
	BDATA	attr_group;
	BDATA	attr_member;

	_IKED_XAUTH_LDAP();
	virtual ~_IKED_XAUTH_LDAP();

	virtual const char * name();

	virtual bool	auth_pwd( IKE_XAUTH & xauth );
	virtual bool	auth_grp( IKE_XAUTH & xauth, BDATA & group );

}IKED_XAUTH_LDAP;

#endif
