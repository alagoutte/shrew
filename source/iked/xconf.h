
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
// XCONF abstract class
//

typedef struct POOL4
{
	in_addr	addr;
	bool	used;

}POOL4;

typedef class _IKED_XCONF
{
	public:

	POOL4 *		pool4_array;
	long		pool4_inuse;
	long		pool4_total;
	ITH_LOCK	pool4_lock;

	IKE_XCONF		config;
	IDB_LIST_DOMAIN	domains;
	BDATA			banner;

	virtual ~_IKED_XCONF();

	virtual const char * name() = 0;
	virtual bool	rslt( IDB_TUNNEL * tunnel ) = 0;

	bool	pool4_set( in_addr & base, long bits, long max );
	bool	pool4_get( in_addr & addr );
	bool	pool4_rel( in_addr & addr );

}IKED_XCONF;

//
// XCONF functional classes
//

typedef class _IKED_XCONF_LOCAL : public _IKED_XCONF
{
	public:

	_IKED_XCONF_LOCAL();
	virtual ~_IKED_XCONF_LOCAL();

	virtual const char * name();
	virtual bool	rslt( IDB_TUNNEL * tunnel );

}IKED_XCONF_LOCAL;
