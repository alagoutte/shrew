
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
// XCONF - BASE CLASS
//

_IKED_XCONF::~_IKED_XCONF()
{
	delete [] pool4_array;
}

bool _IKED_XCONF::pool4_set( in_addr & base, long bits, long max )
{
	//
	// calculate network mask and addr
	//

	config.mask.s_addr = 0;

	for( long i = 0; i < bits; i++ )
	{
		config.mask.s_addr >>= 1;
		config.mask.s_addr |= 0x80000000;
	}

	config.mask.s_addr = htonl( config.mask.s_addr );
	config.addr.s_addr = base.s_addr & config.mask.s_addr;

	if( pool4_array != NULL )
		delete [] pool4_array;

	//
	// calculate max total addresses
	// for the given network and the
	// first and last usable address
	//

	long len = ntohl( base.s_addr | ~config.mask.s_addr ) -
			   ntohl( base.s_addr ) + 1; 

	if( max )
	{
		if( max <= len )
			pool4_total = max;
		else
			pool4_total = len;
	}
	else
		pool4_total = len;

	in_addr last;
	last.s_addr = htonl( ntohl( base.s_addr ) + pool4_total - 1 );

	static const char * adj = "( adjusted )";
	static const char * org = "";
	const char * adj_base = org;
	const char * adj_last = org;

	if( base.s_addr == config.addr.s_addr )
	{
		if( max )
			adj_base = adj;

		base.s_addr = htonl( ntohl( base.s_addr ) + 1 );
		pool4_total--;
	}

	if( last.s_addr == ( base.s_addr | ~config.mask.s_addr ) )
	{
		if( max )
			adj_last = adj;

		last.s_addr = htonl( ntohl( last.s_addr ) - 1 );
		pool4_total--;
	}

	//
	// create our address pool
	//

	pool4_array = new POOL4[ pool4_total ];
	if( pool4_array == NULL )
		return false;

	for( long a = 0; a < pool4_total; a++ )
	{
		pool4_array[ a ].addr.s_addr = htonl( ntohl( base.s_addr ) + a );
		pool4_array[ a ].used = false;
	}

	char txtaddr[ LIBIKE_MAX_TEXTADDR ];
	char txtmask[ LIBIKE_MAX_TEXTADDR ];
	char txtbase[ LIBIKE_MAX_TEXTADDR ];
	char txtlast[ LIBIKE_MAX_TEXTADDR ];

	iked.text_addr( txtaddr, config.addr );
	iked.text_addr( txtmask, config.mask );
	iked.text_addr( txtbase, base );
	iked.text_addr( txtlast, last );

	iked.log.txt( LLOG_DEBUG,
		"ii : created %s address pool\n"
		"ii : - network   %s\n"
		"ii : - netmask   %s\n"
		"ii : - base addr %s %s\n"
		"ii : - last addr %s %s\n"
		"ii : - available %i\n",
		name(),
		txtaddr,
		txtmask,
		txtbase,
		adj_base,
		txtlast,
		adj_last,
		pool4_total );

	return true;
}

bool _IKED_XCONF::pool4_get( in_addr & addr )
{
	if( pool4_inuse == pool4_total )
		return false;

	pool4_lock.lock();

	long index = 0;
	for( ; index < pool4_total; index++ )
	{
		if( !pool4_array[ index ].used )
		{
			addr = pool4_array[ index ].addr;
			pool4_array[ index ].used = true;

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			iked.text_addr( txtaddr, addr );

			iked.log.txt( LLOG_DEBUG,
				"ii : address %s aquired from %s pool\n",
				txtaddr,
				name() );

			break;
		}
	}

	pool4_lock.unlock();

	return ( index < pool4_total );
}

bool _IKED_XCONF::pool4_rel( in_addr & addr )
{
	pool4_lock.lock();

	long index = 0;
	for( ; index < pool4_total; index++ )
	{
		if( pool4_array[ index ].used )
		{
			if( addr.s_addr == pool4_array[ index ].addr.s_addr )
			{
				pool4_array[ index ].used = false;

				char txtaddr[ LIBIKE_MAX_TEXTADDR ];
				iked.text_addr( txtaddr, addr );

				iked.log.txt( LLOG_DEBUG,
					"ii : address %s returned to %s pool\n",
					txtaddr,
					name() );

				break;
			}
		}
	}

	pool4_lock.unlock();

	return ( index < pool4_total );
}

//
// XCONF - LOCAL CONFIG DB
//

static const char * iked_xconf_local_name = "local";

_IKED_XCONF_LOCAL::_IKED_XCONF_LOCAL()
{
}

_IKED_XCONF_LOCAL::~_IKED_XCONF_LOCAL()
{
}

const char * _IKED_XCONF_LOCAL::name()
{
	return iked_xconf_local_name;
}

bool _IKED_XCONF_LOCAL::rslt( IDB_TUNNEL * tunnel )
{
	tunnel->xconf.opts = tunnel->xconf.rqst;
	tunnel->xconf.opts &= config.opts;

	if( tunnel->xconf.opts & IPSEC_OPTS_ADDR )
		pool4_get( tunnel->xconf.addr );

	if( tunnel->xconf.opts & IPSEC_OPTS_MASK )
		tunnel->xconf.mask = config.mask;

	if( tunnel->xconf.opts & IPSEC_OPTS_DNSS )
	{
		memcpy( tunnel->xconf.nscfg.dnss_list,
			config.nscfg.dnss_list,
			sizeof( config.nscfg.dnss_list ) );

		tunnel->xconf.nscfg.dnss_count = config.nscfg.dnss_count;
	}

	if( tunnel->xconf.opts & IPSEC_OPTS_DOMAIN )
		memcpy( tunnel->xconf.nscfg.dnss_suffix,
			config.nscfg.dnss_suffix, CONF_STRLEN );

	if( tunnel->xconf.opts & IPSEC_OPTS_SPLITDNS )
	{
		BDATA suffix;
		long index = 0;
		while( domains.get( suffix, index++ ) )
			tunnel->domains.add( suffix );
	}

	if( tunnel->xconf.opts & IPSEC_OPTS_NBNS )
	{
		memcpy( tunnel->xconf.nscfg.nbns_list,
			config.nscfg.nbns_list,
			sizeof( config.nscfg.nbns_list ) );

		tunnel->xconf.nscfg.nbns_count = config.nscfg.nbns_count;
	}

	if( tunnel->xconf.opts & IPSEC_OPTS_PFS )
		tunnel->xconf.dhgr = config.dhgr;

	if( tunnel->xconf.opts & IPSEC_OPTS_BANNER )
		tunnel->banner.set( banner );

	return true;
}
