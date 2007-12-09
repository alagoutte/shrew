
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
// general network helper functions
//

void _IKED::text_addr( char * text, in_addr & addr )
{
	unsigned long haddr = ntohl( addr.s_addr );

	sprintf_s( text, LIBIKE_MAX_TEXTADDR,
		"%lu.%lu.%lu.%lu",
		0xff & ( haddr >> 24 ),
		0xff & ( haddr >> 16 ),
		0xff & ( haddr >>  8 ),
		0xff & haddr );
}

void _IKED::text_mask( char * text, in_addr & addr )
{
	unsigned long bits;
	unsigned long mask;

	bits = 0;
	mask = ntohl( addr.s_addr );

	while( mask & 0x80000000 )
	{
		mask <<= 1;
		bits++;
	}

	sprintf_s(
		text,
		LIBIKE_MAX_TEXTADDR,
		"%lu",
		bits );
}

void _IKED::text_addr( char * text, sockaddr * saddr, bool port )
{
	switch( saddr->sa_family )
	{
		case AF_INET:
		{
			sockaddr_in * saddr_in = ( sockaddr_in * ) saddr;

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, saddr_in->sin_addr );

			if( port )
			{
				sprintf_s(
					text,
					LIBIKE_MAX_TEXTADDR,
					"%s:%u",
					txtaddr,
					ntohs( saddr_in->sin_port ) );
			}
			else
			{
				sprintf_s(
					text,
					LIBIKE_MAX_TEXTADDR,
					"%s",
					txtaddr );
			}

			break;
		}

		default:

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTADDR,
				"<UNKNOWN AF>" );
	}
}

void _IKED::text_addr( char * text, IKE_SADDR * iaddr, bool port )
{
	text_addr( text, &iaddr->saddr, port );
}

void _IKED::text_addr( char * text, PFKI_ADDR * paddr, bool port, bool netmask )
{
	char txtaddr[ LIBIKE_MAX_TEXTADDR ];
	text_addr( txtaddr, &paddr->saddr, port );

	if( netmask && paddr->prefix )
	{
		sprintf_s(
			text,
			LIBIKE_MAX_TEXTADDR,
			"%s/%u",
			txtaddr,
			paddr->prefix );
	}
	else
	{
		sprintf_s(
			text,
			LIBIKE_MAX_TEXTADDR,
			"%s",
			txtaddr );
	}
}

void _IKED::text_ph1id( char * text, IKE_PH1ID * ph1id )
{
	switch( ph1id->type )
	{
		case ISAKMP_ID_NONE:
		{
			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP1ID,
				"%s",
				find_name( NAME_IDENT, ph1id->type ) );

			break;
		}

		case ISAKMP_ID_IPV4_ADDR:
		{
			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, ph1id->addr );

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP1ID,
				"%s %s",
				find_name( NAME_IDENT, ph1id->type ),
				txtaddr );

			break;
		}

		case ISAKMP_ID_FQDN:
		case ISAKMP_ID_USER_FQDN:
		{
			BDATA varid;
			varid.set( ph1id->varid );
			varid.add( 0, 1 );

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP1ID,
				"%s %s",
				find_name( NAME_IDENT, ph1id->type ),
				varid.buff() );

			break;
		}

		case ISAKMP_ID_ASN1_DN:
		case ISAKMP_ID_ASN1_GN:
		{
			BDATA varid;
			asn1_text( ph1id->varid, varid );
			varid.add( 0, 1 );

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP1ID,
				"%s %s",
				find_name( NAME_IDENT, ph1id->type ),
				varid.buff() );

			break;
		}

		case ISAKMP_ID_KEY_ID:
		{
			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP1ID,
				"%s [ %lu bytes ]",
				find_name( NAME_IDENT, ph1id->type ),
				ph1id->varid.size() );

			break;
		}

		default:

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP1ID,
				"<UNKNOWN P1ID>" );
	}
}

void _IKED::text_ph2id( char * text, IKE_PH2ID * ph2id )
{
	char txtaddr1[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr2[ LIBIKE_MAX_TEXTADDR ];

	switch( ph2id->type )
	{
		case ISAKMP_ID_IPV4_ADDR:

			text_addr( txtaddr1, ph2id->addr1 );

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"%s",
				txtaddr1 );

			break;

		case ISAKMP_ID_IPV4_ADDR_SUBNET:

			text_addr( txtaddr1, ph2id->addr1 );
			text_mask( txtaddr2, ph2id->addr2 );

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"%s/%s",
				txtaddr1,
				txtaddr2 );

			break;

		case ISAKMP_ID_IPV4_ADDR_RANGE:

			text_addr( txtaddr1, ph2id->addr1 );
			text_addr( txtaddr2, ph2id->addr2 );

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"%s-%s",
				txtaddr1,
				txtaddr2 );

			break;

		default:

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"<UNKNOWN P2ID>" );
	}
}

bool _IKED::find_addr_r( sockaddr_in & raddr, unsigned short rport, char * rname )
{
	//
	// trim whitespaces from the
	// hostname or address string
	//

	if( !rname  )
		return false;

	if( !( *rname ) )
		return false;

	while( rname && *rname == ' ' )
		rname++;

	//
	// determine if this is an ip
	// address or hostname. convert
	// this into a sockaddr struct
	//

	long rsize = sizeof( sockaddr_in );
	memset( &raddr, 0, rsize );

	if( isdigit( rname[ 0 ] ) )
	{
		//
		// looks like an address 
		//

		raddr.sin_family		= AF_INET;
		raddr.sin_addr.s_addr	= inet_addr( rname );
		raddr.sin_port			= htons( rport );
	}
	else
	{
		//
		// looks like a hostname
		//

		struct hostent * hp = gethostbyname( rname );
		if( !hp )
			return false;

		memcpy( &raddr.sin_addr, hp->h_addr, hp->h_length );
		raddr.sin_family = hp->h_addrtype;
		raddr.sin_port = htons( rport );
	}

	return true;
}

bool _IKED::find_addr_l( IKE_SADDR & saddr_r, IKE_SADDR & saddr_l, unsigned short lport )
{
	//
	// determine the best interface to
	// reach the remote host address
	//

	bool	local;
	in_addr	addr = saddr_r.saddr4.sin_addr;
	in_addr	mask;
	in_addr	next;

	bool found = iproute.best(
					saddr_l.saddr4.sin_addr,
					local,
					addr,
					mask,
					next );

	saddr_l.saddr4.sin_family = AF_INET;
	saddr_l.saddr4.sin_port	= htons( lport );

	//
	// log the result
	//

	if( found )
	{
		char txtaddr[ LIBIKE_MAX_TEXTADDR ];
		text_addr( txtaddr, &saddr_l, true );

		log.txt( LLOG_DEBUG,
				"ii : local address %s selected for peer\n",
				txtaddr );
	}
	else
	{
		char txtaddr[ LIBIKE_MAX_TEXTADDR ];
		text_addr( txtaddr, &saddr_r, true );

		log.txt( LLOG_DEBUG,
				"ii : unable to select local address for peer %s\n",
				txtaddr );
	}

	return found;
}


