
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

void _IKED::text_prot( char * text, int prot )
{
	static const char * prot_00 = "ANY";
	static const char * prot_01 = "ICMP";
	static const char * prot_04 = "IPIP";
	static const char * prot_06 = "TCP";
	static const char * prot_17 = "UDP";
	static const char * prot_47 = "GRE";
	static const char * prot_50 = "ESP";
	static const char * prot_51 = "AH";

	const char * temp = NULL;

	switch( prot )
	{
		case 0:
			temp = prot_00;
			break;

		case 1:
			temp = prot_01;
			break;

		case 4:
			temp = prot_04;
			break;

		case 6:
			temp = prot_06;
			break;

		case 17:
			temp = prot_17;
			break;

		case 47:
			temp = prot_47;
			break;

		case 50:
			temp = prot_50;
			break;

		case 51:
			temp = prot_51;
			break;
	}

	if( temp != NULL )
		strcpy_s(
			text,
			LIBIKE_MAX_TEXTPROT,
			temp );
	else
		sprintf_s(
			text,
			LIBIKE_MAX_TEXTPROT,
			"%i",
			prot );
}

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

void _IKED::text_port( char * text, int port )
{
	if( !port )
		strcpy_s(
			text,
			LIBIKE_MAX_TEXTPORT,
			"*" );
	else
		sprintf_s(
			text,
			LIBIKE_MAX_TEXTPORT,
			"%i",
			ntohs( port ) );
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
	char txtprot[ LIBIKE_MAX_TEXTPROT ];
	char txtaddr1[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr2[ LIBIKE_MAX_TEXTADDR ];
	char txtport[ LIBIKE_MAX_TEXTPORT ];

	switch( ph2id->type )
	{
		case ISAKMP_ID_IPV4_ADDR:

			text_prot( txtprot, ph2id->prot );
			text_addr( txtaddr1, ph2id->addr1 );
			text_port( txtport, ph2id->port );

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"%s:%s:%s",
				txtprot,
				txtaddr1,
				txtport );

			break;

		case ISAKMP_ID_IPV4_ADDR_SUBNET:

			text_prot( txtprot, ph2id->prot );
			text_addr( txtaddr1, ph2id->addr1 );
			text_mask( txtaddr2, ph2id->addr2 );
			text_port( txtport, ph2id->port );

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"%s:%s/%s:%s",
				txtprot,
				txtaddr1,
				txtaddr2,
				txtport );

			break;

		case ISAKMP_ID_IPV4_ADDR_RANGE:

			text_prot( txtprot, ph2id->prot );
			text_addr( txtaddr1, ph2id->addr1 );
			text_addr( txtaddr2, ph2id->addr2 );
			text_port( txtport, ph2id->port );

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"%s:%s-%s:%s",
				txtprot,
				txtaddr1,
				txtaddr2,
				txtport );

			break;

		default:

			sprintf_s(
				text,
				LIBIKE_MAX_TEXTP2ID,
				"<UNKNOWN P2ID>" );
	}
}

bool has_sockaddr( sockaddr * saddr )
{
	switch( saddr->sa_family )
	{
		case AF_INET:
		{
			sockaddr_in * saddr_in = ( sockaddr_in * ) saddr;
			if( saddr_in->sin_addr.s_addr )
				return true;
		}
	}

	return false;
}

bool cmp_sockaddr( sockaddr & saddr1, sockaddr & saddr2, bool port )
{
	if( saddr1.sa_family !=
		saddr2.sa_family )
		return false;

	switch( saddr1.sa_family )
	{
		case AF_INET:
		{
			sockaddr_in * saddr1_in = ( sockaddr_in * ) &saddr1;
			sockaddr_in * saddr2_in = ( sockaddr_in * ) &saddr2;

			if( saddr1_in->sin_addr.s_addr !=
				saddr2_in->sin_addr.s_addr )
				return false;

			if( port )
				if( saddr1_in->sin_port !=
					saddr2_in->sin_port )
					return false;

			return true;
		}
	}

	return false;
}

bool cpy_sockaddr( sockaddr & saddr1, sockaddr & saddr2, bool port )
{
	switch( saddr1.sa_family )
	{
		case AF_INET:
		{
			sockaddr_in * saddr1_in = ( sockaddr_in * ) &saddr1;
			sockaddr_in * saddr2_in = ( sockaddr_in * ) &saddr2;

			SET_SALEN( saddr2_in, sizeof( sockaddr_in  ) );
			saddr2_in->sin_family = AF_INET;
			saddr2_in->sin_addr = saddr1_in->sin_addr;

			if( port )
				saddr2_in->sin_port = saddr1_in->sin_port;
			else
				saddr2_in->sin_port = 0;

			return true;
		}
	}

	return false;
}

bool get_sockport( sockaddr & saddr, u_int16_t & port )
{
	switch( saddr.sa_family )
	{
		case AF_INET:
		{
			sockaddr_in * saddr_in = ( sockaddr_in * ) &saddr;
			port = saddr_in->sin_port;

			return true;
		}
	}

	return false;
}

bool set_sockport( sockaddr & saddr, u_int16_t port )
{
	switch( saddr.sa_family )
	{
		case AF_INET:
		{
			sockaddr_in * saddr_in = ( sockaddr_in * ) &saddr;
			saddr_in->sin_port = port;

			return true;
		}
	}

	return false;
}

bool cmp_ikeaddr( IKE_SADDR & addr1, IKE_SADDR & addr2, bool port )
{
	return cmp_sockaddr( addr1.saddr, addr2.saddr, port );
}
