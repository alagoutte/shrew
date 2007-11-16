
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

#include "libip.h"

uint16_t _PACKET_IP::checksum()
{
	uint16_t *	data = ( uint16_t * ) data_buff;
	uint16_t	size = sizeof( IP_HEADER );
	uint32_t	cksum = 0;

	while( size > 1 )
	{
		cksum += *data++;
		size -= sizeof( uint16_t );
	}

	if( size )
		cksum += *( uint8_t * ) data;

	while( cksum >> 16 )
		cksum = ( cksum & 0xffff ) + ( cksum >> 16 );

	return ( ( uint16_t ) ~cksum );
}

bool _PACKET_IP::read( in_addr & addr_src, in_addr & addr_dst, unsigned char & prot )
{
	IP_HEADER ip_header;

	data_oset = 0;
	if( !get( &ip_header, sizeof( IP_HEADER ) ) )
		return false;

	unsigned short	ip_hdsize = 4 * ( ip_header.verlen & 0xF );

	addr_src.s_addr = ip_header.ip_src;
	addr_dst.s_addr = ip_header.ip_dst;
	prot = ip_header.protocol;

	if( ip_hdsize > data_oset )
		get_null( ip_hdsize - data_oset );

	return true;
}

bool _PACKET_IP::write( in_addr addr_src, in_addr addr_dst, unsigned short ident, unsigned char prot )
{
	del();

	IP_HEADER ip_header;
	ip_header.verlen	= IP_V4_VERLEN;
	ip_header.tos		= 0;
	ip_header.size		= 0;
	ip_header.ident		= ident;
	ip_header.flags		= 0;
	ip_header.ttl		= 64;
	ip_header.protocol	= prot;
	ip_header.ip_src	= addr_src.s_addr;
	ip_header.ip_dst	= addr_dst.s_addr;
	ip_header.checksum	= 0;

	return add( &ip_header, sizeof( ip_header ) );
}

bool _PACKET_IP::frag( bool more, size_t oset )
{
	//
	// set packet fragmentation flags
	//

	IP_HEADER * ip_header = ( IP_HEADER * ) data_buff;

	if( more )
		ip_header->flags |= htons( IP_FLAG_MORE );

	if( oset )
		ip_header->flags |= htons( short( oset >> 3 ) );

	return true;
}

bool _PACKET_IP::done()
{
	//
	// set ident, size and checksum
	//

	IP_HEADER * ip_header = ( IP_HEADER * ) data_buff;
	ip_header->size = htons( ( unsigned short ) data_size );
	ip_header->checksum = 0;
	ip_header->checksum = checksum();

	return true;
}
