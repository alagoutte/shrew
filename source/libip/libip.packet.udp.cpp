
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

uint16_t _PACKET_UDP::checksum( in_addr addr_src, in_addr addr_dst )
{
	unsigned char * data = data_buff;
	size_t size = data_size;
	size_t oset = 0;

	uint32_t cksum = 0;

	for( ; ( oset + 1 ) < size; oset += 2 )
	{
		cksum += ( ( data[ oset ] << 8 ) & 0xff00 );
		cksum += ( data[ oset + 1 ] & 0x00ff );
	}

	if( oset < size )
		cksum += ( ( data[ oset ] << 8 ) & 0xff00 );

	cksum += htons( ( uint16_t ) ( addr_src.s_addr >> 16 ) & 0xffff );
	cksum += htons( ( uint16_t ) addr_src.s_addr & 0xffff );

	cksum += htons( ( uint16_t ) ( addr_dst.s_addr >> 16 ) & 0xffff );
	cksum += htons( ( uint16_t ) addr_dst.s_addr & 0xffff );

	cksum += PROTO_IP_UDP;
	cksum += size;

	while( cksum >> 16 )
		cksum = ( cksum & 0xffff ) + ( cksum >> 16 );

	return htons( ( uint16_t ) ~cksum );
}

bool _PACKET_UDP::read( unsigned short & port_src, unsigned short & port_dst )
{
	data_oset = 0;

	if( data_size < ( long ) sizeof( UDP_HEADER ) )
		return false;

	UDP_HEADER udp_header;
	get( &udp_header, sizeof( udp_header ) );
	port_src = udp_header.port_src;
	port_dst = udp_header.port_dst;

	return true;
}

bool _PACKET_UDP::write( unsigned short port_src, unsigned short port_dst )
{
	del();

	UDP_HEADER udp_header;
	udp_header.port_src = port_src;
	udp_header.port_dst = port_dst;
	udp_header.size = 0;
	udp_header.checksum = 0;

	return ins( &udp_header, sizeof( udp_header ) );
}

bool _PACKET_UDP::done( in_addr addr_src, in_addr addr_dst )
{
	//
	// sanity checks
	//

	if( data_size < ( long ) sizeof( UDP_HEADER ) )
		return false;

	//
	// write size and calc checksum
	//

	UDP_HEADER * udp_header = ( UDP_HEADER * ) data_buff;
	udp_header->size = htons( ( unsigned short ) data_size );
	udp_header->checksum = 0;
	udp_header->checksum = checksum( addr_src, addr_dst );

	return true;
}
