
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

_PACKET_IKE::_PACKET_IKE()
{
	reset();
	memset( &header, 0, sizeof( header ) );
	notify = 0;
}

_PACKET_IKE::~_PACKET_IKE()
{
	reset();
}

void _PACKET_IKE::reset()
{
	size( 0 );
	pld_depth = 0;
}

void _PACKET_IKE::set_msgid( uint32_t msgid )
{
	header.msgid = msgid;
}

uint32_t _PACKET_IKE::get_msgid()
{
	return header.msgid;
}

bool _PACKET_IKE::write( IKE_COOKIES & cookies, uint8_t payload, uint8_t exchange, uint8_t flags )
{
	// reset packet data

	reset();

	// define header information and add

	header.cookies = cookies;
	header.payload = payload;
	header.version = ISAKMP_VERSION;
	header.exchange = exchange;
	header.flags = flags;
	header.length = 0;

	add( &header, sizeof( header ) );

	return true;
}

bool _PACKET_IKE::done()
{
	header.length = ( uint32_t ) data_size;

	IKE_HEADER * tmp_header = ( IKE_HEADER * ) data_buff;
	tmp_header->length  = htonl( header.length );

	return true;
}

bool _PACKET_IKE::add_payload( bool encap, uint8_t next )
{
	// encapsulate payload

	if( encap )
		pld_depth++;
	
	// store payload start

	pld_stack[ pld_depth ].oset = data_size;
	pld_stack[ pld_depth ].size = 0;

	// write payload header

	IKE_PAYLOAD payload;
	payload.next = next;
	payload.reserved = 0;
	payload.length = 0;

	return add( &payload, sizeof( payload ) );
}

void _PACKET_IKE::end_payload( bool decap, bool write )
{
	short	pld_oset = ( short ) pld_stack[ pld_depth ].oset;
	short	pld_size = ( short ) data_size - pld_oset;

	//
	// write the payload params
	// in the packet
	//

	if( write )
	{
		// set payload size in packet

		IKE_PAYLOAD * payload = ( IKE_PAYLOAD * )( data_buff + pld_oset );
		payload->length = htons( pld_size );

		// potentially add payload size
		// to the parent payload size

		if( pld_depth > 0 )
			pld_stack[ pld_depth - 1 ].size += pld_size;
	}

	// decapsulate payload

	if( decap )
		pld_depth--;
}

bool _PACKET_IKE::read( IKE_COOKIES & cookies, uint8_t & payload, uint8_t & exchange, uint8_t & flags )
{
	// reset packet read positions

	data_oset = 0;
	pld_depth = 0;

	// get and determine header information

	if( !get( &header, sizeof( header ) ) )
		return false;

	header.length = ntohl( header.length );

	cookies = header.cookies;
	payload = header.payload;
	exchange = header.exchange;
	flags = header.flags;

	return true;
}

bool _PACKET_IKE::get_payload( bool encap, uint8_t & next )
{
	//
	// check packet size for enough
	// data to contain a payload
	//

	if( ( data_oset + 4 ) > data_size )
		return false;

	// encapsulate payload

	if( encap )
		pld_depth++;
	
	// store payload start

	pld_stack[ pld_depth ].oset = data_oset;

	// read payload header

	IKE_PAYLOAD payload;

	if( !get( &payload, sizeof( payload ) ) )
		return false;

	// store payload size

	pld_stack[ pld_depth ].size = ntohs( payload.length );

	// store caller next payload type

	next = payload.next;

	return true;
}

size_t _PACKET_IKE::get_payload_left()
{
	return pld_stack[ pld_depth ].oset + pld_stack[ pld_depth ].size - data_oset;
}
