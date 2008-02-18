
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

#include <stdio.h>

#define MAX_DNS_NAME	255

PACKET_DNS::_PACKET_DNS()
{
	ident	= 0;
	flags	= 0;
	ques	= 0;
	answ	= 0;
	ath_rr	= 0;
	add_rr	= 0;
}

PACKET_DNS::~_PACKET_DNS()
{
	list_ques.clean();
	list_answ.clean();
	list_ath_rr.clean();
	list_add_rr.clean();
}

bool PACKET_DNS::read_name( char * name, long & size )
{
	uint8_t	tag1;
	uint8_t	tag2;
	long	oset = 0;

	//
	// reserve room for our null char
	//

	size--;

	//
	// step through all sequence tags
	//

	while( get_byte( tag1 ) )
	{
		//
		// is this a reserved value
		//

		if( ( ( tag1 & 0xc0 ) == 0x80 ) ||
			( ( tag1 & 0xc0 ) == 0x40 ) )
			break;

		//
		// is this an end tag
		//

		if( tag1 == 0 )
		{
			//
			// end of our segment, null
			// terminate and return
			//

			name[ oset ] = 0;
			return true;
		}

		//
		// append a period if neccessary
		//

		if( oset )
		{
			if( size < 1 )
			break;

			name[ oset ] = '.';
			oset++;
			size--;
		}

		//
		// is this a name segment or
		// name segment pointer
		//
		if( ( tag1 & 0xc0 ) == 0xc0 )
		{
			size_t tmp_oset = 0;
			size_t new_oset = 0;

			//
			// its a pointer, recurse
			//

			if( !get_byte( tag2 ) )
				break;

			new_oset |= ( tag1 & 0x3f );
			new_oset <<= 8;
			new_oset |= tag2;

			if( new_oset >= data_size )
				break;

			tmp_oset = data_oset;
			data_oset = new_oset;

			bool rslt = read_name( name + oset, size );

			data_oset = tmp_oset;

			if( rslt )
				return true;
		}
		else
		{
			//
			// its a segment, append
			//

			long temp = tag1;
			if( temp >= size )
				break;

			if( !get( &name[ oset ], temp ) )
				break;

			oset += temp;
			size -= temp;
		}
	}

	return false;
}

bool PACKET_DNS::read_query( DNS_QUERY ** query )
{
	//
	// read the name
	//

	char name_data[ MAX_DNS_NAME ];
	long name_size = MAX_DNS_NAME;

	if( !read_name( name_data, name_size ) )
		return false;

	uint16_t type;
	if( !get_word( type ) )
		return false;

	uint16_t clss;
	if( !get_word( clss ) )
		return false;

	//
	// create our query struct
	//

	DNS_QUERY * tmp_query = new DNS_QUERY;
	if( tmp_query == NULL )
		return false;

	tmp_query->name = new char[ name_size + 1 ];
	memcpy( tmp_query->name, name_data, name_size );
	tmp_query->name[ name_size ] = 0;
	tmp_query->type = type;
	tmp_query->clss = clss;

	*query = tmp_query;

	return true;
}

bool PACKET_DNS::read_record( DNS_RECORD ** record )
{
	//
	// read the name
	//

	char name_data[ MAX_DNS_NAME ];
	long name_size = MAX_DNS_NAME;

	if( !read_name( name_data, name_size ) )
		return false;

	uint16_t type;
	if( !get_word( type ) )
		return false;

	uint16_t clss;
	if( !get_word( clss ) )
		return false;

	uint32_t rttl;
	if( !get_quad( rttl ) )
		return false;

	uint16_t rlen;
	if( !get_word( rlen ) )
		return false;

	get_null( rlen );

	//
	// create our record struct
	//

	DNS_RECORD * tmp_record = new DNS_RECORD;
	if( tmp_record == NULL )
		return false;

	tmp_record->name = new char[ name_size + 1 ];
	memcpy( tmp_record->name, name_data, name_size );
	tmp_record->name[ name_size ] = 0;
	tmp_record->type = type;
	tmp_record->clss = clss;
	tmp_record->rttl = rttl;
	tmp_record->rlen = rlen;

	*record = tmp_record;

	return true;
}

bool PACKET_DNS::read()
{
	//
	// read the header
	//

	DNS_HEADER dns_head;
	if( !get( &dns_head, sizeof( dns_head ) ) )
		return false;

	ident	= ntohs( dns_head.ident );
	flags	= ntohs( dns_head.flags );
	ques	= ntohs( dns_head.ques );
	answ	= ntohs( dns_head.answ );
	ath_rr	= ntohs( dns_head.ath_rr );
	add_rr	= ntohs( dns_head.add_rr );

	//
	// read question section
	//

	long index;

	for( index = 0; index < ques; index++ )
	{
		DNS_QUERY * query;
		if( !read_query( &query ) )
			return false;

		list_ques.add_entry( query );
	}

	//
	// read answer section
	//

	for( index = 0; index < answ; index++ )
	{
		DNS_RECORD * record;
		if( !read_record( &record ) )
			return false;

		list_answ.add_entry( record );
	}

	//
	// authoritative section
	//

	for( index = 0; index < ath_rr; index++ )
	{
		DNS_RECORD * record;
		if( !read_record( &record ) )
			return false;

		list_ath_rr.add_entry( record );
	}

	//
	// additional section
	//

	for( index = 0; index < add_rr; index++ )
	{
		DNS_RECORD * record;
		if( !read_record( &record ) )
			return false;

		list_add_rr.add_entry( record );
	}

	return true;
}

bool PACKET_DNS::write()
{
	return true;
}

bool PACKET_DNS::get_question( DNS_QUERY ** query, long index )
{
	*query = static_cast<DNS_QUERY*>( list_ques.get_entry( index ) );
	return ( *query != NULL );
}

bool PACKET_DNS::get_answer( DNS_RECORD ** record, long index )
{
	*record = static_cast<DNS_RECORD*>(list_answ.get_entry( index ) );
	return ( *record != NULL );
}

bool PACKET_DNS::get_authority( DNS_RECORD ** record, long index )
{
	*record = static_cast<DNS_RECORD*>( list_ath_rr.get_entry( index ) );
	return ( *record != NULL );
}

bool PACKET_DNS::get_additional( DNS_RECORD ** record, long index )
{
	*record = static_cast<DNS_RECORD*>( list_add_rr.get_entry( index ) );
	return ( *record != NULL );
}

