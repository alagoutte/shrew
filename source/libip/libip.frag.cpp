
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

_IPFRAG::_IPFRAG()
{
	lastchk = 0;
}

//
// is this packet a fragment
//

bool _IPFRAG::isfrag( PACKET_IP & packet )
{
	//
	// obtain the packet ip header
	//

	IP_HEADER *	ip_header = ( IP_HEADER * ) packet.buff();

	//
	// is this packet a fragment
	//

	unsigned short flags = htons( ip_header->flags );

	if( ( flags & IP_FLAG_MORE ) ||
		( flags & IP_MASK_OFFSET ) )
		return true;

	return false;
}

//
// check for the do not fragment flag
//

bool _IPFRAG::dnfrag( PACKET_IP & packet )
{
	//
	// obtain the packet ip header
	//

	IP_HEADER *	ip_header = ( IP_HEADER * ) packet.buff();

	//
	// is this packet a fragment
	//

	unsigned short flags = htons( ip_header->flags );

	if( flags & IP_FLAG_DONT_FRAG )
		return true;

	return false;
}

bool _IPFRAG::dofrag( PACKET_IP & packet, PACKET_IP & fragment, size_t & offset, size_t max_size )
{
	//
	// determine packet ip header size
	//

	IP_HEADER *		ip_header = ( IP_HEADER * ) packet.buff();
	unsigned short	ip_hdsize = 4 * ( ip_header->verlen & 0xF );

	//
	// determine total payload size
	//

	size_t pld_size;
	pld_size = packet.size();
	pld_size -= ip_hdsize;

	//
	// determine fragment payload size
	//

	size_t frg_size;
	frg_size = pld_size;
	frg_size -= offset;

	if( frg_size > ( max_size - sizeof( IP_HEADER ) ) )
		frg_size = ( max_size - sizeof( IP_HEADER ) );

	//
	// calculate payload left
	//

	size_t pld_left = 0;
	pld_left = pld_size;
	pld_left -= ( offset + frg_size );

	//
	// will this be the last fragment
	//

	bool more = false;

	if( pld_left != 0 )
	{
		more = true;

		//
		// there are more packet fragments to
		// follow, the ip standard states that
		// the three least significant bits are
		// discarded in the fragment offset
		//

		frg_size &= ( ~7 );
	}

	//
	// calculate fragment buffer start
	//

	unsigned char * frg_buff;
	frg_buff = packet.buff();
	frg_buff += ip_hdsize;
	frg_buff += offset;

	//
	// create the new packet fragment
	//

	in_addr addr_src;
	in_addr addr_dst;

	addr_src.s_addr = ip_header->ip_src;
	addr_dst.s_addr = ip_header->ip_dst;

	fragment.write(
		addr_src,
		addr_dst,
		ip_header->ident,
		ip_header->protocol );

	fragment.add(
		frg_buff,
		frg_size );

	fragment.frag( more, offset );
	fragment.done();

	//
	// determine next packet offset
	//

	offset += frg_size;

	return more;
}

bool _IPFRAG::defrag_add( PACKET_IP & fragment, unsigned short & id )
{
	//
	// cleanup any stale fragments
	// but only once per second
	//

	time_t current = time( NULL );

	if( lastchk < current )
	{
		lastchk = current;

		//
		// step through all our fragments
		//

		long count = used.count();
		long index = 0;

		for( ; index < count; index++ )
		{
			//
			// get the next fragment in our list
			//

			IPFRAG_ENTRY * entry = static_cast<IPFRAG_ENTRY*>( used.get_entry( index ) );
			assert( entry != NULL );

			//
			// ckeck this fragment to see if
			// it has expired
			//

			if( entry->expire <= current )
			{
				//
				// remove the fragment from the used
				// list and move it to the free list
				//

				used.del_entry( entry );
				free.add_entry( entry );

				//
				// correct for our change in list
				// index and item count
				//

				index--;
				count--;
			}
		}
	}

	//
	// attempt to aquire a frag entry from
	// our free list. if none are available
	// then create one if appropriate
	//

	IPFRAG_ENTRY * entry = NULL;

	if( free.count() > 0 )
		entry = static_cast<IPFRAG_ENTRY*>( free.del_entry( 0 ) );
	else
	{
		long count = used.count() + free.count();
		if( count < IPFRAG_MAX_FRAGCOUNT )
			entry = new IPFRAG_ENTRY();
	}

	if( entry == NULL )
		return false;

	//
	// store the ip packet data in our entry
	//

	entry->expire = current + IPFRAG_MAX_LIFETIME;
	entry->packet.set( fragment );

	//
	// obtain the packet ip header and record
	// the ip identity
	//

	IP_HEADER *	ip_header = ( IP_HEADER * ) fragment.buff();
	id = ip_header->ident;

	//
	// add this fragment to our used list
	//

	return used.add_entry( entry );
}

bool _IPFRAG::defrag_chk( unsigned short ident )
{
	//
	// check to see if we have a complete list
	// of ip fragments for a given ip identity
	//

	unsigned long next_offset = 0;
	unsigned long temp_offset = 0;

	while( true )
	{
		//
		// find the next fragment based
		// on the fragmentation offset
		//

		long index = 0;
		long count = used.count();

		for( ; index < count; index++ )
		{
			//
			// get the next fragment in our list
			//

			IPFRAG_ENTRY * entry = static_cast<IPFRAG_ENTRY*>( used.get_entry( index ) );
			assert( entry != NULL );

			//
			// ckeck the ip header identity to
			// see if it matches our identity
			//

			IP_HEADER *		ip_header = ( IP_HEADER * ) entry->packet.buff();
			unsigned short	ip_hdsize = 4 * ( ip_header->verlen & 0xF );

			if( ip_header->ident != ident )
				continue;

			//
			// evaluate this fragments offset to
			// determine if its the next fragment
			// in our packet
			//

			unsigned short flags = ntohs( ip_header->flags );
			temp_offset = ( flags & IP_MASK_OFFSET ) << 3;

			if( temp_offset != next_offset )
				continue;

			//
			// calculate this fragments data size
			// to our running total and determine
			// if this was the last fragment in
			// our packet
			//

			next_offset += ntohs( ip_header->size ) - ip_hdsize;

			//
			// complete packet is available
			//

			if( !( flags & IP_FLAG_MORE ) )
				return true;
		}

		//
		// next fragment not found
		//

		if( index >= count )
			break;
	}

	//
	// complete packet is not available
	//

	return false;
}

bool _IPFRAG::defrag_get( unsigned short ident, PACKET_IP & packet )
{
	//
	// make sure we have a clean packet
	//

	packet.del();

	//
	// assemble a complete packet from
	// a list of ip fragments given the
	// ip packet identity
	//

	unsigned long next_offset = 0;
	unsigned long temp_offset = 0;

	while( true )
	{
		//
		// find the next fragment based
		// on the fragmentation offset
		//

		long count = used.count();
		long index = 0;

		for( ; index < count; index++ )
		{
			//
			// get the next fragment in our list
			//

			IPFRAG_ENTRY * entry = static_cast<IPFRAG_ENTRY*>( used.get_entry( index ) );
			assert( entry != NULL );

			//
			// ckeck the ip header identity to
			// see if it matches our identity
			//

			IP_HEADER *		ip_header = ( IP_HEADER * ) entry->packet.buff();
			unsigned short	ip_hdsize = 4 * ( ip_header->verlen & 0xF );

			if( ip_header->ident != ident )
				continue;

			//
			// evaluate this fragments offset to
			// determine if its the next fragment
			// in our packet
			//

			unsigned short flags = ntohs( ip_header->flags );
			temp_offset = ( flags & IP_MASK_OFFSET ) << 3;

			if( temp_offset != next_offset )
				continue;

			//
			// if this is the first fragment,
			// build a new ip header based on
			// first fragments ip header info
			//

			if( next_offset == 0 )
			{
				in_addr addr_s;
				in_addr addr_d;

				addr_s.s_addr = ip_header->ip_src;
				addr_d.s_addr = ip_header->ip_dst;

				packet.write(
					addr_s,
					addr_d,
					ip_header->ident,
					ip_header->protocol );
			}

			//
			// correct for our change in list
			// index and item count
			//

			index--;
			count--;

			//
			// calculate this fragments data size
			// and add it to our complete packet
			//

			unsigned short fragsize = ntohs( ip_header->size ) - ip_hdsize;

			packet.add(
				entry->packet.buff() + ip_hdsize,
				fragsize );

			//
			// add this fragments data size to our
			// running offset
			//
			
			next_offset += fragsize;

			//
			// remove the fragment from our list
			// and free its resources
			//

			used.del_entry( entry );
			free.add_entry( entry );

			//
			// complete packet is available
			//

			if( !( flags & IP_FLAG_MORE ) )
			{
				packet.done();
				return true;
			}
		}

		//
		// we shouldn't ever get here but break
		// if we are missing a packet fragment
		//

		if( index >= count )
			break;
	}

	//
	// return error
	//

	return false;
}
