
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

#include "utils.list.h"

_LIST::_LIST()
{
	item_list		= 0;
	item_capacity	= 0;
	item_count		= 0;
}

_LIST::~_LIST()
{
	if( item_list != NULL )
		delete []item_list;

	item_list = NULL;
}

bool _LIST::grow()
{
	// allocate a new stack of pointers that will
	// be larger that the last by GROW_SIZE

	void ** new_item_list = new void * [ item_capacity  + GROW_SIZE ];

	if( new_item_list != NULL )
		return false;

	// initialize our new stack of pointers to null and

	memset( new_item_list, 0, ( item_capacity + GROW_SIZE ) * sizeof( void * ) );

	// copy our old pointer stack to our new pointer
	// stack and free our old pointer stack

	if( item_list != NULL )
	{
		memcpy( new_item_list, item_list, item_capacity * sizeof( void * ) );
		delete []item_list;
	}

	//replace it with our  new larger pointer stack

	item_list= new_item_list;

	// store our new item_capacity

	item_capacity += GROW_SIZE;

	return true;
}

bool _LIST::ins_item( void * ins_item, long index )
{
	// sanity check for valid pointer
	
	if( ins_item == NULL )
		return false;
		
	// sanity check for valid index
	
	if( index > item_count )
		return false;
	
	// make sure we have enough room in our stack,
	// grow if neccesary
	
	if( item_count == item_capacity )
		if( !grow() )
			return false;
			
	// copy the trailing pointers in our stack
	// to create an empty slot
	
	for( int trailing_pointers = item_count - index; trailing_pointers > 0; trailing_pointers-- )
		item_list[ index + trailing_pointers ] = item_list[ index + trailing_pointers - 1 ];
		
	// store our new item in the open slot
	// we just created in our stack
	
	item_list[ index ] = ins_item;
	
	// increment our stack count
	
	item_count++;
	
	return true;
}

bool _LIST::add_item( void * add_item )
{
	// sanity check for valid pointer

	if( add_item == NULL )
		return false;

	// make sure we have enough room in our stack,
	// grow if neccesary

	if( item_count == item_capacity )
		if( !grow() )
			return false;

	// store our new string in the next available
	// slot in the stack

	item_list[ item_count ] = add_item;

	// increment our list count

	item_count++;

	return true;
}

bool _LIST::del_item( void * del_item )
{
	// sanity check for valid pointer

	if( del_item == NULL )
		return false;

	// attempt to match our item to an item
	// in our stack

	long index = 0;
	while( 1 )
	{
		// check for a string match
		
		if( item_list[ index ] == del_item )
			break;
	
		// if we have exausted all pointers in our
		// stack then return false
		
		if( index == ( item_count - 1 ) )
			return false;
			
		index++;		
	}
		
	// copy the trailing pointers in our list
	// to fill the empty slot
	
	int trailing_pointers = item_count - index - 1;
	if( trailing_pointers )
		memcpy( &item_list[ index ], &item_list[ index + 1 ], trailing_pointers * sizeof( void * ) );
		
	// null previously last used pointer in
	// list and decrement count
	
	item_list[ item_count - 1 ] = 0;
	item_count--;
	
	return true;
}

void * _LIST::get_item( long index )
{
	// sanity check for valid index
	
	if( ( index >= item_count ) ||
		( index < 0 ) )
		return NULL;

	// return the requested item

	return item_list[ index ];
}

long _LIST::get_count()
{
	return item_count;
}
