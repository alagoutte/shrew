
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

_IPROUTE::_IPROUTE()
{
}

//
// interface address from index
//

bool _IPROUTE::iface_2_addr( in_addr & iface, unsigned long & iindex )
{
	//
	// obtain the adapter info list
	//
	
	IP_ADAPTER_INFO *	ipinfo = NULL;
	DWORD				ipsize = 0;

	GetAdaptersInfo( ipinfo, &ipsize );

	ipinfo = ( IP_ADAPTER_INFO * ) new char[ ipsize ];
	
	GetAdaptersInfo( ipinfo, &ipsize );

	//
	// step through our adapter list
	// and find the index
	//
	
	IP_ADAPTER_INFO *	ipadapter = ipinfo;
	bool				ipfound = false;

	while( ipadapter )
	{
		//
		// is this the adapter we are
		// looking for?
		//
	
		if( ipadapter->Index == iindex )
		{
			ipfound = true;
			iface.s_addr = inet_addr( ipadapter->IpAddressList.IpAddress.String );
			break;
		}
	
		ipadapter = ipadapter->Next;
	}
		
	delete [] ( char * ) ipinfo;

	return ipfound;
}

bool _IPROUTE::addr_2_iface( unsigned long & iindex, in_addr & iface )
{
	//
	// obtain the adapter info list
	//
	
	IP_ADAPTER_INFO *	ipinfo = NULL;
	DWORD				ipsize = 0;

	GetAdaptersInfo( ipinfo, &ipsize );

	ipinfo = ( IP_ADAPTER_INFO * ) new char[ ipsize ];
	
	GetAdaptersInfo( ipinfo, &ipsize );

	//
	// step through our adapter list
	// and find the index
	//
	
	IP_ADAPTER_INFO *	ipadapter = ipinfo;
	bool				ipfound = false;

	while( ipadapter )
	{
		//
		// is this the adapter we are
		// looking for?
		//
	
		if( iface.s_addr == inet_addr( ipadapter->IpAddressList.IpAddress.String ) )
		{
			ipfound = true;
			iindex = ipadapter->Index;
			break;
		}
	
		ipadapter = ipadapter->Next;
	}
		
	delete [] ( char * ) ipinfo;

	return ipfound;
}

//
// add a route
//

bool _IPROUTE::add( in_addr & iface, bool local, in_addr addr, in_addr mask, in_addr next )
{
	unsigned long iindex;
	addr_2_iface( iindex, iface );

	MIB_IPFORWARDROW ipfwdrow;
	memset( &ipfwdrow, 0, sizeof( ipfwdrow ) );

	ipfwdrow.dwForwardDest = addr.s_addr;
	ipfwdrow.dwForwardMask = mask.s_addr;
	ipfwdrow.dwForwardIfIndex = iindex;
	ipfwdrow.dwForwardNextHop = next.s_addr;
	ipfwdrow.dwForwardProto = PROTO_IP_OTHER;
	ipfwdrow.dwForwardMetric1 = 1;
	ipfwdrow.dwForwardMetric2 = 1;
	ipfwdrow.dwForwardMetric3 = 1;
	ipfwdrow.dwForwardMetric4 = 1;
	ipfwdrow.dwForwardMetric5 = 1;

	if( local )
		ipfwdrow.dwForwardType = 3;
	else
		ipfwdrow.dwForwardType = 4;

	long result = CreateIpForwardEntry( &ipfwdrow );
	if( result != NO_ERROR )
		return false;

	return true;
}

//
// delete a route 
//

bool _IPROUTE::del( in_addr & iface, bool local, in_addr addr, in_addr mask, in_addr next )
{
	bool removed = false;

	PMIB_IPFORWARDTABLE ipfwdtable = NULL;
	char *	buff = NULL;
	DWORD	size = 0;

	unsigned long iindex;
	addr_2_iface( iindex, iface );

	long result = GetIpForwardTable(
					ipfwdtable,
					&size, 0 );

	if( result != ERROR_INSUFFICIENT_BUFFER )
		return false;

	buff = new char[ size ];
	if( buff == NULL )
		return false;

	ipfwdtable = ( PMIB_IPFORWARDTABLE ) buff;

	result = GetIpForwardTable(
				ipfwdtable,
				&size, 0 );

	if( result == NO_ERROR )
	{
		unsigned long type = 3;
		if( !local )
			type = 4;

		long count = ipfwdtable->dwNumEntries;
		long index = 0;

		for( ; index < count; index++ )
		{
			if( ( ipfwdtable->table[ index ].dwForwardIfIndex == iindex ) &&
				( ipfwdtable->table[ index ].dwForwardDest == addr.s_addr ) &&
				( ipfwdtable->table[ index ].dwForwardMask == mask.s_addr ) &&
				( ipfwdtable->table[ index ].dwForwardNextHop == next.s_addr ) &&
				( ipfwdtable->table[ index ].dwForwardType == type ) &&
				( ipfwdtable->table[ index ].dwForwardProto == PROTO_IP_OTHER ) )
			{
				//
				// store the route information
				//

				if( DeleteIpForwardEntry( &ipfwdtable->table[ index ] ) == NO_ERROR )
					removed = true;

				break;
			}
		}
	}

	delete [] buff;

	return removed;
}

//
// get a route ( by addr and mask )
//

bool _IPROUTE::get( in_addr & iface, bool & local, in_addr & addr, in_addr & mask, in_addr & next )
{
	bool found = false;

	PMIB_IPFORWARDTABLE ipfwdtable = NULL;
	char *	buff = NULL;
	DWORD	size = 0;

	long result = GetIpForwardTable(
					ipfwdtable,
					&size, 0 );

	if( result != ERROR_INSUFFICIENT_BUFFER )
		return false;

	buff = new char[ size ];
	if( buff == NULL )
		return false;

	ipfwdtable = ( PMIB_IPFORWARDTABLE ) buff;

	result = GetIpForwardTable(
				ipfwdtable,
				&size, 0 );

	if( result == NO_ERROR )
	{
		long count = ipfwdtable->dwNumEntries;
		long index = 0;

		for( ; index < count; index++ )
		{
			if( ( ipfwdtable->table[ index ].dwForwardDest == addr.s_addr ) &&
				( ipfwdtable->table[ index ].dwForwardMask == mask.s_addr ) )
			{
				//
				// obtain the interface address
				//

				iface_2_addr( iface, ipfwdtable->table[ index ].dwForwardIfIndex );

				//
				// obtain the next hop and type
				//

				next.s_addr = ipfwdtable->table[ index ].dwForwardNextHop;

				if( ipfwdtable->table[ index ].dwForwardType == 3 )
					local = true;
				else
					local = false;

				found = true;
				break;
			}
		}
	}

	delete [] buff;

	return true;
}

//
// best route ( by address )
//

bool _IPROUTE::best( in_addr & iface, bool & local, in_addr & addr, in_addr & mask, in_addr & next )
{
	MIB_IPFORWARDROW ipfwdrow;
	memset( &ipfwdrow, 0, sizeof( ipfwdrow ) );

	long result = GetBestRoute(
					addr.s_addr,
					0,
					&ipfwdrow );

	if( result != NO_ERROR )
		return false;

	//
	// obtain the route information
	//

	addr.s_addr = ipfwdrow.dwForwardDest;
	mask.s_addr = ipfwdrow.dwForwardMask;
	next.s_addr = ipfwdrow.dwForwardNextHop;

	if( ipfwdrow.dwForwardType == 3 )
		local = true;
	else
		local = false;

	//
	// obtain the interface address
	//

	iface_2_addr( iface, ipfwdrow.dwForwardIfIndex );

	return true;
}

//
// decrement route costs
//

bool _IPROUTE::increment( in_addr addr, in_addr mask )
{
	//
	// get the route specified
	// by the address and mask
	//

	bool changed = false;

	PMIB_IPFORWARDTABLE ipfwdtable = NULL;
	char *	buff = NULL;
	DWORD	size = 0;

	long result = GetIpForwardTable(
					ipfwdtable,
					&size, 0 );

	if( result != ERROR_INSUFFICIENT_BUFFER )
		return false;

	buff = new char[ size ];
	if( buff == NULL )
		return false;

	ipfwdtable = ( PMIB_IPFORWARDTABLE ) buff;

	result = GetIpForwardTable(
				ipfwdtable,
				&size, 0 );

	if( result == NO_ERROR )
	{
		long count = ipfwdtable->dwNumEntries;
		long index = 0;

		for( ; index < count; index++ )
		{
			if( ( ipfwdtable->table[ index ].dwForwardDest == addr.s_addr ) &&
				( ipfwdtable->table[ index ].dwForwardMask == mask.s_addr ) )
			{
				//
				// modify the route metric
				//

				ipfwdtable->table[ index ].dwForwardMetric1++;
				ipfwdtable->table[ index ].dwForwardMetric2++;
				ipfwdtable->table[ index ].dwForwardMetric3++;
				ipfwdtable->table[ index ].dwForwardMetric4++;
				ipfwdtable->table[ index ].dwForwardMetric5++;

				if( SetIpForwardEntry( &ipfwdtable->table[ index ] ) == NO_ERROR )
					changed = true;
			}
		}
	}

	delete [] buff;

	return changed;
}

//
// increment route costs
//

bool _IPROUTE::decrement( in_addr addr, in_addr mask )
{
	//
	// get the route specified
	// by the address and mask
	//

	bool changed = false;

	PMIB_IPFORWARDTABLE ipfwdtable = NULL;
	char *	buff = NULL;
	DWORD	size = 0;

	long result = GetIpForwardTable(
					ipfwdtable,
					&size, 0 );

	if( result != ERROR_INSUFFICIENT_BUFFER )
		return false;

	buff = new char[ size ];
	if( buff == NULL )
		return false;

	ipfwdtable = ( PMIB_IPFORWARDTABLE ) buff;

	result = GetIpForwardTable(
				ipfwdtable,
				&size, 0 );

	if( result == NO_ERROR )
	{
		long count = ipfwdtable->dwNumEntries;
		long index = 0;

		for( ; index < count; index++ )
		{
			if( ( ipfwdtable->table[ index ].dwForwardDest == addr.s_addr ) &&
				( ipfwdtable->table[ index ].dwForwardMask == mask.s_addr ) )
			{
				//
				// modify the route metric
				//

				ipfwdtable->table[ index ].dwForwardMetric1--;
				ipfwdtable->table[ index ].dwForwardMetric2--;
				ipfwdtable->table[ index ].dwForwardMetric3--;
				ipfwdtable->table[ index ].dwForwardMetric4--;
				ipfwdtable->table[ index ].dwForwardMetric5--;

				if( SetIpForwardEntry( &ipfwdtable->table[ index ] ) == NO_ERROR )
					changed = true;
			}
		}
	}

	delete [] buff;

	return changed;
}


bool _IPROUTE::flusharp( in_addr & iface )
{
	unsigned long iindex;
	addr_2_iface( iindex, iface );

	FlushIpNetTable( iindex );

	return true;
}
