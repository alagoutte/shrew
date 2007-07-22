
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
