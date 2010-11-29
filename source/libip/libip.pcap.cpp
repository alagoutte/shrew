
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

_PCAP_DUMP::_PCAP_DUMP()
{
	fp = NULL;
}

_PCAP_DUMP::~_PCAP_DUMP()
{
	close();
}

bool _PCAP_DUMP::open( char * path )
{
	if( path == NULL )
		return false;

	close();

	//
	// create file
	//

#ifdef WIN32

	if( fopen_s( &fp, path, "w+b" ) )
		return false;

#else

	fp = fopen( path, "w+b" );
	if( fp == NULL )
		return false;

#endif

	//
	// write pcap file header
	//

	pcap_file_header pfh;
	pfh.magic = TCPDUMP_MAGIC;
	pfh.version_major = PCAP_VERSION_MAJOR;
	pfh.version_minor = PCAP_VERSION_MINOR;
	pfh.thiszone = 0;
	pfh.sigfigs = 0;
	pfh.snaplen = 1514;
	pfh.linktype = 1;

	fwrite( &pfh, sizeof( pfh ), 1, fp );

	return true;
}

void _PCAP_DUMP::close()
{
	if( fp != NULL )
	{
//		fflush( fp );
//		fclose( fp );
		fp = NULL;
	}
}

bool _PCAP_DUMP::dump( unsigned char * buff, size_t size )
{
	if( fp == NULL )
		return false;

	pcap_pkthdr pph;
	pph.ts_sec = 0;
	pph.ts_usec = 0;
	pph.caplen = ( uint32_t ) size;
	pph.len = ( uint32_t ) size;

	fwrite( &pph, sizeof( pph ), 1, fp );
	fwrite( buff, size, 1, fp );

	return true;
}

bool _PCAP_DUMP::dump( ETH_HEADER & header, PACKET_IP & packet )
{
	if( fp == NULL )
		return false;

	pcap_pkthdr pph;
	pph.ts_sec = 0;
	pph.ts_usec = 0;
	pph.caplen = ( uint32_t ) packet.size() + sizeof( ETH_HEADER );
	pph.len = ( uint32_t ) packet.size() + sizeof( ETH_HEADER );

	fwrite( &pph, sizeof( pph ), 1, fp );
	fwrite( &header, sizeof( header ), 1, fp );
	fwrite( packet.buff(), packet.size(), 1, fp );

	return true;
}

bool _PCAP_DUMP::flush()
{
	if( fp == NULL )
		return false;

	fflush( fp );

	return true;
}
