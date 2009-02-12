
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

static char encap_ike[] = "IKE";
static char encap_nat[] = "NAT-T:IKE";

long _IKED::packet_ike_send( IDB_PH1 * ph1, IDB_XCH * xch, PACKET_IKE & packet, bool retry )
{
	//
	// if we are dumping decrytped ike
	// packets, we need to build an ip
	// packet using the un-encrypted
	// ike payload
	//

	if( dump_decrypt )
	{
		PACKET_IP packet_ip_dump;

		//
		// store the isakmp flags
		//

		unsigned char *	data = packet.buff();
		unsigned char	flags = data[ ISAKMP_FLAGS_OFFSET ];

		//
		// temporarily strip the encrypt flag
		//

		data[ ISAKMP_FLAGS_OFFSET ] = flags & ~ISAKMP_FLAG_ENCRYPT;

		//
		// create ip dump packet
		//

		packet_ike_encap(
			packet,
			packet_ip_dump,
			ph1->tunnel->saddr_l,
			ph1->tunnel->saddr_r,
			ph1->tunnel->natt_version );

		//
		// obtain ethernet header
		//

		ETH_HEADER ethhdr;
		header( packet_ip_dump, ethhdr );

		//
		// dump the ike packet
		//

		pcap_decrypt.dump( ethhdr, packet_ip_dump );

		//
		// restore the isakmp flags
		//

		data[ ISAKMP_FLAGS_OFFSET ] = flags;
	}

	//
	// encrypt the packet if necessary
	//

	packet_ike_encrypt( ph1, packet, &xch->iv );

	//
	// clear any old packets associated
	// with this db object
	//

	xch->resend_clear( true, true );

	//
	// estimate the maximum packet size
	// after ike encapsulation overhead
	//

	size_t encap_size = 0;

	// account for udp header length
	encap_size += sizeof( UDP_HEADER );

	// account for non-esp marker
	if( ph1->tunnel->natt_version >= IPSEC_NATT_V02 )
		encap_size += sizeof( unsigned long );

	//
	// determine if ike fragmentation
	// will be used on this packet
	//

	bool packet_frag = false;
	size_t packet_left = packet.size();

	if( ph1->vendopts_l.flag.frag &&
		ph1->vendopts_r.flag.frag )
		if( ( packet_left + encap_size ) > ph1->tunnel->peer->frag_ike_size )
			packet_frag = true;

	//
	// fragment and send the packet
	// or just send the packet
	//

	if( packet_frag )
	{
		//
		// calculate the max fragment payload size
		//

		size_t frag_max = ph1->tunnel->peer->frag_ike_size - encap_size;
		size_t frag_sent = packet.size() - packet_left;

		//
		// set out initial fragment index
		//

		unsigned char frag_index = 1;

		//
		// fragment the ike packet by
		// recursing on this function
		//

		while( packet_left > 0 )
		{
			//
			// send the remaining packet size
			// as out next fragment size. the
			// payload handler will adjust to
			// accomodate the largest size
			// possible
			//

			size_t frag_size = packet_left;

			//
			// create ike fragment using the
			// original ike packet as a source
			//

			PACKET_IKE packet_frag;
			packet_frag.write( ph1->cookies, ISAKMP_PAYLOAD_FRAGMENT, ph1->exchange, 0 );

			payload_add_frag(
				packet_frag,
				frag_index,
				packet.buff() + frag_sent,
				frag_size,
				frag_max );

			packet_frag.done();

			//
			// transmit the packet
			//

			packet_ike_xmit( ph1, xch, packet_frag, retry );

			//
			// log the result
			//

			log.txt( LLOG_DEBUG,
				"ii : ike packet fragment #%i sized to %i bytes\n",
				frag_index,
				frag_size );

			//
			// decrement sent packet size and
			// increment fragment index
			//

			packet_left -= frag_size;
			frag_sent += frag_size;
			frag_index++;
		}
	}
	else
	{
		//
		// transmit the packet
		//

		packet_ike_xmit( ph1, xch, packet, retry );
	}

	//
	// potentially schedule resend
	//

	if( retry )
		xch->resend_sched( true );

	return LIBIKE_OK;
}

long _IKED::packet_ike_xmit( IDB_PH1 * ph1, IDB_XCH * xch, PACKET_IKE & packet, bool retry )
{
	//
	// prepare for log output
	//

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	char * encap_mode = encap_ike;
	if( ph1->tunnel->natt_version != IPSEC_NATT_NONE )
		encap_mode = encap_nat;

	//
	// encapsulate ike packet into UDP/IP packet
	//

	PACKET_IP packet_ip;
	packet_ike_encap(
		packet,
		packet_ip,
		ph1->tunnel->saddr_l,
		ph1->tunnel->saddr_r,
		ph1->tunnel->natt_version );

	//
	// log the result
	//

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		packet_ip.buff(),
		packet_ip.size(),
		"-> : send %s packet %s -> %s",
		encap_mode,
		txtaddr_l,
		txtaddr_r );

	//
	// send ike packet
	//

	ETH_HEADER header;

	long result = send_ip(
					packet_ip,
					&header );

	if( result != LIBIKE_OK )
	{
		ph1->status( XCH_STATUS_DEAD, XCH_FAILED_NETWORK, 0 );
		xch->status( XCH_STATUS_DEAD, XCH_FAILED_NETWORK, 0 );
		return LIBIKE_FAILED;
	}

	//
	// queue packet for resend
	//

	xch->resend_queue( packet_ip );

	//
	// dump for encoded packets
	//

	if( dump_encrypt )
		pcap_encrypt.dump( header, packet_ip );

	return LIBIKE_OK;
}

long _IKED::packet_ike_encap( PACKET_IKE & packet_ike, PACKET_IP & packet_ip, IKE_SADDR & src, IKE_SADDR & dst, long natt )
{
	PACKET_UDP packet_udp;

	packet_udp.write(
		src.saddr4.sin_port,
		dst.saddr4.sin_port );

	if( natt >= IPSEC_NATT_V02 )
		packet_udp.add_null( 4 );

	packet_udp.add( packet_ike );

	packet_udp.done(
		src.saddr4.sin_addr,
		dst.saddr4.sin_addr );

	packet_ip.write(
		src.saddr4.sin_addr,
		dst.saddr4.sin_addr,
		ident++,
		PROTO_IP_UDP );

	packet_ip.add( packet_udp );

	packet_ip.done();

	return true;
}

long _IKED::packet_ike_decrypt( IDB_PH1 * sa, PACKET_IKE & packet, BDATA * iv )
{
	log.txt( LLOG_INFO,
		"=< : cookies %08x%08x:%08x%08x\n",
		htonl( *( long * ) &sa->cookies.i[ 0 ] ),
		htonl( *( long * ) &sa->cookies.i[ 4 ] ),
		htonl( *( long * ) &sa->cookies.r[ 0 ] ),
		htonl( *( long * ) &sa->cookies.r[ 4 ] ) );

	log.txt( LLOG_INFO,
		"=< : message %08x\n",
		htonl( packet.get_msgid() ) );

	//
	// check if decrypt is required
	//

	unsigned char *	data = packet.buff();
	size_t		    size = packet.size();

	if( !( data[ ISAKMP_FLAGS_OFFSET ] & ISAKMP_FLAG_ENCRYPT ) )
		return LIBIKE_OK;

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		iv->buff(),
		iv->size(),
		"=< : decrypt iv" );

	//
	// temporarily save enough
	// of the packet to store
	// as iv data post decrypt
	//

	unsigned char iv_data[ HMAC_MAX_MD_CBLOCK ];

	memcpy(
		iv_data,
		data + size - iv->size(),
		iv->size() );

	//
	// init cipher key and iv
	//

	EVP_CIPHER_CTX ctx_cipher;
	EVP_CIPHER_CTX_init( &ctx_cipher );

	EVP_CipherInit_ex(
		&ctx_cipher,
		sa->evp_cipher,
		NULL,
		NULL,
		NULL,
		0 );

	EVP_CIPHER_CTX_set_key_length(
		&ctx_cipher,
		( int ) sa->key.size() );

	EVP_CipherInit_ex(
		&ctx_cipher,
		NULL,
		NULL,
		sa->key.buff(),
		iv->buff(),
		0 );

	//
	// decrypt all but header
	//

	EVP_Cipher(
		&ctx_cipher,
		data + sizeof( IKE_HEADER ),
		data + sizeof( IKE_HEADER ),
		( int ) size - sizeof( IKE_HEADER ) );

	EVP_CIPHER_CTX_cleanup( &ctx_cipher );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		data,
		size,
		"== : decrypt packet" );

	//
	// validate the packet integrity
	//

	IKE_HEADER * header = ( IKE_HEADER * ) packet.buff();

	size = sizeof( IKE_HEADER );

	if( packet.size() < size )
	{
		log.txt( LLOG_ERROR,
			"!! : validate packet failed ( truncated header )\n" );

		return LIBIKE_FAILED;
	}

	while( true )
	{
		IKE_PAYLOAD * payload = ( IKE_PAYLOAD * )( packet.buff() + size );

		if( packet.size() < ( size + sizeof( IKE_PAYLOAD ) ) )
		{
			log.txt( LLOG_ERROR,
				"!! : validate packet failed ( truncated payload )\n" );

			return LIBIKE_FAILED;
		}

		if( payload->reserved )
		{
			log.txt( LLOG_ERROR,
				"!! : validate packet failed ( reserved value is non-null )\n" );

			return LIBIKE_FAILED;
		}

		size += ntohs( payload->length );

		if( packet.size() < size )
		{
			log.txt( LLOG_ERROR,
				"!! : validate packet failed ( payload length is invalid )\n" );

			return LIBIKE_FAILED;
		}

		if( payload->next == ISAKMP_PAYLOAD_NONE )
			break;
	}

	//
	// validate packet padding. if the encrypted
	// packet size is equal to the ike message
	// length, we can skip this step. although the
	// RFC states there should at least be one pad
	// byte that describes the padding length, if
	// we are strict we will break compatibility
	// with many implementations including cisco
	//

	if( size < packet.size() )
	{
		//
		// trim packet padding
		//

		size_t diff = packet.size() - size;

		packet.size( size );

		log.txt( LLOG_DEBUG,
			"<= : trimmed packet padding ( %i bytes )\n",
			 diff );

		header = ( IKE_HEADER * ) packet.buff();
		header->length = htonl( ( uint32_t ) size );
	}

	//
	// store cipher iv data
	//

	memcpy(
		iv->buff(),
		iv_data,
		iv->size() );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		iv->buff(),
		iv->size(),
		"<= : stored iv" );
	
	return LIBIKE_OK;
}

long _IKED::packet_ike_encrypt( IDB_PH1 * sa, PACKET_IKE & packet, BDATA * iv )
{
	log.txt( LLOG_INFO,
		">= : cookies %08x%08x:%08x%08x\n",
		htonl( *( long * ) &sa->cookies.i[ 0 ] ),
		htonl( *( long * ) &sa->cookies.i[ 4 ] ),
		htonl( *( long * ) &sa->cookies.r[ 0 ] ),
		htonl( *( long * ) &sa->cookies.r[ 4 ] ) );

	log.txt( LLOG_INFO,
		">= : message %08x\n",
		htonl( packet.get_msgid() ) );

	//
	// check if encrypt is required
	//

	unsigned char *	data = packet.buff();
	size_t		    size = packet.size();

	if( !( data[ ISAKMP_FLAGS_OFFSET ] & ISAKMP_FLAG_ENCRYPT ) )
		return LIBIKE_OK;

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		iv->buff(),
		iv->size(),
		">= : encrypt iv" );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		packet.buff(),
		packet.size(),
		"== : encrypt packet" );

	//
	// determine pad length
	//

	size_t plen = size - sizeof( IKE_HEADER );
	size_t blen = EVP_CIPHER_block_size( sa->evp_cipher );
	size_t padd = 0;

	if( plen % blen )
		padd += blen - ( plen % blen );

	packet.add_null( padd );

	data = packet.buff();
	size = packet.size();

	//
	// set new packet length in header
	//

	IKE_HEADER * header = ( IKE_HEADER * ) packet.buff();
	header->length = htonl( ( uint32_t ) size );

	//
	// init cipher key and iv and
	// encrypt all but header
	//

	EVP_CIPHER_CTX ctx_cipher;
	EVP_CIPHER_CTX_init( &ctx_cipher );

	EVP_CipherInit_ex(
		&ctx_cipher,
		sa->evp_cipher,
		NULL,
		NULL,
		NULL,
		1 );

	EVP_CIPHER_CTX_set_key_length(
		&ctx_cipher,
		( int ) sa->key.size() );

	EVP_CipherInit_ex(
		&ctx_cipher,
		NULL,
		NULL,
		sa->key.buff(),
		iv->buff(),
		1 );

	EVP_Cipher(
		&ctx_cipher,
		data + sizeof( IKE_HEADER ),
		data + sizeof( IKE_HEADER ),
		( int ) size - sizeof( IKE_HEADER ) );

	EVP_CIPHER_CTX_cleanup( &ctx_cipher );

	//
	// store cipher iv data
	//

	memcpy(
		iv->buff(),
		data + size - iv->size(),
		iv->size() );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		iv->buff(),
		iv->size(),
		"== : stored iv" );

	return LIBIKE_OK;
}

