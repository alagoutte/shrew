
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
	// if we are dumping ike packets,
	// we need to build an ip packet
	// using the un-encrypted ike
	// payload
	//

	if( dump_ike )
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
			ph1->tunnel->natt_v );

		//
		// obtain ethernet header
		//

		ETH_HEADER ethhdr;
		header( packet_ip_dump, ethhdr );

		//
		// dump the ike packet
		//

		pcap_ike.dump( ethhdr, packet_ip_dump );

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
	// if we will be attempting resends
	// for this packet, clear any old
	// packets that had previously been
	// scheduled for resending that are
	// associated with this db object
	//

	if( retry )
		xch->resend_clear();

	//
	// estimate the maximum packet size
	// after ike encapsulation overhead
	//

	long encap_size = 0;

	// account for udp header length
	encap_size += sizeof( UDP_HEADER );

	// account for non-esp marker
	if( ph1->tunnel->natt_v != IPSEC_NATT_NONE )
		encap_size += sizeof( unsigned long );

	//
	// determine if ike fragmentation
	// will be used on this packet
	//

	bool packet_frag = false;
	long packet_left = packet.size();

	if( ph1->frag_l && ph1->frag_r )
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

		long frag_max = ph1->tunnel->peer->frag_ike_size - encap_size;
		long frag_sent = packet.size() - packet_left;

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

			long frag_size = packet_left;

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

			log.txt( LOG_DEBUG,
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
		xch->resend_sched();

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
	if( ph1->tunnel->natt_v != IPSEC_NATT_NONE )
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
		ph1->tunnel->natt_v );

	//
	// log the result
	//

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
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

	if( result == LIBIKE_SOCKET )
	{
		ph1->tunnel->close = TERM_SOCKET;
		return LIBIKE_FAILED;
	}

	//
	// potentially queue for resend
	//

	if( retry )
		xch->resend_queue( packet_ip );

	//
	// dump for public interface
	//

	if( dump_pub )
		pcap_pub.dump( header, packet_ip );

	return LIBIKE_OK;
}

long _IKED::packet_ike_encap( PACKET_IKE & packet_ike, PACKET_IP & packet_ip, IKE_SADDR & src, IKE_SADDR & dst, long natt )
{
	PACKET_UDP packet_udp;

	packet_udp.write(
		src.saddr4.sin_port,
		dst.saddr4.sin_port );

	if( natt != IPSEC_NATT_NONE )
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
	//
	// check if decrypt is required
	//

	unsigned char *	data = packet.buff();
	long		    size = packet.size();

	if( data[ ISAKMP_FLAGS_OFFSET ] & ISAKMP_FLAG_ENCRYPT )
	{
		log.bin(
			LOG_DEBUG,
			LOG_DECODE,
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

		EVP_CipherInit_ex( &ctx_cipher,
							sa->evp_cipher,
							NULL,
							NULL,
							NULL,
							0 );

//		if( sa->transform.ciph_kl )
			EVP_CIPHER_CTX_set_key_length( &ctx_cipher, sa->key.size() );

		EVP_CipherInit_ex( &ctx_cipher,
							NULL,
							NULL,
							sa->key.buff(),
							iv->buff(),
							0 );

		//
		// decrypt all but header
		//

		EVP_Cipher( &ctx_cipher,
					data + ISAKMP_HEADER_SIZE,
					data + ISAKMP_HEADER_SIZE,
					size - ISAKMP_HEADER_SIZE );

		EVP_CIPHER_CTX_cleanup( &ctx_cipher );

		log.bin(
			LOG_DEBUG,
			LOG_DECODE,
			data,
			size,
			"<= : decrypt packet" );

		//
		// store cipher iv data
		//

		memcpy(
			iv->buff(),
			iv_data,
			iv->size() );

		log.bin(
			LOG_DEBUG,
			LOG_DECODE,
			iv->buff(),
			iv->size(),
			"== : stored iv" );
	}
	
	return LIBIKE_OK;
}

long _IKED::packet_ike_encrypt( IDB_PH1 * sa, PACKET_IKE & packet, BDATA * iv )
{
	//
	// check if encrypt is required
	//

	unsigned char *	data = packet.buff();
	long		    size = packet.size();

	if( data[ ISAKMP_FLAGS_OFFSET ] & ISAKMP_FLAG_ENCRYPT )
	{
		unsigned char *	encr = 0;
		long			padd = 0;

		log.bin(
			LOG_DEBUG,
			LOG_DECODE,
			iv->buff(),
			iv->size(),
			">= : encrypt iv" );

		log.bin(
			LOG_DEBUG,
			LOG_DECODE,
			data,
			size,
			"=> : encrypt packet" );

		//
		// determine padding
		//

		long plen = size - ISAKMP_HEADER_SIZE;
		long blen = EVP_CIPHER_block_size( sa->evp_cipher );

		if( plen % blen )
			padd += blen - plen % blen;

		//
		// duplicate packet data
		// and null padding data
		//

		encr = new unsigned char[ size + padd ];
		if( !encr )
			return LIBIKE_MEMORY;

		memcpy( encr, data, size );
		memset( encr + size, 0, padd );

		//
		// init cipher key and iv and
		// encrypt all but header
		//

		EVP_CIPHER_CTX ctx_cipher;
		EVP_CIPHER_CTX_init( &ctx_cipher );

		EVP_CipherInit_ex( &ctx_cipher,
							sa->evp_cipher,
							NULL,
							NULL,
							NULL,
							1 );

//		if( sa->transform.ciph_kl )
			EVP_CIPHER_CTX_set_key_length( &ctx_cipher, sa->key.size() );

		EVP_CipherInit_ex( &ctx_cipher,
							NULL,
							NULL,
							sa->key.buff(),
							iv->buff(),
							1 );

		EVP_Cipher( &ctx_cipher,
					encr + ISAKMP_HEADER_SIZE,
					encr + ISAKMP_HEADER_SIZE,
					size - ISAKMP_HEADER_SIZE + padd );

		EVP_CIPHER_CTX_cleanup( &ctx_cipher );

		//
		// set new encrypted packet data
		//

		packet.reset();

		packet.add(
			encr,
			size + padd );

		packet.done();

		//
		// store cipher iv data
		//

		memcpy(
			iv->buff(),
			encr + size + padd - iv->size(),
			iv->size() );

		log.bin(
			LOG_DEBUG,
			LOG_DECODE,
			iv->buff(),
			iv->size(),
			"== : stored iv" );

		//
		// cleanup
		//

		delete [] encr;
	}

	return LIBIKE_OK;
}

