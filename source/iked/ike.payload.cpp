
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

long _IKED::payload_add_frag( PACKET_IKE & packet, unsigned char & index, unsigned char * data, size_t & size, size_t max )
{
	log.txt( LLOG_DEBUG, ">> : fragment payload\n" );

	//
	// adjust the callers max to account for
	// the fragment header size
	//

	max -= 8;

	//
	// check if this will be the last fragment
	// and calculate the source packets offset
	// and size
	//

	unsigned char flags = 0;
	if( size <= max )
		flags |= IKE_FRAG_FLAG_LAST;

	if( size > max )
		size = max;

	//
	// sanity check size to make sure it doesn't
	// overflow the 16bit value
	//

	if( ( size + 8 ) > 0xFFFF )
	{
		log.txt( LLOG_DEBUG, "!! : ike fragment length > 16bit\n" );
		return LIBIKE_FAILED;
	}

	uint16_t total = ( uint16_t ) size + 8;

	//
	// write the fragment header
	//

	packet.add_word( 0 );		// always set to 0 ?
	packet.add_word( total );
	packet.add_word( 1 );		// always set to 1 ?
	packet.add_byte( index );
	packet.add_byte( flags );

	// write the fragment data

	packet.add( data, size );

	return LIBIKE_OK;
}

long _IKED::payload_get_frag( PACKET_IKE & packet, IDB_PH1 * ph1, bool & complete )
{
	log.txt( LLOG_DEBUG, "<< : fragment payload\n" );

	//
	// read the frag payload header
	//

	uint16_t	unknown;
	uint16_t	size;
	uint8_t		index;
	uint8_t		flags;

	packet.get_word( unknown );		// always set to 0 ?
	packet.get_word( size );
	packet.get_word( unknown );		// always set to 1 ?
	packet.get_byte( index );
	packet.get_byte( flags );

	//
	// adjust the size to take the
	// fragment header into account
	//

	size -= 8;

	//
	// perform some sanity check
	//

	size_t data_real = packet.size() - packet.oset();
	if( data_real < size )
	{
		log.txt( LLOG_ERROR, "!! : packet size is invalid for given fragment size\n" );
		return LIBIKE_DECODE;
	}

	log.txt( LLOG_DEBUG,
		"ii : - frag index = %i\n"
		"ii : - frag size = %i\n",
		index,
		size );

	//
	// add to our ph1 fragment list
	//

	ph1->frag_add(
		packet.buff() + packet.oset(),
		size,
		index,
		( flags & IKE_FRAG_FLAG_LAST ) );

	//
	// attempt to retrieve the complete packet
	//

	if( ph1->frag_get( packet ) )
		complete = true;

	return LIBIKE_OK;
}

long _IKED::payload_add_attr( PACKET_IKE & packet, IKE_ATTR & attrib  )
{
	if( attrib.basic )
	{
		packet.add_word( BASIC | attrib.atype );
		packet.add_word( attrib.bdata );
	}
	else
	{
		packet.add_word( attrib.atype );
		packet.add_word( short( attrib.vdata.size() ) );
		packet.add(	attrib.vdata );
	}

	return LIBIKE_OK;
}

long _IKED::payload_get_attr( PACKET_IKE & packet, IKE_ATTR & attrib )
{
	//
	// get the attribute type
	//

	if( !packet.get_word( attrib.atype ) )
		return LIBIKE_DECODE;

	//
	// determine if this is a
	// four byte attribute or a
	// variable lenth attribute
	//

	if( attrib.atype & BASIC )
	{
		//
		// basic two byte attribute
		//

		attrib.atype &= ~BASIC;
		attrib.basic = true;

		if( !packet.get_word( attrib.bdata ) )
			return LIBIKE_DECODE;
	}
	else
	{
		//
		// variable length attribute
		//

		uint16_t alen;
		if( !packet.get_word( alen ) )
			return LIBIKE_DECODE;

		//
		// sanity check for packet data
		//

		if( ( packet.size() - packet.oset() ) > alen )
			return LIBIKE_DECODE;

		//
		// read the variable length data
		//

		packet.get( attrib.vdata, alen );
	}

	return LIBIKE_OK;
}

long _IKED::payload_add_sa( PACKET_IKE & packet, IDB_LIST_PROPOSAL & plist, uint8_t next )
{
	//
	// write security association payload
	//

	log.txt( LLOG_DEBUG, ">> : security association payload\n" );

	packet.add_payload( false, next );						// ADD - sa
	packet.add_quad( ISAKMP_DOI_IPSEC );					// domain of interop
	packet.add_quad( ISAKMP_SIT_IDENT_ONLY );				// identity protect situation

	//
	// step through our proposal list
	//

	IKE_PROPOSAL * proposal;

	long pindex = 0;
	long tcount;
	long tindex;

	while( plist.nextp( &proposal, pindex, tindex, tcount ) )
	{
		//
		// write proposal payload
		//

		log.txt( LLOG_DEBUG, ">> : - proposal #%i payload \n", proposal->pnumb );

		next = ISAKMP_PAYLOAD_PROPOSAL;
		if( pindex == -1 )
			next = ISAKMP_PAYLOAD_NONE;

		packet.add_payload( true, next );						// ADD - sa.proposal
		packet.add_byte( proposal->pnumb );						// proposal number
		packet.add_byte( proposal->proto );						// protocol type

		//
		// add spi data
		//

		switch( proposal->proto )
		{
			case ISAKMP_PROTO_ISAKMP:

				packet.add_byte( 0 );							// spi size
				packet.add_byte( ( unsigned char ) tcount );	// number of transforms

				break;

			case ISAKMP_PROTO_IPSEC_AH:
			case ISAKMP_PROTO_IPSEC_ESP:

				packet.add_byte( ISAKMP_SPI_SIZE );				// spi size
				packet.add_byte( ( unsigned char ) tcount );	// number of transforms
				packet.add_quad( proposal->spi.spi, false );	// spi data

				break;

			case ISAKMP_PROTO_IPCOMP:

				packet.add_byte( ISAKMP_CPI_SIZE );				// spi size
				packet.add_byte( ( unsigned char ) tcount );	// number of transforms
				packet.add_word( proposal->spi.cpi, false );	// spi data

				break;
		}

		//
		// step through our transform list
		//

		while( plist.nextt( &proposal, tindex ) )
		{
			//
			// add our transform
			//

			next = ISAKMP_PAYLOAD_TRANSFORM;
			if( tindex == - 1 )
				next = ISAKMP_PAYLOAD_NONE;

			payload_add_xform( packet, proposal, next );
		}

		packet.end_payload( true );								// END -> sa.proposal
		packet.end_payload( false );							// END -> sa
	}

	return LIBIKE_OK;
}

long _IKED::payload_get_sa( PACKET_IKE & packet, IDB_LIST_PROPOSAL & plist )
{
	log.txt( LLOG_DEBUG, "<< : security association payload\n" );

	//
	// read security association packet
	//

	uint32_t doi;
	uint32_t sit;

	//
	// check domain of interpretation
	//

	packet.get_quad( doi );

	if( doi != ISAKMP_DOI_IPSEC )
	{
		log.txt( LLOG_ERROR,
			"!! : rejecting sa payload, invalid doi ( %i )\n",
			doi );

		packet.notify = ISAKMP_N_DOI_NOT_SUPPORTED;

		return LIBIKE_FAILED;
	}

	//
	// check situation
	//

	packet.get_quad( sit );

	if( doi != ISAKMP_SIT_IDENT_ONLY )
	{
		log.txt( LLOG_ERROR,
			"!! : rejecting sa payload, invalid situation ( %i )\n",
			sit );

		packet.notify = ISAKMP_N_SITUATION_NOT_SUPPORTED;

		return LIBIKE_FAILED;
	}

	//
	// read all proposal payloads
	//

	while( 1 )
	{
		//
		// read next proposal payload
		//

		uint8_t next_proposal;
		if( !packet.get_payload( true, next_proposal ) )
			return LIBIKE_DECODE;

		uint8_t	pnumb;
		uint8_t	proto;
		uint8_t	xform_count = 0;
		uint8_t	xform_index = 0;

		IKE_SPI spi;
		
		packet.get_byte( pnumb );
		packet.get_byte( proto );
		packet.get_byte( spi.size );
		packet.get_byte( xform_count );

		log.txt( LLOG_DEBUG, "<< : - propsal #%i payload \n", pnumb );

		//
		// validate the protocol and spi
		//

		bool badspi = false;

		switch( proto )
		{
			case ISAKMP_PROTO_ISAKMP:

				if( spi.size % ISAKMP_COOKIE_SIZE )
					badspi = true;
				else
					packet.get_null( spi.size );

				break;

			case ISAKMP_PROTO_IPSEC_AH:
			case ISAKMP_PROTO_IPSEC_ESP:

				if( spi.size != ISAKMP_SPI_SIZE )
					badspi = true;
				else
					packet.get_quad( spi.spi, false );

				break;

			case ISAKMP_PROTO_IPCOMP:

				if( spi.size != ISAKMP_CPI_SIZE )
					badspi = true;
				else
					packet.get_word( spi.cpi, false );

				break;

			default:

				log.txt( LLOG_ERROR,
					"\n"
					"!! : rejecting sa payload\n"
					"!! : invalid protocol %s ( %i ) \n"
					"\n",
					find_name( NAME_PROTOCOL, proto ),
					proto );

				packet.notify = ISAKMP_N_INVALID_PROTOCOL_ID;

				return LIBIKE_FAILED;
		}

		if( badspi )
		{
			log.txt( LLOG_ERROR,
				"!! : invalid spi size of %i for protocol %s \n",
				spi.size,
				find_name( NAME_PROTOCOL, proto ) );

			packet.notify = ISAKMP_N_INVALID_SPI;

			return LIBIKE_FAILED;
		}

		//
		// read all transforms
		//

		for( ; xform_index < xform_count; xform_index++ )
		{
			IKE_PROPOSAL transform;
			memset( &transform, 0, sizeof( transform ) );

			transform.pnumb = pnumb;
			transform.proto = proto;
			transform.spi = spi;

			long result = payload_get_xform( packet, &transform );
			if( result != LIBIKE_OK )
				return result;

			plist.add( &transform, !xform_index );
		}

		//
		// end proposal
		//

		packet.end_payload( true, false );

		//
		// stop if last proposal
		//

		if( !next_proposal )
			break;
	}

	//
	// end sa payload
	//

	return LIBIKE_OK;
}

long _IKED::payload_add_xform( PACKET_IKE & packet, IKE_PROPOSAL * proposal, uint8_t next )
{
	//
	// write transform payload
	//

	log.txt( LLOG_DEBUG, ">> : -- transform #%i payload \n", proposal->tnumb );

	packet.add_payload( true, next );						// ADD -> sa.proposal.transform
	packet.add_byte( proposal->tnumb );						// transform number
	packet.add_byte( proposal->xform );						// transform type
	packet.add_word( 0 );									// reserved

	// write attributes based on protocol
	// type ( phase1 or phase2 )
	//

	switch( proposal->proto )
	{
		//
		// phase1 attributes
		//

		case ISAKMP_PROTO_ISAKMP:
		{
			packet.add_word( BASIC | IKE_ATTR_TRANSFORM );			// A - transform algorithm
			packet.add_word( proposal->ciph_id );					// V - algorithm id

			if( proposal->ciph_kl )
			{
				packet.add_word( BASIC | IKE_ATTR_KEY_LENGTH );		// A - transform key length
				packet.add_word( proposal->ciph_kl );				// V - key length value
			}

			packet.add_word( BASIC | IKE_ATTR_HASH );				// A - hash algorithm
			packet.add_word( proposal->hash_id );					// V - algorithm id

			packet.add_word( BASIC | IKE_ATTR_GROUP_DESC );			// A - group description
			packet.add_word( proposal->dhgr_id );					// V - description id

			packet.add_word( BASIC | IKE_ATTR_AUTH_METHOD );		// A - authentication method
			packet.add_word( proposal->auth_id );					// V - method id

			if( proposal->life_sec )
			{
				packet.add_word( BASIC | IKE_ATTR_LIFE_TYPE );		// A - life type
				packet.add_word( IKE_LIFE_TYPE_SECONDS );			// V - in seconds

				packet.add_word( IKE_ATTR_LIFE_DURATION );			// A - life duration
				packet.add_word( 4 );								// L - value length
				packet.add_quad( proposal->life_sec );				// V - number of seconds
			}

			if( proposal->life_kbs )
			{
				packet.add_word( BASIC | IKE_ATTR_LIFE_TYPE );		// A - life type
				packet.add_word( IKE_LIFE_TYPE_KBYTES );			// V - in seconds

				packet.add_word( IKE_ATTR_LIFE_DURATION );			// A - life duration
				packet.add_word( 4 );								// L - value length
				packet.add_quad( proposal->life_kbs );				// V - number of seconds
			}

			break;
		}

		//
		// phase2 attributes
		//

		case ISAKMP_PROTO_IPSEC_AH:
		case ISAKMP_PROTO_IPSEC_ESP:
		case ISAKMP_PROTO_IPCOMP:
		{
			packet.add_word( BASIC | ISAKMP_ATTR_ENCAP_MODE );		// A - encapsulation method
			packet.add_word( proposal->encap );						// V - method id

			if( proposal->ciph_kl )
			{
				//
				// only for ciphers with
				// variable length keys
				//

				packet.add_word( BASIC | ISAKMP_ATTR_KEY_LEGTH );		// A - transform key length
				packet.add_word( proposal->ciph_kl );					// V - key length value
			}

			if( proposal->hash_id )
			{
				packet.add_word( BASIC | ISAKMP_ATTR_AUTH_ALGORITHM );	// A - authentication method
				packet.add_word( proposal->hash_id );					// V - algorithm id
			}

			if( proposal->dhgr_id )
			{
				//
				// only for transforms which
				// require a pfs group
				//
				
				packet.add_word( BASIC | ISAKMP_ATTR_GROUP_DESC );		// A - group description
				packet.add_word( proposal->dhgr_id );					// V - description id
			}

			if( proposal->life_sec )
			{
				packet.add_word( BASIC | ISAKMP_ATTR_LIFE_TYPE );	// A - life type
				packet.add_word( ISAKMP_LIFETYPE_SECONDS );			// V - in seconds

				packet.add_word( ISAKMP_ATTR_LIFE_DURATION );		// A - life duration
				packet.add_word( 4 );								// L - value length
				packet.add_quad( proposal->life_sec );				// V - number of seconds
			}

			if( proposal->life_kbs )
			{
				packet.add_word( BASIC | ISAKMP_ATTR_LIFE_TYPE );	// A - life type
				packet.add_word( ISAKMP_LIFETYPE_KBYTES );			// V - in seconds

				packet.add_word( ISAKMP_ATTR_LIFE_DURATION );		// A - life duration
				packet.add_word( 4 );								// L - value length
				packet.add_quad( proposal->life_kbs );				// V - number of seconds
			}

			break;
		}

		default:

			log.txt( LLOG_ERROR, "!! : invalid protocol in proposal" );

			return LIBIKE_FAILED;
	}

	packet.end_payload( true );								// END -> sa.proposal.transform

	return LIBIKE_OK;
}

long _IKED::payload_get_xform( PACKET_IKE & packet, IKE_PROPOSAL * proposal )
{
	//
	// read next transform payload
	//

	uint8_t next;
	packet.get_payload( true, next );

	uint16_t reserved;

	packet.get_byte( proposal->tnumb );		// transform number
	packet.get_byte( proposal->xform );		// transform type
	packet.get_word( reserved );			// reserved 2 bytes

	log.txt( LLOG_DEBUG, "<< : -- transform #%i payload \n", proposal->tnumb );

	//
	// validate the transform type
	//

	bool valid = false;

	switch( proposal->proto )
	{
		case ISAKMP_PROTO_ISAKMP:

			switch( proposal->xform )
			{
				case ISAKMP_KEY_IKE:
					valid = true;
					break;
			}

			break;

		case ISAKMP_PROTO_IPSEC_ESP:

			switch( proposal->xform )
			{
				case ISAKMP_ESP_DES:
				case ISAKMP_ESP_3DES:
				case ISAKMP_ESP_AES:
				case ISAKMP_ESP_BLOWFISH:
				case ISAKMP_ESP_CAST:
					valid = true;
					break;
			}

			break;

		case ISAKMP_PROTO_IPCOMP:

			switch( proposal->xform )
			{
				case ISAKMP_IPCOMP_DEFLATE:
				case ISAKMP_IPCOMP_LZS:
					valid = true;
					break;
			}

			break;
	}

	size_t size = packet.get_payload_left();

	uint32_t lvalue = 0;
	uint16_t svalue = 0;
	uint16_t ltype = 0;
	
	while( size )
	{
		uint16_t attrib;
		uint16_t length;

		//
		// get the attribute type
		//

		packet.get_word( attrib );

		//
		// determine if this is a
		// four byte attribute or a
		// variable lenth attribute
		//

		if( attrib & BASIC )
		{
			//
			// basic four byte attribute
			//

			attrib &= ~BASIC;

			packet.get_word( svalue );
			lvalue = svalue;
		}
		else
		{
			//
			// variable length attribute
			//

			packet.get_word( length );

			//
			// the only attributes we understand are
			// two or four bytes long so reject any
			// values that are longer
			//

			switch( length )
			{
				case 2:

					packet.get_word( svalue );
					lvalue = svalue;

					break;

				case 4:

					packet.get_quad( lvalue );

					break;
			}
		}

		//
		// read attributes based on protocol
		//

		switch( proposal->proto )
		{
			//
			// phase1 attributes
			//

			case ISAKMP_PROTO_ISAKMP:
			{
				//
				// read all attribute / value pairs
				//

				switch( attrib )
				{
					case IKE_ATTR_TRANSFORM:

						proposal->ciph_id = svalue;

						break;

					case IKE_ATTR_KEY_LENGTH:

						proposal->ciph_kl = svalue;

						break;

					case IKE_ATTR_HASH:

						proposal->hash_id = svalue;

						break;

					case IKE_ATTR_GROUP_DESC:

						proposal->dhgr_id = svalue;

						break;

					case IKE_ATTR_AUTH_METHOD:

						proposal->auth_id = svalue;

						break;

					case IKE_ATTR_LIFE_TYPE:

						ltype = svalue;

						break;

					case IKE_ATTR_LIFE_DURATION:
					{
						switch( ltype )
						{
							case IKE_LIFE_TYPE_SECONDS:

								proposal->life_sec = lvalue;

								break;

							case IKE_LIFE_TYPE_KBYTES:

								proposal->life_kbs = lvalue;

								break;

							default:

								log.txt( LLOG_ERROR,
									"\n"
									"!! : rejecting phase1 proposal\n"
									"!! : unhandled life type ( %i )\n"
									"\n",
									ltype );

								packet.notify = ISAKMP_N_BAD_PROPOSAL_SYNTAX;

								return LIBIKE_DECODE;
						}

						break;
					}

					default:
					{
						log.txt( LLOG_ERROR,
							"\n"
							"!! : rejecting phase1 proposal\n"
							"!! : unhandled attribute type ( %i )\n"
							"\n",
							attrib );

						packet.notify = ISAKMP_N_ATTRIBUTES_NOT_SUPPORTED;

						return LIBIKE_DECODE;
					}
				}

				break;
			}

			//
			// phase2 attributes
			//

			case ISAKMP_PROTO_IPSEC_AH:
			case ISAKMP_PROTO_IPSEC_ESP:
			case ISAKMP_PROTO_IPCOMP:
			{
				//
				// read all attribute / value pairs
				//

				switch( attrib )
				{
					case ISAKMP_ATTR_LIFE_TYPE:

						ltype = svalue;

						break;

					case ISAKMP_ATTR_LIFE_DURATION:
					{
						switch( ltype )
						{
							case ISAKMP_LIFETYPE_SECONDS:

								proposal->life_sec = lvalue;

								break;

							case ISAKMP_LIFETYPE_KBYTES:

								proposal->life_kbs = lvalue;

								break;

							default:

								log.txt( LLOG_ERROR,
									"\n"
									"!! : rejecting phase2 proposal\n"
									"!! : unhandled life type ( %i )\n"
									"\n",
									ltype );

								packet.notify = ISAKMP_N_BAD_PROPOSAL_SYNTAX;

								return LIBIKE_DECODE;
						}

						break;
					}

					case ISAKMP_ATTR_GROUP_DESC:

						proposal->dhgr_id = svalue;

						break;

					case ISAKMP_ATTR_ENCAP_MODE:

						proposal->encap = svalue;

						break;

					case ISAKMP_ATTR_AUTH_ALGORITHM:

						proposal->hash_id = svalue;

						break;

					case ISAKMP_ATTR_KEY_LEGTH:

						proposal->ciph_kl = svalue;

						break;

					default:
					{
						log.txt( LLOG_ERROR,
							"\n"
							"!! : rejecting phase2 proposal\n"
							"!! : unhandled attribute type ( %i )\n"
							"\n",
							attrib );

						packet.notify = ISAKMP_N_ATTRIBUTES_NOT_SUPPORTED;

						return LIBIKE_DECODE;
					}
				}

				break;
			}
		}

		size = packet.get_payload_left();
	}

	//
	// end transform
	//

	packet.end_payload( true, false );

	return LIBIKE_OK;
}

long _IKED::payload_add_kex( PACKET_IKE & packet, BDATA & gx, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : key exchange payload\n" );

	//
	// write key exchange payload
	//

	packet.add_payload( false, next );			// ADD -> kex
	packet.add( gx );							// public value
	packet.end_payload( false );				// END -> kex

	return LIBIKE_OK;
}

long _IKED::payload_get_kex( PACKET_IKE & packet, BDATA & gx )
{
	log.txt( LLOG_DEBUG, "<< : key exchange payload\n" );

	//
	// read key exchange payload
	//

	size_t size = packet.get_payload_left();

	if( size > LIBIKE_MAX_DHGRP )
	{
		log.txt( LLOG_ERROR,
			"<< : invalid dh size ( %i > %i )\n",
			size,
			LIBIKE_MAX_DHGRP );

		packet.notify = ISAKMP_N_INVALID_HASH_INFORMATION;

		return LIBIKE_DECODE;
	}

	packet.get( gx, size );

	return LIBIKE_OK;
}

long _IKED::payload_add_nonce( PACKET_IKE & packet, BDATA & nonce, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : nonce payload\n" );

	//
	// write nonce payload
	//

	packet.add_payload( false, next );					// ADD -> nonce
	packet.add( nonce );								// nonce value
	packet.end_payload( false );						// END -> nonce

	return LIBIKE_OK;
}

long _IKED::payload_get_nonce( PACKET_IKE & packet, BDATA & nonce )
{
	log.txt( LLOG_DEBUG, "<< : nonce payload\n" );

	//
	// read nonce payload
	//

	size_t size = packet.get_payload_left();

	if( ( size < ISAKMP_NONCE_MIN ) ||
		( size > ISAKMP_NONCE_MAX ) )
		return LIBIKE_FAILED;

	packet.get( nonce, size );		// nonce value

	return LIBIKE_OK;
}

long _IKED::payload_add_ph1id( PACKET_IKE & packet, IKE_PH1ID & ph1id, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : identification payload\n" );

	//
	// write identity payload
	//

	packet.add_payload( false, next );		// ADD - identity
	packet.add_byte( ph1id.type );			// id type
	packet.add_byte( 0 );					// protocol ( ignore )
	packet.add_word( 0 );					// IP port ( ignore )

	switch( ph1id.type )
	{
		case ISAKMP_ID_NONE:
			
			//
			// used for hybrid auth
			//

			break;

		case ISAKMP_ID_FQDN:
		case ISAKMP_ID_USER_FQDN:
		case ISAKMP_ID_ASN1_DN:
		case ISAKMP_ID_ASN1_GN:
		case ISAKMP_ID_KEY_ID:

			packet.add( ph1id.varid );						// string ids

			break;
	
		case ISAKMP_ID_IPV4_ADDR:

			packet.add_quad( ph1id.addr.s_addr, false );	// host address

			break;

		default:

			log.txt( LLOG_ERROR,
				"!! : unhandled phase1 id type \'%s\'( %i )\n",
				find_name( NAME_IDENT, ph1id.type ),
				ph1id.type );

			return LIBIKE_ENCODE;
	}

	packet.end_payload( false, true );		// END - identity

	return LIBIKE_OK;
}

long _IKED::payload_get_ph1id( PACKET_IKE & packet, IKE_PH1ID & ph1id )
{
	log.txt( LLOG_DEBUG, "<< : identification payload\n" );

	//
	// read responder identity payload
	//

	uint8_t		r_prot;
	uint16_t	r_port;
	uint32_t	temp = 0;

	size_t		size;

	packet.get_byte( ph1id.type );			// id type
	packet.get_byte( r_prot );				// protocol ( ignore )
	packet.get_word( r_port );				// IP port ( ignore )

	switch( ph1id.type )
	{
		case ISAKMP_ID_NONE:
			
			//
			// used for hybrid auth
			//

			break;

		case ISAKMP_ID_FQDN:
		case ISAKMP_ID_USER_FQDN:
		case ISAKMP_ID_ASN1_DN:
		case ISAKMP_ID_ASN1_GN:
		case ISAKMP_ID_KEY_ID:

			size = packet.get_payload_left();
			if( size < LIBIKE_MAX_VARID )
				packet.get( ph1id.varid, size );		// string ids

			break;
	
		case ISAKMP_ID_IPV4_ADDR:

			packet.get_quad( temp, false );				// host address

			break;

		default:

			log.txt( LLOG_ERROR,
				"!! : unhandled phase1 id type \'%s\'( %i )\n",
				find_name( NAME_IDENT, ph1id.type ),
				ph1id.type );

			packet.notify = ISAKMP_N_INVALID_ID_INFORMATION;
			
			return LIBIKE_DECODE;
	}

	ph1id.addr.s_addr = temp;

	return LIBIKE_OK;
}

long _IKED::payload_add_ph2id( PACKET_IKE & packet, IKE_PH2ID & ph2id, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : identification payload\n" );

	//
	// write identity payload
	//

	packet.add_payload( false, next );		// ADD - identity
	packet.add_byte( ph2id.type );			// id type
	packet.add_byte( ph2id.prot );			// protocol
	packet.add_word( ph2id.port, false );	// IP port

	switch( ph2id.type )
	{
		case ISAKMP_ID_IPV4_ADDR:

			packet.add_quad( ph2id.addr1.s_addr, false );	// host address

			break;

		case ISAKMP_ID_IPV4_ADDR_RANGE:
		case ISAKMP_ID_IPV4_ADDR_SUBNET:

			packet.add_quad( ph2id.addr1.s_addr, false );	// address range / subnet
			packet.add_quad( ph2id.addr2.s_addr, false );	// address range / subnet mask

			break;

		default:

			log.txt( LLOG_ERROR,
				"!! : unhandled ipv4 id type \'%s\'( %i )\n",
				find_name( NAME_IDENT, ph2id.type ),
				ph2id.type );
				
			return LIBIKE_ENCODE;
	}

	packet.end_payload( false, true );		// END - identity

	return LIBIKE_OK;
}

long _IKED::payload_get_ph2id( PACKET_IKE & packet, IKE_PH2ID & ph2id )
{
	log.txt( LLOG_DEBUG, "<< : identification payload\n" );

	//
	// read responder identity payload
	//

	uint32_t	temp1 = 0;
	uint32_t	temp2 = 0;

	packet.get_byte( ph2id.type );			// id type
	packet.get_byte( ph2id.prot );			// protocol
	packet.get_word( ph2id.port, false );	// IP port

	switch( ph2id.type )
	{
		case ISAKMP_ID_IPV4_ADDR:

			packet.get_quad( temp1, false );	// host address

			break;

		case ISAKMP_ID_IPV4_ADDR_RANGE:
		case ISAKMP_ID_IPV4_ADDR_SUBNET:

			packet.get_quad( temp1, false );	// address range / subnet
			packet.get_quad( temp2, false );	// address range / subnet mask

			break;

		default:

			log.txt( LLOG_ERROR,
				"!! : unhandled ipv4 id type \'%s\'( %i )\n",
				find_name( NAME_IDENT, ph2id.type ),
				ph2id.type );

			packet.notify = ISAKMP_N_INVALID_ID_INFORMATION;
			
			return LIBIKE_DECODE;
	}

	ph2id.addr1.s_addr = temp1;
	ph2id.addr2.s_addr = temp2;

	return LIBIKE_OK;
}

long _IKED::payload_add_cert( PACKET_IKE & packet, uint8_t type, BDATA & cert, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : certificate payload\n" );

	//
	// write certificate payload
	//

	packet.add_payload( false, next );		// ADD - certificate
	packet.add_byte( type );				// certificate type
	packet.add( cert );						// certificate data
	packet.end_payload( false );			// END - certificate

	return LIBIKE_OK;
}

long _IKED::payload_get_cert( PACKET_IKE & packet, uint8_t & type, BDATA & cert )
{
	log.txt( LLOG_DEBUG, "<< : certificate payload\n" );

	//
	// read certificate payload
	//

	size_t size = packet.get_payload_left();
	size--;

	if( size > ISAKMP_CERT_MAX )
	{
		log.txt( LLOG_ERROR,
			"!! : invalid certificate size ( %i > %i )\n",
			size,
			ISAKMP_CERT_MAX );

		packet.notify = ISAKMP_N_PAYLOAD_MALFORMED;

		return LIBIKE_DECODE;
	}

	packet.get_byte( type );				// certificate type

	//
	// check certificate type
	//

	if( type == ISAKMP_CERT_X509_SIG )
		packet.get( cert, size );			// certificate data
	else
		packet.get_null( size );			// certificate data

	return LIBIKE_OK;
}

long _IKED::payload_add_creq( PACKET_IKE & packet, uint8_t type, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : cert request payload\n" );

	//
	// write certificate request payload
	//

	packet.add_payload( false, next );		// ADD - certificate
	packet.add_byte( type );				// certificate request data
	packet.end_payload( false );			// END - certificate

	return LIBIKE_OK;
}

long _IKED::payload_get_creq( PACKET_IKE & packet, uint8_t & type, BDATA & dn )
{
	log.txt( LLOG_DEBUG, "<< : cert request payload\n" );

	//
	// read certificate request payload
	//

	size_t size = packet.get_payload_left();
	size--;

	if( size > ISAKMP_CREQ_MAX )
	{
		log.txt( LLOG_ERROR,
			"!! : invalid certificate request size ( %i > %i )\n",
			size,
			ISAKMP_CREQ_MAX );

		packet.notify = ISAKMP_N_PAYLOAD_MALFORMED;

		return LIBIKE_DECODE;
	}

	packet.get_byte( type );				// certificate request type
	packet.get( dn, size );					// certificate request dn data

	//
	// check certificate type
	//

//	if( type != ISAKMP_CERT_X509_SIG )
//	{
//		packet.notify = ISAKMP_N_CERT_TYPE_UNSUPPORTED;
//		return LIBIKE_DECODE;
//	}

	return LIBIKE_OK;
}

long _IKED::payload_add_sign( PACKET_IKE & packet, BDATA & sign, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : signature payload\n" );

	//
	// write signature payload
	//

	packet.add_payload( false, next );		// ADD - signature
	packet.add( sign );						// signature data
	packet.end_payload( false );			// END - signature

	return LIBIKE_OK;
}

long _IKED::payload_get_sign( PACKET_IKE & packet, BDATA & sign )
{
	log.txt( LLOG_DEBUG, "<< : signature payload\n" );

	//
	// read signature payload
	//

	size_t size = packet.get_payload_left();

	if( size > ISAKMP_SIGN_MAX )
	{
		log.txt( LLOG_ERROR,
			"!! : invalid signature payload size ( %i > %i )\n",
			size,
			ISAKMP_SIGN_MAX );

		packet.notify = ISAKMP_N_PAYLOAD_MALFORMED;

		return LIBIKE_DECODE;
	}

	packet.get( sign, size );				// signature data

	return LIBIKE_OK;
}

long _IKED::payload_add_hash( PACKET_IKE & packet, BDATA & hash, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : hash payload\n" );

	//
	// write hash payload
	//

	packet.add_payload( false, next );		// ADD - hash
	packet.add( hash );						// hash value
	packet.end_payload( false );			// END - hash

	return LIBIKE_OK;
}

long _IKED::payload_get_hash( PACKET_IKE & packet, BDATA & hash, long hash_size )
{
	log.txt( LLOG_DEBUG, "<< : hash payload\n" );

	//
	// read hash payload
	//

	size_t size = packet.get_payload_left();

	if( size != hash_size )
	{
		log.txt( LLOG_ERROR,
			"!! : invalid hash size ( %i != %i )\n",
			size,
			hash_size );

		packet.notify = ISAKMP_N_INVALID_HASH_INFORMATION;

		return LIBIKE_DECODE;
	}

	packet.get( hash, size );				// hash value

	return LIBIKE_OK;
}

long _IKED::payload_add_vend( PACKET_IKE & packet, BDATA & vend, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : vendor id payload\n" );

	//
	// write vendor id payload
	//

	packet.add_payload( false, next );
	packet.add( vend );
	packet.end_payload( false );

	return LIBIKE_OK;
}

long _IKED::payload_get_vend( PACKET_IKE & packet, BDATA & vend )
{
	log.txt( LLOG_DEBUG, "<< : vendor id payload\n" );

	//
	// read vendor id payload
	//

	size_t size = packet.get_payload_left();

	//
	// if the vendor id is greater
	// than our max allowable vend
	// id size, skip it as we wont
	// recognize it anyway
	//

	if( size <= ISAKMP_SIGN_MAX )
		packet.get( vend, size );
	else
		packet.get_null( size );

	return LIBIKE_OK;
}

long _IKED::payload_add_cfglist( PACKET_IKE & packet, IDB_CFG * cfg, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : attribute payload\n" );

	//
	// write attribute payload
	//

	packet.add_payload( false, next );
	packet.add_byte( cfg->mtype );			// message type
	packet.add_byte( 0 );					// reserved
	packet.add_word( cfg->ident );			// identity

	long count = cfg->attr_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		IKE_ATTR * attr = cfg->attr_get( index );

		if( attr->basic )
		{
			packet.add_word( BASIC | attr->atype );
			packet.add_word( attr->bdata );
		}
		else
		{
			packet.add_word( attr->atype );
			packet.add_word( short( attr->vdata.size() ) );
			packet.add( attr->vdata );
		}
	}

	packet.end_payload( false );

	return LIBIKE_OK;
}

long _IKED::payload_get_cfglist( PACKET_IKE & packet, IDB_CFG * cfg )
{
	log.txt( LLOG_DEBUG, "<< : attribute payload\n" );

	//
	// read attribute payload
	//

	packet.get_byte( cfg->mtype );			// message type
	packet.get_null( 1 );					// reserved
	packet.get_word( cfg->ident );			// identity

	//
	// get remaining payload length
	//

	size_t size = packet.get_payload_left();

	while( size )
	{
		//
		// get the attribute type
		//

		uint16_t atype;
		packet.get_word( atype );

		//
		// determine if this is a
		// four byte attribute or a
		// variable lenth attribute
		//

		if( atype & BASIC )
		{
			//
			// basic two byte attribute
			//

			uint16_t adata;
			packet.get_word( adata );

			cfg->attr_add_b( atype & ~BASIC, adata );
		}
		else
		{
			//
			// variable length attribute
			//

			uint16_t	asize;
			BDATA		adata;

			packet.get_word( asize );
			packet.get(	adata, asize );

			cfg->attr_add_v( atype, adata.buff(), adata.size() );
		}

		//
		// get remaining payload length
		//

		size = packet.get_payload_left();
	}

	return LIBIKE_OK;
}

long _IKED::payload_add_natd( PACKET_IKE & packet, BDATA & natd, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : nat discovery payload\n" );

	//
	// write natd hash payload
	//

	packet.add_payload( false, next );		// ADD - hash
	packet.add( natd );						// hash value
	packet.end_payload( false );			// END - hash

	return LIBIKE_OK;
}

long _IKED::payload_get_natd( PACKET_IKE & packet, BDATA & natd, long natd_size )
{
	log.txt( LLOG_DEBUG, "<< : nat discovery payload\n" );

	//
	// read hash payload
	//

	size_t size = packet.get_payload_left();

	if( size != natd_size )
	{
		log.txt( LLOG_ERROR,
			"!! : invalid natd hash size ( %i != %i )\n",
			size,
			natd_size );

		packet.notify = ISAKMP_N_INVALID_HASH_INFORMATION;

		return LIBIKE_DECODE;
	}

	packet.get( natd, size );				// hash value

	return LIBIKE_OK;
}

long _IKED::payload_add_notify( PACKET_IKE & packet, IKE_NOTIFY * notify, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : notification payload\n" );

	//
	// write notification payload
	//

	packet.add_payload( false, next );
	packet.add_quad( notify->doi );
	packet.add_byte( notify->proto );
	packet.add_byte( notify->spi.size );
	packet.add_word( notify->code );

	switch( notify->spi.size )
	{
		case ( ISAKMP_COOKIE_SIZE * 2 ):
			packet.add( notify->spi.cookies.i, ISAKMP_COOKIE_SIZE );
			packet.add( notify->spi.cookies.r, ISAKMP_COOKIE_SIZE );
			break;

		case ISAKMP_SPI_SIZE:
			packet.add_quad( notify->spi.spi, false );
			break;

		case ISAKMP_CPI_SIZE:
			packet.add_word( notify->spi.cpi, false );
			break;
	}

	//
	// write any extra notify data
	//

	packet.add( notify->data );

	packet.end_payload( false );

	return LIBIKE_OK;
}

long _IKED::payload_get_notify( PACKET_IKE & packet, IKE_NOTIFY * notify )
{
	log.txt( LLOG_DEBUG, "<< : notification payload\n" );

	//
	// read notification payload
	//

	notify->type = ISAKMP_PAYLOAD_NOTIFY;

	packet.get_quad( notify->doi );
	packet.get_byte( notify->proto );
	packet.get_byte( notify->spi.size );
	packet.get_word( notify->code );

	//
	// read the spi
	//

	switch( notify->spi.size )
	{
		case 0:
			break;

		case ( ISAKMP_COOKIE_SIZE * 2 ):
			packet.get( notify->spi.cookies.i, ISAKMP_COOKIE_SIZE );
			packet.get( notify->spi.cookies.r, ISAKMP_COOKIE_SIZE );
			break;

		case ISAKMP_SPI_SIZE:
			packet.get_quad( notify->spi.spi, false );
			break;

		case ISAKMP_CPI_SIZE:
			packet.get_word( notify->spi.cpi, false );
			break;

		default:
			log.txt( LLOG_ERROR, "<< : notification payload contained invalid spi\n" );
			return LIBIKE_FAILED;
	}

	//
	// read any extra notify data
	//

	size_t size = packet.get_payload_left();
	packet.get( notify->data, size );

	return LIBIKE_OK;
}

long _IKED::payload_add_delete( PACKET_IKE & packet, IKE_NOTIFY * notify, uint8_t next )
{
	log.txt( LLOG_DEBUG, ">> : delete payload\n" );

	//
	// write delete payload
	//

	packet.add_payload( false, next );
	packet.add_quad( notify->doi );
	packet.add_byte( notify->proto );
	packet.add_byte( notify->spi.size );
	packet.add_word( 1 );

	switch( notify->spi.size )
	{
		case ( ISAKMP_COOKIE_SIZE * 2 ):
			packet.add( notify->spi.cookies.i, ISAKMP_COOKIE_SIZE );
			packet.add( notify->spi.cookies.r, ISAKMP_COOKIE_SIZE );
			break;

		case ISAKMP_SPI_SIZE:
			packet.add_quad( notify->spi.spi, false );
			break;

		case ISAKMP_CPI_SIZE:
			packet.add_word( notify->spi.cpi, false );
			break;
	}

	packet.end_payload( false );

	return LIBIKE_OK;
}

long _IKED::payload_get_delete( PACKET_IKE & packet, IKE_NOTIFY * notify )
{
	log.txt( LLOG_DEBUG, "<< : delete payload\n" );

	//
	// read notification payload
	//

	uint16_t spi_count;

	notify->type = ISAKMP_PAYLOAD_DELETE;

	packet.get_quad( notify->doi );
	packet.get_byte( notify->proto );
	packet.get_byte( notify->spi.size );

	//
	// TODO : deal with multiple spi's
	//

	packet.get_word( spi_count );

	switch( notify->spi.size )
	{
		case 0:
			break;

		case ( ISAKMP_COOKIE_SIZE * 2 ):
			packet.get( notify->spi.cookies.i, ISAKMP_COOKIE_SIZE );
			packet.get( notify->spi.cookies.r, ISAKMP_COOKIE_SIZE );
			break;

		case ISAKMP_SPI_SIZE:
			packet.get_quad( notify->spi.spi, false );
			break;

		case ISAKMP_CPI_SIZE:
			packet.get_word( notify->spi.cpi, false );
			break;

		default:
			log.txt( LLOG_ERROR, "<< : notification payload contained invalid spi\n" );
			return LIBIKE_FAILED;
	}

	return LIBIKE_OK;
}

