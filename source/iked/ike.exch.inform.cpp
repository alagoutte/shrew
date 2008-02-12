
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

long _IKED::process_inform_send( IDB_PH1 * ph1, IDB_XCH * inform )
{
	//
	// sanity checks
	//

	assert( ph1 != NULL );
	assert( inform->notifications.count() != 0 );

	//
	// create notification packet
	//

	PACKET_IKE packet;
	packet.set_msgid( inform->msgid );

	//
	// determine encryption
	//

	unsigned char flags = 0;
	if( ph1->status() >= XCH_STATUS_MATURE )
		flags |= ISAKMP_FLAG_ENCRYPT;

	//
	// determine next payload
	//

	IKE_NOTIFY notify;
	inform->notifications.get( notify, 0 );

	unsigned char next;
	if( flags & ISAKMP_FLAG_ENCRYPT )
		next = ISAKMP_PAYLOAD_HASH;
	else
		next = notify.type;

	//
	// write packet header
	//

	packet.write( ph1->cookies, next, ISAKMP_EXCH_INFORMATIONAL, flags );

	//
	// optionally add null hash payload
	//

	size_t off = packet.size();

	if( flags & ISAKMP_FLAG_ENCRYPT )
	{
		inform->hash_l.size( ph1->hash_size );
		payload_add_hash( packet, inform->hash_l, notify.type );
	}

	//
	// add all notify / delete payloads
	//

	size_t beg = packet.size();

	long nindex = 0;

	while( 1 )
	{
		//
		// get next notification
		//

		if( !inform->notifications.get( notify, nindex++ ) )
			break;

		//
		// determine following notification
		//

		next = ISAKMP_PAYLOAD_NONE;
		if( inform->notifications.count() > nindex )
		{
			IKE_NOTIFY next_notify;
			inform->notifications.get( next_notify, nindex );

			next = next_notify.type;
		}

		//
		// add notification payload
		//

		switch( notify.type )
		{
			case ISAKMP_PAYLOAD_NOTIFY:
				payload_add_notify( packet, &notify, next );
				break;

			case ISAKMP_PAYLOAD_DELETE:
				payload_add_delete( packet, &notify, next );
				break;
		}
	}

	size_t end = packet.size();

	inform->hda.add( packet.buff() + beg, end - beg );

	//
	// end packet
	//

	packet.done();

	//
	// optionaly build crypto iv
	//

	if( flags & ISAKMP_FLAG_ENCRYPT )
	{
		inform_gen_hash( ph1, inform );

		memcpy(
			packet.buff() + off + 4,
			inform->hash_l.buff(),
			inform->hash_l.size() );

		phase2_gen_iv( ph1, inform->msgid, inform->iv );
	}

	//
	// send the packet
	//

	return packet_ike_send( ph1, inform, packet, false );
}

long _IKED::process_inform_recv( IDB_PH1 * ph1, PACKET_IKE & packet, unsigned char payload )
{
	IDB_INF	inform;
	bool	secure = false;
	long	result = LIBIKE_OK;

	//
	// log packet type
	//

	log.txt( LLOG_INFO,
		"ii : processing informational packet ( %i bytes )\n",
		packet.size() );

	//
	// calculate iv for this
	// informational exchange
	//

	packet.get_msgid( inform.msgid );

	phase2_gen_iv( ph1, inform.msgid, inform.iv );

	//
	// decrypt packet
	//

	if( packet_ike_decrypt( ph1, packet, &inform.iv ) != LIBIKE_OK )
	{
		log.txt( LLOG_ERROR,
			"!! : informational packet ignored ( packet decryption error )\n" );

		return LIBIKE_OK;
	}

	//
	// if we are dumping decrypted packets,
	// we need to rebuild a full packet to
	// dump to pcap format 
	//

	if( dump_decrypt )
	{
		//
		// strip the isakmp encryption flag
		//

		packet.buff()[ ISAKMP_FLAGS_OFFSET ] &= ~ISAKMP_FLAG_ENCRYPT;

		//
		// build ip dump packet
		//

		PACKET_IP packet_ip_dump;
		packet_ike_encap(
			packet,
			packet_ip_dump,
			ph1->tunnel->saddr_r,
			ph1->tunnel->saddr_l,
			ph1->tunnel->natt_v );

		//
		// obtain ethernet header
		//

		ETH_HEADER ethhdr;
		header( packet_ip_dump, ethhdr );

		//
		// dump the packet
		//

		pcap_decrypt.dump(
			ethhdr,
			packet_ip_dump );
	}

	//
	// read and process all payloads
	//

	while( payload != ISAKMP_PAYLOAD_NONE )
	{
		//
		// read the payload header
		//

		uint8_t next_payload;
		if( !packet.get_payload( false, next_payload ) )
			break;

		//
		// check the payload type
		//

		switch( payload )
		{
			//
			// hash payload
			//

			case ISAKMP_PAYLOAD_HASH:
			{
				result = payload_get_hash( packet, inform.hash_r, ph1->hash_size );

				inform.xstate |= XSTATE_RECV_HA;

				break;
			}

			//
			// notify payload
			//

			case ISAKMP_PAYLOAD_NOTIFY:
			{
				IKE_NOTIFY notify;
				size_t beg = packet.oset() - 4;
				result = payload_get_notify( packet, &notify );
				size_t end = packet.oset();
				inform.hda.set( packet.buff() + beg, end - beg );

				if( result == LIBIKE_OK )
					inform.notifications.add( notify );

				break;
			}

			//
			// delete payload
			//

			case ISAKMP_PAYLOAD_DELETE:
			{
				IKE_NOTIFY notify;
				size_t beg = packet.oset() - 4;
				result = payload_get_delete( packet, &notify );
				size_t end = packet.oset();
				inform.hda.set( packet.buff() + beg, end - beg );

				if( result == LIBIKE_OK )
					inform.notifications.add( notify );

				break;
			}

			//
			// unhandled payload
			//

			default:

				log.txt( LLOG_ERROR,
					"!! : unhandled informational payload \'%s\' ( %i )\n",
					find_name( NAME_PAYLOAD, payload ),
					payload );

				result = LIBIKE_FAILED;

				break;
		}

		//
		// was the entire payload read
		//

		if( packet.get_payload_left() )
			log.txt( LLOG_ERROR, "XX : warning, unprocessed payload data !!!\n" );

		//
		// check the result
		//

		if( result != LIBIKE_OK )
			return result;

		//
		// read next payload
		//

		payload = next_payload;
	}

	//
	// now that all payloads have been read,
	// validate any received hash values
	//

	if( inform.xstate & XSTATE_RECV_HA )
		if( inform_chk_hash( ph1, &inform ) )
			secure = true;

	//
	// check all notification payloads
	//

	if( inform.notifications.count() )
	{
		IKE_NOTIFY notify;

		long nindex = 0;
		while( inform.notifications.get( notify, nindex++ ) )
		{
			switch( notify.type )
			{
				case ISAKMP_PAYLOAD_NOTIFY:
					inform_chk_notify( ph1, &notify, secure );
					break;

				case ISAKMP_PAYLOAD_DELETE:
					inform_chk_delete( ph1, &notify, secure );
					break;
			}
		}
	}

	return LIBIKE_OK;
}


long _IKED::inform_chk_hash( IDB_PH1 * ph1, IDB_XCH * inform )
{
	BDATA hash_c;
	hash_c.size( ph1->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_Init( &ctx_prf, ph1->skeyid_a.buff(), ( int ) ph1->skeyid_a.size(), ph1->evp_hash );
	HMAC_Update( &ctx_prf, ( unsigned char * ) &inform->msgid, 4 );
	HMAC_Update( &ctx_prf, inform->hda.buff(), inform->hda.size() );
	HMAC_Final( &ctx_prf, hash_c.buff(), NULL );
	HMAC_cleanup( &ctx_prf );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		hash_c.buff(),
		hash_c.size(),
		"== : informational hash_i ( computed )" );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		inform->hash_r.buff(),
		inform->hash_r.size(),
		"== : informational hash_c ( received )" );

	if( memcmp( inform->hash_r.buff(), hash_c.buff(), hash_c.size() ) )
	{
		log.txt( LLOG_ERROR,	"!! : informational hash verification failed\n" );

		return LIBIKE_FAILED;
	}

	log.txt( LLOG_DEBUG,	"ii : informational hash verified\n" );

	return LIBIKE_OK;
}

long _IKED::inform_gen_hash( IDB_PH1 * ph1, IDB_XCH * inform )
{
	inform->hash_l.size( ph1->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_Init( &ctx_prf, ph1->skeyid_a.buff(), ( int ) ph1->skeyid_a.size(), ph1->evp_hash );
	HMAC_Update( &ctx_prf, ( unsigned char * ) &inform->msgid, sizeof( inform->msgid ) );
	HMAC_Update( &ctx_prf, inform->hda.buff(), inform->hda.size() );
	HMAC_Final( &ctx_prf, inform->hash_l.buff(), 0 );
	HMAC_cleanup( &ctx_prf );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		inform->hash_l.buff(),
		inform->hash_l.size(),
		"== : new informational hash" );

	return LIBIKE_OK;
}

long _IKED::inform_get_spi( char * text, IDB_PH1 * ph1, IKE_NOTIFY * notify )
{
	switch( notify->spi.size )
	{
		case 0:
			sprintf_s( text, LIBIKE_MAX_TEXTSPI, "none" );
			break;

		case ( ISAKMP_COOKIE_SIZE * 2 ):
			sprintf_s( text, LIBIKE_MAX_TEXTSPI,
				"%08x%08x:%08x%08x",
				htonl( *( long * ) &notify->spi.cookies.i[ 0 ] ),
				htonl( *( long * ) &notify->spi.cookies.i[ 4 ] ),
				htonl( *( long * ) &notify->spi.cookies.r[ 0 ] ),
				htonl( *( long * ) &notify->spi.cookies.r[ 4 ] ) );
			break;

		case ISAKMP_SPI_SIZE:
			sprintf_s( text, LIBIKE_MAX_TEXTSPI, "0x%08x", ntohl( notify->spi.spi ) );
			break;

		case ISAKMP_CPI_SIZE:
			sprintf_s( text, LIBIKE_MAX_TEXTSPI, "0x%04x", ntohs( notify->spi.cpi ) );
			break;

		default:
			sprintf_s( text, LIBIKE_MAX_TEXTSPI, "unspecified value" );
			return LIBIKE_FAILED;
	}

	return LIBIKE_OK;
}

long _IKED::inform_chk_notify( IDB_PH1 * ph1, IKE_NOTIFY * notify, bool secure )
{
	assert( ph1 != NULL );

	//
	// build text strings for logging
	//

	char txtspi[ LIBIKE_MAX_TEXTSPI ];

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	inform_get_spi( txtspi, ph1, notify );
	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	//
	// log the notification
	//

	log.txt( LLOG_INFO,
		"ii : received peer %s notification\n"
		"ii : - %s -> %s\n"
		"ii : - %s spi = %s\n"
		"ii : - data size %i\n",
		find_name( NAME_NOTIFY, notify->code ),
		txtaddr_r,
		txtaddr_l,
		find_name( NAME_PROTOCOL, notify->proto ),
		txtspi,
		notify->data.size() );

	//
	// only process this message if
	// it came under the protection
	// of a mature phase1 sa
	//

	if( secure )
		if( ( ph1->status() <= XCH_STATUS_MATURE ) ||
			( ph1->status() >= XCH_STATUS_EXPIRING ) )
			return LIBIKE_FAILED;

	//
	// process the notify message
	//

	switch( notify->spi.size )
	{
		//
		// phase1 notify
		//

		case ( ISAKMP_COOKIE_SIZE * 2 ):
		{
			switch( notify->code )
			{
				case ISAKMP_N_DPD_R_U_THERE:
				{
					uint32_t dpdseq;
					notify->data.get( &dpdseq, sizeof( dpdseq ) );
					dpdseq = ntohl( dpdseq );

					inform_new_notify( ph1, NULL, ISAKMP_N_DPD_R_U_THERE_ACK, &notify->data );

					log.txt( LLOG_DEBUG, "ii : DPD ARE-YOU-THERE sequence %08x returned\n", dpdseq );

					break;
				}

				case ISAKMP_N_DPD_R_U_THERE_ACK:
				{
					if( notify->data.size() == sizeof( ph1->dpd_res ) )
					{
						//
						// obtain sequence number and
						// convert to host byte order
						//

						uint32_t dpdseq;
						notify->data.get( &dpdseq, sizeof( dpdseq ) );
						dpdseq = ntohl( dpdseq );

						//
						// check dpd sequence number. if accepted,
						// set dpd response to current sequence
						//

						if( dpdseq <= ph1->dpd_req )
						{
							log.txt( LLOG_DEBUG, "ii : DPD ARE-YOU-THERE-ACK sequence %08x accepted\n", dpdseq );
							ph1->dpd_res = ph1->dpd_req;
						}
						else
							log.txt( LLOG_ERROR, "!! : DPD ARE-YOU-THERE-ACK sequence %08x rejected\n", dpdseq );
					}

					break;
				}
			}

			break;
		}

		//
		// phase2 notify
		//

		case ISAKMP_SPI_SIZE:
		{
			switch( notify->code )
			{
				case ISAKMP_N_RESPONDER_LIFETIME:
				{
					//
					// attempt to locate phase2 sa
					// and adjust its lifetime
					//

					unsigned long	lsecs = 0;
					unsigned long	ldata = 0;
					unsigned short	ltype;

					IDB_PH2 * ph2_notify;

					if( idb_list_ph2.find(
							true,
							&ph2_notify,
							ph1->tunnel,
							XCH_STATUS_ANY,
							XCH_STATUS_DEAD,
							NULL,
							NULL,
							NULL,
							&notify->spi ) )
					{
						//
						// create a temp packet for parsing
						//

						PACKET_IKE packet;
						packet.add(	notify->data );

						//
						// read all attributes
						//

						IKE_ATTR attrib;

						while( payload_get_attr( packet, attrib ) == LIBIKE_OK )
						{
							switch( attrib.atype )
							{
								case ISAKMP_ATTR_LIFE_TYPE:
								{
									if( ( attrib.bdata != IKE_LIFE_TYPE_SECONDS ) &&
										( attrib.bdata != IKE_LIFE_TYPE_KBYTES ) )
										break;

									ltype = attrib.bdata;

									break;
								}

								case ISAKMP_ATTR_LIFE_DURATION:
								{
									unsigned long lval;
									if( attrib.vdata.size() != sizeof( lval ) )
										break;

									memcpy( &lval, attrib.vdata.buff(), attrib.vdata.size() );
									lval = ntohl( lval );

									switch( ltype )
									{
										case ISAKMP_LIFETYPE_SECONDS:
											lsecs = lval;
											break;

										case ISAKMP_LIFETYPE_KBYTES:
											ldata = lval;
											break;
									}

									break;
								}
							}
						}

						if( lsecs )
						{
							log.txt( LLOG_INFO, "ii : adjusted phase2 sa lifetime to %i seconds\n", lsecs );

							IKE_PROPOSAL * proposal_l;
							IKE_PROPOSAL * proposal_r;
							long pindex = 0;

							while( ph2_notify->plist_l.get( &proposal_l, pindex ) &&
								   ph2_notify->plist_r.get( &proposal_r, pindex ) )
							{
								proposal_l->life_sec = lsecs;
								proposal_r->life_sec = lsecs;

								log.txt( LLOG_DEBUG, "XX : spi_l = 0x%08x\n", ntohl( proposal_l->spi.spi ) );
								log.txt( LLOG_DEBUG, "XX : spi_r = 0x%08x\n", ntohl( proposal_r->spi.spi ) );
								pindex++;
							}
						}

						if( ldata )
							log.txt( LLOG_INFO, "ii : adjusted phase2 sa lifetime to %i kbytes\n", ldata );

						if( !lsecs && !ldata )
							log.txt( LLOG_INFO, "ii : invalid RESPONDER-LIFETIME attribute data\n" );

						ph2_notify->dec( true );
					}
				}
			}

			break;
		}
	}

	return LIBIKE_OK;
}

long _IKED::inform_chk_delete( IDB_PH1 * ph1, IKE_NOTIFY * notify, bool secure )
{
	assert( ph1 != NULL );

	//
	// build text strings for logging
	//

	char txtspi[ LIBIKE_MAX_TEXTSPI ];

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	inform_get_spi( txtspi, ph1, notify );
	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	//
	// log the delete notification
	//

	log.txt( LLOG_INFO,
		"ii : received peer DELETE message\n"
		"ii : - %s -> %s\n"
		"ii : - %s spi = %s\n",
		txtaddr_r,
		txtaddr_l,
		find_name( NAME_PROTOCOL, notify->proto ),
		txtspi );

	//
	// only process this message if
	// it came under the protection
	// of a mature phase1 sa
	//

	if( secure )
		if( ( ph1->status() <= XCH_STATUS_MATURE ) ||
			( ph1->status() >= XCH_STATUS_EXPIRING ) )
			return LIBIKE_FAILED;

	//
	// process the delete message
	//

	switch( notify->spi.size )
	{
		//
		// phase1 notify
		//

		case ( ISAKMP_COOKIE_SIZE * 2 ):
		{
			//
			// attempt to cleanup sa
			//

			IDB_PH1 * ph1_delete;
			if( idb_list_ph1.find(
					true,
					&ph1_delete,
					ph1->tunnel,
					XCH_STATUS_MATURE,
					XCH_STATUS_DEAD,
					&notify->spi.cookies ) )
			{
				log.txt( LLOG_INFO,
					"ii : cleanup, marked phase1 %s for removal\n",
					txtspi );

				ph1_delete->status( XCH_STATUS_DEAD, XCH_FAILED_PEER_DELETE, 0 );
				ph1_delete->dec( true );
			}

			break;
		}

		//
		// phase2 notify
		//

		case ISAKMP_SPI_SIZE:
		{
			//
			// attempt to cleanup sa
			//

			IDB_PH2 * ph2_delete;
			if( idb_list_ph2.find(
					true,
					&ph2_delete,
					ph1->tunnel,
					XCH_STATUS_MATURE,
					XCH_STATUS_DEAD,
					NULL,
					NULL, 
					NULL,
					&notify->spi ) )
			{
				log.txt( LLOG_INFO,
					"DB : cleanup, marked phase2 %s for removal\n",
					txtspi );

				ph2_delete->status( XCH_STATUS_DEAD, XCH_FAILED_PEER_DELETE, 0 );
				ph2_delete->dec( true );
			}

			break;
		}
	}

	return LIBIKE_OK;
}

long _IKED::inform_new_notify( IDB_PH1 * ph1, IDB_PH2 * ph2, unsigned short code, BDATA * data )
{
	assert( ph1 != NULL );

	//
	// build text strings for logging
	//

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	//
	// create message id
	//

	IDB_INF inform;
	rand_bytes( &inform.msgid, 4 );

	//
	// will this be a phase1 or phase2 notification
	//

	if( ph2 == NULL ) 
	{
		//
		// phase1 notification
		//

		IKE_NOTIFY notify;
		notify.type = ISAKMP_PAYLOAD_NOTIFY;
		notify.code = code;
		notify.doi = ISAKMP_DOI_IPSEC;
		notify.proto = ISAKMP_PROTO_ISAKMP;
		notify.spi.size = sizeof( ph1->cookies );
		notify.spi.cookies = ph1->cookies;

		if( data != NULL )
			notify.data.set( *data );

		//
		// log the notification
		//

		char txtspi[ LIBIKE_MAX_TEXTSPI ];

		inform_get_spi( txtspi, ph1, &notify );

		log.txt( LLOG_INFO,
			"ii : sending peer %s notification\n"
			"ii : - %s -> %s\n"
			"ii : - %s spi = %s\n"
			"ii : - data size %i\n",
			find_name( NAME_NOTIFY, notify.code ),
			txtaddr_l,
			txtaddr_r,
			find_name( NAME_PROTOCOL, notify.proto ),
			txtspi,
			notify.data.size() );

		//
		// add notification data
		//

		inform.notifications.add( notify );
	}
	else
	{
		//
		// phase2 notification
		//

		IKE_NOTIFY notify;
		notify.type = ISAKMP_PAYLOAD_NOTIFY;
		notify.code = code;
		notify.doi = ISAKMP_DOI_IPSEC;
		notify.proto = ISAKMP_PROTO_ISAKMP;
		notify.spi.size = 0;

		if( data != NULL )
			notify.data.set( *data );

		//
		// log the notification
		//

		log.txt( LLOG_INFO,
			"ii : sending peer %s notification\n"
			"ii : - %s -> %s\n",
			find_name( NAME_NOTIFY, notify.code ),
			txtaddr_l,
			txtaddr_r );

		//
		// add notification data
		//

		inform.notifications.add( notify );
	}

	return process_inform_send( ph1, &inform );
}

long _IKED::inform_new_delete( IDB_PH1 * ph1, IDB_PH2 * ph2 )
{
	assert( ph1 != NULL );

	//
	// build text strings for logging
	//

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	text_addr( txtaddr_l, &ph1->tunnel->saddr_l, true );
	text_addr( txtaddr_r, &ph1->tunnel->saddr_r, true );

	//
	// create message id
	//

	IDB_INF inform;
	rand_bytes( &inform.msgid, 4 );

	//
	// will this be a phase1 or phase2 notification
	//

	if( ph2 == NULL )
	{
		//
		// phase1 delete
		//

		IKE_NOTIFY notify;
		notify.type = ISAKMP_PAYLOAD_DELETE;
		notify.doi = ISAKMP_DOI_IPSEC;
		notify.proto = ISAKMP_PROTO_ISAKMP;
		notify.spi.size = sizeof( ph1->cookies );
		notify.spi.cookies = ph1->cookies;

		//
		// log the delete
		//

		char txtspi[ LIBIKE_MAX_TEXTSPI ];

		inform_get_spi( txtspi, ph1, &notify );

		log.txt( LLOG_INFO,
			"ii : sending peer DELETE message\n"
			"ii : - %s -> %s\n"
			"ii : - %s spi = %s\n"
			"ii : - data size %i\n",
			txtaddr_l,
			txtaddr_r,
			find_name( NAME_PROTOCOL, notify.proto ),
			txtspi,
			notify.data.size() );

		//
		// add notification data
		//

		inform.notifications.add( notify );
	}
	else
	{
		//
		// phase2 delete
		//

		IKE_NOTIFY notify;
		notify.type = ISAKMP_PAYLOAD_DELETE;
		notify.doi = ISAKMP_DOI_IPSEC;

		//
		// log the delete addresses
		//

		log.txt( LLOG_INFO,
			"ii : sending peer DELETE message\n"
			"ii : - %s -> %s\n",
			txtaddr_l,
			txtaddr_r );

		//
		// add one notify per proposal
		//

		IKE_PROPOSAL * proposal;

		long pindex = 0;
		while( ph2->plist_l.get( &proposal, pindex++ ) )
		{
			notify.proto = proposal->proto;
			notify.spi = proposal->spi;

			//
			// log the delete protocol and spi
			//

			char txtspi[ LIBIKE_MAX_TEXTSPI ];

			inform_get_spi( txtspi, ph1, &notify );

			log.txt( LLOG_INFO,
				"ii : - %s spi = %s\n"
				"ii : - data size %i\n",
				find_name( NAME_PROTOCOL, notify.proto ),
				txtspi,
				notify.data.size() );

			//
			// add notification data
			//

			inform.notifications.add( notify );
		}
	}

	return process_inform_send( ph1, &inform );
}
