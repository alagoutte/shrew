
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

long _IKED::process_config_recv( IDB_PH1 * ph1, PACKET_IKE & packet, unsigned char payload )
{
	long result = LIBIKE_OK;

	//
	// log packet type
	//

	log.txt( LLOG_INFO,
		"ii : processing config packet ( %i bytes )\n",
		packet.size() );

	//
	// attempt to locate a known
	// config for this phase1
	//

	uint32_t msgid = packet.get_msgid();

	IDB_CFG * cfg = NULL;
	if( !idb_list_cfg.find(	true, &cfg, ph1 ) )
	{
		//
		// create new object config object
		//

		cfg = new IDB_CFG( ph1, false );
		cfg->add( true );
	}

	//
	// if the msgid has changed, set the
	// config msgid value and the iv
	//

	if( cfg->msgid != msgid )
	{
		cfg->msgid = msgid;
		cfg->new_msgiv( ph1 );
	}

	//
	// make sure we are not dealing
	// with an sa marked for delete
	//

	if( ph1->status() == XCH_STATUS_DEAD )
	{
		log.txt( LLOG_ERROR, "!! : config packet ignored ( phase1 marked for death )\n" );
		cfg->dec( true );
		return LIBIKE_OK;
	}

	if( cfg->status() == XCH_STATUS_DEAD )
	{
		log.txt( LLOG_ERROR, "!! : config packet ignored ( config marked for death )\n" );
		cfg->dec( true );
		return LIBIKE_OK;
	}

	//
	// make sure we are not dealing
	// whith an imature phase1 sa
	//

	if( ph1->status() < XCH_STATUS_MATURE )
	{
		log.txt( LLOG_ERROR, "!! : config packet ignored ( phase1 not mature )\n" );
		cfg->dec( true );
		return LIBIKE_OK;
	}

	//
	// make sure we are not dealing
	// with a mature sa
	//

	if( cfg->status() >= XCH_STATUS_MATURE )
	{
		log.txt( LLOG_ERROR, "!! : config packet ignored ( config already mature )\n" );
		cfg->dec( true );
		return LIBIKE_OK;
	}

	//
	// decrypt packet
	//

	if( packet_ike_decrypt( ph1, packet, &cfg->iv ) != LIBIKE_OK )
	{
		log.txt( LLOG_ERROR, "!! : config packet ignored ( packet decryption error )\n" );
		cfg->dec( true );
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
			cfg->tunnel->saddr_r,
			cfg->tunnel->saddr_l,
			cfg->tunnel->natt_version );

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

	cfg->hda.del();
	cfg->attr_reset();

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
				result = payload_get_hash( packet, cfg->hash_r, ph1->hash_size );

				cfg->xstate |= XSTATE_RECV_HA;

				break;
			}

			//
			// attribute payload
			//

			case ISAKMP_PAYLOAD_ATTRIB:
			{
				size_t beg = packet.oset() - 4;
				result = payload_get_cfglist( packet, cfg );
				size_t end = packet.oset();
				cfg->hda.add( packet.buff() + beg, end - beg );

				break;
			}

			//
			// unhandled payload
			//

			default:

				log.txt( LLOG_ERROR,
					"!! : unhandled config payload \'%s\' ( %i )\n",
					find_name( NAME_PAYLOAD, payload ),
					payload );

				result = LIBIKE_FAILED;

				break;
		}

		//
		// was the entire payload read
		//

		if( packet.get_payload_left() )
			log.txt( LLOG_ERROR, "!! : unprocessed payload data !!!\n" );

		//
		// check the result
		//

		if( result != LIBIKE_OK )
		{
			//
			// flag sa for removal
			//

			ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, packet.notify );
			cfg->dec( true );

			return result;
		}

		//
		// read next payload
		//

		payload = next_payload;
	}

	//
	// now that all payloads have been read,
	// validate any received hash values
	//

	if( config_chk_hash( ph1, cfg, msgid ) != LIBIKE_OK )
	{
		//
		// update status and release
		//

		ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_AUTH, ISAKMP_N_INVALID_HASH_INFORMATION );
		cfg->dec( true );

		return LIBIKE_FAILED;
	}

	//
	// hanlde server to client messages
	//

	while( ph1->initiator )
	{
		//
		// handle xauth messages
		//

		if( ph1->vendopts_l.flag.xauth )
			if( !( cfg->xstate & CSTATE_RECV_XRSLT ) )
				if( !config_client_xauth_recv( cfg, ph1 ) )
					break;

		//
		// handle modecfg pull messages
		//

		if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PULL )
			if( !( cfg->xstate & CSTATE_RECV_XCONF ) )
				if( !config_client_xconf_pull_recv( cfg, ph1 ) )
					break;

		//
		// handle modecfg push messages
		//

		if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PUSH )
			if( !( cfg->xstate & CSTATE_RECV_XCONF ) )
				if( !config_client_xconf_push_recv( cfg, ph1 ) )
					break;

		//
		// unexpected message
		//

		break;
	}

	//
	// now build and send any response
	// packets that may be necessary
	//

	if( ( ph1->status() != XCH_STATUS_DEAD ) &&
		( cfg->status() != XCH_STATUS_MATURE ) )
		process_config_send( ph1, cfg );

	//
	// cleanup
	//

	cfg->dec( true );

	return LIBIKE_OK;
}

long _IKED::process_config_send( IDB_PH1 * ph1, IDB_CFG * cfg )
{
	cfg->attr_reset();

	//
	// hanlde server to client messages
	//

	while( ph1->initiator )
	{
		//
		// handle xauth messages
		//

		if( ph1->vendopts_l.flag.xauth )
			if( !( cfg->xstate & CSTATE_SENT_XRSLT ) )
				if( !config_client_xauth_send( cfg, ph1 ) )
					break;

		//
		// handle modecfg pull messages
		//

		if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PULL )
			if( !( cfg->xstate & CSTATE_SENT_ACK ) )
				if( !config_client_xconf_pull_send( cfg, ph1 ) )
					break;

		//
		// handle modecfg push messages
		//

		if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PUSH )
			if( !( cfg->xstate & CSTATE_SENT_ACK ) )
				if( !config_client_xconf_push_send( cfg, ph1 ) )
					break;

		//
		// handle dhcp over ipsec
		//

		if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_DHCP )
		{
			log.txt( LLOG_INFO, "ii : configuration method is DHCP over IPsec \n" );
			socket_dhcp_create( ph1->tunnel );
			break;
		}

		//
		// handle manual config
		//

		if( ph1->tunnel->peer->xconf_mode == CONFIG_MODE_NONE )
		{
			log.txt( LLOG_INFO, "ii : configuration method is manual\n" );
			break;
		}

		//
		// unexpected message
		//

		break;
	}

	//
	// if all required operations are
	// complete, make sure the config
	// handle is flagged as mature
	//

	if( ( cfg->xstate & CSTATE_RECV_XRSLT ) &&
		( cfg->xstate & CSTATE_SENT_XRSLT ) &&
		( cfg->xstate & CSTATE_RECV_XCONF ) &&
		( cfg->xstate & CSTATE_SENT_XCONF ) )
	{
		if( cfg->tunnel->peer->xconf_mode != CONFIG_MODE_DHCP )
		{
			if( !( cfg->tunnel->tstate & TSTATE_VNET_CONFIG ) )
			{
				cfg->tunnel->tstate |= TSTATE_VNET_CONFIG;
				cfg->tunnel->ikei->wakeup();
			}
		}

		cfg->status( XCH_STATUS_MATURE, XCH_NORMAL, 0 );
		cfg->resend_clear( true, false );
	}

	return LIBIKE_OK;
}

bool _IKED::config_client_xauth_recv( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	//
	// expecting xauth request
	//

	if( cfg->mtype == ISAKMP_CFG_REQUEST )
	{
		//
		// if we have have previously received a
		// comlete xauth request, authentication
		// failed and the gateway is prompting
		// us for an alternate user & password
		//

		if( ( cfg->xstate & CSTATE_RECV_XUSER ) &&
			( cfg->xstate & CSTATE_RECV_XPASS ) )
		{
			log.txt( LLOG_ERROR, "!! : duplicate xauth request, authentication failed\n" );
			ph1->status( XCH_STATUS_DEAD, XCH_FAILED_USER_AUTH, 0 );

			return false;
		}

		//
		// read the request attributes
		//

		cfg->tunnel->xauth.type = XAUTH_TYPE_GENERIC;

		BDATA message;

		long count = cfg->attr_count();
		long index = 0;

		for( ; index < count; index++ )
		{
			IKE_ATTR * attr = cfg->attr_get( index );

			switch( attr->atype )
			{
				case XAUTH_TYPE:
				case CHKPT_TYPE:
					if( attr->basic )
						cfg->tunnel->xauth.type = attr->bdata;
					log.txt( LLOG_INFO, "ii : - xauth authentication type\n" );
					break;

				case XAUTH_USER_NAME:
				case CHKPT_USER_NAME:
					cfg->xstate |= CSTATE_RECV_XUSER;
					log.txt( LLOG_INFO, "ii : - xauth username\n" );
					break;

				case XAUTH_USER_PASSWORD:
				case CHKPT_USER_PASSWORD:
					cfg->xstate |= CSTATE_RECV_XPASS;
					log.txt( LLOG_INFO, "ii : - xauth password\n" );
					break;

				case XAUTH_PASSCODE:
					cfg->xstate |= CSTATE_RECV_XPASS | CSTATE_USE_PASSCODE;
					log.txt( LLOG_INFO, "ii : - xauth passcode\n" );
					break;

				case XAUTH_CHALLENGE:
				case CHKPT_CHALLENGE:
					cfg->xstate |= CSTATE_RECV_XPASS;
					log.txt( LLOG_INFO, "ii : - xauth challenge\n" );
					if( !attr->basic )
						cfg->tunnel->xauth.hash = attr->vdata;
					break;

				case XAUTH_MESSAGE:
				case CHKPT_MESSAGE:
					if( !attr->basic )
						message.add( attr->vdata );
					break;

				default:
					log.txt( LLOG_INFO, "ww : unhandled xauth attribute %i\n", attr->atype );
					break;
			}
		}

		message.add( 0, 1 );

		//
		// examine the xauth request
		//

		switch( cfg->tunnel->xauth.type )
		{
			case XAUTH_TYPE_GENERIC:
				log.txt( LLOG_INFO,
					"ii : received basic xauth request - %s\n",
					message.text() );
				break;

			case XAUTH_TYPE_RADIUS_CHAP:
				log.txt( LLOG_INFO,
					"ii : received chap xauth request - %s\n",
					message.text() );
				break;

			default:
				log.txt( LLOG_ERROR,
					"!! : received unhandled xauth request type\n" );
				ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );
				break;
		}

		return false;
	}

	//
	// expecting xauth response
	//

	if( cfg->mtype == ISAKMP_CFG_SET )
	{
		//
		// read the result attributes
		//

		BDATA message;

		long count = cfg->attr_count();
		long index = 0;
		long status = -1;

		for( ; index < count; index++ )
		{
			IKE_ATTR * attr = cfg->attr_get( index );

			switch( attr->atype )
			{
				case XAUTH_STATUS:
				case CHKPT_STATUS:
					if( attr->basic )
						status = attr->bdata;
						break;

				case XAUTH_MESSAGE:
				case CHKPT_MESSAGE:
					if( !attr->basic )
						message.add( attr->vdata );
					break;
			}
		}

		message.add( 0, 1 );

		//
		// make sure we received a status value
		//

		if( status == -1 )
		{
			//
			// some gateways will send a config push
			// message before an xauth response. in
			// this case, call the correct handler
			//

			if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PUSH )
				return config_client_xconf_push_recv( cfg, ph1 );

			log.txt( LLOG_ERROR,
				"!! : no xauth status received and config mode is not push\n" );

			ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );

			return false;
		}

		//
		// examine the xauth result
		//

		log.txt( LLOG_INFO, "ii : received xauth result - %s\n", message.text() );

		BDATA user;
		user = cfg->tunnel->xauth.user;
		user.add( 0, 1 );

		if( status == 1 )
		{
			log.txt( LLOG_INFO,
				"ii : user %s authentication succeeded\n", user.text() );
		}
		else
		{
			log.txt( LLOG_ERROR,
				"!! : user %s authentication failed\n", user.text() );

			ph1->status( XCH_STATUS_DEAD, XCH_FAILED_USER_AUTH, 0 );
		}

		//
		// NOTE : we set the username and password
		// as already sent and received in case the
		// gateway bypasses xauth on rekey
		//

		cfg->xstate |= CSTATE_SENT_XUSER;
		cfg->xstate |= CSTATE_SENT_XPASS;
		cfg->xstate |= CSTATE_RECV_XUSER;
		cfg->xstate |= CSTATE_RECV_XPASS;
		cfg->xstate |= CSTATE_RECV_XRSLT;

		return false;
	}

	//
	// unhandled message type
	//

	log.txt( LLOG_ERROR, "!! : config message type is invalid for xauth\n" );
	ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );

	return false;
}

bool _IKED::config_client_xauth_send( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	if( !( cfg->xstate & CSTATE_SENT_XUSER ) ||
		!( cfg->xstate & CSTATE_SENT_XPASS ) )
	{
		cfg->mtype = ISAKMP_CFG_REPLY;

		if( !ph1->vendopts_r.flag.chkpt )
		{
			//
			// standard xauth processing
			//

			cfg->attr_add_b( XAUTH_TYPE, cfg->tunnel->xauth.type );

			if(  ( cfg->xstate & CSTATE_RECV_XUSER ) &&
				!( cfg->xstate & CSTATE_SENT_XUSER ) )
			{
				cfg->attr_add_v( XAUTH_USER_NAME,
					cfg->tunnel->xauth.user.buff(),
					cfg->tunnel->xauth.user.size() );

				cfg->xstate |= CSTATE_SENT_XUSER;

				log.txt( LLOG_INFO,
					"ii : - standard xauth username\n" );
			}

			if(  ( cfg->xstate & CSTATE_RECV_XPASS ) &&
				!( cfg->xstate & CSTATE_SENT_XPASS ) )
			{
				switch( cfg->tunnel->xauth.type )
				{
					case XAUTH_TYPE_GENERIC:

						if( !( cfg->xstate & CSTATE_USE_PASSCODE ) )
						{
							cfg->attr_add_v( XAUTH_USER_PASSWORD,
								cfg->tunnel->xauth.pass.buff(),
								cfg->tunnel->xauth.pass.size() );

							log.txt( LLOG_INFO,
								"ii : - standard xauth password\n" );
						}
						else
						{
							cfg->attr_add_v( XAUTH_PASSCODE,
								cfg->tunnel->xauth.pass.buff(),
								cfg->tunnel->xauth.pass.size() );

							log.txt( LLOG_INFO,
								"ii : - standard xauth passcode\n" );
						}

						break;

					case XAUTH_TYPE_RADIUS_CHAP:
					{
						if( !cfg->tunnel->xauth.hash.size() )
						{
							cfg->attr_add_v( XAUTH_USER_PASSWORD,
								cfg->tunnel->xauth.pass.buff(),
								cfg->tunnel->xauth.pass.size() );

							log.txt( LLOG_INFO,
								"ii : - standard xauth password ( no chap challenge received )\n" );
						}
						else
						{
							uint8_t id;
							rand_bytes( &id, 1 );

							BDATA rslt;
							rslt.add( &id, sizeof( id ) );
							rslt.add( 0, MD5_DIGEST_LENGTH );

							MD5_CTX ctx;
							MD5_Init( &ctx );
							MD5_Update( &ctx, &id, sizeof( id ) );
							MD5_Update( &ctx, cfg->tunnel->xauth.pass.buff(), cfg->tunnel->xauth.pass.size() );
							MD5_Update( &ctx, cfg->tunnel->xauth.hash.buff(), cfg->tunnel->xauth.hash.size() );
							MD5_Final( rslt.buff() + sizeof( id ), &ctx );

							cfg->attr_add_v( XAUTH_USER_PASSWORD,
								rslt.buff(),
								rslt.size() );

							log.txt( LLOG_INFO,
								"ii : - standard xauth chap password\n" );
						}

						break;
					}
				}

				cfg->xstate |= CSTATE_SENT_XPASS;
			}
		}
		else
		{
			//
			// checkpoint xauth processing
			//

			cfg->attr_add_b( XAUTH_TYPE, cfg->tunnel->xauth.type );

			if(  ( cfg->xstate & CSTATE_RECV_XUSER ) &&
				!( cfg->xstate & CSTATE_SENT_XUSER ) )
			{
				cfg->attr_add_v( CHKPT_USER_NAME,
					cfg->tunnel->xauth.user.buff(),
					cfg->tunnel->xauth.user.size() );

				cfg->xstate |= CSTATE_SENT_XUSER;

				log.txt( LLOG_INFO,
					"ii : - checkpoint xauth username\n" );
			}

			if(  ( cfg->xstate & CSTATE_RECV_XPASS ) &&
				!( cfg->xstate & CSTATE_SENT_XPASS ) )
			{
				switch( cfg->tunnel->xauth.type )
				{
					case XAUTH_TYPE_GENERIC:
					{
						cfg->attr_add_v( CHKPT_USER_PASSWORD,
							cfg->tunnel->xauth.pass.buff(),
							cfg->tunnel->xauth.pass.size() );

						log.txt( LLOG_INFO,
							"ii : - checkpoint xauth password\n" );

						break;
					}

					case XAUTH_TYPE_RADIUS_CHAP:
					{
						uint8_t id;
						rand_bytes( &id, 1 );

						BDATA rslt;
						rslt.add( &id, sizeof( id ) );
						rslt.add( 0, MD5_DIGEST_LENGTH );

						MD5_CTX ctx;
						MD5_Init( &ctx );
						MD5_Update( &ctx, &id, sizeof( id ) );
						MD5_Update( &ctx, cfg->tunnel->xauth.pass.buff(), cfg->tunnel->xauth.pass.size() );
						MD5_Update( &ctx, cfg->tunnel->xauth.hash.buff(), cfg->tunnel->xauth.hash.size() );
						MD5_Final( rslt.buff() + sizeof( id ), &ctx );

						cfg->attr_add_v( CHKPT_USER_PASSWORD,
							rslt.buff(),
							rslt.size() );

						log.txt( LLOG_INFO,
							"ii : - checkpoint xauth chap password\n" );

						break;
					}
				}

				cfg->xstate |= CSTATE_SENT_XPASS;
			}
		}

		//
		// send config packet
		//

		BDATA user;
		user = cfg->tunnel->xauth.user;
		user.add( 0, 1 );

		log.txt( LLOG_INFO,	"ii : sending xauth response for %s\n", user.buff() );
		config_message_send( ph1, cfg );

		return false;
	}

	if( !( cfg->xstate & CSTATE_SENT_XRSLT ) )
	{
		//
		// if we have have not yet received an
		// xauth result message, postpone this
		// ack until later

		if( !( cfg->xstate & CSTATE_RECV_XRSLT ) )
			return true;

		cfg->mtype = ISAKMP_CFG_ACK;

		//
		// add the status attribute
		//

		if( ph1->vendopts_r.flag.chkpt ) 
			cfg->attr_add_b( CHKPT_STATUS, 1 );

//		if( !ph1->vendopts_r.flag.chkpt ) 
//			cfg->attr_add_b( XAUTH_STATUS, 1 );
//		else
//			cfg->attr_add_b( CHKPT_STATUS, 1 );

		//
		// send config packet
		//

		log.txt( LLOG_INFO, "ii : sending xauth acknowledge\n" );
		config_message_send( ph1, cfg );

		cfg->xstate |= CSTATE_SENT_XRSLT;

		return true;
	}

	return false;
}

bool _IKED::config_client_xconf_pull_recv( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	//
	// expecting configuration pull reply
	//

	if( cfg->mtype == ISAKMP_CFG_REPLY )
	{
		//
		// get configuration attributes
		//

		log.txt( LLOG_INFO, "ii : received config pull response\n" );

		long getbits = 0;
		config_xconf_get( cfg,
			getbits,
			cfg->tunnel->xconf.rqst,
			ph1->vendopts_r );

		//
		// add negotiated options
		//

		cfg->tunnel->xconf.opts |= cfg->tunnel->xconf.rqst & getbits;

		cfg->xstate |= CSTATE_RECV_XCONF;

		return false;
	}

	//
	// unhandled message type
	//

	log.txt( LLOG_ERROR, "!! : config message type is invalid for pull config\n" );
	ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );

	return false;
}

bool _IKED::config_client_xconf_pull_send( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	if( !( cfg->xstate & CSTATE_SENT_XCONF ) )
	{
		//
		// set configuration attributes
		//

		log.txt( LLOG_INFO, "ii : building config attribute list\n" );

		cfg->mtype = ISAKMP_CFG_REQUEST;

		if( ph1->vendopts_r.flag.chkpt )
			iked.rand_bytes( &cfg->ident, sizeof( cfg->ident ) );

		config_xconf_set( cfg,
			cfg->tunnel->xconf.rqst,
			0xffffffff,
			ph1->vendopts_r );

		if( cfg->attr_count() )
		{
			//
			// create new msgid and iv
			//

			cfg->new_msgid();
			cfg->new_msgiv( ph1 );

			//
			// send config packet
			//

			log.txt( LLOG_INFO, "ii : sending config pull request\n" );
			config_message_send( ph1, cfg );

			cfg->xstate |= CSTATE_SENT_XCONF;
		}
		else
		{
			//
			// config not required
			//

			log.txt( LLOG_INFO, "ii : config pull is not required\n" );

			cfg->xstate |= CSTATE_SENT_XCONF;
			cfg->xstate |= CSTATE_RECV_XCONF;
		}

		return false;
	}

	return false;
}

bool _IKED::config_client_xconf_push_recv( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	//
	// expecting configuration push request
	//

	if( cfg->mtype == ISAKMP_CFG_SET )
	{
		//
		// get xconf attributes
		//

		log.txt( LLOG_INFO, "ii : received config push request\n" );

		long getbits = 0;
		config_xconf_get( cfg,
			getbits,
			cfg->tunnel->xconf.rqst,
			ph1->vendopts_r );

		//
		// add negotiated options
		//

		cfg->tunnel->xconf.opts |= cfg->tunnel->xconf.rqst & getbits;

		//
		// config is now mature
		//

		cfg->xstate |= CSTATE_RECV_XCONF;

		return false;
	}

	//
	// unhandled message type
	//

	log.txt( LLOG_ERROR, "!! : config message type is invalid for push config\n" );
	ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );

	return false;
}

bool _IKED::config_client_xconf_push_send( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	if( !( cfg->xstate & CSTATE_SENT_XCONF ) )
	{
		//
		// set xconf attributes
		//

		log.txt( LLOG_INFO, "ii : building config attribute list\n" );

		cfg->mtype = ISAKMP_CFG_ACK;

		config_xconf_set( cfg,
			cfg->tunnel->xconf.rqst,
			0xffffffff,
			ph1->vendopts_r );

		//
		// send config packet
		//

		log.txt( LLOG_INFO, "ii : sending config push acknowledge\n" );
		config_message_send( ph1, cfg );

		cfg->xstate |= CSTATE_SENT_XCONF;

		return false;
	}

	return false;
}

bool _IKED::config_server_xauth_recv( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	if( cfg->mtype == ISAKMP_CFG_REPLY )
	{
		log.txt( LLOG_INFO, "ii : received xauth response\n" );

		//
		// make sure we at least have
		// user and password attribs
		//

		long count = cfg->attr_count();
		long index = 0;

		for( ; index < count; index++ )
		{
			IKE_ATTR * attr = cfg->attr_get( index );

			switch( attr->atype )
			{
				case XAUTH_USER_NAME:
					cfg->xstate |= CSTATE_RECV_XUSER;
					cfg->tunnel->xauth.user.set( attr->vdata );
					break;

				case XAUTH_USER_PASSWORD:
					cfg->xstate |= CSTATE_RECV_XPASS;
					cfg->tunnel->xauth.pass.set( attr->vdata );
					break;
			}
		}

		if( !cfg->tunnel->xauth.user.size() )
			log.txt( LLOG_ERROR, "!! : missing required username attribute\n" );

		if( !cfg->tunnel->xauth.pass.size() )
			log.txt( LLOG_ERROR, "!! : missing required password attribute\n" );

		return false;
	}

	if( cfg->mtype == ISAKMP_CFG_ACK )
	{
		log.txt( LLOG_INFO, "ii : received xauth ack\n" );

		cfg->xstate |= CSTATE_RECV_XRSLT;

		if( cfg->tunnel->peer->xconf_mode != CONFIG_MODE_PUSH )
			cfg->status( XCH_STATUS_MATURE, XCH_NORMAL, 0 );

		return false;
	}

	return false;
}

bool _IKED::config_server_xauth_send( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	if( !( cfg->xstate & CSTATE_SENT_XUSER ) )
	{
		//
		// set request attributes
		//

		cfg->mtype = ISAKMP_CFG_REQUEST;

		cfg->attr_add_b( XAUTH_TYPE, XAUTH_TYPE_GENERIC );
		cfg->attr_add_v( XAUTH_USER_NAME, NULL, 0 );
		cfg->attr_add_v( XAUTH_USER_PASSWORD, NULL, 0 );

		//
		// create new msgid and iv
		//

		cfg->new_msgid();
		cfg->new_msgiv( ph1 );

		//
		// send config packet
		//

		config_message_send( ph1, cfg );

		//
		// flag as sent
		//

		cfg->xstate |= CSTATE_SENT_XUSER;
		cfg->xstate |= CSTATE_SENT_XPASS;

		log.txt( LLOG_INFO, "ii : sent xauth request\n" );

		return false;
	}

	if( !( cfg->xstate & CSTATE_SENT_XRSLT ) )
	{
		bool allow = false;
		if( cfg->tunnel->xauth.user.size() &&
			cfg->tunnel->xauth.pass.size() )
			allow = true;

		//
		// check user password
		//

		if( allow )
		{
			cfg->tunnel->xauth.user.add( 0, 1 );
			cfg->tunnel->xauth.pass.add( 0, 1 );

			allow = cfg->tunnel->peer->xauth_source->auth_pwd(
						cfg->tunnel->xauth );

			if( allow )
				iked.log.txt( LLOG_INFO,
					"ii : xauth user %s password accepted ( %s )\n",
					cfg->tunnel->xauth.user.text(),
					cfg->tunnel->peer->xauth_source->name() );
			else
				iked.log.txt( LLOG_ERROR,
					"!! : xauth user %s password rejected ( %s )\n",
					cfg->tunnel->xauth.user.text(),
					cfg->tunnel->peer->xauth_source->name() );
		}

		//
		// check user group membership
		//

		if( allow && cfg->tunnel->peer->xauth_group.size() )
		{
			allow = cfg->tunnel->peer->xauth_source->auth_grp(
						cfg->tunnel->xauth,
						cfg->tunnel->peer->xauth_group );

			if( allow )
				log.txt( LLOG_INFO,
					"ii : xauth user %s group %s membership accepted ( %s )\n",
					cfg->tunnel->xauth.user.text(),
					cfg->tunnel->peer->xauth_group.text(),
					cfg->tunnel->peer->xauth_source->name() );
			else
				log.txt( LLOG_ERROR,
					"!! : xauth user %s group %s membership rejected ( %s )\n",
					cfg->tunnel->xauth.user.text(),
					cfg->tunnel->peer->xauth_group.text(),
					cfg->tunnel->peer->xauth_source->name() );
		}

		//
		// set result attributes
		//

		cfg->mtype = ISAKMP_CFG_SET;

		if( allow )
			cfg->attr_add_b( XAUTH_STATUS, 1 );
		else
			cfg->attr_add_b( XAUTH_STATUS, 0 );

		//
		// create new msgid and iv
		//

		cfg->new_msgid();
		cfg->new_msgiv( ph1 );

		//
		// send config packet
		//

		config_message_send( ph1, cfg );

		//
		// flag as sent and release
		//

		cfg->xstate |= CSTATE_SENT_XRSLT;

		log.txt( LLOG_INFO, "ii : sent xauth result\n" );

		if( !allow )
			ph1->status( XCH_STATUS_DEAD, XCH_FAILED_USER_AUTH, 0 );

		return false;
	}

	return false;
}

bool _IKED::config_server_xconf_pull_recv( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	if( cfg->mtype == ISAKMP_CFG_REQUEST )
	{
		//
		// get xconf attributes
		//

		log.txt( LLOG_INFO, "ii : received config pull request\n" );

		config_xconf_get( cfg,
			cfg->tunnel->xconf.rqst,
			0,
			ph1->vendopts_r );

		cfg->xstate |= CSTATE_RECV_XCONF;

		return false;
	}

	return false;
}

bool _IKED::config_server_xconf_pull_send( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	if( !( cfg->xstate & CSTATE_SENT_XCONF ) )
	{
		//
		// obtain the client xconf config
		//

		cfg->tunnel->peer->xconf_source->rslt(
			cfg->tunnel );

		//
		// if we are to generate a policy
		// list during config, do this now
		//

		if( cfg->tunnel->peer->plcy_mode == POLICY_MODE_CONFIG )
			policy_list_create( cfg->tunnel, false );

		if( cfg->tunnel->peer->plcy_mode != POLICY_MODE_DISABLE )
			cfg->tunnel->xconf.opts |= IPSEC_OPTS_SPLITNET;

		//
		// set result attributes
		//

		cfg->mtype = ISAKMP_CFG_REPLY;

		log.txt( LLOG_INFO, "ii : building config attribute list\n" );

		config_xconf_set( cfg,
			cfg->tunnel->xconf.opts,
			0,
			ph1->vendopts_r );

		//
		// send config packet
		//

		log.txt( LLOG_INFO, "ii : sending config pull response\n" );
		config_message_send( ph1, cfg );

		//
		// flag as sent
		//

		cfg->tunnel->tstate |= CSTATE_SENT_XCONF;

		return false;
	}

	return false;
}

bool _IKED::config_server_xconf_push_recv( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	if( cfg->mtype == ISAKMP_CFG_ACK )
	{
		//
		// get xconf attributes
		//

		log.txt( LLOG_INFO, "ii : received config push acknowledge\n" );

		long readmask = 0;

		config_xconf_get( cfg,
			readmask,
			0,
			ph1->vendopts_r );

		cfg->xstate |= CSTATE_RECV_XCONF;

		return false;
	}

	return false;
}

bool _IKED::config_server_xconf_push_send( IDB_CFG * cfg, IDB_PH1 * ph1 )
{
	if( !( cfg->xstate & CSTATE_SENT_XCONF ) )
	{
		//
		// in push mode the client doesnt
		// request its desired attributes
		//

		cfg->tunnel->xconf.rqst = cfg->tunnel->peer->xconf_source->config.opts;

		//
		// obtain the client xconf config
		//

		cfg->tunnel->peer->xconf_source->rslt(
			cfg->tunnel );

		//
		// if we are to generate a policy
		// list during config, do this now
		//

		if( cfg->tunnel->peer->plcy_mode == POLICY_MODE_CONFIG )
			policy_list_create( cfg->tunnel, false );

		if( cfg->tunnel->peer->plcy_mode != POLICY_MODE_DISABLE )
			cfg->tunnel->xconf.opts |= IPSEC_OPTS_SPLITNET;

		//
		// set attributes
		//

		cfg->mtype = ISAKMP_CFG_SET;

		log.txt( LLOG_INFO, "ii : building config attribute list\n" );

		config_xconf_set( cfg,
			cfg->tunnel->xconf.opts,
			0,
			ph1->vendopts_r );

		//
		// create new msgid and iv
		//

		cfg->new_msgid();
		cfg->new_msgiv( ph1 );

		//
		// send config packet
		//

		log.txt( LLOG_INFO, "ii : sending config push request\n" );

		config_message_send( ph1, cfg );

		cfg->attr_reset();

		//
		// flag as sent
		//

		cfg->xstate |= CSTATE_SENT_XCONF;

		return false;
	}

	return false;
}

long _IKED::config_xconf_set( IDB_CFG * cfg, long setbits, long setmask, VENDOPTS vendopts )
{
	//
	// the modecfg draft defines valid lengths
	// for most attribute values. a checkpoint
	// client always submits 4 null bytes even
	// for values that are not constrained to
	// 0 or 4 byte lengths. we mimic this odd
	// behavior for compatibility sake.
	//

	void *	null_ptr = NULL;
	char	null_len = 0;
	char	null_val[ 4 ] = { 0 };

	if( vendopts.flag.chkpt )
	{
		null_ptr = null_val;
		null_len = 4;
	}

	//
	// standard attributes
	//

	if( setbits & IPSEC_OPTS_ADDR )
	{
		if( setmask & IPSEC_OPTS_ADDR )
		{
			cfg->attr_add_v( INTERNAL_IP4_ADDRESS,
				null_ptr, null_len );

			log.txt( LLOG_DEBUG,	"ii : - IP4 Address\n" );

			cfg->attr_add_v( INTERNAL_ADDRESS_EXPIRY,
				null_ptr, null_len );

			log.txt( LLOG_DEBUG,	"ii : - Address Expiry\n" );
		}
		else
		{
			cfg->attr_add_v( INTERNAL_IP4_ADDRESS,
				&cfg->tunnel->xconf.addr,
				sizeof( cfg->tunnel->xconf.addr ) );

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, cfg->tunnel->xconf.addr );

			log.txt( LLOG_DEBUG,
				"ii : - IP4 Address = %s\n",
				txtaddr );

			cfg->attr_add_v( INTERNAL_ADDRESS_EXPIRY,
				&cfg->tunnel->xconf.expi,
				sizeof( cfg->tunnel->xconf.expi ) );

			log.txt( LLOG_DEBUG,
				"ii : - Address Expiry = %i secs\n",
				cfg->tunnel->xconf.expi );
		}
	}

	if( setbits & IPSEC_OPTS_MASK )
	{
		if( setmask & IPSEC_OPTS_MASK )
		{
			cfg->attr_add_v( INTERNAL_IP4_NETMASK,
				null_ptr, null_len );

			log.txt( LLOG_DEBUG,	"ii : - IP4 Netmask\n" );
		}
		else
		{
			cfg->attr_add_v( INTERNAL_IP4_NETMASK,
				&cfg->tunnel->xconf.mask,
				sizeof( cfg->tunnel->xconf.mask ) );

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, cfg->tunnel->xconf.mask );

			log.txt( LLOG_DEBUG,
				"ii : - IP4 Netmask = %s\n",
				txtaddr );
		}
	}

	if( setbits & IPSEC_OPTS_DNSS )
	{
		if( setmask & IPSEC_OPTS_DNSS )
		{
			cfg->attr_add_v( INTERNAL_IP4_DNS,
				null_ptr, null_len );

			log.txt( LLOG_DEBUG, "ii : - IP4 DNS Server\n" );
		}
		else
		{
			uint32_t index = 0;
			uint32_t count = cfg->tunnel->xconf.nscfg.dnss_count;

			for( ; index < count; index++ )
			{
				cfg->attr_add_v( INTERNAL_IP4_DNS,
					&cfg->tunnel->xconf.nscfg.dnss_list[ index ], 4 );

				char txtaddr[ LIBIKE_MAX_TEXTADDR ];
				text_addr( txtaddr, cfg->tunnel->xconf.nscfg.dnss_list[ index ] );

				log.txt( LLOG_DEBUG,
					"ii : - IP4 DNS Server = %s\n",
					txtaddr );
			}
		}
	}

	if( setbits & IPSEC_OPTS_NBNS )
	{
		if( setmask & IPSEC_OPTS_NBNS )
		{
			cfg->attr_add_v( INTERNAL_IP4_NBNS,
				null_ptr, null_len );

			log.txt( LLOG_DEBUG,	"ii : - IP4 WINS Server\n" );
		}
		else
		{
			uint32_t index = 0;
			uint32_t count = cfg->tunnel->xconf.nscfg.nbns_count;

			for( ; index < count; index++ )
			{
				cfg->attr_add_v( INTERNAL_IP4_NBNS,
					&cfg->tunnel->xconf.nscfg.nbns_list[ index ], 4 );

				char txtaddr[ LIBIKE_MAX_TEXTADDR ];
				text_addr( txtaddr, cfg->tunnel->xconf.nscfg.nbns_list[ index ] );

				log.txt( LLOG_DEBUG,
					"ii : - IP4 WINS Server = %s\n",
					txtaddr );
			}
		}
	}

	//
	// non cisco unity attributes
	//

	if( !vendopts.flag.unity )
	{
		if( setbits & IPSEC_OPTS_SPLITNET )
		{
			if( setmask & IPSEC_OPTS_SPLITNET )
			{
				cfg->attr_add_v( INTERNAL_IP4_SUBNET, NULL, 0 );

				log.txt( LLOG_DEBUG,
					"ii : - IP4 Subnet\n" );
			}
			else
			{
				IKE_PH2ID ph2id;

				long index = 0;

				while( cfg->tunnel->idlist_incl.get( ph2id, index++ ) )
				{
					IKE_SUBNET subnet;
					memset( &subnet, 0, sizeof( subnet ) );

					subnet.addr = ph2id.addr1;
					subnet.mask = ph2id.addr2;

					char txtid[ LIBIKE_MAX_TEXTP2ID ];
					text_ph2id( txtid, &ph2id );

					if( subnet.addr.s_addr &&
						subnet.mask.s_addr )
					{
						cfg->attr_add_v(
							INTERNAL_IP4_SUBNET,
							&subnet,
							sizeof( subnet ) );

						log.txt( LLOG_DEBUG,
							"ii : - IP4 Subnet = %s\n",
							txtid );
					}
					else
					{
						log.txt( LLOG_DEBUG,
							"ii : - IP4 Subnet = %s\n ( invalid subnet ignored )",
							txtid );
					}
				}
			}
		}
	}

	//
	// cisco unity attributes
	//

	if( vendopts.flag.unity )
	{
		if( setbits & IPSEC_OPTS_DOMAIN )
		{
			if( setmask & IPSEC_OPTS_DOMAIN )
			{
				cfg->attr_add_v( UNITY_DEF_DOMAIN, NULL, 0 );
				log.txt( LLOG_DEBUG,
					"ii : - DNS Suffix\n" );
			}
			else
			{
				cfg->attr_add_v( UNITY_DEF_DOMAIN,
					&cfg->tunnel->xconf.nscfg.dnss_suffix,
					strlen( cfg->tunnel->xconf.nscfg.dnss_suffix ) );

				log.txt( LLOG_DEBUG,
					"ii : - DNS Suffix = %s\n",
					cfg->tunnel->xconf.nscfg.dnss_suffix );
			}
		}

		if( setbits & IPSEC_OPTS_SPLITDNS )
		{
			if( setmask & IPSEC_OPTS_SPLITDNS )
			{
				cfg->attr_add_v( UNITY_SPLIT_DOMAIN, NULL, 0 );
				log.txt( LLOG_DEBUG, "ii : - Split DNS Domain\n" );
			}
			else
			{
				BDATA domain;

				long index = 0;

				while( cfg->tunnel->domains.get( domain, index++ ) )
				{
					log.txt( LLOG_DEBUG,
						"ii : - Split DNS Domain = %s\n",
						domain.text() );

					if( index > 1 )
						domain.ins( ',', 1 );

					cfg->attr_add_v( UNITY_SPLIT_DOMAIN,
						domain.buff(),
						domain.size() );
				}
			}
		}

		if( setbits & IPSEC_OPTS_SPLITNET )
		{
			if( setmask & IPSEC_OPTS_SPLITNET )
			{
				cfg->attr_add_v( UNITY_SPLIT_INCLUDE, NULL, 0 );
				cfg->attr_add_v( UNITY_SPLIT_EXCLUDE, NULL, 0 );

				log.txt( LLOG_DEBUG,
					"ii : - IP4 Split Network Include\n"
					"ii : - IP4 Split Network Exclude\n" );
			}
			else
			{
				IKE_PH2ID ph2id;

				long index = 0;

				while( cfg->tunnel->idlist_incl.get( ph2id, index++ ) )
				{
					IKE_UNITY_NET unity_net;
					memset( &unity_net, 0, sizeof( unity_net ) );

					unity_net.prot = ph2id.prot;
					unity_net.addr = ph2id.addr1;
					unity_net.mask = ph2id.addr2;
					unity_net.port_rmt = ph2id.port;

					char txtid[ LIBIKE_MAX_TEXTP2ID ];
					text_ph2id( txtid, &ph2id );

					if( unity_net.addr.s_addr &&
						unity_net.mask.s_addr )
					{
						cfg->attr_add_v( UNITY_SPLIT_INCLUDE,
							&unity_net,
							sizeof( unity_net ) );

						log.txt( LLOG_DEBUG,
							"ii : - IP4 Split Network Include = %s\n",
							txtid );
					}
					else
					{
						log.txt( LLOG_DEBUG,
							"ii : - IP4 Split Network Include = %s\n ( invalid subnet ignored )",
							txtid );
					}
				}

				index = 0;

				while( cfg->tunnel->idlist_excl.get( ph2id, index++ ) )
				{
					IKE_UNITY_NET unity_net;
					memset( &unity_net, 0, sizeof( unity_net ) );

					unity_net.prot = ph2id.prot;
					unity_net.addr = ph2id.addr1;
					unity_net.mask = ph2id.addr2;
					unity_net.port_rmt = ph2id.port;

					char txtid[ LIBIKE_MAX_TEXTP2ID ];
					text_ph2id( txtid, &ph2id );

					if( unity_net.addr.s_addr &&
						unity_net.mask.s_addr )
					{
						cfg->attr_add_v( UNITY_SPLIT_EXCLUDE,
							&unity_net,
							sizeof( unity_net ) );

						log.txt( LLOG_DEBUG,
							"ii : - IP4 Split Network Exclude = %s\n",
							txtid );
					}
					else
					{
						log.txt( LLOG_DEBUG,
							"ii : - IP4 Split Network Exclude = %s\n ( invalid subnet ignored )",
							txtid );
					}
				}
			}
		}

		if( setbits & IPSEC_OPTS_BANNER )
		{
			if( setmask & IPSEC_OPTS_BANNER )
			{
				cfg->attr_add_v( UNITY_BANNER, NULL, 0 );
				log.txt( LLOG_DEBUG,
					"ii : - Login Banner\n" );
			}
			else
			{
				cfg->attr_add_v( UNITY_BANNER,
					cfg->tunnel->banner.buff(),
					cfg->tunnel->banner.size() );

				cfg->tunnel->banner.add( 0, 1 );

				log.txt( LLOG_DEBUG,
					"ii : - Login Banner ( %i bytes )\n",
					cfg->tunnel->banner.size() );
			}
		}

		if( setbits & IPSEC_OPTS_PFS )
		{
			if( setmask & IPSEC_OPTS_PFS )
			{
				cfg->attr_add_v( UNITY_PFS, NULL, 0 );
				log.txt( LLOG_DEBUG,
					"ii : - PFS Group\n" );
			}
			else
			{
				cfg->attr_add_b( UNITY_PFS,
					cfg->tunnel->xconf.dhgr );

				log.txt( LLOG_DEBUG,
					"ii : - PFS Group = %i\n",
					cfg->tunnel->xconf.dhgr );
			}
		}

		if( setbits & IPSEC_OPTS_SAVEPW )
		{
			if( setmask & IPSEC_OPTS_SAVEPW )
			{
				cfg->attr_add_v( UNITY_SAVE_PASSWD, NULL, 0 );
				log.txt( LLOG_DEBUG,
					"ii : - Save Password\n" );
			}
			else
			{
				cfg->attr_add_b( UNITY_SAVE_PASSWD,
					cfg->tunnel->xconf.svpw );

				log.txt( LLOG_DEBUG,
					"ii : - Save Password = %i\n",
					cfg->tunnel->xconf.svpw );
			}
		}

		if( setbits & IPSEC_OPTS_CISCO_UDP )
		{
			if( setmask & IPSEC_OPTS_CISCO_UDP )
			{
				cfg->attr_add_v( UNITY_NATT_PORT, NULL, 0 );
				log.txt( LLOG_DEBUG,
					"ii : - CISCO UDP Port\n" );
			}
			else
			{
				cfg->attr_add_b( UNITY_NATT_PORT,
					cfg->tunnel->peer->natt_port );

				log.txt( LLOG_DEBUG,
					"ii : - CISCO UDP Port = %i\n",
					ntohs( cfg->tunnel->peer->natt_port ) );
			}
		}

		cfg->attr_add_v( APPLICATION_VERSION,
			UNITY_APP_VERSION_STRING,
			strlen( UNITY_APP_VERSION_STRING ) );

		log.txt( LLOG_DEBUG,
			"ii : - Application Version = %s\n",
			UNITY_APP_VERSION_STRING );

		cfg->attr_add_v( UNITY_FW_TYPE,
			unity_fwtype.buff(),
			unity_fwtype.size() );

		log.txt( LLOG_DEBUG,
			"ii : - Firewall Type = CISCO-UNKNOWN\n" );
	}

	//
	// checkpoint attributes
	//

	if( vendopts.flag.chkpt )
	{
		cfg->attr_add_v( CHKPT_MARCIPAN_REASON_CODE,
				null_ptr, null_len );

		log.txt( LLOG_DEBUG,
			"ii : - Marcipan Reason Code\n" );

		uint8_t macaddr[ 6 ];
		rand_bytes( &macaddr, 6 );
		cfg->attr_add_v( CHKPT_MAC_ADDRESS, macaddr, 6 );

		log.txt( LLOG_DEBUG,
			"ii : - Adapter MAC Address = %02x:%02x:%02x:%02x:%02x:%02x\n",
			macaddr[ 0 ],
			macaddr[ 1 ],
			macaddr[ 2 ],
			macaddr[ 3 ],
			macaddr[ 4 ],
			macaddr[ 5 ] );

		if( setbits & IPSEC_OPTS_DOMAIN )
		{
			if( setmask & IPSEC_OPTS_DOMAIN )
			{
				cfg->attr_add_v( CHKPT_DEF_DOMAIN,
					null_ptr, null_len );

				log.txt( LLOG_DEBUG,
					"ii : - DNS Suffix\n" );
			}
			else
			{
				cfg->attr_add_v( CHKPT_DEF_DOMAIN,
					&cfg->tunnel->xconf.nscfg.dnss_suffix,
					strlen( cfg->tunnel->xconf.nscfg.dnss_suffix ) );

				log.txt( LLOG_DEBUG,
					"ii : - DNS Suffix = %s\n",
					cfg->tunnel->xconf.nscfg.dnss_suffix );
			}
		}
	}

	return LIBIKE_OK;
}

long _IKED::config_xconf_get( IDB_CFG * cfg, long & getbits, long getmask, VENDOPTS vendopts )
{
	long count = cfg->attr_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		IKE_ATTR * attr = cfg->attr_get( index );

		//
		// standard attributes
		//

		bool unhandled = false;

		switch( attr->atype )
		{
			case INTERNAL_IP4_ADDRESS:
			{
				getbits |= IPSEC_OPTS_ADDR;

				if( ( getmask & IPSEC_OPTS_ADDR ) && attr->vdata.size() )
				{
					if( attr->vdata.size() != 4 )
					{
						log.txt( LLOG_ERROR,
							"!! : - IP4 Address has invalid size ( %i bytes )\n",
							attr->vdata.size() );

						break;
					}

					memcpy(
						&cfg->tunnel->xconf.addr,
						attr->vdata.buff(), 4 );

					char txtaddr[ LIBIKE_MAX_TEXTADDR ];
					text_addr( txtaddr, cfg->tunnel->xconf.addr );

					log.txt( LLOG_DEBUG,
						"ii : - IP4 Address = %s\n",
						txtaddr );
				}
				else
					log.txt( LLOG_DEBUG, "ii : - IP4 Address\n" );

				break;
			}

			case INTERNAL_IP4_NETMASK:
			{
				getbits |= IPSEC_OPTS_MASK;

				if( ( getmask & IPSEC_OPTS_MASK ) && attr->vdata.size() )
				{
					if( attr->vdata.size() != 4 )
					{
						log.txt( LLOG_ERROR,
							"!! : - IP4 Netmask has invalid size ( %i bytes )\n",
							attr->vdata.size() );

						break;
					}

					memcpy(
						&cfg->tunnel->xconf.mask,
						attr->vdata.buff(), 4 );

					char txtaddr[ LIBIKE_MAX_TEXTADDR ];
					text_addr( txtaddr, cfg->tunnel->xconf.mask );

					log.txt( LLOG_DEBUG,
						"ii : - IP4 Netmask = %s\n",
						txtaddr );
				}
				else
					log.txt( LLOG_DEBUG, "ii : - IP4 Netmask\n" );

				break;
			}

			case INTERNAL_IP4_DNS:
			{
				getbits |= IPSEC_OPTS_DNSS;

				if( ( getmask & IPSEC_OPTS_DNSS ) && attr->vdata.size() )
				{
					if( cfg->tunnel->xconf.nscfg.dnss_count < IPSEC_DNSS_MAX )
					{
						if( attr->vdata.size() != 4 )
						{
							log.txt( LLOG_ERROR,
								"!! : - IP4 DNS Server has invalid size ( %i bytes )\n",
								attr->vdata.size() );

							break;
						}

						memcpy(
							&cfg->tunnel->xconf.nscfg.dnss_list[ cfg->tunnel->xconf.nscfg.dnss_count ],
							attr->vdata.buff(), 4 );

						char txtaddr[ LIBIKE_MAX_TEXTADDR ];
						text_addr( txtaddr, cfg->tunnel->xconf.nscfg.dnss_list[ cfg->tunnel->xconf.nscfg.dnss_count ] );

						cfg->tunnel->xconf.nscfg.dnss_count++;

						log.txt( LLOG_DEBUG,
							"ii : - IP4 DNS Server = %s\n",
							txtaddr );
					}
				}
				else
					log.txt( LLOG_DEBUG, "ii : - IP4 DNS Server\n" );

				break;
			}

			case INTERNAL_IP4_NBNS:
			{
				getbits |= IPSEC_OPTS_NBNS;

				if( ( getmask & IPSEC_OPTS_NBNS ) && attr->vdata.size() )
				{
					if( cfg->tunnel->xconf.nscfg.nbns_count < IPSEC_NBNS_MAX )
					{
						if( attr->vdata.size() != 4 )
						{
							log.txt( LLOG_ERROR,
								"!! : - IP4 WINS Server has invalid size ( %i bytes )\n",
								attr->vdata.size() );

							break;
						}

						memcpy(
							&cfg->tunnel->xconf.nscfg.nbns_list[ cfg->tunnel->xconf.nscfg.nbns_count ],
							attr->vdata.buff(), 4 );

						char txtaddr[ LIBIKE_MAX_TEXTADDR ];
						text_addr( txtaddr, cfg->tunnel->xconf.nscfg.nbns_list[ cfg->tunnel->xconf.nscfg.nbns_count ] );

						cfg->tunnel->xconf.nscfg.nbns_count++;

						log.txt( LLOG_DEBUG,
							"ii : - IP4 WINS Server = %s\n",
							txtaddr );
					}
				}
				else
					log.txt( LLOG_DEBUG, "ii : - IP4 WINS Server\n" );

				break;
			}

			case INTERNAL_ADDRESS_EXPIRY:
			{
				getbits |= IPSEC_OPTS_ADDR;

				if( ( getmask & IPSEC_OPTS_ADDR ) && attr->vdata.size() )
				{
					if( attr->vdata.size() != 4 )
					{
						log.txt( LLOG_ERROR,
							"!! : - Address Expiry has invalid size ( %i bytes )\n",
							attr->vdata.size() );

						break;
					}

					memcpy(
						&cfg->tunnel->xconf.expi,
						attr->vdata.buff(), 4 );

					log.txt( LLOG_DEBUG,
						"ii : - Address Expiry = %i\n",
						 cfg->tunnel->xconf.expi );
				}
				else
					log.txt( LLOG_DEBUG, "ii : - Address Expiry\n" );

				break;
			}

			case APPLICATION_VERSION:
			{
				if( attr->vdata.size() )
				{
					BDATA appver;
					appver = attr->vdata;
					appver.add( "", 1 );

					log.txt( LLOG_DEBUG,
						"ii : - Application Version = %s\n",
						appver.text() );
				}
				else
					log.txt( LLOG_DEBUG, "ii : - Application Version\n" );

				break;
			}

			default:
				unhandled = true;
		}

		//
		// non cisco unity attributes
		//

		if( !vendopts.flag.unity && unhandled )
		{
			unhandled = false;
	
			switch( attr->atype )
			{
				case INTERNAL_IP4_SUBNET:
				{
					getbits |= IPSEC_OPTS_SPLITNET;

					if( ( getmask & IPSEC_OPTS_SPLITNET ) && attr->vdata.size() )
					{
						int net_count = int( attr->vdata.size() / sizeof( IKE_SUBNET ) );
						int net_index = 0;

						for( ; net_index < net_count; net_index++ )
						{
							long offset = sizeof( IKE_SUBNET ) * net_index;
							IKE_SUBNET * subnet = ( IKE_SUBNET * ) ( attr->vdata.buff() + offset );

							IKE_PH2ID ph2id;
							memset( &ph2id, 0, sizeof( ph2id ) );

							ph2id.type = ISAKMP_ID_IPV4_ADDR_SUBNET;
							ph2id.addr1 = subnet->addr;
							ph2id.addr2 = subnet->mask;

							char txtid[ LIBIKE_MAX_TEXTP2ID ];
							text_ph2id( txtid, &ph2id );

							if( subnet->addr.s_addr &&
								subnet->mask.s_addr )
							{
								log.txt( LLOG_DEBUG,
									"ii : - IP4 Subnet = %s\n",
									txtid );

								cfg->tunnel->idlist_incl.add( ph2id );
							}
							else
							{
								log.txt( LLOG_DEBUG,
									"ii : - IP4 Subnet = %s ( invalid subnet ignored )\n",
									txtid );
							}
						}
					}
					else
						log.txt( LLOG_DEBUG, "ii : - IP4 Subnet\n" );

					break;
				}

				default:
					unhandled = true;
			}
		}

		//
		// cisco unity attributes
		//

		if( vendopts.flag.unity && unhandled )
		{
			unhandled = false;

			switch( attr->atype )
			{
				case UNITY_DEF_DOMAIN:
				{
					getbits |= IPSEC_OPTS_DOMAIN;

					if( ( getmask & IPSEC_OPTS_DOMAIN ) && attr->vdata.size() )
					{
						size_t nlen = attr->vdata.size();
						if( nlen > ( CONF_STRLEN - 1 ) )
							nlen = ( CONF_STRLEN - 1 );

						memcpy(
							cfg->tunnel->xconf.nscfg.dnss_suffix,
							attr->vdata.buff(), nlen );

						cfg->tunnel->xconf.nscfg.dnss_suffix[ nlen ] = 0;

						log.txt( LLOG_DEBUG,
							"ii : - DNS Suffix = %s\n",
							cfg->tunnel->xconf.nscfg.dnss_suffix );
					}
					else
						log.txt( LLOG_DEBUG, "ii : - DNS Suffix\n" );

					break;
				}

				case UNITY_SPLIT_DOMAIN:
				{
					getbits |= IPSEC_OPTS_SPLITDNS;

					if( ( getmask & IPSEC_OPTS_SPLITDNS ) && attr->vdata.size() )
					{
						attr->vdata.add( 0, 1 );

						unsigned char *	dnsstr = attr->vdata.buff();
						size_t			dnslen = 0;

						while( dnslen < ( attr->vdata.size() - 1 ) )
						{
							if( *dnsstr == ',' )
							{
								dnslen += 1;
								dnsstr += 1;
							}

							size_t tmplen = strlen( ( char * ) dnsstr ) + 1;

							BDATA domain;
							domain.set( dnsstr, tmplen );

							log.txt( LLOG_DEBUG,
								"ii : - Split Domain = %s\n",
								dnsstr );

							dnslen += tmplen;
							dnsstr += tmplen;

							if( getmask & IPSEC_OPTS_SPLITDNS )
								cfg->tunnel->domains.add( domain );
						}
					}
					else
						log.txt( LLOG_DEBUG, "ii : - Split Domain\n" );

					break;
				}

				case UNITY_SPLIT_INCLUDE:
				case UNITY_SPLIT_EXCLUDE:
				{
					getbits |= IPSEC_OPTS_SPLITNET;

					if( ( getmask & IPSEC_OPTS_SPLITNET ) && attr->vdata.size() )
					{
						int net_count = int( attr->vdata.size() / sizeof( IKE_UNITY_NET ) );
						int net_index = 0;

						for( ; net_index < net_count; net_index++ )
						{
							long offset = sizeof( IKE_UNITY_NET ) * net_index;
							IKE_UNITY_NET * unity_net = ( IKE_UNITY_NET * ) ( attr->vdata.buff() + offset );

							IKE_PH2ID ph2id;
							memset( &ph2id, 0, sizeof( ph2id ) );

							ph2id.prot = unity_net->prot;
							ph2id.type = ISAKMP_ID_IPV4_ADDR_SUBNET;
							ph2id.addr1 = unity_net->addr;
							ph2id.addr2 = unity_net->mask;
							ph2id.port = unity_net->port_rmt;

							//
							// FIXME : there is a bug in racoon
							// that sends bogus protocol and port
							// information. I have comitted a fix
							// to ipsec-tools head and 0.7 but we
							// need to wait for that to settle
							// before we can remove the next two
							// lines of code;
							//

							ph2id.prot = 0;
							ph2id.port = 0;

							char txtid[ LIBIKE_MAX_TEXTP2ID ];
							text_ph2id( txtid, &ph2id );

							if( attr->atype == UNITY_SPLIT_INCLUDE )
							{
								if( unity_net->addr.s_addr &&
									unity_net->addr.s_addr )
								{
									log.txt( LLOG_DEBUG,
										"ii : - IP4 Split Network Include = %s\n",
										txtid );

									cfg->tunnel->idlist_incl.add( ph2id );
								}
								else
								{
									log.txt( LLOG_DEBUG,
										"ii : - IP4 Split Network Include = %s ( invalid subnet ignored )\n",
										txtid );
								}
							}
							else
							{
								if( unity_net->addr.s_addr &&
									unity_net->addr.s_addr )
								{
									log.txt( LLOG_DEBUG,
										"ii : - IP4 Split Network Exclude = %s\n",
										txtid );

									cfg->tunnel->idlist_excl.add( ph2id );
								}
								else
								{
									log.txt( LLOG_DEBUG,
										"ii : - IP4 Split Network Exclude = %s ( invalid subnet ignored )\n",
										txtid );
								}
							}
						}
					}
					else
					{
						if( attr->atype == UNITY_SPLIT_INCLUDE )
							log.txt( LLOG_DEBUG,	"ii : - IP4 Split Network Include\n" );

						if( attr->atype == UNITY_SPLIT_EXCLUDE )
							log.txt( LLOG_DEBUG,	"ii : - IP4 Split Network Exclude\n" );
					}

					break;
				}

				case UNITY_BANNER:
				{
					getbits |= IPSEC_OPTS_BANNER;

					if( ( getmask & IPSEC_OPTS_BANNER ) && attr->vdata.size() )
					{
						cfg->tunnel->banner.add( 0, 1 );

						size_t size = 15;
						char text[ 16 ] = { 0 };
						if( size > attr->vdata.size() )
							size = attr->vdata.size();

						memcpy( text, attr->vdata.buff(), size );

						log.txt( LLOG_DEBUG,
							"ii : - Login Banner = %s ...\n",
							text );

						cfg->tunnel->banner.set( attr->vdata );
						cfg->tunnel->banner.add( 0, 1 );
					}
					else
						log.txt( LLOG_DEBUG, "ii : - Login Banner\n" );

					break;
				}

				case UNITY_PFS:
				{
					getbits |= IPSEC_OPTS_PFS;

					if( ( getmask & IPSEC_OPTS_PFS ) && attr->basic )
					{
						log.txt( LLOG_DEBUG,
							"ii : - PFS Group = %d\n",
							attr->bdata );

						cfg->tunnel->xconf.dhgr = attr->bdata;
					}
					else
						log.txt( LLOG_DEBUG, "ii : - PFS Group\n" );

					break;
				}

				case UNITY_SAVE_PASSWD:
				{
					getbits |= IPSEC_OPTS_SAVEPW;

					if( ( getmask & IPSEC_OPTS_SAVEPW ) && attr->basic )
					{
						log.txt( LLOG_DEBUG,
							"ii : - Save Password = %d\n",
							attr->bdata );

						cfg->tunnel->xconf.svpw = attr->bdata;
					}
					else
						log.txt( LLOG_DEBUG, "ii : - Save Password\n" );

					break;
				}

				case UNITY_NATT_PORT:
				{
					getbits |= IPSEC_OPTS_CISCO_UDP;

					if( ( getmask & IPSEC_OPTS_CISCO_UDP ) && attr->basic )
					{
						log.txt( LLOG_DEBUG,
							"ii : - Cisco UDP Port = %d\n",
							attr->bdata );

						if( cfg->tunnel->natt_version == IPSEC_NATT_NONE )
						{
							cfg->tunnel->natt_version = IPSEC_NATT_CISCO;
							cfg->tunnel->peer->natt_port = htons( attr->bdata );

							cfg->tunnel->inc( true );
							cfg->tunnel->event_natt.delay = cfg->tunnel->peer->natt_rate * 1000;
							ith_timer.add( &cfg->tunnel->event_natt );

							log.txt( LLOG_INFO, "ii : switching nat-t to cisco-udp\n" );
						}
					}
					else
						log.txt( LLOG_DEBUG, "ii : - Cisco UDP Port\n" );

					break;
				}

				case UNITY_FW_TYPE:
				{
					if( attr->vdata.size() )
					{
						log.txt( LLOG_DEBUG,
							"ii : - Firewall Type = %i bytes\n",
							attr->vdata.size() );
					}
					else
						log.txt( LLOG_DEBUG, "ii : - Firewall Type\n" );

					break;
				}

				default:
					unhandled = true;
			}
		}

		//
		// unknown attribute type
		//

		if( unhandled )
		{
			if( attr->basic )
				log.txt( LLOG_DEBUG,
					"ii : - Unkown BASIC %u = %u\n",
					attr->atype,
					attr->bdata );
			else
				log.txt( LLOG_DEBUG,
					"ii : - Unkown VARIABLE %u = %u bytes\n",
					attr->atype,
					attr->vdata.size() );
		}
	}

	return LIBIKE_OK;
}

long _IKED::config_chk_hash( IDB_PH1 * ph1, IDB_CFG * cfg, unsigned long msgid )
{
	BDATA hash_c;
	hash_c.size( ph1->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_CTX_init( &ctx_prf );

	HMAC_Init_ex( &ctx_prf, ph1->skeyid_a.buff(), ( int ) ph1->skeyid_a.size(), ph1->evp_hash, NULL );
	HMAC_Update( &ctx_prf, ( unsigned char * ) &msgid, 4 );
	HMAC_Update( &ctx_prf, cfg->hda.buff(), cfg->hda.size() );
	HMAC_Final( &ctx_prf, hash_c.buff(), NULL );

	HMAC_CTX_cleanup( &ctx_prf );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		cfg->hash_r.buff(),
		cfg->hash_r.size(),
		"== : configure hash_i ( computed )" );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		hash_c.buff(),
		hash_c.size(),
		"== : configure hash_c ( computed )" );

	if( cfg->hash_r != hash_c )
	{
		log.txt( LLOG_ERROR,	"!! : configure hash verification failed\n" );
		return LIBIKE_FAILED;
	}

	log.txt( LLOG_DEBUG,	"ii : configure hash verified\n" );
	return LIBIKE_OK;
}

long _IKED::config_message_send( IDB_PH1 * ph1, IDB_CFG * cfg )
{
	//
	// create config exchange packet
	//

	BDATA hash;
	hash.size( ph1->hash_size );

	PACKET_IKE packet;
	packet.set_msgid( cfg->msgid );

	packet.write( ph1->cookies, ISAKMP_PAYLOAD_HASH, ISAKMP_EXCH_CONFIG, ISAKMP_FLAG_ENCRYPT );

	size_t off = packet.size();

	payload_add_hash( packet, hash, ISAKMP_PAYLOAD_ATTRIB );

	size_t beg = packet.size();
	payload_add_cfglist( packet, cfg, ISAKMP_PAYLOAD_NONE );
	size_t end = packet.size();

	packet.done();

	//
	// create message authentication hash
	//

	HMAC_CTX ctx_prf;
	HMAC_CTX_init( &ctx_prf );

	HMAC_Init_ex( &ctx_prf, ph1->skeyid_a.buff(), ( int ) ph1->skeyid_a.size(), ph1->evp_hash, NULL );
	HMAC_Update( &ctx_prf, ( unsigned char * ) &cfg->msgid, sizeof( cfg->msgid ) );
	HMAC_Update( &ctx_prf, packet.buff() + beg, end - beg );
	HMAC_Final( &ctx_prf, hash.buff(), 0 );

	HMAC_CTX_cleanup( &ctx_prf );

	memcpy( packet.buff() + off + 4, hash.buff(), hash.size() );

	log.bin(
		LLOG_DEBUG,
		LLOG_DECODE,
		hash.buff(),
		hash.size(),
		"== : new configure hash" );

	packet_ike_send( ph1, cfg, packet, true );

	return LIBIKE_OK;
}
