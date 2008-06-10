
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
	// config for this message id
	//

	IDB_CFG * cfg = NULL;

	uint32_t msgid;
	packet.get_msgid( msgid );

	idb_list_cfg.find( true, &cfg, ph1->tunnel, msgid );

	if( cfg == NULL )
	{
		//
		// looks like a unique config
		// exchange, create new object
		//

		cfg = new IDB_CFG( ph1->tunnel, false, msgid );
		cfg->add( true );

		//
		// calculate iv for this config
		//

		phase2_gen_iv( ph1, cfg->msgid, cfg->iv );
	}

	//
	// make sure we are not dealing
	// whith a sa marked for delete
	//

	if( ( ph1->status() == XCH_STATUS_DEAD ) ||
	    ( cfg->status() == XCH_STATUS_DEAD ) )
	{
		log.txt( LLOG_ERROR, "!! : config packet ignored ( sa marked for death )\n" );
		cfg->dec( true );
		return LIBIKE_OK;
	}

	//
	// make sure we are not dealing
	// whith an imature phase1 sa
	//

	if( ph1->status() < XCH_STATUS_MATURE )
	{
		log.txt( LLOG_ERROR, "!! : config packet ignored ( sa not mature )\n" );
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
		// and swap the src and
		// dst mac addresses
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
			log.txt( LLOG_ERROR, "XX : warning, unprocessed payload data !!!\n" );

		//
		// check the result
		//

		if( result != LIBIKE_OK )
		{
			//
			// flag sa for removal
			//

			cfg->status( XCH_STATUS_DEAD, XCH_NORMAL, 0 );
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
		if( !ph1->vendopts_r.flag.zwall )
		{
			//
			// update status and release
			//

			cfg->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_AUTH, 0 );
			cfg->dec( true );

			return LIBIKE_FAILED;
		}
		else
		{
			//
			// the zywall 5 xauth set response
			// always includes an invalid hash
			//

			log.txt( LLOG_ERROR,
				"!! : zywall sent a bad config hash value, ignored\n" );
		}
	}

	//
	// are we the initiator or responder
	//

	if( ph1->initiator )
	{
		//
		// evaluate config transaction
		//

		switch( cfg->mtype )
		{
			case ISAKMP_CFG_REQUEST:
			{
				//
				// check for gateway xauth request
				//

				BDATA message;

				long count = cfg->attr_count();
				long index = 0;

				bool auth_type = false;

				for( ; index < count; index++ )
				{
					IKE_ATTR * attr = cfg->attr_get( index );

					switch( attr->atype )
					{
						case XAUTH_TYPE:
						case CHKPT_TYPE:
							auth_type = true;
							break;

						case XAUTH_USER_NAME:
						case CHKPT_USER_NAME:
							cfg->tunnel->tstate |= TSTATE_RECV_XUSER;
							if( attr->basic )
								log.txt( LLOG_INFO, "!! : warning, basic xauth username attribute type\n" );
							break;

						case XAUTH_USER_PASSWORD:
						case CHKPT_USER_PASSWORD:
							cfg->tunnel->tstate |= TSTATE_RECV_XPASS;
							if( attr->basic )
								log.txt( LLOG_INFO, "!! : warning, basic xauth password attribute type\n" );
							break;

						case XAUTH_MESSAGE:
						case CHKPT_MESSAGE:
							if( !attr->basic )
								message.add( attr->vdata );
							break;

						default:
							log.txt( LLOG_INFO, "!! : warning, unhandled xauth attribute %i\n", attr->atype );
							break;
					}
				}

				//
				// examine the xauth request
				//

				if( message.size() )
				{
					if( message.text()[ message.size() - 1 ] != '\n' )
						message.add( '\n', 1 );

					message.add( 0, 1 );

					log.txt( LLOG_INFO, "ii : received xauth request - %s", message.text() );
				}
				else
					log.txt( LLOG_INFO, "ii : received xauth request\n" );

				//
				// if this is the first request
				//

				if( ( cfg->tunnel->tstate & TSTATE_RECV_XAUTH ) != TSTATE_RECV_XAUTH )
				{
					//
					// make sure we received a xauth type attribute
					//

					if( !auth_type )
					{
						log.txt( LLOG_INFO, "!! : warning, missing required xauth type attribute\n" );

//						cfg->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );
//						ph1->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );
					}
				}

				//
				// if this is a duplicate request
				//

				if( ( cfg->tunnel->tstate & TSTATE_SENT_XAUTH ) == TSTATE_SENT_XAUTH )
				{
					//
					// looks like we already sent an
					// xauth response. this means we
					// failed to authenticate
					//

					log.txt( LLOG_ERROR, "!! : duplicate xauth request, authentication failed\n" );

					cfg->status( XCH_STATUS_DEAD, XCH_FAILED_USER_AUTH, 0 );
					ph1->status( XCH_STATUS_DEAD, XCH_FAILED_USER_AUTH, 0 );
				}

				cfg->attr_reset();

				break;
			}

			case ISAKMP_CFG_SET:
			{
				//
				// gateway xauth server result
				//

				if( !( cfg->tunnel->tstate & TSTATE_RECV_XRSLT ) )
				{
					//
					// we should have an xauth status
					// attribute that shows the result
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

					//
					// process xauth status if present
					//

					if( status != -1 )
					{
						//
						// check xauth result
						//

						if( message.size() )
						{
							if( message.text()[ message.size() - 1 ] != '\n' )
								message.add( '\n', 1 );

							message.add( 0, 1 );

							log.txt( LLOG_INFO, "ii : received xauth result - %s", message.text() );
						}
						else
							log.txt( LLOG_INFO, "ii : received xauth result\n" );

						if( status == 1 )
						{
							log.txt( LLOG_INFO,
								"ii : user %s authentication succeeded\n",
								cfg->tunnel->xauth.user.text() );
						}
						else
						{
							log.txt( LLOG_ERROR,
								"!! : user %s authentication failed\n",
								cfg->tunnel->xauth.user.text() );

							cfg->status( XCH_STATUS_DEAD, XCH_FAILED_USER_AUTH, 0 );
							ph1->status( XCH_STATUS_DEAD, XCH_FAILED_USER_AUTH, 0 );
						}

						cfg->tunnel->tstate |= TSTATE_RECV_XRSLT;

						break;
					}

					//
					// unfortunately, not all gateways
					// are compliant. a config push can
					// be sent before sending the xauth
					// status. in this case, we resort
					// to processing the push request
					//

					if( cfg->tunnel->peer->xconf_mode != CONFIG_MODE_PUSH )
					{
						log.txt( LLOG_ERROR,
							"!! : no xauth status received and config mode is not push\n" );

							cfg->status( XCH_STATUS_DEAD, XCH_FAILED_MSG_FORMAT, 0 );

						break;
					}
				}

				//
				// gateway config push request
				//

				if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PUSH )
				{
					if( !( cfg->tunnel->tstate & TSTATE_RECV_CONFIG ) )
					{
						//
						// get xconf attributes
						//

						log.txt( LLOG_INFO, "ii : received config push request\n" );

						long getmask = 0;

						config_xconf_get( cfg,
							getmask,
							cfg->tunnel->xconf.rqst,
							ph1->vendopts_r );

						//
						// update state and flag for removal
						//

						cfg->tunnel->tstate |= TSTATE_RECV_CONFIG;

						cfg->tunnel->ikei->wakeup();
					}

					break;
				}

				break;
			}

			case ISAKMP_CFG_REPLY:
			{
				//
				// gateway config pull response
				//

				if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PULL )
				{
					if(  ( cfg->tunnel->tstate & TSTATE_SENT_CONFIG ) &&
						!( cfg->tunnel->tstate & TSTATE_RECV_CONFIG ) )
					{
						//
						// get xconf attributes
						//

						log.txt( LLOG_INFO, "ii : received config pull response\n" );

						long getmask = 0;

						config_xconf_get( cfg,
							getmask,
							cfg->tunnel->xconf.rqst,
							ph1->vendopts_r );

						//
						// update state and flag for removal
						//

						cfg->status( XCH_STATUS_DEAD, XCH_NORMAL, 0 );

						cfg->tunnel->tstate |= TSTATE_RECV_CONFIG;

						cfg->tunnel->ikei->wakeup();
					}
				}

				break;
			}
		}
	}
	else
	{
		//
		// evaluate config transaction
		//

		switch( cfg->mtype )
		{
			case ISAKMP_CFG_REQUEST:
			{
				//
				// client config pull request
				//

				if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PULL )
				{
					if( !( cfg->tunnel->tstate & TSTATE_RECV_CONFIG ) )
					{
						//
						// get xconf attributes
						//

						log.txt( LLOG_INFO, "ii : received config pull request\n" );

						config_xconf_get( cfg,
							cfg->tunnel->xconf.rqst,
							0,
							ph1->vendopts_r );

						cfg->attr_reset();

						cfg->tunnel->tstate |= TSTATE_RECV_CONFIG;
					}
				}

				break;
			}

			case ISAKMP_CFG_REPLY:
			{
				//
				// client xauth response
				//

				if(  ( cfg->tunnel->tstate & TSTATE_SENT_XAUTH ) &&
					!( cfg->tunnel->tstate & TSTATE_RECV_XRSLT ) )
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
								cfg->tunnel->xauth.user.set( attr->vdata );
								break;

							case XAUTH_USER_PASSWORD:
								cfg->tunnel->xauth.pass.set( attr->vdata );
								break;
						}
					}

					if( !cfg->tunnel->xauth.user.size() )
						log.txt( LLOG_ERROR, "!! : missing required username attribute\n" );

					if( !cfg->tunnel->xauth.pass.size() )
						log.txt( LLOG_ERROR, "!! : missing required password attribute\n" );

					cfg->tunnel->tstate |= TSTATE_RECV_XAUTH;
				}

				break;
			}

			case ISAKMP_CFG_ACK:
			{
				//
				// client xauth acknowledge
				//

				if( !( cfg->tunnel->tstate & TSTATE_RECV_XRSLT ) )
				{
					log.txt( LLOG_INFO, "ii : received xauth ack\n" );

					cfg->tunnel->tstate |= TSTATE_RECV_XRSLT;

					//
					// if the config mode is not push, we
					// can flag this handle for deletion
					//

					if( cfg->tunnel->peer->xconf_mode != CONFIG_MODE_PUSH )
						cfg->status( XCH_STATUS_DEAD, XCH_NORMAL, 0 );

					break;
				}

				//
				// client config push acknowledge
				//

				if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PUSH )
				{
					if( !( cfg->tunnel->tstate & TSTATE_RECV_CONFIG ) )
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

						cfg->attr_reset();

						cfg->tunnel->tstate |= TSTATE_RECV_CONFIG;
					}

					break;
				}

				break;
			}
		}
	}


	//
	// now build and send any response
	// packets that may be necessary
	//

	if( ( ph1->status() != XCH_STATUS_DEAD ) &&
		( cfg->status() != XCH_STATUS_DEAD ) )
		process_config_send( ph1, cfg );

	//
	// cleanup
	//

	cfg->dec( true );

	return LIBIKE_OK;
}

long _IKED::process_config_send( IDB_PH1 * ph1, IDB_CFG * cfg )
{
	//
	// are we the initiator or responder
	//

	if( ph1->initiator )
	{
		//
		// determine xauth operation
		//

		if( ph1->vendopts_l.flag.xauth )
		{
			//
			// client xauth response
			//

			if( ( cfg->tunnel->tstate & TSTATE_RECV_XAUTH ) &&
				( cfg->tunnel->tstate & TSTATE_SENT_XAUTH ) != TSTATE_SENT_XAUTH )
			{
				//
				// set attributes
				//

				cfg->mtype = ISAKMP_CFG_REPLY;
				cfg->attr_reset();

				//
				// check for special case processing
				//

				if( !ph1->vendopts_r.flag.chkpt )
				{
					//
					// standard xauth processing
					//

					cfg->attr_add_b( XAUTH_TYPE, XAUTH_TYPE_GENERIC );

					if(  ( cfg->tunnel->tstate & TSTATE_RECV_XUSER ) &&
						!( cfg->tunnel->tstate & TSTATE_SENT_XUSER ) )
					{
						cfg->attr_add_v( XAUTH_USER_NAME,
							cfg->tunnel->xauth.user.buff(),
							cfg->tunnel->xauth.user.size() );

						cfg->tunnel->tstate |= TSTATE_SENT_XUSER;

						log.txt( LLOG_INFO,
							"ii : added standard xauth username attribute\n" );
					}

					if(  ( cfg->tunnel->tstate & TSTATE_RECV_XPASS ) &&
						!( cfg->tunnel->tstate & TSTATE_SENT_XPASS ) )
					{
						cfg->attr_add_v( XAUTH_USER_PASSWORD,
							cfg->tunnel->xauth.pass.buff(),
							cfg->tunnel->xauth.pass.size() );

						cfg->tunnel->tstate |= TSTATE_SENT_XPASS;

						log.txt( LLOG_INFO,
							"ii : added standard xauth password attribute\n" );
					}

					//
					// remove this handle unless communicating
					// with a zywall or sidewinder which use
					// the same msgid and iv from xauth through
					// modecfg
					//

					if( ( cfg->tunnel->tstate & TSTATE_SENT_XAUTH ) == TSTATE_SENT_XAUTH )
						if( !ph1->vendopts_r.flag.zwall &&
							!ph1->vendopts_r.flag.swind )
							cfg->status( XCH_STATUS_DEAD, XCH_NORMAL, 0 );
				}
				else
				{
					//
					// checkpoint xauth processing
					//

					cfg->attr_add_b( CHKPT_TYPE, XAUTH_TYPE_GENERIC );

					if(  ( cfg->tunnel->tstate & TSTATE_RECV_XUSER ) &&
						!( cfg->tunnel->tstate & TSTATE_SENT_XUSER ) )
					{
						cfg->attr_add_v( CHKPT_USER_NAME,
							cfg->tunnel->xauth.user.buff(),
							cfg->tunnel->xauth.user.size() );

						cfg->tunnel->tstate |= TSTATE_SENT_XUSER;

						log.txt( LLOG_INFO,
							"ii : added checkpoint xauth username attribute\n" );
					}

					if(  ( cfg->tunnel->tstate & TSTATE_RECV_XPASS ) &&
						!( cfg->tunnel->tstate & TSTATE_SENT_XPASS ) )
					{
						cfg->attr_add_v( CHKPT_USER_PASSWORD,
							cfg->tunnel->xauth.pass.buff(),
							cfg->tunnel->xauth.pass.size() );

						cfg->tunnel->tstate |= TSTATE_SENT_XPASS;

						log.txt( LLOG_INFO,
							"ii : added checkpoint xauth password attribute\n" );
					}
				}

				//
				// send config packet
				//

				config_message_send( ph1, cfg );

				cfg->tunnel->xauth.user.add( 0, 1 );

				log.txt( LLOG_INFO,
					"ii : sent xauth response for %s\n",
					cfg->tunnel->xauth.user.buff() );
			}

			//
			// client xauth acknowledge
			//

			if(  ( cfg->tunnel->tstate & TSTATE_RECV_XRSLT ) &&
				!( cfg->tunnel->tstate & TSTATE_SENT_XRSLT ) )
			{
				//
				// reset ack attributes
				//

				cfg->mtype = ISAKMP_CFG_ACK;
				cfg->attr_reset();

				//
				// send config packet
				//

				config_message_send( ph1, cfg );

				log.txt( LLOG_INFO, "ii : sent xauth acknowledge\n" );

				//
				// update state and flag for removal
				//

				cfg->tunnel->tstate |= TSTATE_SENT_XRSLT;

				//
				// if the config mode is not pull, we
				// can flag this handle for deletion
				//

				if( cfg->tunnel->peer->xconf_mode != CONFIG_MODE_PULL )
					cfg->status( XCH_STATUS_DEAD, XCH_NORMAL, 0 );
			}
		}
		else
		{
			//
			// xauth not required
			//

			log.txt( LLOG_INFO, "ii : xauth is not required\n" );

			cfg->tunnel->tstate |= TSTATE_RECV_XAUTH;
			cfg->tunnel->tstate |= TSTATE_SENT_XAUTH;
			cfg->tunnel->tstate |= TSTATE_RECV_XRSLT;
			cfg->tunnel->tstate |= TSTATE_SENT_XRSLT;
		}

		//
		// client config pull request
		//

		if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PULL )
		{
			if(  ( cfg->tunnel->tstate & TSTATE_SENT_XRSLT ) &&
				!( cfg->tunnel->tstate & TSTATE_SENT_CONFIG ) )
			{
				//
				// set attributes
				//

				log.txt( LLOG_INFO, "ii : building config attribute list\n" );

				cfg->mtype = ISAKMP_CFG_REQUEST;
				cfg->attr_reset();

				if( ph1->vendopts_r.flag.chkpt )
					iked.rand_bytes( &cfg->ident, sizeof( cfg->ident ) );

				config_xconf_set( cfg,
					cfg->tunnel->xconf.rqst,
					0xffffffff,
					ph1->vendopts_r );

				//
				// flag as sent and release
				//

				if( cfg->attr_count() )
				{
					log.txt( LLOG_INFO, "ii : sending config pull request\n" );

					//
					// make sure the msgid is unique
					//

					rand_bytes( &cfg->msgid, sizeof( cfg->msgid ) );

					//
					// calculate iv for this config
					//

					phase2_gen_iv( ph1, cfg->msgid, cfg->iv );

					//
					// send config packet
					//

					config_message_send( ph1, cfg );

					cfg->attr_reset();

					//
					// flag as sent
					//

					cfg->tunnel->tstate |= TSTATE_SENT_CONFIG;
				}
				else
				{
					//
					// config not required
					//

					log.txt( LLOG_INFO, "ii : config is not required\n" );

					cfg->tunnel->tstate |= TSTATE_SENT_CONFIG;
					cfg->tunnel->tstate |= TSTATE_RECV_CONFIG;

					cfg->tunnel->ikei->wakeup();
				}
			}
		}

		//
		// client config push acknowledge
		//

		if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PUSH )
		{
			if(  ( cfg->tunnel->tstate & TSTATE_RECV_CONFIG ) &&
				!( cfg->tunnel->tstate & TSTATE_SENT_CONFIG ) )
			{
				//
				// set attributes
				//

				log.txt( LLOG_INFO, "ii : building config attribute list\n" );

				cfg->mtype = ISAKMP_CFG_ACK;
				cfg->attr_reset();

				config_xconf_set( cfg,
					cfg->tunnel->xconf.rqst,
					0xffffffff,
					ph1->vendopts_r );

				//
				// flag as sent and release
				//

				log.txt( LLOG_INFO, "ii : sending config push acknowledge\n" );

				//
				// send config packet
				//

				config_message_send( ph1, cfg );

				cfg->attr_reset();

				//
				// flag as sent
				//

				cfg->tunnel->tstate |= TSTATE_SENT_CONFIG;

				cfg->status( XCH_STATUS_DEAD, XCH_NORMAL, 0 );
			}
		}

		//
		// other configuration methods
		//

		if( ph1->tunnel->peer->xconf_mode == CONFIG_MODE_DHCP )
		{
			//
			// begin after xauth
			//

			if( cfg->tunnel->tstate & TSTATE_RECV_XRSLT )
			{
				//
				// begin our DHCP over IPsec processing
				//

				socket_dhcp_create( ph1->tunnel );

				cfg->status( XCH_STATUS_DEAD, XCH_NORMAL, 0 );
			}
		}

		if( ph1->tunnel->peer->xconf_mode == CONFIG_MODE_NONE )
		{
			//
			// config not required
			//

			log.txt( LLOG_INFO, "ii : config method is manual\n" );

			cfg->tunnel->tstate |= TSTATE_SENT_CONFIG;
			cfg->tunnel->tstate |= TSTATE_RECV_CONFIG;

			cfg->tunnel->ikei->wakeup();
		}
	}
	else
	{
		//
		// determine xauth operation
		//

		if( ph1->vendopts_l.flag.xauth )
		{
			//
			// gateway xauth request
			//

			if( !( cfg->tunnel->tstate & TSTATE_SENT_XAUTH ) )
			{
				//
				// set request attributes
				//

				cfg->mtype = ISAKMP_CFG_REQUEST;

				cfg->attr_reset();

				cfg->attr_add_b( XAUTH_TYPE, XAUTH_TYPE_GENERIC );
				cfg->attr_add_v( XAUTH_USER_NAME, NULL, 0 );
				cfg->attr_add_v( XAUTH_USER_PASSWORD, NULL, 0 );

				//
				// generate message iv
				//

				phase2_gen_iv( ph1, cfg->msgid, cfg->iv );

				//
				// send config packet
				//

				config_message_send( ph1, cfg );

				cfg->attr_reset();

				//
				// flag as sent
				//

				cfg->tunnel->tstate |= TSTATE_SENT_XAUTH;

				log.txt( LLOG_INFO, "ii : sent xauth request\n" );
			}

			//
			// gateway xauth result
			//

			if(  ( cfg->tunnel->tstate & TSTATE_RECV_XAUTH ) &&
				!( cfg->tunnel->tstate & TSTATE_SENT_XRSLT ) )
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

				cfg->attr_reset();

				if( allow )
					cfg->attr_add_b( XAUTH_STATUS, 1 );
				else
					cfg->attr_add_b( XAUTH_STATUS, 0 );

				//
				// make sure the msgid is unique
				//

				rand_bytes( &cfg->msgid, sizeof( cfg->msgid ) );

				//
				// generate message iv
				//

				phase2_gen_iv( ph1, cfg->msgid, cfg->iv );

				//
				// send config packet
				//

				config_message_send( ph1, cfg );

				cfg->attr_reset();

				//
				// flag as sent and release
				//

				cfg->tunnel->tstate |= TSTATE_SENT_XRSLT;

				log.txt( LLOG_INFO, "ii : sent xauth result\n" );

				if( !allow )
				{
					cfg->status( XCH_STATUS_DEAD, XCH_FAILED_USER_AUTH, 0 );
					ph1->status( XCH_STATUS_DEAD, XCH_FAILED_USER_AUTH, 0 );
				}
			}
		}
		else
		{
			//
			// xauth not required
			//

			log.txt( LLOG_INFO, "ii : xauth is not required\n" );

			cfg->tunnel->tstate |= TSTATE_RECV_XAUTH;
			cfg->tunnel->tstate |= TSTATE_SENT_XAUTH;
			cfg->tunnel->tstate |= TSTATE_RECV_XRSLT;
			cfg->tunnel->tstate |= TSTATE_SENT_XRSLT;
		}

		//
		// gateway config pull response
		//

		if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PULL )
		{
			if(  ( cfg->tunnel->tstate & TSTATE_RECV_CONFIG ) &&
				!( cfg->tunnel->tstate & TSTATE_SENT_CONFIG ) )
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

				cfg->attr_reset();

				//
				// flag as sent
				//

				cfg->tunnel->tstate |= TSTATE_SENT_CONFIG;

				cfg->status( XCH_STATUS_DEAD, XCH_NORMAL, 0 );
			}
		}

		//
		// gateway config push request
		//

		if( cfg->tunnel->peer->xconf_mode == CONFIG_MODE_PUSH )
		{
			if(  ( cfg->tunnel->tstate & TSTATE_RECV_XRSLT ) &&
				!( cfg->tunnel->tstate & TSTATE_SENT_CONFIG ) )
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
				// make sure the msgid is unique
				//

				rand_bytes( &cfg->msgid, sizeof( cfg->msgid ) );

				//
				// generate message iv
				//

				phase2_gen_iv( ph1, cfg->msgid, cfg->iv );

				//
				// send config packet
				//

				log.txt( LLOG_INFO, "ii : sending config push request\n" );

				config_message_send( ph1, cfg );

				cfg->attr_reset();

				//
				// flag as sent
				//

				cfg->tunnel->tstate |= TSTATE_SENT_CONFIG;
			}
		}
	}

	//
	// if all required operations are
	// complete, make sure the config
	// handle is flagged for deletion
	//

	if( ( cfg->tunnel->tstate & TSTATE_RECV_XRSLT ) &&
		( cfg->tunnel->tstate & TSTATE_SENT_XRSLT ) &&
		( cfg->tunnel->tstate & TSTATE_SENT_CONFIG ) &&
		( cfg->tunnel->tstate & TSTATE_RECV_CONFIG ) )
		cfg->status( XCH_STATUS_DEAD, XCH_NORMAL, 0 );

	return LIBIKE_OK;
}

long _IKED::config_xconf_set( IDB_CFG * cfg, long & setmask, long nullmask, VENDOPTS vendopts )
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

	if( setmask & IPSEC_OPTS_ADDR )
	{
		if( nullmask & IPSEC_OPTS_ADDR )
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

	if( setmask & IPSEC_OPTS_MASK )
	{
		if( nullmask & IPSEC_OPTS_MASK )
		{
			cfg->attr_add_v( INTERNAL_IP4_NETMASK,
				null_ptr, null_len );

			log.txt( LLOG_DEBUG,	"ii : - IP4 Netamask\n" );
		}
		else
		{
			cfg->attr_add_v( INTERNAL_IP4_NETMASK,
				&cfg->tunnel->xconf.mask,
				sizeof( cfg->tunnel->xconf.mask ) );

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, cfg->tunnel->xconf.mask );

			log.txt( LLOG_DEBUG,
				"ii : - IP4 Netamask = %s\n",
				txtaddr );
		}
	}

	if( setmask & IPSEC_OPTS_DNSS )
	{
		if( nullmask & IPSEC_OPTS_DNSS )
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

	if( setmask & IPSEC_OPTS_NBNS )
	{
		if( nullmask & IPSEC_OPTS_NBNS )
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
		if( setmask & IPSEC_OPTS_SPLITNET )
		{
			if( nullmask & IPSEC_OPTS_SPLITNET )
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

					cfg->attr_add_v( INTERNAL_IP4_SUBNET,
						&subnet,
						sizeof( subnet ) );

					char txtid[ LIBIKE_MAX_TEXTP2ID ];
					text_ph2id( txtid, &ph2id );

					log.txt( LLOG_DEBUG,
						"ii : - IP4 Subnet = %s\n",
						txtid );

					//
					// we need to perform special
					// operations if we instruct
					// our peer to force all via
					// this tunnel
					//

					if( !subnet.addr.s_addr &&
						!subnet.mask.s_addr )
						cfg->tunnel->force_all = true;
				}
			}
		}
	}

	//
	// cisco unity attributes
	//

	if( vendopts.flag.unity )
	{
		if( setmask & IPSEC_OPTS_DOMAIN )
		{
			if( nullmask & IPSEC_OPTS_DOMAIN )
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

		if( setmask & IPSEC_OPTS_SPLITDNS )
		{
			if( nullmask & IPSEC_OPTS_SPLITDNS )
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

		if( setmask & IPSEC_OPTS_SPLITNET )
		{
			if( nullmask & IPSEC_OPTS_SPLITNET )
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

					cfg->attr_add_v( UNITY_SPLIT_INCLUDE,
						&unity_net,
						sizeof( unity_net ) );

					char txtid[ LIBIKE_MAX_TEXTP2ID ];
					text_ph2id( txtid, &ph2id );

					log.txt( LLOG_DEBUG,
						"ii : - IP4 Split Network Include = %s\n",
						txtid );

					//
					// we need to perform special
					// operations if we instruct
					// our peer to force all via
					// this tunnel
					//

					if( !unity_net.addr.s_addr &&
						!unity_net.mask.s_addr )
						cfg->tunnel->force_all = true;
				}

				index = 0;

				while( cfg->tunnel->idlist_excl.get( ph2id, index++ ) )
				{
					IKE_UNITY_NET unity_net;
					memset( &unity_net, 0, sizeof( unity_net ) );

					unity_net.addr = ph2id.addr1;
					unity_net.mask = ph2id.addr2;

					cfg->attr_add_v( UNITY_SPLIT_EXCLUDE,
						&unity_net,
						sizeof( unity_net ) );

					char txtid[ LIBIKE_MAX_TEXTP2ID ];
					text_ph2id( txtid, &ph2id );

					log.txt( LLOG_DEBUG,
						"ii : - IP4 Split Network Exclude = %s\n",
						txtid );
				}
			}
		}

		if( setmask & IPSEC_OPTS_BANNER )
		{
			if( nullmask & IPSEC_OPTS_BANNER )
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

		if( setmask & IPSEC_OPTS_PFS )
		{
			if( nullmask & IPSEC_OPTS_PFS )
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

		if( setmask & IPSEC_OPTS_SAVEPW )
		{
			if( nullmask & IPSEC_OPTS_SAVEPW )
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

		if( setmask & IPSEC_OPTS_DOMAIN )
		{
			if( nullmask & IPSEC_OPTS_DOMAIN )
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

long _IKED::config_xconf_get( IDB_CFG * cfg, long & getmask, long readmask, VENDOPTS vendopts )
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
				getmask |= IPSEC_OPTS_ADDR;

				if( ( readmask & IPSEC_OPTS_ADDR ) && attr->vdata.size() )
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
					log.txt( LLOG_DEBUG,	"ii : - IP4 Address\n" );

				break;
			}

			case INTERNAL_ADDRESS_EXPIRY:
			{
				getmask |= IPSEC_OPTS_ADDR;

				if( ( readmask & IPSEC_OPTS_ADDR ) && attr->vdata.size() )
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

			case INTERNAL_IP4_NETMASK:
			{
				getmask |= IPSEC_OPTS_MASK;

				if( ( readmask & IPSEC_OPTS_MASK ) && attr->vdata.size() )
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
					log.txt( LLOG_DEBUG,	"ii : - IP4 Netmask\n" );

				break;
			}

			case INTERNAL_IP4_NBNS:
			{
				getmask |= IPSEC_OPTS_NBNS;

				if( ( readmask & IPSEC_OPTS_NBNS ) && attr->vdata.size() )
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

			case INTERNAL_IP4_DNS:
			{
				getmask |= IPSEC_OPTS_DNSS;

				if( ( readmask & IPSEC_OPTS_DNSS ) && attr->vdata.size() )
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
					getmask |= IPSEC_OPTS_SPLITNET;

					if( ( readmask & IPSEC_OPTS_SPLITNET ) && attr->vdata.size() )
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

							log.txt( LLOG_DEBUG,
								"ii : - IP4 Subnet = %s\n",
								txtid );

							if( readmask & IPSEC_OPTS_SPLITNET )
								cfg->tunnel->idlist_incl.add( ph2id );

							//
							// we need to perform special
							// operations if we force all
							// taffic via this tunnel
							//

							if( !subnet->addr.s_addr &&
								!subnet->mask.s_addr )
								cfg->tunnel->force_all = true;
						}
					}
					else
					{
						log.txt( LLOG_DEBUG, "ii : - IP4 Subnet\n" );
					}

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
					getmask |= IPSEC_OPTS_DOMAIN;

					if( ( readmask & IPSEC_OPTS_DOMAIN ) && attr->vdata.size() )
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
					getmask |= IPSEC_OPTS_SPLITDNS;

					if( ( readmask & IPSEC_OPTS_SPLITDNS ) && attr->vdata.size() )
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

							if( readmask & IPSEC_OPTS_SPLITDNS )
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
					getmask |= IPSEC_OPTS_SPLITNET;

					if( ( readmask & IPSEC_OPTS_SPLITNET ) && attr->vdata.size() )
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
								log.txt( LLOG_DEBUG,
									"ii : - IP4 Split Network Include = %s\n",
									txtid );

								if( readmask & IPSEC_OPTS_SPLITNET )
									cfg->tunnel->idlist_incl.add( ph2id );

								//
								// we need to perform special
								// operations if we force all
								// taffic via this tunnel
								//

								if( !unity_net->addr.s_addr &&
									!unity_net->mask.s_addr )
									cfg->tunnel->force_all = true;
							}
							else
							{
								log.txt( LLOG_DEBUG,
									"ii : - IP4 Split Network Exclude = %s\n",
									txtid );

								if( readmask & IPSEC_OPTS_SPLITNET )
									cfg->tunnel->idlist_excl.add( ph2id );
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
					getmask |= IPSEC_OPTS_BANNER;

					if( ( readmask & IPSEC_OPTS_BANNER ) && attr->vdata.size() )
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
						log.txt( LLOG_DEBUG,	"ii : - Login Banner\n" );

					break;
				}

				case UNITY_PFS:
				{
					getmask |= IPSEC_OPTS_PFS;

					if( ( readmask & IPSEC_OPTS_PFS ) && attr->basic )
					{
						log.txt( LLOG_DEBUG,
							"ii : - PFS Group = %d\n",
							attr->bdata );

						cfg->tunnel->xconf.dhgr = attr->bdata;
					}
					else
						log.txt( LLOG_DEBUG,	"ii : - PFS Group\n" );

					break;
				}

				case UNITY_SAVE_PASSWD:
				{
					getmask |= IPSEC_OPTS_SAVEPW;

					if( ( readmask & IPSEC_OPTS_SAVEPW ) && attr->basic )
					{
						log.txt( LLOG_DEBUG,
							"ii : - Save Password = %d\n",
							attr->bdata );

						cfg->tunnel->xconf.svpw = attr->bdata;
					}
					else
						log.txt( LLOG_DEBUG,	"ii : - Save Password\n" );

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
	HMAC_Init( &ctx_prf, ph1->skeyid_a.buff(), ( int ) ph1->skeyid_a.size(), ph1->evp_hash );
	HMAC_Update( &ctx_prf, ( unsigned char * ) &msgid, 4 );
	HMAC_Update( &ctx_prf, cfg->hda.buff(), cfg->hda.size() );
	HMAC_Final( &ctx_prf, hash_c.buff(), NULL );
	HMAC_cleanup( &ctx_prf );

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

	if( memcmp( cfg->hash_r.buff(), hash_c.buff(), hash_c.size() ) )
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
	HMAC_Init( &ctx_prf, ph1->skeyid_a.buff(), ( int ) ph1->skeyid_a.size(), ph1->evp_hash );
	HMAC_Update( &ctx_prf, ( unsigned char * ) &cfg->msgid, sizeof( cfg->msgid ) );
	HMAC_Update( &ctx_prf, packet.buff() + beg, end - beg );
	HMAC_Final( &ctx_prf, hash.buff(), 0 );
	HMAC_cleanup( &ctx_prf );

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
