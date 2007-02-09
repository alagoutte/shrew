
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

	IDB_CFG * cfg = NULL;

	//
	// attempt to locate a known
	// config for this message id
	//

	uint32_t msgid;
	packet.get_msgid( msgid );

	get_config( true, &cfg, ph1->tunnel, msgid );

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

	if( ( ph1->lstate & LSTATE_DELETE ) ||
	    ( cfg->lstate & LSTATE_DELETE ) )
	{
		log.txt( LOG_ERROR, "!! : ignore config packet, sa marked for death\n" );

		cfg->dec( true );
		return LIBIKE_OK;
	}

	//
	// decrypt packet
	//

	packet_ike_decrypt( ph1, packet, &cfg->iv );

	//
	// if we are dumping the ike packets,
	// we need to rebuild a full packet
	// to dump to pcap format 
	//

	if( dump_ike )
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
			cfg->tunnel->natt_v );

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

		pcap_ike.dump(
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
			// attribute payload
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
				long beg = packet.oset() - 4;
				result = payload_get_cfglist( packet, cfg );
				long end = packet.oset();
				cfg->hda.set( packet.buff() + beg, end - beg );

				break;
			}

			//
			// unhandled payload
			//

			default:

				log.txt( LOG_ERROR,
					"!! : unhandled config payload \'%s\' ( %i )\n",
					find_name( NAME_PAYLOAD, payload ),
					payload );

				result = LIBIKE_FAILED;

				break;
		}

		//
		// was the entire payload read
		//

		long bytes_left;
		packet.chk_payload( bytes_left );
		if( bytes_left )
			log.txt( LOG_ERROR, "XX : warning, unprocessed payload data !!!\n" );

		//
		// check the result
		//

		if( result != LIBIKE_OK )
		{
			//
			// flag sa for removal
			//

			cfg->lstate |= LSTATE_DELETE;
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
		// potentialy notify our peer
		//

		if( cfg->tunnel->peer->notify )
			inform_new_notify( ph1, NULL, ISAKMP_N_INVALID_HASH_INFORMATION );

		//
		// flag sa for removal
		//

		cfg->lstate |= LSTATE_DELETE;
		cfg->dec( true );

		return LIBIKE_FAILED;
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
				// xauth request
				//

				if( !( ph1->tunnel->state & TSTATE_RECV_XAUTH ) )
				{
					log.txt( LOG_INFO, "ii : received xauth request\n" );

					ph1->tunnel->state |= TSTATE_RECV_XAUTH;
				}

				break;
			}

			case ISAKMP_CFG_SET:
			{
				//
				// xauth result
				//

				if(  ( ph1->tunnel->state & TSTATE_SENT_XAUTH ) &&
					!( ph1->tunnel->state & TSTATE_RECV_XRSLT ) )
				{
					log.txt( LOG_INFO, "ii : received xauth result\n" );

					if( cfg->attr_count() != 1 )
					{
						log.txt( LOG_ERROR,
							"!! : invalid config set attribute count ( %i )\n",
							cfg->attr_count() );

						break;
					}

					IKE_ATTR * attr = cfg->attr_get( 0 );
					if( ( attr->atype != XAUTH_STATUS ) ||
						( attr->basic != true ) )
					{
						log.txt( LOG_ERROR,
							"!! : invalid config set attribute type\n" );

						break;
					}

					if( attr->bdata )
					{
						log.txt( LOG_INFO,
							"ii : user %s authentication succeeded\n",
							cfg->tunnel->xauth.user.text() );
					}
					else
					{
						log.txt( LOG_ERROR,
							"!! : user %s authentication failed\n",
							cfg->tunnel->xauth.user.text() );

						ph1->tunnel->close = TERM_USER_AUTH;

						cfg->lstate |= LSTATE_DELETE;
					}

					ph1->tunnel->state |= TSTATE_RECV_XRSLT;
				}

				break;
			}

			case ISAKMP_CFG_REPLY:
			{
				//
				// config response
				//

				if(  ( ph1->tunnel->state & TSTATE_SENT_CONFIG ) &&
					!( ph1->tunnel->state & TSTATE_RECV_CONFIG ) )
				{
					//
					// get xconf attributes
					//

					log.txt( LOG_INFO, "ii : received isakmp config reply\n" );

					long getmask = 0;

					config_xconf_get( cfg,
						getmask,
						cfg->tunnel->xconf.rqst );

					//
					// update state and flag for removal
					//

					ph1->tunnel->state |= TSTATE_RECV_CONFIG;

					cfg->lstate |= LSTATE_DELETE;
				}

				break;
			}

			case ISAKMP_CFG_ACK:
			{
				//
				// config ack
				//

				if( !( ph1->tunnel->state & TSTATE_RECV_XRSLT ) )
				{
					log.txt( LOG_INFO, "ii : received config ack\n" );

					ph1->tunnel->state |= TSTATE_RECV_XRSLT;
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
				// config request
				//

				if( !( ph1->tunnel->state & TSTATE_RECV_CONFIG ) )
				{
					//
					// get xconf attributes
					//

					log.txt( LOG_INFO, "ii : received config request\n" );

					config_xconf_get( cfg,
						cfg->tunnel->xconf.rqst,
						0 );

					cfg->attr_reset();

					ph1->tunnel->state |= TSTATE_RECV_CONFIG;
				}

				break;
			}

			case ISAKMP_CFG_REPLY:
			{
				//
				// xauth response
				//

				if(  ( ph1->tunnel->state & TSTATE_SENT_XAUTH ) &&
					!( ph1->tunnel->state & TSTATE_RECV_XRSLT ) )
				{
					log.txt( LOG_INFO, "ii : received xauth response\n" );

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
						log.txt( LOG_ERROR, "!! : missing required username attribute\n" );

					if( !cfg->tunnel->xauth.pass.size() )
						log.txt( LOG_ERROR, "!! : missing required password attribute\n" );

					ph1->tunnel->state |= TSTATE_RECV_XAUTH;
				}

				break;
			}

			case ISAKMP_CFG_ACK:
			{
				//
				// xauth acknowledge
				//

				if( !( ph1->tunnel->state & TSTATE_RECV_XRSLT ) )
				{
					log.txt( LOG_INFO, "ii : received xauth ack\n" );

					ph1->tunnel->state |= TSTATE_RECV_XRSLT;

					cfg->lstate |= LSTATE_DELETE;
				}

				break;
			}
		}
	}


	//
	// now build and send any response
	// packets that may be necessary
	//

	if( !( cfg->lstate & LSTATE_MATURE ) &&
		!( cfg->lstate & LSTATE_DELETE ) )
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

		if( ph1->xauth_l )
		{
			//
			// send xauth client response
			//

			if(  ( ph1->tunnel->state & TSTATE_RECV_XAUTH ) &&
				!( ph1->tunnel->state & TSTATE_SENT_XAUTH ) )
			{
				//
				// set xauth attributes
				//

				cfg->mtype = ISAKMP_CFG_REPLY;

				long count = cfg->attr_count();
				long index = 0;

				for( ; index < count; index++ )
				{
					IKE_ATTR * attr = cfg->attr_get( index );

					switch( attr->atype )
					{
						case XAUTH_USER_NAME:
							attr->vdata.set( ph1->tunnel->xauth.user );
							break;

						case XAUTH_USER_PASSWORD:
							attr->vdata.set( ph1->tunnel->xauth.pass );
							break;
					}
				}

				//
				// send config packet
				//

				config_message_send( ph1, cfg );

				cfg->attr_reset();

				ph1->tunnel->xauth.user.add( 0, 1 );

				log.txt( LOG_INFO,
					"ii : sent xauth response for %s\n",
					ph1->tunnel->xauth.user.buff() );

				//
				// update state and flag for removal
				//

				ph1->tunnel->state |= TSTATE_SENT_XAUTH;

				cfg->lstate |= LSTATE_DELETE;
			}

			//
			// send xauth client acknowledge
			//

			if(  ( ph1->tunnel->state & TSTATE_RECV_XRSLT ) &&
				!( ph1->tunnel->state & TSTATE_SENT_XRSLT ) )
			{
				//
				// reset ack attributes
				//

				cfg->mtype = ISAKMP_CFG_ACK;

				config_message_send( ph1, cfg );

				log.txt( LOG_INFO, "ii : sent xauth ack\n" );

				//
				// update state and flag for removal
				//

				ph1->tunnel->state |= TSTATE_SENT_XRSLT;
			}
		}
		else
		{
			//
			// xauth not required
			//

			cfg->tunnel->state |= TSTATE_RECV_XAUTH;
			cfg->tunnel->state |= TSTATE_SENT_XAUTH;
			cfg->tunnel->state |= TSTATE_RECV_XRSLT;
			cfg->tunnel->state |= TSTATE_SENT_XRSLT;
		}

		//
		// config request
		//

		if(  ( cfg->tunnel->state & TSTATE_SENT_XRSLT ) &&
			!( cfg->tunnel->state & TSTATE_SENT_CONFIG ) )
		{
			//
			// set xconf attributes
			//

			log.txt( LOG_INFO, "ii : building config request attributes\n" );

			cfg->mtype = ISAKMP_CFG_REQUEST;

			cfg->attr_reset();

			config_xconf_set( cfg,
				cfg->tunnel->xconf.rqst,
				0xffffffff );

			//
			// flag as sent and release
			//

			if( cfg->attr_count() )
			{
				log.txt( LOG_INFO, "ii : sending config request\n" );

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

				cfg->tunnel->state |= TSTATE_SENT_CONFIG;
			}
			else
			{
				log.txt( LOG_INFO, "ii : config request is not required\n" );

				cfg->tunnel->state |= TSTATE_SENT_CONFIG;
				cfg->tunnel->state |= TSTATE_RECV_CONFIG;

				cfg->lstate |= LSTATE_DELETE;
			}
		}
	}
	else
	{
		//
		// determine xauth operation
		//

		if( ph1->xauth_l )
		{
			//
			// send xauth server request
			//

			if( !( cfg->tunnel->state & TSTATE_SENT_XAUTH ) )
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

				cfg->tunnel->state |= TSTATE_SENT_XAUTH;

				log.txt( LOG_INFO, "ii : sent xauth request\n" );
			}

			//
			// send xauth server result
			//

			if(  ( cfg->tunnel->state & TSTATE_RECV_XAUTH ) &&
				!( cfg->tunnel->state & TSTATE_SENT_XRSLT ) )
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
						iked.log.txt( LOG_INFO,
							"ii : xauth user %s password accepted ( %s )\n",
							cfg->tunnel->xauth.user.text(),
							cfg->tunnel->peer->xauth_source->name() );
					else
						iked.log.txt( LOG_ERROR,
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
						log.txt( LOG_INFO,
							"ii : xauth user %s group %s membership accepted ( %s )\n",
							cfg->tunnel->xauth.user.text(),
							cfg->tunnel->peer->xauth_group.text(),
							cfg->tunnel->peer->xauth_source->name() );
					else
						log.txt( LOG_ERROR,
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

				cfg->tunnel->state |= TSTATE_SENT_XRSLT;

				log.txt( LOG_INFO, "ii : sent xauth result\n" );

				if( !allow )
				{
					cfg->lstate |= LSTATE_DELETE;
					ph1->lstate |= LSTATE_DELETE;
				}
			}
		}
		else
		{
			//
			// xauth not required
			//

			cfg->tunnel->state |= TSTATE_RECV_XAUTH;
			cfg->tunnel->state |= TSTATE_SENT_XAUTH;
			cfg->tunnel->state |= TSTATE_RECV_XRSLT;
			cfg->tunnel->state |= TSTATE_SENT_XRSLT;
		}

		//
		// config response
		//

		if(  ( cfg->tunnel->state & TSTATE_RECV_CONFIG ) &&
			!( cfg->tunnel->state & TSTATE_SENT_CONFIG ) )
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

			//
			// set result attributes
			//

			cfg->mtype = ISAKMP_CFG_REPLY;

			log.txt( LOG_INFO, "ii : building config response attributes\n" );

			config_xconf_set( cfg,
				cfg->tunnel->xconf.opts,
				0 );

			//
			// send config packet
			//

			log.txt( LOG_INFO, "ii : sending config response\n" );

			config_message_send( ph1, cfg );

			cfg->attr_reset();

			//
			// flag as sent
			//

			cfg->tunnel->state |= TSTATE_SENT_CONFIG;

			cfg->lstate |= LSTATE_DELETE;
		}
	}

	return LIBIKE_OK;
}

long _IKED::config_xconf_set( IDB_CFG * cfg, long & setmask, long nullmask )
{
	if( setmask & IPSEC_OPTS_ADDR )
	{
		if( nullmask & IPSEC_OPTS_ADDR )
		{
			cfg->attr_add_v( INTERNAL_IP4_ADDRESS, NULL, 0 );
			log.txt( LOG_DEBUG,	"ii : - IP4 Address\n" );
		}
		else
		{
			cfg->attr_add_v( INTERNAL_IP4_ADDRESS,
				&cfg->tunnel->xconf.addr,
				sizeof( cfg->tunnel->xconf.addr ) );

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, cfg->tunnel->xconf.addr );

			log.txt( LOG_DEBUG,
				"ii : - IP4 Address = %s\n",
				txtaddr );
		}
	}

	if( setmask & IPSEC_OPTS_MASK )
	{
		if( nullmask & IPSEC_OPTS_MASK )
		{
			cfg->attr_add_v( INTERNAL_IP4_NETMASK, NULL, 0 );
			log.txt( LOG_DEBUG,	"ii : - IP4 Netamask\n" );
		}
		else
		{
			cfg->attr_add_v( INTERNAL_IP4_NETMASK,
				&cfg->tunnel->xconf.mask,
				sizeof( cfg->tunnel->xconf.mask ) );

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, cfg->tunnel->xconf.mask );

			log.txt( LOG_DEBUG,
				"ii : - IP4 Netamask = %s\n",
				txtaddr );
		}
	}

	if( setmask & IPSEC_OPTS_DNSS )
	{
		if( nullmask & IPSEC_OPTS_DNSS )
		{
			cfg->attr_add_v( INTERNAL_IP4_DNS, NULL, 0 );
			log.txt( LOG_DEBUG, "ii : - IP4 DNS Server\n" );
		}
		else
		{
			cfg->attr_add_v( INTERNAL_IP4_DNS,
				&cfg->tunnel->xconf.dnss,
				sizeof( cfg->tunnel->xconf.dnss ) );

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, cfg->tunnel->xconf.dnss );

			log.txt( LOG_DEBUG,
				"ii : - IP4 DNS Server = %s\n",
				txtaddr );
		}
	}

	if( setmask & IPSEC_OPTS_DOMAIN )
	{
		if( nullmask & IPSEC_OPTS_DOMAIN )
		{
			cfg->attr_add_v( UNITY_DEF_DOMAIN, NULL, 0 );
			log.txt( LOG_DEBUG,	"ii : - IP4 DNS Suffix\n" );
		}
		else
		{
			cfg->attr_add_v( UNITY_DEF_DOMAIN,
				&cfg->tunnel->xconf.suffix,
				strlen( cfg->tunnel->xconf.suffix ) );

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, cfg->tunnel->xconf.dnss );

			log.txt( LOG_DEBUG,
				"ii : - IP4 DNS Suffix = %s\n",
				cfg->tunnel->xconf.suffix );
		}
	}

	if( setmask & IPSEC_OPTS_SPLITDNS )
	{
		if( nullmask & IPSEC_OPTS_SPLITDNS )
		{
			cfg->attr_add_v( UNITY_SPLIT_DOMAIN, NULL, 0 );
			log.txt( LOG_DEBUG, "ii : - Split DNS Domain\n" );
		}
		else
		{
			BDATA suffix;

			long index = 0;

			while( cfg->tunnel->dlist.get( suffix, index++ ) )
			{
				log.txt( LOG_DEBUG,
					"ii : - Split DNS Domain = %s\n",
					suffix.text() );

				if( index > 1 )
					suffix.ins( ',', 1 );

				cfg->attr_add_v( UNITY_SPLIT_DOMAIN,
					suffix.buff(),
					suffix.size() );
			}
		}
	}

	if( setmask & IPSEC_OPTS_NBNS )
	{
		if( nullmask & IPSEC_OPTS_NBNS )
		{
			cfg->attr_add_v( INTERNAL_IP4_NBNS, NULL, 0 );
			log.txt( LOG_DEBUG,	"ii : - IP4 WINS Server\n" );
		}
		else
		{
			cfg->attr_add_v( INTERNAL_IP4_NBNS,
				&cfg->tunnel->xconf.nbns,
				sizeof( cfg->tunnel->xconf.nbns ) );

			char txtaddr[ LIBIKE_MAX_TEXTADDR ];
			text_addr( txtaddr, cfg->tunnel->xconf.nbns );

			log.txt( LOG_DEBUG,
				"ii : - IP4 WINS Server = %s\n",
				txtaddr );
		}
	}

	if( setmask & IPSEC_OPTS_SPLITNET )
	{
		if( nullmask & IPSEC_OPTS_SPLITNET )
		{
			cfg->attr_add_v( UNITY_SPLIT_INCLUDE, NULL, 0 );
			cfg->attr_add_v( UNITY_SPLIT_EXCLUDE, NULL, 0 );

			log.txt( LOG_DEBUG,
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

				unity_net.addr = ph2id.addr1;
				unity_net.mask = ph2id.addr2;

				cfg->attr_add_v( UNITY_SPLIT_INCLUDE,
					&unity_net,
					sizeof( unity_net ) );

				char txtid[ LIBIKE_MAX_TEXTP2ID ];
				text_ph2id( txtid, &ph2id );

				log.txt( LOG_DEBUG,
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

				log.txt( LOG_DEBUG,
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
			log.txt( LOG_DEBUG,	"ii : Login Banner\n" );
		}
		else
		{
			cfg->attr_add_v( UNITY_BANNER,
				cfg->tunnel->banner.buff(),
				cfg->tunnel->banner.size() );

			cfg->tunnel->banner.add( 0, 1 );

			log.txt( LOG_DEBUG,
				"ii : - Login Banner ( %i bytes )\n",
				cfg->tunnel->banner.size() );
		}
	}

	if( setmask & IPSEC_OPTS_PFS )
	{
		if( nullmask & IPSEC_OPTS_PFS )
		{
			cfg->attr_add_v( UNITY_PFS, NULL, 0 );
			log.txt( LOG_DEBUG,	"ii : - PFS Group\n" );
		}
		else
		{
			cfg->attr_add_b( UNITY_PFS,
				cfg->tunnel->xconf.dhgr );

			log.txt( LOG_DEBUG,
				"ii : - PFS Group = %i\n",
				cfg->tunnel->xconf.dhgr );
		}
	}

	return LIBIKE_OK;
}

long _IKED::config_xconf_get( IDB_CFG * cfg, long & getmask, long readmask )
{
	long count = cfg->attr_count();
	long index = 0;

	for( ; index < count; index++ )
	{
		IKE_ATTR * attr = cfg->attr_get( index );

		switch( attr->atype )
		{
			case INTERNAL_IP4_ADDRESS:
			{
				getmask |= IPSEC_OPTS_ADDR;

				if( ( readmask & IPSEC_OPTS_ADDR ) && attr->vdata.size() )
				{
					if( attr->vdata.size() != 4 )
					{
						log.txt( LOG_ERROR,
							"!! : - IP4 Address has invalid size ( %i bytes )\n",
							attr->vdata.size() );

						break;
					}

					memcpy(
						&cfg->tunnel->xconf.addr,
						attr->vdata.buff(), 4 );

					char txtaddr[ LIBIKE_MAX_TEXTADDR ];
					text_addr( txtaddr, cfg->tunnel->xconf.addr );

					log.txt( LOG_DEBUG,
						"ii : - IP4 Address = %s\n",
						txtaddr );
				}
				else
					log.txt( LOG_DEBUG,	"ii : - IP4 Address\n" );

				break;
			}

			case INTERNAL_IP4_NETMASK:
			{
				getmask |= IPSEC_OPTS_MASK;

				if( ( readmask & IPSEC_OPTS_MASK ) && attr->vdata.size() )
				{
					if( attr->vdata.size() != 4 )
					{
						log.txt( LOG_ERROR,
							"!! : - IP4 Netmask has invalid size ( %i bytes )\n",
							attr->vdata.size() );

						break;
					}

					memcpy(
						&cfg->tunnel->xconf.mask,
						attr->vdata.buff(), 4 );

					char txtaddr[ LIBIKE_MAX_TEXTADDR ];
					text_addr( txtaddr, cfg->tunnel->xconf.mask );

					log.txt( LOG_DEBUG,
						"ii : - IP4 Netmask = %s\n",
						txtaddr );
				}
				else
					log.txt( LOG_DEBUG,	"ii : - IP4 Netmask\n" );

				break;
			}

			case INTERNAL_IP4_NBNS:
			{
				getmask |= IPSEC_OPTS_NBNS;

				if( ( readmask & IPSEC_OPTS_NBNS ) && attr->vdata.size() )
				{
					if( attr->vdata.size() != 4 )
					{
						log.txt( LOG_ERROR,
							"!! : - IP4 WINS Server has invalid size ( %i bytes )\n",
							attr->vdata.size() );

						break;
					}

					memcpy(
						&cfg->tunnel->xconf.nbns,
						attr->vdata.buff(), 4 );

					char txtaddr[ LIBIKE_MAX_TEXTADDR ];
					text_addr( txtaddr, cfg->tunnel->xconf.nbns );

					log.txt( LOG_DEBUG,
						"ii : - IP4 WINS Server = %s\n",
						txtaddr );
				}
				else
					log.txt( LOG_DEBUG, "ii : - IP4 WINS Server\n" );

				break;
			}

			case INTERNAL_IP4_DNS:
			{
				getmask |= INTERNAL_IP4_DNS;

				if( ( readmask & INTERNAL_IP4_DNS ) && attr->vdata.size() )
				{
					if( attr->vdata.size() != 4 )
					{
						log.txt( LOG_ERROR,
							"!! : - IP4 DNS Server has invalid size ( %i bytes )\n",
							attr->vdata.size() );

						break;
					}

					memcpy(
						&cfg->tunnel->xconf.dnss,
						attr->vdata.buff(), 4 );

					char txtaddr[ LIBIKE_MAX_TEXTADDR ];
					text_addr( txtaddr, cfg->tunnel->xconf.dnss );

					log.txt( LOG_DEBUG,
						"ii : - IP4 DNS Server = %s\n",
						txtaddr );
				}
				else
					log.txt( LOG_DEBUG, "ii : - IP4 DNS Server\n" );

				break;
			}

			case UNITY_DEF_DOMAIN:
			{
				getmask |= IPSEC_OPTS_DOMAIN;

				if( ( readmask & IPSEC_OPTS_DOMAIN ) && attr->vdata.size() )
				{
					long nlen = attr->vdata.size();
					if( nlen > ( CONF_STRLEN - 1 ) )
						nlen = ( CONF_STRLEN - 1 );

					memcpy(
						cfg->tunnel->xconf.suffix,
						attr->vdata.buff(), nlen );

					cfg->tunnel->xconf.suffix[ nlen ] = 0;

					log.txt( LOG_DEBUG,
						"ii : - DNS Suffix = %s\n",
						cfg->tunnel->xconf.suffix );
				}
				else
					log.txt( LOG_DEBUG, "ii : - DNS Suffix\n" );

				break;
			}

			case UNITY_SPLIT_DOMAIN:
			{
				getmask |= IPSEC_OPTS_SPLITDNS;

				if( ( readmask & IPSEC_OPTS_SPLITDNS ) && attr->vdata.size() )
				{
					attr->vdata.add( 0, 1 );

					unsigned char *	dnsstr = attr->vdata.buff();
					long			dnslen = 0;

					while( dnslen < ( attr->vdata.size() - 1 ) )
					{
						if( *dnsstr == ',' )
						{
							dnslen += 1;
							dnsstr += 1;
						}

						long tmplen = strlen( ( char * ) dnsstr ) + 1;

						BDATA suffix;
						suffix.set( dnsstr, tmplen );

						log.txt( LOG_DEBUG,
							"ii : - Split Domain = %s\n",
							dnsstr );

						dnslen += tmplen;
						dnsstr += tmplen;

						if( readmask & IPSEC_OPTS_SPLITDNS )
							cfg->tunnel->dlist.add( suffix );
					}
				}
				else
					log.txt( LOG_DEBUG, "ii : - Split Domain\n" );

				break;
			}

			case UNITY_SPLIT_INCLUDE:
			case UNITY_SPLIT_EXCLUDE:
			{
				getmask |= IPSEC_OPTS_SPLITNET;

				if( ( readmask & IPSEC_OPTS_SPLITNET ) && attr->vdata.size() )
				{
					int net_count = attr->vdata.size() / sizeof( IKE_UNITY_NET );
					int net_index = 0;

					for( ; net_index < net_count; net_index++ )
					{
						long offset = sizeof( IKE_UNITY_NET ) * net_index;
						IKE_UNITY_NET * unity_net = ( IKE_UNITY_NET * ) ( attr->vdata.buff() + offset );

						IKE_PH2ID ph2id;
						memset( &ph2id, 0, sizeof( ph2id ) );

						ph2id.type = ISAKMP_ID_IPV4_ADDR_SUBNET;
						ph2id.addr1 = unity_net->addr;
						ph2id.addr2 = unity_net->mask;

						char txtid[ LIBIKE_MAX_TEXTP2ID ];
						text_ph2id( txtid, &ph2id );

						if( attr->atype == UNITY_SPLIT_INCLUDE )
						{
							log.txt( LOG_DEBUG,
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
							log.txt( LOG_DEBUG,
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
						log.txt( LOG_DEBUG,	"ii : - IP4 Split Network Include\n" );

					if( attr->atype == UNITY_SPLIT_EXCLUDE )
						log.txt( LOG_DEBUG,	"ii : - IP4 Split Network Exclude\n" );
				}

				break;
			}

			case UNITY_BANNER:
			{
				getmask |= IPSEC_OPTS_BANNER;

				if( ( readmask & IPSEC_OPTS_BANNER ) && attr->vdata.size() )
				{
					cfg->tunnel->banner.add( 0, 1 );

					long size = 15;
					char text[ 16 ] = { 0 };
					if( size > attr->vdata.size() )
						size = attr->vdata.size();

					memcpy( text, attr->vdata.buff(), size );

					log.txt( LOG_DEBUG,
						"ii : - Login Banner = %s ...\n",
						text );

					cfg->tunnel->banner.set( attr->vdata );
				}
				else
					log.txt( LOG_DEBUG,	"ii : - Login Banner\n" );

				break;
			}

			case UNITY_PFS:
			{
				getmask |= IPSEC_OPTS_PFS;

				if( ( readmask & IPSEC_OPTS_BANNER ) && attr->vdata.size() )
				{
					log.txt( LOG_DEBUG,
						"ii : - PFS Group = %d\n",
						attr->bdata );

					cfg->tunnel->xconf.dhgr = attr->bdata;
				}
				else
					log.txt( LOG_DEBUG,	"ii : - PFS Group\n" );

				break;
			}
		}
	}

	return LIBIKE_OK;
}

long _IKED::config_chk_hash( IDB_PH1 * ph1, IDB_CFG * cfg, unsigned long msgid )
{
	BDATA hash_c;
	hash_c.set( 0, ph1->hash_size );

	HMAC_CTX ctx_prf;
	HMAC_Init( &ctx_prf, ph1->skeyid_a.buff(), ph1->skeyid_a.size(), ph1->evp_hash );
	HMAC_Update( &ctx_prf, ( unsigned char * ) &msgid, 4 );
	HMAC_Update( &ctx_prf, cfg->hda.buff(), cfg->hda.size() );
	HMAC_Final( &ctx_prf, hash_c.buff(), NULL );
	HMAC_cleanup( &ctx_prf );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
		cfg->hash_r.buff(),
		cfg->hash_r.size(),
		"== : configure hash_i ( computed )" );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
		hash_c.buff(),
		hash_c.size(),
		"== : configure hash_c ( computed )" );

	if( memcmp( cfg->hash_r.buff(), hash_c.buff(), hash_c.size() ) )
	{
		log.txt( LOG_ERROR,	"!! : configure hash verification failed\n" );
		return LIBIKE_FAILED;
	}

	log.txt( LOG_DEBUG,	"ii : configure hash verified\n" );
	return LIBIKE_OK;
}

long _IKED::config_message_send( IDB_PH1 * ph1, IDB_CFG * cfg )
{
	//
	// create config exchange packet
	//

	BDATA hash;
	hash.set( 0, ph1->hash_size );

	PACKET_IKE packet;
	packet.set_msgid( cfg->msgid );

	packet.write( ph1->cookies, ISAKMP_PAYLOAD_HASH, ISAKMP_EXCH_CONFIG, ISAKMP_FLAG_ENCRYPT );

	long off = packet.size();

	payload_add_hash( packet, hash, ISAKMP_PAYLOAD_ATTRIB );

	long beg = packet.size();

	payload_add_cfglist( packet, cfg, ISAKMP_PAYLOAD_NONE );

	long end = packet.size();

	packet.done();

	//
	// create message authentication hash
	//

	HMAC_CTX ctx_prf;
	HMAC_Init( &ctx_prf, ph1->skeyid_a.buff(), ph1->skeyid_a.size(), ph1->evp_hash );
	HMAC_Update( &ctx_prf, ( unsigned char * ) &cfg->msgid, sizeof( cfg->msgid ) );
	HMAC_Update( &ctx_prf, packet.buff() + beg, end - beg );
	HMAC_Final( &ctx_prf, hash.buff(), 0 );
	HMAC_cleanup( &ctx_prf );

	memcpy( packet.buff() + off + 4, hash.buff(), hash.size() );

	log.bin(
		LOG_DEBUG,
		LOG_DECODE,
		hash.buff(),
		hash.size(),
		"== : new configure hash" );

	packet_ike_send( ph1, cfg, packet, true );

	return LIBIKE_OK;
}
