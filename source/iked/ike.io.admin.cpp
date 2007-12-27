
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

//
// ike admin io thread
//

long ITH_ADMIN::func( void * arg )
{
	IKEI * ikei = ( IKEI * ) arg;
	long result = iked.loop_ike_admin( ikei );
	return result;
}

long _IKED::loop_ike_admin( IKEI * ikei )
{
	log.txt( LLOG_INFO, "ii : admin process thread begin ...\n" );

	IDB_PEER *		peer = NULL;
	IDB_TUNNEL *	tunnel = NULL;
	VNET_ADAPTER *	adapter = NULL;

#ifdef OPT_DTP

	DTPI dtpi;

#endif

	time_t stattick = 0;

	//
	// enter client ctrl loop
	//

	IKEI_MSG msg;

	while( 1 )
	{
		long result;

		char text[ MAX_PATH ];
		size_t size = MAX_PATH;

		//
		// check for tunnel close
		//

		if( tunnel != NULL )
			if( tunnel->close )
				break;

		//
		// get the next message
		//

		result = ikei->next_msg( msg );

		if( result == IKEI_FAILED )
			break;

		if( result != IKEI_NODATA )
		{
			switch( msg.type )
			{
				//
				// peer config add message
				//

				case IKEI_MSGID_PEER:
				{
					log.txt( LLOG_INFO, "<A : peer config add message\n" );

					IKE_PEER ike_peer;
					if( !ikei->recv_msg_peer( &ike_peer ) )
						break;

					//
					// create new peer
					//

					peer = new IDB_PEER( &ike_peer );

					//
					// add new peer
					//

					if( !peer->add( true ) )
					{
						log.txt( LLOG_ERROR, "!! : unable to add peer object\n" );

						delete peer;

						ikei->send_msg_result( IKEI_FAILED );

						break;
					}

					//
					// determine local tunnel addresses
					//

					IKE_SADDR saddr_l;

					find_addr_l(
						peer->saddr,
						saddr_l,
						500 );

					//
					// create new tunnel
					//

					tunnel = new IDB_TUNNEL( peer, &saddr_l, &peer->saddr );

					//
					// add new tunnel
					//

					if( !tunnel->add( true ) )
					{
						log.txt( LLOG_ERROR, "!! : unable to add tunnel object\n" );

						delete tunnel;

						ikei->send_msg_result( IKEI_FAILED );

						break;
					}

					ikei->send_msg_result( IKEI_OK );

					break;
				}

				//
				// proposal config message
				//

				case IKEI_MSGID_PROPOSAL:
				{
					log.txt( LLOG_INFO, "<A : proposal config message\n" );

					IKE_PROPOSAL proposal;
					if( !ikei->recv_msg_proposal( &proposal ) )
						break;

					if( !peer->prop_list.add( &proposal, true ) )
					{
						log.txt( LLOG_ERROR, "!! : unable to add peer proposal\n" );

						tunnel->close = TERM_CLIENT;
						ikei->send_msg_result( IKEI_FAILED );

						break;
					}

					ikei->send_msg_result( IKEI_OK );

					break;
				}

				//
				// client config message
				//

				case IKEI_MSGID_CLIENT:
				{
					log.txt( LLOG_INFO, "<A : client config message\n" );

					IKE_XCONF xconf;
					if( !ikei->recv_msg_client( &xconf ) )
						break;

					tunnel->xconf = xconf;
					ikei->send_msg_result( IKEI_OK );

					break;
				}

				//
				// remote id message
				//

				case IKEI_MSGID_NETWORK:
				{
					log.txt( LLOG_INFO, "<A : remote resource message\n" );

					IKE_PH2ID ph2id;
					memset( &ph2id, 0, sizeof( ph2id ) );

					long type;

					if( !ikei->recv_msg_network( &ph2id, &type ) )
						break;

					switch( type )
					{
						case UNITY_SPLIT_INCLUDE:
							tunnel->idlist_incl.add( ph2id );
							break;

						case UNITY_SPLIT_EXCLUDE:
							tunnel->idlist_excl.add( ph2id );
							break;
					}

					ikei->send_msg_result( IKEI_OK );

					break;
				}

				//
				// config string message
				//

				case IKEI_MSGID_CFGSTR:
				{
					long type;

					if( !ikei->recv_msg_cfgstr( &type, text, &size ) )
						break;

					text[ size ] = 0;

					switch( type )
					{
						//
						// xauth username
						//

						case CFGSTR_CRED_XAUTH_USER:
						{
							log.txt( LLOG_INFO, "<A : xauth username message\n" );

							tunnel->xauth.user.set( text, size );
							ikei->send_msg_result( IKEI_OK );

							break;
						}

						//
						// xauth password
						//

						case CFGSTR_CRED_XAUTH_PASS:
						{
							log.txt( LLOG_INFO, "<A : xauth password message\n" );

							tunnel->xauth.pass.set( text, size );
							ikei->send_msg_result( IKEI_OK );

							break;
						}

						//
						// preshared key
						//

						case CFGSTR_CRED_PSK:
						{
							log.txt( LLOG_INFO, "<A : preshared key message\n" );

							tunnel->peer->psk.set( text, size );
							ikei->send_msg_result( IKEI_OK );

							break;
						}

						//
						// preshared key
						//

						case CFGSTR_CRED_FILE_PASS:
						{
							log.txt( LLOG_INFO, "<A : file password\n" );

							tunnel->peer->fpass.set( text, size );
							ikei->send_msg_result( IKEI_OK );

							break;
						}

						//
						// remote certificate
						//

						case CFGSTR_CRED_RSA_RCRT:
						{
							log.txt( LLOG_INFO, "<A : remote cert \'%s\' message\n", text );

							long loaded = cert_load( tunnel->peer->cert_r, text, true, tunnel->peer->fpass );

							switch( loaded )
							{
								case FILE_OK:
									ikei->send_msg_result( IKEI_OK );
									log.txt( LLOG_DEBUG, "ii : \'%s\' loaded\n", text );
									break;

								case FILE_PATH:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, invalid path\n", text );
									ikei->send_msg_result( IKEI_FAILED );
									tunnel->close = TERM_CLIENT;
									break;

								case FILE_FAIL:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, requesting password\n", text );
									ikei->send_msg_result( IKEI_PASSWD );
									break;
							}

							break;
						}

						//
						// local certificate
						//

						case CFGSTR_CRED_RSA_LCRT:
						{
							log.txt( LLOG_INFO, "<A : local cert \'%s\' message\n", text );

							long loaded = cert_load( tunnel->peer->cert_l, text, false, tunnel->peer->fpass );

							switch( loaded )
							{
								case FILE_OK:
									ikei->send_msg_result( IKEI_OK );
									log.txt( LLOG_DEBUG, "ii : \'%s\' loaded\n", text );
									break;

								case FILE_PATH:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, invalid path\n", text );
									ikei->send_msg_result( IKEI_FAILED );
									tunnel->close = TERM_CLIENT;
									break;

								case FILE_FAIL:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, requesting password\n", text );
									ikei->send_msg_result( IKEI_PASSWD );
									break;
							}

							break;
						}

						//
						// local private key
						//

						case CFGSTR_CRED_RSA_LKEY:
						{
							log.txt( LLOG_INFO, "<A : local key \'%s\' message\n", text );

							long loaded = prvkey_rsa_load( &tunnel->peer->key, text, tunnel->peer->fpass );

							switch( loaded )
							{
								case FILE_OK:
									ikei->send_msg_result( IKEI_OK );
									log.txt( LLOG_DEBUG, "ii : \'%s\' loaded\n", text );
									break;

								case FILE_PATH:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, invalid path\n", text );
									ikei->send_msg_result( IKEI_FAILED );
									tunnel->close = TERM_CLIENT;
									break;

								case FILE_FAIL:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, requesting password\n", text );
									ikei->send_msg_result( IKEI_PASSWD );
									break;
							}

							break;
						}

						//
						// local identity data
						//

						case CFGSTR_CRED_LID:
						{
							log.txt( LLOG_INFO, "<A : local id \'%s\' message\n", text );

							tunnel->peer->iddata_l.set( text, size );
							ikei->send_msg_result( IKEI_OK );

							break;
						}

						//
						// remote identity data
						//

						case CFGSTR_CRED_RID:
						{
							log.txt( LLOG_INFO, "<A : remote id \'%s\' message\n", text );

							tunnel->peer->iddata_r.set( text, size );
							ikei->send_msg_result( IKEI_OK );

							break;
						}

						//
						// split domain
						//

						case CFGSTR_SPLIT_DOMAIN:
						{
							log.txt( LLOG_INFO, "<A : split dns \'%s\' message\n", text );

							BDATA suffix;
							suffix.set( text, size + 1 );
							tunnel->dlist.add( suffix );

							ikei->send_msg_result( IKEI_OK );

							break;
						}
					}

					break;
				}

				//
				// enable tunnel message
				//

				case IKEI_MSGID_ENABLE:
				{
					long enable;

					if( !ikei->recv_msg_enable( &enable ) )
						break;

					if( enable )
					{
						log.txt( LLOG_INFO, "<A : peer tunnel enable message\n" );

						//
						// if the tunnel peer definition states
						// that we are to act as a client, create
						// a new phase1 sa and add it to our list
						//

						if( ( tunnel->peer->contact == IPSEC_CONTACT_CLIENT ) ||
							( tunnel->peer->contact == IPSEC_CONTACT_INIT ) ||
							( tunnel->peer->contact == IPSEC_CONTACT_BOTH ) )
						{
							IDB_PH1 * ph1 = new IDB_PH1( tunnel, true, NULL );
							ph1->add( true );
							process_phase1_send( ph1 );
							ph1->dec( true );
						}

						if( tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
						{
							//
							// configure our private tunnel endpoint
							//

							if( tunnel->xconf.opts & IPSEC_OPTS_ADDR )
							{
								//
								// if we require a virutal adapter,
								// create one now as the startup
								// time can be long if a new device
								// instance needs to be created
								//

								if( !vnet_get( &adapter ) )
								{
									log.txt( LLOG_ERROR, "ii : unable to create vnet adapter ...\n" );
									tunnel->close = TERM_CLIENT;

									enable = false;
								}
							}
							else
							{
								//
								// if we are using a public adapter,
								// set our client info to match the
								// selected interface
								//

								tunnel->xconf.addr = tunnel->saddr_l.saddr4.sin_addr;
								tunnel->xconf.mask.s_addr = 0xffffffff;
							}

						}

						ikei->send_msg_enable( true );
					}
					else
					{
						log.txt( LLOG_INFO, "<A : peer tunnel disable message\n" );

						tunnel->close = TERM_USER_CLOSE;

						ikei->send_msg_enable( false );
					}

					break;
				}

				default:

					log.txt( LLOG_ERROR, "!! : message type is invalid ( %u )\n", msg.type );
			}
		}

		//
		// tunnel configuration steps
		//

		if( tunnel != NULL )
		{
			//
			// start client receive thread when ready
			//

			if( !( tunnel->close ) &&
				 ( tunnel->state & TSTATE_RECV_CONFIG ) &&
				!( tunnel->state & TSTATE_VNET_ENABLE ) )
			{
				//
				// if there is a banner, show it now
				//

				if( tunnel->banner.size() )
					ikei->send_msg_status(
					STATUS_BANNER,
					( char * ) tunnel->banner.buff() );

				//
				// make sure we have a valid vnet
				// address and netmask
				//

				if( !tunnel->xconf.addr.s_addr )
				{
					log.txt( LLOG_ERROR, "!! : invalid private address\n" );
					ikei->send_msg_status( STATUS_FAIL, "invalid private address or netmask\n" );
					tunnel->close = TERM_CLIENT;
					break;
				}

				if( !tunnel->xconf.mask.s_addr )
				{
					log.txt( LLOG_ERROR, "!! : invalid private netmask, defaulting to class c\n" );
					tunnel->xconf.mask.s_addr = inet_addr( "255.255.255.0" );
				}

				//
				// disable split dns if the domain
				// list has no elements
				//

				if( !tunnel->dlist.count() )
					tunnel->xconf.opts &= ~IPSEC_OPTS_SPLITDNS;

				//
				// setup client parameters
				//

				client_setup( adapter, tunnel );
				ikei->send_msg_status( STATUS_INFO, "network device configured\n" );

				//
				// generate a policy list now
				//

				policy_list_create( tunnel, true );

				//
				// setup dns transparent proxy
				//

#ifdef OPT_DTP

				if( tunnel->xconf.opts & IPSEC_OPTS_SPLITDNS )
					dnsproxy_setup( dtpi, tunnel );

#endif

				//
				// tunnel is enabled
				//

				ikei->send_msg_status( STATUS_ENABLED, "tunnel enabled\n" );

				tunnel->state |= TSTATE_VNET_ENABLE;
			}

			//
			// check tunnel status and send
			// message once every second
			//

			if( !( tunnel->close ) &&
			     ( tunnel->state & TSTATE_VNET_ENABLE ) )
			{
				if( stattick < time( NULL ) )
				{
					ikei->send_msg_stats( &tunnel->stats );

					stattick = time( NULL );
				}
			}
		}
	}

	//
	// flush our private pcap dump files
	//

	if( dump_decrypt )
		pcap_decrypt.flush();

	//
	// perform tunnel cleanup steps
	//

	if( tunnel != NULL )
	{
		//
		// cleaup our security policy lists
		// ( caller must hold the sdb lock )
		//

		iked.lock_sdb.lock();

		if( tunnel->peer->plcy_mode != POLICY_MODE_DISABLE )
			iked.policy_list_remove( tunnel, true );

		if( tunnel->peer->xconf_mode == CONFIG_MODE_DHCP )
			iked.socket_dhcp_remove( tunnel );

		iked.lock_sdb.unlock();

		//
		// cleanup client settings
		//

		client_cleanup( adapter, tunnel );

		//
		// if we were using a virutal adapter,
		// perform some addition cleanup
		//

		if( tunnel->xconf.opts & IPSEC_OPTS_ADDR )
		{
			//
			// disable the adapter
			//

			if( adapter != NULL )
				vnet_rel( adapter );
		}

		//
		// mark all tunnel refrences for deletion
		//

		tunnel->end( true );

		//
		// report reason for closing the tunnel
		//

		switch( tunnel->close )
		{
			//
			// client specific reason with
			// a notification already sent
			//
			case TERM_CLIENT:
				break;

			//
			// network communication error
			//
			case TERM_SOCKET:
				ikei->send_msg_status( STATUS_FAIL, "network unavailable\n" );
				break;

			//
			// phase1 sa expired
			//
			case TERM_EXPIRE:
				ikei->send_msg_status( STATUS_WARN, "session has expired\n" );
				break;

			//
			// an invalid message was received
			//
			case TERM_BADMSG:
				ikei->send_msg_status( STATUS_FAIL, "invalid message from peer\n" );
				break;

			//
			// user authentication error
			//
			case TERM_USER_AUTH:
				ikei->send_msg_status( STATUS_FAIL, "user authentication error\n" );
				break;

			//
			// peer authentication error
			//
			case TERM_PEER_AUTH:
				ikei->send_msg_status( STATUS_FAIL, "peer authentication error\n" );
				break;

			//
			// terminated by peer
			//
			case TERM_PEER_CLOSE:
				ikei->send_msg_status( STATUS_FAIL, "session terminated by gateway\n" );
				break;

			//
			// terminated by user
			//
			case TERM_USER_CLOSE:
				ikei->send_msg_status( STATUS_WARN, "session terminated by user\n" );
				break;

			//
			// peer unresponsive
			//
			case TERM_PEER_DEAD:
				ikei->send_msg_status( STATUS_FAIL, "gateway not responding\n" );
				break;

			//
			// dhcp unresponsive
			//
			case TERM_PEER_DHCP:
				ikei->send_msg_status( STATUS_FAIL, "no response from dhcp server\n" );
				break;

			//
			// unknown
			//
			default:
				ikei->send_msg_status( STATUS_FAIL, "internal error occurred\n" );
				break;
		}

		//
		// flush our arp cache
		//

		iproute.flusharp( tunnel->saddr_l.saddr4.sin_addr );

		//
		// destroy the tunnel object
		//

		tunnel->lstate |= LSTATE_DELETE;
		tunnel->dec( true );

		//
		// cleanup
		//

		peer->lstate |= LSTATE_DELETE;
		peer->dec( true );
	}

	//
	// cleanup dns transparent proxy
	//

#ifdef OPT_DTP

	if( tunnel->xconf.opts & IPSEC_OPTS_SPLITDNS )
		dnsproxy_cleanup( dtpi );

#endif

	//
	// close the client interface
	//

	ikei->send_msg_status( STATUS_DISABLED, "tunnel disabled\n" );
	ikei->detach();

	log.txt( LLOG_INFO, "ii : admin process thread exit ...\n" );

	return true;
}

void _IKED::attach_ike_admin()
{
	IKEI * ikei = ikes.inbound();

	if( ikei != NULL )
		ith_admin.exec( ikei );
}
