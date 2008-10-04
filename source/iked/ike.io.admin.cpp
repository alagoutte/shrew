
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
// ike client io thread
//

long ITH_IKES::func( void * arg )
{
	IKED * iked = ( IKED * ) arg;
	return iked->loop_ipc_server();
}

long _IKED::loop_ipc_server()
{
	//
	// begin admin thread
	//

	loop_ref_inc( "ipc server" );

	while( true )
	{
		IKEI * ikei;
		long result = ikes.inbound( &ikei );

		switch( result )
		{
			case IPCERR_OK:
				ith_ikec.exec( ikei );
				continue;

			case IPCERR_NODATA:
				continue;
		}

		break;
	}

	loop_ref_dec( "ipc server" );

	return true;
}

long ITH_IKEC::func( void * arg )
{
	IKEI * ikei = ( IKEI * ) arg;
	long result = iked.loop_ipc_client( ikei );
	return result;
}

long _IKED::loop_ipc_client( IKEI * ikei )
{
	loop_ref_inc( "ipc client" );

	IDB_PEER *		peer = NULL;
	IDB_TUNNEL *	tunnel = NULL;
	VNET_ADAPTER *	adapter = NULL;

#ifdef OPT_DTP
	DTPI dtpi;
#endif

	//
	// enter client ctrl loop
	//

	IKEI_MSG msg;

	bool failure = false;

	while( !failure )
	{
		long result;

		//
		// check for tunnel close
		//

		if( tunnel != NULL )
			if( tunnel->close )
				break;

		//
		// get the next message
		//

		result = ikei->recv_message( msg );

		if( result == IPCERR_CLOSED )
			break;

		if( result == IPCERR_NODATA )
			continue;

		if( result == IPCERR_OK )
		{
			switch( msg.header.type )
			{
				//
				// peer config add message
				//

				case IKEI_MSGID_PEER:
				{
					log.txt( LLOG_INFO, "<A : peer config add message\n" );

					IKE_PEER ike_peer;
					if( msg.get_peer( &ike_peer ) != IPCERR_OK )
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

						msg.set_result( IKEI_RESULT_FAILED );
						ikei->send_message( msg );

						failure = true;

						break;
					}

					//
					// determine local tunnel addresses
					//

					IKE_SADDR saddr_l;

					if( !find_addr_l(
							peer->saddr,
							saddr_l,
							500 ) )
					{
						log.txt( LLOG_ERROR, "!! : no route to host\n" );

						delete tunnel;

						msg.set_result( IKEI_RESULT_FAILED );
						ikei->send_message( msg );

						failure = true;

						break;
					}

					//
					// create new tunnel
					//

					tunnel = new IDB_TUNNEL( peer, &saddr_l, &peer->saddr );
					tunnel->ikei = ikei;

					//
					// add new tunnel
					//

					if( !tunnel->add( true ) )
					{
						log.txt( LLOG_ERROR, "!! : unable to add tunnel object\n" );

						delete tunnel;

						msg.set_result( IKEI_RESULT_FAILED );
						ikei->send_message( msg );

						tunnel->close = XCH_FAILED_CLIENT;

						break;
					}

					msg.set_result( IKEI_RESULT_OK );
					ikei->send_message( msg );

					break;
				}

				//
				// proposal config message
				//

				case IKEI_MSGID_PROPOSAL:
				{
					log.txt( LLOG_INFO, "<A : proposal config message\n" );

					IKE_PROPOSAL proposal;
					if( msg.get_proposal( &proposal ) != IPCERR_OK )
						break;

					//
					// fortigate hack
					//

//					if( ( proposal.auth_id == XAUTH_AUTH_INIT_PSK ) &&
//						( peer->xconf_mode == CONFIG_MODE_DHCP ) )
//						proposal.auth_id = IKE_AUTH_PRESHARED_KEY;

					if( !peer->proposals.add( &proposal, true ) )
					{
						log.txt( LLOG_ERROR, "!! : unable to add peer proposal\n" );

						msg.set_result( IKEI_RESULT_FAILED );
						ikei->send_message( msg );

						tunnel->close = XCH_FAILED_CLIENT;

						break;
					}

					msg.set_result( IKEI_RESULT_OK );
					ikei->send_message( msg );

					break;
				}

				//
				// client config message
				//

				case IKEI_MSGID_CLIENT:
				{
					log.txt( LLOG_INFO, "<A : client config message\n" );

					IKE_XCONF xconf;
					if( msg.get_client( &xconf ) != IPCERR_OK )
						break;

					tunnel->xconf = xconf;

					msg.set_result( IKEI_RESULT_OK );
					ikei->send_message( msg );

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

					if( msg.get_network( &type, &ph2id ) != IPCERR_OK )
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

					msg.set_result( IKEI_RESULT_OK );
					ikei->send_message( msg );

					break;
				}

				//
				// config string message
				//

				case IKEI_MSGID_CFGSTR:
				{
					BDATA	text;
					long	type;

					if( msg.get_cfgstr( &type, &text ) != IPCERR_OK )
						break;

					switch( type )
					{
						//
						// xauth username
						//

						case CFGSTR_CRED_XAUTH_USER:
						{
							log.txt( LLOG_INFO, "<A : xauth username message\n" );

							tunnel->xauth.user = text;

							msg.set_result( IKEI_RESULT_OK );
							ikei->send_message( msg );

							break;
						}

						//
						// xauth password
						//

						case CFGSTR_CRED_XAUTH_PASS:
						{
							log.txt( LLOG_INFO, "<A : xauth password message\n" );

							tunnel->xauth.pass = text;

							msg.set_result( IKEI_RESULT_OK );
							ikei->send_message( msg );

							break;
						}

						//
						// preshared key
						//

						case CFGSTR_CRED_PSK:
						{
							log.txt( LLOG_INFO, "<A : preshared key message\n" );

							tunnel->peer->psk = text;

							msg.set_result( IKEI_RESULT_OK );
							ikei->send_message( msg );

							break;
						}

						//
						// preshared key
						//

						case CFGSTR_CRED_FILE_PASS:
						{
							log.txt( LLOG_INFO, "<A : file password\n" );

							tunnel->peer->fpass = text;

							msg.set_result( IKEI_RESULT_OK );
							ikei->send_message( msg );

							break;
						}

						//
						// remote certificate
						//

						case CFGSTR_CRED_RSA_RCRT:
						{
							text.add( "", 1 );

							log.txt( LLOG_INFO, "<A : remote cert \'%s\' message\n", text.text() );

							long loaded = cert_load( tunnel->peer->cert_r, text.text(), true, tunnel->peer->fpass );

							switch( loaded )
							{
								case FILE_OK:
									msg.set_result( IKEI_RESULT_OK );
									ikei->send_message( msg );
									log.txt( LLOG_DEBUG, "ii : \'%s\' loaded\n", text.text() );
									break;

								case FILE_PATH:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, invalid path\n", text.text() );
									msg.set_result( IKEI_RESULT_FAILED );
									ikei->send_message( msg );
									tunnel->close = XCH_FAILED_CLIENT;
									break;

								case FILE_FAIL:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, requesting password\n", text.text() );
									msg.set_result( IKEI_RESULT_PASSWD );
									ikei->send_message( msg );
									break;
							}

							break;
						}

						//
						// local certificate
						//

						case CFGSTR_CRED_RSA_LCRT:
						{
							text.add( "", 1 );

							log.txt( LLOG_INFO, "<A : local cert \'%s\' message\n", text.text() );

							long loaded = cert_load( tunnel->peer->cert_l, text.text(), false, tunnel->peer->fpass );

							switch( loaded )
							{
								case FILE_OK:
									msg.set_result( IKEI_RESULT_OK );
									ikei->send_message( msg );
									log.txt( LLOG_DEBUG, "ii : \'%s\' loaded\n", text.text() );
									break;

								case FILE_PATH:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, invalid path\n", text.text() );
									msg.set_result( IKEI_RESULT_FAILED );
									ikei->send_message( msg );
									tunnel->close = XCH_FAILED_CLIENT;
									break;

								case FILE_FAIL:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, requesting password\n", text.text() );
									msg.set_result( IKEI_RESULT_PASSWD );
									ikei->send_message( msg );
									break;
							}

							break;
						}

						//
						// local private key
						//

						case CFGSTR_CRED_RSA_LKEY:
						{
							text.add( "", 1 );

							log.txt( LLOG_INFO, "<A : local key \'%s\' message\n", text.text() );

							long loaded = prvkey_rsa_load( &tunnel->peer->key, text.text(), tunnel->peer->fpass );

							switch( loaded )
							{
								case FILE_OK:
									msg.set_result( IKEI_RESULT_OK );
									ikei->send_message( msg );
									log.txt( LLOG_DEBUG, "ii : \'%s\' loaded\n", text.text() );
									break;

								case FILE_PATH:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, invalid path\n", text.text() );
									msg.set_result( IKEI_RESULT_FAILED );
									ikei->send_message( msg );
									tunnel->close = XCH_FAILED_CLIENT;
									break;

								case FILE_FAIL:
									log.txt( LLOG_ERROR, "!! : \'%s\' load failed, requesting password\n", text.text() );
									msg.set_result( IKEI_RESULT_PASSWD );
									ikei->send_message( msg );
									break;
							}

							break;
						}

						//
						// local identity data
						//

						case CFGSTR_CRED_LID:
						{
							BDATA idval;
							idval = text;
							idval.add( "", 1 );

							log.txt( LLOG_INFO, "<A : local id \'%s\' message\n", idval.text() );

							tunnel->peer->iddata_l = text;

							msg.set_result( IKEI_RESULT_OK );
							ikei->send_message( msg );

							break;
						}

						//
						// remote identity data
						//

						case CFGSTR_CRED_RID:
						{
							BDATA idval;
							idval = text;
							idval.add( "", 1 );

							log.txt( LLOG_INFO, "<A : remote id \'%s\' message\n", idval.text() );

							tunnel->peer->iddata_r = text;

							msg.set_result( IKEI_RESULT_OK );
							ikei->send_message( msg );

							break;
						}

						//
						// split domain
						//

						case CFGSTR_SPLIT_DOMAIN:
						{
							text.add( "", 1 );

							log.txt( LLOG_INFO, "<A : split dns \'%s\' message\n", text.text() );

							tunnel->domains.add( text );

							msg.set_result( IKEI_RESULT_OK );
							ikei->send_message( msg );

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

					if( msg.get_enable( &enable ) != IPCERR_OK )
						break;

					if( enable )
					{
						log.txt( LLOG_INFO, "<A : peer tunnel enable message\n" );

						//
						// if the tunnel peer definition states
						// that we are to act as a client, create
						// a new phase1 sa and add it to our list
						//

						if( tunnel->peer->contact == IPSEC_CONTACT_CLIENT )
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
									tunnel->close = XCH_FAILED_ADAPTER;

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

							//
							// add the statistics event
							//

							tunnel->inc( true );
							tunnel->event_stats.delay = 1000;
							ith_timer.add( &tunnel->event_stats );
						}
					}
					else
					{
						log.txt( LLOG_INFO, "<A : peer tunnel disable message\n" );
						tunnel->close = XCH_FAILED_USERREQ;
					}

					if( enable )
					{
						msg.set_enable( true );
						ikei->send_message( msg );
					}
					else
					{
						msg.set_enable( false );
						ikei->send_message( msg );
					}

					break;
				}

				default:
					log.txt( LLOG_ERROR, "!! : message type is invalid ( %u )\n", msg.header.type );
					tunnel->close = XCH_FAILED_CLIENT;
					break;
			}

			continue;
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
				 ( tunnel->tstate & TSTATE_VNET_CONFIG ) &&
				!( tunnel->tstate & TSTATE_VNET_ENABLE ) )
			{
				//
				// if there is a banner, show it now
				//

				if( tunnel->banner.size() )
				{
					msg.set_status( STATUS_BANNER, &tunnel->banner );
					ikei->send_message( msg );
				}

				//
				// make sure we have a valid vnet
				// address and netmask
				//

				if( !tunnel->xconf.addr.s_addr )
				{
					log.txt( LLOG_ERROR, "!! : invalid private address\n" );
					tunnel->close = XCH_FAILED_ADAPTER;
					break;
				}

				if( !tunnel->xconf.mask.s_addr )
				{
					log.txt( LLOG_ERROR, "!! : invalid private netmask, defaulting to class c\n" );
					tunnel->xconf.mask.s_addr = inet_addr( "255.255.255.0" );
				}

				//
				// setup client parameters
				//

				client_setup( adapter, tunnel );

				msg.set_status( STATUS_INFO, "network device configured\n" );
				ikei->send_message( msg );

				//
				// generate a policy list now
				//

				policy_list_create( tunnel, true );

				//
				// setup dns transparent proxy
				//

#ifdef OPT_DTP
				dnsproxy_setup( dtpi, tunnel );
#endif

				//
				// tunnel is enabled
				//

				msg.set_status( STATUS_ENABLED, "tunnel enabled\n" );
				ikei->send_message( msg );

				tunnel->tstate |= TSTATE_VNET_ENABLE;
			}
		}
	}

	//
	// flush our private pcap dump files
	//

	if( dump_decrypt )
		pcap_decrypt.flush();

	//
	// perform tunnel cleanup
	//

	if( tunnel == NULL )
	{
		//
		// peer or tunnel setup failed
		//

		msg.set_status( STATUS_FAIL, "client configuration error\n" );
		ikei->send_message( msg );
	}
	else
	{
		//
		// cleaup our security policy lists
		// ( caller must hold the sdb lock )
		//

		lock_idb.lock();

		if( tunnel->peer->plcy_mode != POLICY_MODE_DISABLE )
			iked.policy_list_remove( tunnel, true );

		if( tunnel->peer->xconf_mode == CONFIG_MODE_DHCP )
			iked.socket_dhcp_remove( tunnel );

		lock_idb.unlock();

		//
		// cleanup client settings
		//

		if( tunnel->tstate & TSTATE_VNET_ENABLE )
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
		// report reason for closing the tunnel
		//

		switch( tunnel->close )
		{
			//
			// client message error
			//
			case XCH_FAILED_CLIENT:
				msg.set_status( STATUS_FAIL, "client configuration error\n" );
				break;

			//
			// network communication error
			//
			case XCH_FAILED_NETWORK:
				msg.set_status( STATUS_FAIL, "network unavailable\n" );
				break;

			//
			// adapter configuration error
			//
			case XCH_FAILED_ADAPTER:
				msg.set_status( STATUS_FAIL, "adapter configuration failed\n" );
				break;

			//
			// network timeout occurred
			//
			case XCH_FAILED_TIMEOUT:
				msg.set_status( STATUS_FAIL, "negotiation timout occurred\n" );
				break;

			//
			// terminated by user
			//
			case XCH_FAILED_USERREQ:
				msg.set_status( STATUS_WARN, "session terminated by user\n" );
				break;

			//
			// an invalid message was received
			//
			case XCH_FAILED_MSG_FORMAT:
			case XCH_FAILED_MSG_CRYPTO:
			case XCH_FAILED_MSG_AUTH:
				msg.set_status( STATUS_FAIL, "invalid message from gateway\n" );
				break;

			//
			// user authentication error
			//
			case XCH_FAILED_USER_AUTH:
				msg.set_status( STATUS_FAIL, "user authentication error\n" );
				break;

			//
			// peer authentication error
			//
			case XCH_FAILED_PEER_AUTH:
				msg.set_status( STATUS_FAIL, "gateway authentication error\n" );
				break;

			//
			// peer unresponsive
			//
			case XCH_FAILED_PEER_DEAD:
				msg.set_status( STATUS_FAIL, "gateway is not responding\n" );
				break;

			//
			// terminated by peer
			//
			case XCH_FAILED_PEER_DELETE:
				msg.set_status( STATUS_FAIL, "session terminated by gateway\n" );
				break;

			//
			// dhcp unresponsive
			//
			case XCH_FAILED_IKECONFIG:
				msg.set_status( STATUS_FAIL, "no config response from gateway\n" );
				break;

			//
			// dhcp unresponsive
			//
			case XCH_FAILED_DHCPCONFIG:
				msg.set_status( STATUS_FAIL, "no dhcp response from gateway\n" );
				break;

			//
			// unknown
			//
			default:
				msg.set_status( STATUS_FAIL, "internal error occurred\n" );
				break;
		}

		ikei->send_message( msg );

		//
		// flush our arp cache
		//

		iproute.flusharp( tunnel->saddr_l.saddr4.sin_addr );

		//
		// destroy the tunnel object
		//

		tunnel->dec( true, true );
	}

	//
	// perform peer cleanup
	//

	if( peer != NULL )
		peer->dec( true, true );

	//
	// cleanup dns transparent proxy
	//

#ifdef OPT_DTP
		dnsproxy_cleanup( dtpi );
#endif

	//
	// close the client interface
	//

	msg.set_status( STATUS_DISABLED, "tunnel disabled\n" );
	ikei->send_message( msg );
	ikei->detach();

	delete ikei;

	loop_ref_dec( "ipc client" );

	return true;
}
