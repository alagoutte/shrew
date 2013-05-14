
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

long ITH_IKES::iked_func( void * arg )
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

long ITH_IKEC::iked_func( void * arg )
{
	IKEI * ikei = ( IKEI * ) arg;
	long result = iked.loop_ipc_client( ikei );
	return result;
}

long _IKED::loop_ipc_client( IKEI * ikei )
{
	loop_ref_inc( "ipc client" );

	//
	// temporary configuration data
	//

	IKE_XCONF ike_xconf;
	memset( &ike_xconf, 0, sizeof( ike_xconf ) );

	IKE_PEER ike_peer;
	memset( &ike_peer, 0, sizeof( ike_peer ) );

	BDATA xuser;
	BDATA xpass;
	BDATA psk;
	BDATA cert_r;
	BDATA cert_l;
	BDATA cert_k;
	BDATA iddata_r;
	BDATA iddata_l;

	IDB_LIST_PROPOSAL	proposals;
	IDB_LIST_PH2ID		idlist_incl;
	IDB_LIST_PH2ID		idlist_excl;
	IDB_LIST_DOMAIN		domains;

	IKE_SADDR saddr_l;
	BDATA fpass;

	//
	// db configuration objects
	//

	IDB_PEER *		peer = NULL;
	IDB_TUNNEL *	tunnel = NULL;

	//
	// enter client ctrl loop
	//

	IKEI_MSG msg;

	bool detach = false;
	bool suspended = false;

	while( !detach )
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
			//
			// set default result
			//

			result = IKEI_RESULT_FAILED;

			//
			// handle message by type
			//

			switch( msg.header.type )
			{
				//
				// client config message
				//

				case IKEI_MSGID_CLIENT:
				{
					log.txt( LLOG_INFO, "<A : client config message\n" );

					if( msg.get_client( &ike_xconf ) != IPCERR_OK )
					{
						log.txt( LLOG_ERROR, "!! : failed to read client config message\n" );
						break;
					}

					result = IKEI_RESULT_OK;
					break;
				}

				//
				// peer config message
				//

				case IKEI_MSGID_PEER:
				{
					log.txt( LLOG_INFO, "<A : peer config add message\n" );

					if( msg.get_peer( &ike_peer ) != IPCERR_OK )
					{
						log.txt( LLOG_ERROR, "!! : failed to read peer config message\n" );
						break;
					}

					result = IKEI_RESULT_OK;
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
					{
						log.txt( LLOG_ERROR, "!! : failed to read proposal config message\n" );
						break;
					}

					if( !proposals.add( &proposal, true ) )
					{
						log.txt( LLOG_ERROR, "!! : unable to add proposal\n" );
						break;
					}

					result = IKEI_RESULT_OK;
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
					{
						log.txt( LLOG_ERROR, "!! : failed to read remote resource message\n" );
						break;
					}

					bool added = false;

					if( type == UNITY_SPLIT_INCLUDE )
						added = idlist_incl.add( ph2id );

					if( type == UNITY_SPLIT_EXCLUDE )
						added = idlist_excl.add( ph2id );

					if( !added )
					{
						log.txt( LLOG_ERROR, "!! : unable to add network\n" );
						break;
					}

					result = IKEI_RESULT_OK;
					break;
				}

				//
				// config string message
				//

				case IKEI_MSGID_CFGSTR:
				{
					BDATA	data;
					long	type;

					if( msg.get_cfgstr( &type, &data ) != IPCERR_OK )
					{
						log.txt( LLOG_ERROR, "!! : failed to read config string message\n" );
						break;
					}

					switch( type )
					{
						//
						// xauth username
						//

						case CFGSTR_CRED_XAUTH_USER:
						{
							log.txt( LLOG_INFO, "<A : xauth username message\n" );

							xuser = data;

							result = IKEI_RESULT_OK;
							break;
						}

						//
						// xauth password
						//

						case CFGSTR_CRED_XAUTH_PASS:
						{
							log.txt( LLOG_INFO, "<A : xauth password message\n" );

							xpass = data;

							result = IKEI_RESULT_OK;
							break;
						}

						//
						// preshared key
						//

						case CFGSTR_CRED_PSK:
						{
							log.txt( LLOG_INFO, "<A : preshared key message\n" );

							psk = data;

							result = IKEI_RESULT_OK;
							break;
						}

						//
						// preshared key
						//

						case CFGSTR_CRED_FILE_PASS:
						{
							log.txt( LLOG_INFO, "<A : file password\n" );

							fpass = data;
							fpass.add( "", 0 );

							result = IKEI_RESULT_OK;
							break;
						}

						//
						// remote certificate
						//

						case CFGSTR_CRED_RSA_RCRT:
						{
							log.txt( LLOG_INFO, "<A : remote certificate data message\n" );

							switch( cert_load( cert_r, data, true, fpass ) )
							{
								case FILE_OK:
									log.txt( LLOG_DEBUG, "ii : remote certificate read complete ( %i bytes )\n", cert_r.size() );
									result = IKEI_RESULT_OK;
									break;

								case FILE_FAIL:
									log.txt( LLOG_ERROR, "!! : remote certificate read failed, requesting password\n" );
									result = IKEI_RESULT_PASSWD;
									break;
							}

							break;
						}

						//
						// local certificate
						//

						case CFGSTR_CRED_RSA_LCRT:
						{
							log.txt( LLOG_INFO, "<A : local certificate data message\n" );

							switch( cert_load( cert_l, data, false, fpass ) )
							{
								case FILE_OK:
									log.txt( LLOG_DEBUG, "ii : local certificate read complete ( %i bytes )\n", cert_l.size() );
									result = IKEI_RESULT_OK;
									break;

								case FILE_FAIL:
									log.txt( LLOG_ERROR, "!! : local certificate read failed, requesting password\n" );
									result = IKEI_RESULT_PASSWD;
									break;
							}

							break;
						}

						//
						// local private key
						//

						case CFGSTR_CRED_RSA_LKEY:
						{
							log.txt( LLOG_INFO, "<A : local key data message\n" );

							switch( prvkey_rsa_load( cert_k, data, fpass ) )
							{
								case FILE_OK:
									log.txt( LLOG_DEBUG, "ii : local key read complete ( %i bytes )\n", cert_k.size() );
									result = IKEI_RESULT_OK;
									break;

								case FILE_FAIL:
									log.txt( LLOG_ERROR, "!! : local key read failed, requesting password\n" );
									result = IKEI_RESULT_PASSWD;
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
							idval = data;
							idval.add( 0, 1 );

							log.txt( LLOG_INFO, "<A : local id \'%s\' message\n", idval.text() );

							iddata_l = data;

							result = IKEI_RESULT_OK;
							break;
						}

						//
						// remote identity data
						//

						case CFGSTR_CRED_RID:
						{
							BDATA idval;
							idval = data;
							idval.add( 0, 1 );

							log.txt( LLOG_INFO, "<A : remote id \'%s\' message\n", idval.text() );

							iddata_r = data;

							result = IKEI_RESULT_OK;
							break;
						}

						//
						// split domain
						//

						case CFGSTR_SPLIT_DOMAIN:
						{
							data.add( 0, 1 );

							log.txt( LLOG_INFO, "<A : split dns \'%s\' message\n", data.text() );

							domains.add( data );

							result = IKEI_RESULT_OK;
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
					{
						log.txt( LLOG_ERROR, "!! : failed to read tunnel enable message\n" );
						break;
					}

					if( enable )
					{
						log.txt( LLOG_INFO, "<A : peer tunnel enable message\n" );

						//
						// dns proxy init check
						//
#ifdef WIN32
						if( !dnsproxy_check( ikei ) )
						{
							detach = true;
							break;
						}
#endif
						//
						// create peer object
						//

						peer = new IDB_PEER( &ike_peer );
						if( peer == NULL )
						{
							log.txt( LLOG_ERROR, "!! : unable to create peer object\n" );
							detach = true;
							break;
						}

						peer->contact = IPSEC_CONTACT_CLIENT;
						peer->psk = psk;
						peer->cert_r = cert_r;
						peer->cert_l = cert_l;
						peer->cert_k = cert_k;
						peer->iddata_r = iddata_r;
						peer->iddata_l = iddata_l;

						psk.del();
						cert_l.del();
						cert_k.del();
						iddata_r.del();
						iddata_l.del();

						IKE_PROPOSAL * proposal;

						long index = 0;
						while( proposals.get( &proposal, index++ ) )
							peer->proposals.add( proposal, true );

						if( !peer->add( true ) )
						{
							log.txt( LLOG_ERROR, "!! : unable to add peer object\n" );
							detach = true;
							delete peer;
							peer = NULL;
							break;
						}

						//
						// determine local tunnel addresses
						//

						if( socket_lookup_addr(	peer->saddr, saddr_l ) != LIBIKE_OK )
						{
							log.txt( LLOG_ERROR, "!! : no route to host\n" );
							detach = true;
							break;
						}

						//
						// determine local socket port
						//

						if( socket_lookup_port( saddr_l, false ) != LIBIKE_OK )
						{
							log.txt( LLOG_ERROR, "!! : no socket for selected address\n" );
							detach = true;
							break;
						}

						//
						// create tunnel object
						//

						tunnel = new IDB_TUNNEL( peer, &ike_xconf, &saddr_l, &peer->saddr );
						if( tunnel == NULL )
						{
							log.txt( LLOG_ERROR, "!! : unable to create tunnel object\n" );
							detach = true;
							break;
						}

						tunnel->ikei = ikei;
						tunnel->xauth.user = xuser;
						tunnel->xauth.pass = xpass;

						xuser.del( true );
						xpass.del( true );

						IKE_PH2ID ph2id;

						index = 0;
						while( idlist_incl.get( ph2id, index++ ) )
							tunnel->idlist_incl.add( ph2id );

						index = 0;
						while( idlist_excl.get( ph2id, index++ ) )
							tunnel->idlist_excl.add( ph2id );

						BDATA domain;

						index = 0;
						while( domains.get( domain, index++ ) )
							tunnel->domains.add( domain );

						domain.del();

						if( !tunnel->add( true ) )
						{
							log.txt( LLOG_ERROR, "!! : unable to add tunnel object\n" );
							detach = true;
							delete tunnel;
							tunnel = NULL;
							break;
						}

						//
						// initiate communications with peer
						//

						IDB_PH1 * ph1 = new IDB_PH1( tunnel, true, NULL );
						ph1->add( true );
						process_phase1_send( ph1 );
						ph1->dec( true );

						msg.set_status( STATUS_CONNECTING, "tunnel connecting ...\n" );
						ikei->send_message( msg );
					}
					else
					{
						log.txt( LLOG_INFO, "<A : peer tunnel disable message\n" );

						if( tunnel != NULL )
							tunnel->close = XCH_FAILED_USERREQ;

						msg.set_status( STATUS_DISCONNECTING, "tunnel disconnecting ...\n" );
						ikei->send_message( msg );
					}

					break;
				}
#ifdef WIN32
				//
				// suspend tunnel message
				//

				case IKEI_MSGID_SUSPEND:
				{
					long suspend = 0;

					if( msg.get_suspend( &suspend ) != IPCERR_OK )
					{
						log.txt( LLOG_ERROR, "!! : failed to read tunnel suspend message\n" );
						break;
					}

					if( suspend )
					{
						iked.ith_timer.del( &tunnel->event_stats );

						log.txt( LLOG_DEBUG, "ii : suspended client control of tunnel\n" );
						tunnel->suspended = true;
						tunnel->ikei = NULL;
						tunnel->dec( true );
						suspended = true;
						detach = true;
					}
					else
					{
						if( !iked.idb_list_tunnel.find( true, &tunnel, NULL, NULL, false, true ) )
						{
							log.txt( LLOG_ERROR, "!! : failed to locate suspended tunnel\n" );
							detach = true;
							break;
						}

						log.txt( LLOG_DEBUG, "ii : resumed client control of tunnel\n" );
						peer = tunnel->peer;
						tunnel->suspended = false;
						tunnel->ikei = ikei;

						ith_timer.add( &tunnel->event_stats );
					}

					break;
				}
#endif
				default:
					log.txt( LLOG_ERROR, "!! : message type is invalid ( %u )\n", msg.header.type );
					if( tunnel != NULL )
						tunnel->close = XCH_FAILED_CLIENT;
					break;
			}

			//
			// send result message
			//

			msg.set_result( result );
			ikei->send_message( msg );

			continue;
		}

		//
		// tunnel configuration steps ( IPCERR_WAKEUP )
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
					log.txt( LLOG_ERROR, "!! : invalid private netmask, defaulting to 255.255.255.0\n" );
					tunnel->xconf.mask.s_addr = inet_addr( "255.255.255.0" );
				}

				//
				// setup client network parameters
				//

				if( !client_net_config( tunnel ) )
					break;

				msg.set_status( STATUS_INFO, "network device configured\n" );
				ikei->send_message( msg );

				//
				// generate a policy list now
				//

				policy_list_create( tunnel, true );

				//
				// setup client dns parameters
				//

				client_dns_config( tunnel );

				//
				// tunnel is enabled
				//

				msg.set_status( STATUS_CONNECTED, "tunnel connected\n" );
				ikei->send_message( msg );

				//
				// add the statistics event
				//

				tunnel->inc( true );
				tunnel->event_stats.delay = 1000;
				ith_timer.add( &tunnel->event_stats );

				tunnel->tstate |= TSTATE_VNET_ENABLE;
			}
		}
	}

	//
	// perform tunnel cleanup
	//

	if( tunnel == NULL )
	{
		//
		// tunnel configuration failed
		//

		msg.set_status( STATUS_FAIL, "tunnel configuration failed\n" );
		ikei->send_message( msg );
	}

	if( ( tunnel != NULL ) && !suspended )
	{
		//
		// revert client network parameters
		//

		client_dns_revert( tunnel );

		//
		// cleanup client settings
		//
		// NOTE : policy cleanup must be done here to
		// avoid route deletion failures from occuring
		// after a virtual adapter has been removed
		//

		lock_idb.lock();

		if( tunnel->peer->plcy_mode != POLICY_MODE_DISABLE )
			iked.policy_list_remove( tunnel, true );

		lock_idb.unlock();

		if( tunnel->peer->xconf_mode == CONFIG_MODE_DHCP )
			iked.socket_dhcp_remove( tunnel );

		//
		// revert client network parameters
		//

		client_net_revert( tunnel );

		//
		// flush our arp cache
		//

		iproute.flusharp( saddr_l.saddr4.sin_addr );

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
		// release the tunnel object
		//

		tunnel->dec( true, true );
		msg.set_status( STATUS_DISCONNECTED, "tunnel disconnected\n" );
	}

	//
	// perform peer cleanup
	//

	if( ( peer != NULL ) && !suspended )
	{
		peer->dec( true, true );
		msg.set_status( STATUS_DISCONNECTED, "peer removed\n" );
	}

	//
	// close the client interface
	//

	ikei->send_message( msg );
	ikei->detach();

	delete ikei;

	//
	// flush our private pcap dump files
	//

	if( dump_decrypt )
		pcap_decrypt.flush();

	loop_ref_dec( "ipc client" );

	return true;
}
