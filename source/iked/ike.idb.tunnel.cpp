
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

//==============================================================================
// tunnel events
//==============================================================================

bool _ITH_EVENT_TUNDHCP::func()
{
	//
	// check for tunnel close or
	// retry timeout
	//

	if( tunnel->close || ( retry > 6 ) )
	{
		tunnel->close = XCH_FAILED_DHCPCONFIG;
		tunnel->ikei->wakeup();
		tunnel->dec( true );

		return false;
	}

	//
	// check renew time
	//

	time_t current = time( NULL );

	if( current > renew )
		iked.process_dhcp_recv( tunnel );

	if( current > renew )
		iked.process_dhcp_send( tunnel );

	return true;
}

void _ITH_EVENT_TUNDPD::next()
{
	//
	// remove this event
	//

	if( iked.ith_timer.del( this ) )
	{
		//
		// reset the attempt counter
		//

		attempt = 0;

		//
		// readd this event
		//

		delay = tunnel->peer->dpd_delay * 1000;

		iked.ith_timer.add( this );

		char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];
		iked.text_addr( txtaddr_r, &tunnel->saddr_r, true );

		iked.log.txt( LLOG_DEBUG,
				"ii : next tunnel DPD request in %i secs for peer %s\n",
				tunnel->peer->dpd_delay,
				txtaddr_r );
	}
}

bool _ITH_EVENT_TUNDPD::func()
{
	//
	// check our attempt counter
	//

	if( attempt == tunnel->peer->dpd_retry )
	{
		char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];
		iked.text_addr( txtaddr_r, &tunnel->saddr_r, true );

		iked.log.txt( LLOG_ERROR,
				"!! : tunnel DPD timeout for peer %s\n",
				txtaddr_r );

		tunnel->close = XCH_FAILED_PEER_DEAD;
		tunnel->ikei->wakeup();
		tunnel->dec( true );

		return false;
	}

	//
	// locate mature phase1 handle
	//

	IDB_PH1 * ph1 = NULL;
	if( !iked.idb_list_ph1.find(
			true,
			&ph1,
			tunnel,
			XCH_STATUS_MATURE,
			XCH_STATUS_EXPIRING,
			NULL ) )
	{
		char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];
		iked.text_addr( txtaddr_r, &tunnel->saddr_r, true );

		iked.log.txt( LLOG_ERROR,
				"!! : unable to locate phase1 to process DPD for peer %s\n",
				txtaddr_r );

		return true;
	}

	//
	// determine the next dpd delay
	//

	if( !attempt )
		delay = tunnel->peer->dpd_delay * 1000;
	else
	{
		long retry_secs = tunnel->peer->dpd_retry - attempt;

		delay = retry_secs * 1000;

		char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];
		iked.text_addr( txtaddr_r, &tunnel->saddr_r, true );

		iked.log.txt( LLOG_DEBUG,
				"ii : next tunnel DPD retry in %i secs for peer %s\n",
				retry_secs,
				txtaddr_r );
	}

	//
	// add new sequence number and send
	//

	uint32_t dpdseq = htonl( ++sequence );

	BDATA bdata;
	bdata.add( &dpdseq, sizeof( dpdseq ) );

	iked.inform_new_notify( ph1, NULL, ISAKMP_N_DPD_R_U_THERE, &bdata );

	iked.log.txt( LLOG_DEBUG, "ii : DPD ARE-YOU-THERE sequence %08x requested\n", sequence );

	ph1->dec( true );

	attempt++;

	return true;
}

bool _ITH_EVENT_TUNNATT::func()
{
	//
	// locate mature phase1 handle
	//

	IDB_PH1 * ph1 = NULL;
	if( !iked.idb_list_ph1.find(
			true,
			&ph1,
			tunnel,
			XCH_STATUS_MATURE,
			XCH_STATUS_EXPIRING,
			NULL ) )
	{
		char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];
		iked.text_addr( txtaddr_r, &tunnel->saddr_r, true );

		iked.log.txt( LLOG_ERROR,
				"!! : unable to locate phase1 to process NAT-T for peer %s\n",
				txtaddr_r );

		return true;
	}

	//
	// determine natt ports
	//

	IKE_SADDR saddr_l = ph1->tunnel->saddr_l;
	IKE_SADDR saddr_r = ph1->tunnel->saddr_r;

	if( ph1->tunnel->natt_version == IPSEC_NATT_CISCO )
	{
		iked.socket_lookup_port( saddr_l, true );
		set_sockport( saddr_r.saddr, ph1->tunnel->peer->natt_port );
	}

	//
	// encapsulate natt keep alive
	//

	PACKET_UDP packet_udp;

	packet_udp.write(
		saddr_l.saddr4.sin_port,
		saddr_r.saddr4.sin_port );

	packet_udp.add_byte( 0xff );

	packet_udp.done(
		saddr_l.saddr4.sin_addr,
		saddr_r.saddr4.sin_addr );

	PACKET_IP packet_ip;

	packet_ip.write(
		saddr_l.saddr4.sin_addr,
		saddr_r.saddr4.sin_addr,
		iked.ident++,
		PROTO_IP_UDP );

	packet_ip.add( packet_udp );

	packet_ip.done();

	//
	// send ike packet
	//

	char txtaddr_l[ LIBIKE_MAX_TEXTADDR ];
	char txtaddr_r[ LIBIKE_MAX_TEXTADDR ];

	iked.text_addr( txtaddr_l, &saddr_l, true );
	iked.text_addr( txtaddr_r, &saddr_r, true );

	iked.log.txt( LLOG_DEBUG,
		"-> : send NAT-T:KEEP-ALIVE packet %s -> %s\n",
		txtaddr_l, 
		txtaddr_r );

	iked.send_ip(
		packet_ip );

	ph1->dec( true );

	return true;
}

bool _ITH_EVENT_TUNSTATS::func()
{
	//
	// check tunnel status and send
	// message once every second
	//

	if( !( tunnel->close ) )
	{
		tunnel->stats.peer = tunnel->saddr_r;
		tunnel->stats.natt = tunnel->natt_version;

		IKEI_MSG msg;
		msg.set_stats( &tunnel->stats );
		tunnel->ikei->send_message( msg );
	}

	return true;
}

//==============================================================================
// tunnel list
//==============================================================================

IDB_TUNNEL * _IDB_LIST_TUNNEL::get( int index )
{
	return static_cast<IDB_TUNNEL*>( get_entry( index ) );
}

bool _IDB_LIST_TUNNEL::find( bool lock, IDB_TUNNEL ** tunnel, long * tunnelid, IKE_SADDR * saddr, bool port, bool suspended )
{
	if( tunnel != NULL )
		*tunnel = NULL;

	if( lock )
		iked.lock_idb.lock();

	long tunnel_count = count();
	long tunnel_index = 0;

	for( ; tunnel_index < tunnel_count; tunnel_index++ )
	{
		IDB_TUNNEL * tmp_tunnel = get( tunnel_index );

		//
		// match the tunnel id
		//

		if( tunnelid != NULL )
			if( tmp_tunnel->tunnelid != *tunnelid )
				continue;

		//
		// match the peer address
		//

		if( saddr != NULL )
			if( !cmp_sockaddr( tmp_tunnel->saddr_r.saddr, saddr->saddr, port ) )
				continue;

		//
		// match suspended value
		//

		if( suspended )
			if( !tmp_tunnel->suspended )
				continue;

		iked.log.txt( LLOG_DEBUG, "DB : tunnel found\n" );

		//
		// increase our refrence count
		//

		if( tunnel != NULL )
		{
			tmp_tunnel->inc( false );
			*tunnel = tmp_tunnel;
		}

		if( lock )
			iked.lock_idb.unlock();

		return true;
	}

	iked.log.txt( LLOG_DEBUG, "DB : tunnel not found\n" );

	if( lock )
		iked.lock_idb.unlock();

	return false;
}

//==============================================================================
// tunnel list entry
//==============================================================================

_IDB_TUNNEL::_IDB_TUNNEL( IDB_PEER * set_peer, IKE_XCONF * set_xconf, IKE_SADDR * set_saddr_l, IKE_SADDR * set_saddr_r )
{
	ikei = NULL;

#ifdef OPT_DTP
	dtpi = NULL;
#endif

	adapter = NULL;

	//
	// tunnels are removed immediately
	// when the refcount reaches zero
	//

	setflags( ENTRY_FLAG_IMMEDIATE );

	tstate = 0;
	lstate = 0;
	close = XCH_NORMAL;
	suspended = false;

	natt_version = IPSEC_NATT_NONE;
	dhcp_sock = INVALID_SOCKET;
	force_all = false;

	//
	// initialize the tunnel id
	//

	tunnelid = iked.tunnelid++;
	saddr_l = *set_saddr_l;
	saddr_r = *set_saddr_r;

	peer = set_peer;
	peer->inc( true );

	memset( &stats, 0, sizeof( stats ) );
	memset( &xconf, 0, sizeof( xconf ) );
#ifdef WIN32
	memset( &nscfg, 0, sizeof( nscfg ) );
#endif

	//
	// setup xconf
	//

	if( set_xconf != NULL )
		xconf = *set_xconf;

	if( !( xconf.opts & IPSEC_OPTS_ADDR ) )
	{
		if( peer->contact == IPSEC_CONTACT_CLIENT )
			xconf.addr = saddr_l.saddr4.sin_addr;
		else
			xconf.addr = saddr_r.saddr4.sin_addr;

		xconf.mask.s_addr = 0xffffffff;
	}

	//
	// initialize event info
	//

	event_stats.tunnel = this;

	event_dpd.tunnel = this;
	event_dpd.sequence = 0;
	event_dpd.attempt = 0;

	event_natt.tunnel = this;

	event_dhcp.tunnel = this;
	event_dhcp.lease = 0;
	event_dhcp.renew = 0;
	event_dhcp.retry = 0;

	//
	// determine dpd negotiation
	//

	if( peer->dpd_mode >= IPSEC_DPD_ENABLE )
	{
		iked.rand_bytes( &event_dpd.sequence, sizeof( event_dpd.sequence ) );
		event_dpd.sequence >>= 2;
	}

	//
	// setup our filter
	//

#ifdef WIN32

	iked.tunnel_filter_add( this, false );

#endif
}

_IDB_TUNNEL::~_IDB_TUNNEL()
{
	//
	// cleanup our filter
	//

#ifdef WIN32

	iked.tunnel_filter_del( this );

#endif

	//
	// dereference our peer
	//

	peer->dec( false );
}

//------------------------------------------------------------------------------
// abstract functions from parent class
//

const char * _IDB_TUNNEL::name()
{
	static const char * xname = "tunnel";
	return xname;
}

IKED_RC_LIST * _IDB_TUNNEL::list()
{
	return &iked.idb_list_tunnel;
}

void _IDB_TUNNEL::beg()
{
}

void _IDB_TUNNEL::end()
{
	//
	// remove scheduled events
	//

	if( iked.ith_timer.del( &event_dhcp ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : tunnel dhcp event canceled ( ref count = %i )\n",
			idb_refcount );
	}

	if( iked.ith_timer.del( &event_dpd ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : tunnel dpd event canceled ( ref count = %i )\n",
			idb_refcount );
	}

	if( iked.ith_timer.del( &event_natt ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : tunnel natt event canceled ( ref count = %i )\n",
			idb_refcount );
	}

	if( iked.ith_timer.del( &event_stats ) )
	{
		idb_refcount--;
		iked.log.txt( LLOG_DEBUG,
			"DB : tunnel stats event canceled ( ref count = %i )\n",
			idb_refcount );
	}

	//
	// check for config object references
	//

	iked.log.txt( LLOG_INFO, "DB : removing tunnel config references\n" );

	long cfg_count = iked.idb_list_cfg.count();
	long cfg_index = 0;

	for( ; cfg_index < cfg_count; cfg_index++ )
	{
		//
		// get the next config in our list
		// and attempt to match tunnel ids
		//

		IDB_CFG * cfg = iked.idb_list_cfg.get( cfg_index );

		if( cfg->tunnel == this )
		{
			cfg->inc( false );

			cfg->status( XCH_STATUS_DEAD, XCH_FAILED_USERREQ, 0 );

			if( cfg->dec( false ) )
			{
				cfg_index--;
				cfg_count--;
			}
		}
	}

	//
	// check for phase2 object references
	//

	iked.log.txt( LLOG_INFO, "DB : removing tunnel phase2 references\n" );

	long ph2_count = iked.idb_list_ph2.count();
	long ph2_index = 0;

	for( ; ph2_index < ph2_count; ph2_index++ )
	{
		//
		// get the next phase2 in our list
		// and attempt to match tunnel ids
		//

		IDB_PH2 * ph2 = iked.idb_list_ph2.get( ph2_index );
		if( ph2->tunnel == this )
		{
			ph2->inc( false );

			ph2->status( XCH_STATUS_DEAD, XCH_FAILED_USERREQ, 0 );

			if( ph2->dec( false ) )
			{
				ph2_index--;
				ph2_count--;
			}
		}
	}

	//
	// check for phase1 object references
	//

	iked.log.txt( LLOG_INFO, "DB : removing tunnel phase1 references\n" );

	long ph1_count = iked.idb_list_ph1.count();
	long ph1_index = 0;

	for( ; ph1_index < ph1_count; ph1_index++ )
	{
		//
		// get the next phase1 in our list
		// and attempt to match tunnel ids
		//

		IDB_PH1 * ph1 = iked.idb_list_ph1.get( ph1_index );
		if( ph1->tunnel == this )
		{
			ph1->inc( false );

			ph1->status( XCH_STATUS_DEAD, XCH_FAILED_USERREQ, 0 );

			if( ph1->dec( false ) )
			{
				ph1_index--;
				ph1_count--;
			}
		}
	}

	//
	// cleaup client tunnels
	//

	if( peer->contact == IPSEC_CONTACT_SERVER )
	{
		if( peer->plcy_mode != POLICY_MODE_DISABLE )
			iked.policy_list_remove( this, false );

		if( xconf.opts & IPSEC_OPTS_ADDR )
			peer->xconf_source->pool4_rel( xconf.addr );
	}
}
