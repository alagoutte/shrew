
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

bool _IKED::policy_get_addrs( PFKI_SPINFO * spinfo, IKE_SADDR & src, IKE_SADDR & dst )
{
	memset( &src, 0, sizeof( src ) );
	memset( &dst, 0, sizeof( dst ) );

	bool tunnel = false;
	long xindex = 0;

	while( !tunnel && ( xindex < PFKI_MAX_XFORMS ) )
	{
		if( !spinfo->xforms[ xindex ].proto )
			break;

		switch( spinfo->xforms[ xindex ].mode )
		{
			case IPSEC_MODE_ANY:
			case IPSEC_MODE_TRANSPORT:
			{
				src.saddr = spinfo->paddr_src.saddr;
				dst.saddr = spinfo->paddr_dst.saddr;

				break;
			}

			case IPSEC_MODE_TUNNEL:

				src.saddr = spinfo->xforms[ xindex ].saddr_src;
				dst.saddr = spinfo->xforms[ xindex ].saddr_dst;

				tunnel = true;

				break;
		}

		xindex++;
	}

	return true;
}

bool _IKED::policy_cmp_prots( PFKI_SPINFO * spinfo1, PFKI_SPINFO * spinfo2 )
{
	long xindex = 0;

	while( xindex < PFKI_MAX_XFORMS )
	{
		//
		// compare the protocols
		//

		if( spinfo1->xforms[ xindex ].proto !=
			spinfo2->xforms[ xindex ].proto )
			return false;

		//
		// compare the mode
		//

		if( spinfo1->xforms[ xindex ].mode !=
			spinfo2->xforms[ xindex ].mode )
			return false;

		//
		// compare the level
		//

		if( spinfo1->xforms[ xindex ].level !=
			spinfo2->xforms[ xindex ].level )
			return false;

		xindex++;
	}

	return true;
}

bool _IKED::policy_list_create( IDB_TUNNEL * tunnel, bool initiator )
{
	//
	// if we are the responder, make
	// sure we generate an id list
	// before attempting to create
	// the policies
	//

	if( !initiator )
	{
		log.txt( LLOG_INFO, "ii : creating policy id list\n" );

		long index = 0;

		IDB_ENTRY_NETMAP * netmap;

		while( tunnel->peer->netmaps.get( &netmap, index++ ) )
		{
			//
			// perform group checking if appropriate
			//

			if( netmap->group.size() )
			{
				if( tunnel->peer->plcy_mode == POLICY_MODE_COMPAT )
				{
					log.txt( LLOG_ERROR,
						"!! : - cannot validate netgroup %s before xauth\n",
						netmap->idlist->name.text() );

					continue;
				}

				if( !tunnel->xauth.user.size() ||
					!tunnel->xauth.pass.size() )
				{
					log.txt( LLOG_ERROR,
						"!! : - cannot validate netgroup %s without xauth\n",
						netmap->idlist->name.text() );

					continue;
				}

				if( !tunnel->peer->xauth_source->auth_grp(
						tunnel->xauth,
						netmap->group ) )
				{
					log.txt( LLOG_INFO,
						"ii : - xauth user %s group %s membership rejected ( %s )\n",
						tunnel->xauth.user.text(),
						netmap->group.text(),
						tunnel->peer->xauth_source->name() );

					continue;
				}

				log.txt( LLOG_INFO,
					"ii : - xauth user %s group %s membership accepted ( %s )\n",
					tunnel->xauth.user.text(),
					netmap->group.text(),
					tunnel->peer->xauth_source->name() );
			}

			//
			// add netgroup ids to the tunnel list
			//

			log.txt( LLOG_INFO,
				"ii : - adding policy ids for netgroup %s\n",
				netmap->idlist->name.text() );

			long index2 = 0;

			IKE_PH2ID ph2id;

			while( netmap->idlist->get( ph2id, index2++ ) )
			{
				if( netmap->mode == UNITY_SPLIT_INCLUDE )
					tunnel->idlist_incl.add( ph2id );
				else
					tunnel->idlist_excl.add( ph2id );
			}
		}
	}

	//
	// determine ipsec policy level value
	//

	u_int8_t ipsec_level = IPSEC_LEVEL_DEFAULT;

	switch( tunnel->peer->plcy_level )
	{
		case POLICY_LEVEL_USE:
			ipsec_level = IPSEC_LEVEL_USE;
			break;

		case POLICY_LEVEL_SHARED:
		case POLICY_LEVEL_REQUIRE:
			ipsec_level = IPSEC_LEVEL_REQUIRE;
			break;

		case POLICY_LEVEL_UNIQUE:
			ipsec_level = IPSEC_LEVEL_UNIQUE;
			break;
	}

	log.txt( LLOG_DEBUG,
		"ii : generating IPSEC security policies at %s level\n",
		pfki.name( NAME_SPLEVEL, ipsec_level ) );

	//
	// if we have a empty remote toplology
	// list, add a single all-networks id
	// and flag the tunnel as force all
	//
	
	IKE_PH2ID id1;
	IKE_PH2ID id2;

	if( !tunnel->idlist_incl.count() )
	{
		memset( &id2, 0, sizeof( id2 ) );
		id2.type = ISAKMP_ID_IPV4_ADDR_SUBNET;

		tunnel->idlist_incl.add( id2 );

		tunnel->force_all = true;
	}

	//
	// add NONE policies to ensure we will
	// still communicate with our peer for
	// the case where IPSEC policies exist
	// that encrypt traffic between client
	// and gateway endpoint addresses
	//

	memset( &id1, 0, sizeof( id1 ) );
	id1.type = ISAKMP_ID_IPV4_ADDR;
	id1.addr1 = tunnel->saddr_l.saddr4.sin_addr;

	memset( &id2, 0, sizeof( id2 ) );
	id2.type = ISAKMP_ID_IPV4_ADDR;
	id2.addr1 = tunnel->saddr_r.saddr4.sin_addr;

	policy_create( tunnel, IPSEC_POLICY_NONE, IPSEC_LEVEL_DEFAULT, id1, id2, true );

#ifdef WIN32

	IPROUTE_ENTRY entry;
	memset( &entry, 0, sizeof( entry ) );
	entry.addr = tunnel->saddr_r.saddr4.sin_addr;

	if( iproute.best( entry ) && !entry.local )
	{
		memset( &id1, 0, sizeof( id1 ) );
		id1.type = ISAKMP_ID_IPV4_ADDR;
		id1.addr1 = tunnel->xconf.addr;

		memset( &id2, 0, sizeof( id2 ) );
		id2.type = ISAKMP_ID_IPV4_ADDR;
		id2.addr1 = entry.next;

		policy_create( tunnel, IPSEC_POLICY_NONE, IPSEC_LEVEL_DEFAULT, id1, id2, false );
	}

#endif

	//
	// build the client id
	//

	memset( &id1, 0, sizeof( id1 ) );
	id1.type  = ISAKMP_ID_IPV4_ADDR;
	id1.addr1.s_addr = tunnel->xconf.addr.s_addr;
	id1.addr2.s_addr = 0;

	//
	// create a discard or none policy
	// pair for each id in our exclude list
	//

	long index = 0;

	while( tunnel->idlist_excl.get( id2, index++ ) )
	{
		if( initiator )
			policy_create( tunnel, IPSEC_POLICY_NONE, IPSEC_LEVEL_DEFAULT, id1, id2, true );
		else
			policy_create( tunnel, IPSEC_POLICY_DISCARD, IPSEC_LEVEL_DEFAULT, id2, id1, true );
	}

	//
	// create an ipsec policy pair for
	// each id in our include list
	//

	index = 0;

	while( tunnel->idlist_incl.get( id2, index++ ) )
	{
		if( initiator )
			policy_create( tunnel, IPSEC_POLICY_IPSEC, ipsec_level, id1, id2, true );
		else
			policy_create( tunnel, IPSEC_POLICY_IPSEC, ipsec_level, id2, id1, true );
	}

	return true;
}

bool _IKED::policy_list_remove( IDB_TUNNEL * tunnel, bool initiator )
{
	//
	// determine ipsec policy level value
	//

	u_int8_t ipsec_level = IPSEC_LEVEL_DEFAULT;

	switch( tunnel->peer->plcy_level )
	{
		case POLICY_LEVEL_USE:
			ipsec_level = IPSEC_LEVEL_USE;
			break;

		case POLICY_LEVEL_SHARED:
		case POLICY_LEVEL_REQUIRE:
			ipsec_level = IPSEC_LEVEL_REQUIRE;
			break;

		case POLICY_LEVEL_UNIQUE:
			ipsec_level = IPSEC_LEVEL_UNIQUE;
			break;
	}

	//
	// build the client id
	//

	IKE_PH2ID id1;
	memset( &id1, 0, sizeof( id1 ) );

	id1.type = ISAKMP_ID_IPV4_ADDR;
	id1.addr1.s_addr = tunnel->xconf.addr.s_addr;
	id1.addr2.s_addr = 0;

	//
	// remove the ipsec policy pair for
	// each id in our include list
	//

	IKE_PH2ID id2;

	long index = 0;

	while( tunnel->idlist_incl.get( id2, index++ ) )
	{
		if( initiator )
			policy_remove( tunnel, IPSEC_POLICY_IPSEC, ipsec_level, id1, id2, true );
		else
			policy_remove( tunnel, IPSEC_POLICY_IPSEC, ipsec_level, id2, id1, true );
	}

	//
	// remove the discard or none policy
	// pair for each id in our exclude list
	//

	index = 0;

	while( tunnel->idlist_excl.get( id2, index++ ) )
	{
		if( initiator )
			policy_remove( tunnel, IPSEC_POLICY_NONE, IPSEC_LEVEL_DEFAULT, id1, id2, true );
		else
			policy_remove( tunnel, IPSEC_POLICY_DISCARD, IPSEC_LEVEL_DEFAULT, id2, id1, true );
	}

	//
	// remove our gateway NONE policies
	//

#ifdef WIN32

	IPROUTE_ENTRY entry;
	memset( &entry, 0, sizeof( entry ) );
	entry.addr = tunnel->saddr_r.saddr4.sin_addr;

	if( iproute.best( entry ) && !entry.local )
	{
		memset( &id1, 0, sizeof( id1 ) );
		id1.type = ISAKMP_ID_IPV4_ADDR;
		id1.addr1 = tunnel->xconf.addr;

		memset( &id2, 0, sizeof( id2 ) );
		id2.type = ISAKMP_ID_IPV4_ADDR;
		id2.addr1 = entry.next;

		policy_remove( tunnel, IPSEC_POLICY_NONE, IPSEC_LEVEL_DEFAULT, id1, id2, false );
	}

#endif

	memset( &id1, 0, sizeof( id1 ) );
	id1.type = ISAKMP_ID_IPV4_ADDR;
	id1.addr1 = tunnel->saddr_l.saddr4.sin_addr;

	memset( &id2, 0, sizeof( id2 ) );
	id2.type = ISAKMP_ID_IPV4_ADDR;
	id2.addr1 = tunnel->saddr_r.saddr4.sin_addr;

	policy_remove( tunnel, IPSEC_POLICY_NONE, IPSEC_LEVEL_DEFAULT, id1, id2, true );

	if( tunnel->force_all )
		tunnel->force_all = false;

	return true;
}

bool _IKED::policy_dhcp_create( IDB_TUNNEL * tunnel )
{
	//
	// determine ipsec policy level value
	//

	u_int8_t ipsec_level = IPSEC_LEVEL_DEFAULT;

	switch( tunnel->peer->plcy_level )
	{
		case POLICY_LEVEL_USE:
			ipsec_level = IPSEC_LEVEL_USE;
			break;

		case POLICY_LEVEL_SHARED:
		case POLICY_LEVEL_REQUIRE:
			ipsec_level = IPSEC_LEVEL_REQUIRE;
			break;

		case POLICY_LEVEL_UNIQUE:
			ipsec_level = IPSEC_LEVEL_UNIQUE;
			break;
	}

	//
	// create our DHCP over IPsec policies
	//

	log.txt( LLOG_DEBUG, "ii : creating IPsec over DHCP policies\n" );

	IKE_PH2ID src;
	memset( &src, 0, sizeof( src ) );
	src.type = ISAKMP_ID_IPV4_ADDR;
	src.prot = PROTO_IP_UDP;
	src.port = htons( UDP_PORT_DHCPS );
	src.addr1 = tunnel->saddr_l.saddr4.sin_addr;

	IKE_PH2ID dst;
	memset( &dst, 0, sizeof( dst ) );
	dst.type = ISAKMP_ID_IPV4_ADDR;
	dst.prot = PROTO_IP_UDP;
	dst.port = htons( UDP_PORT_DHCPS );
	dst.addr1 = tunnel->saddr_r.saddr4.sin_addr;

	return policy_create( tunnel, IPSEC_POLICY_IPSEC, ipsec_level, src, dst, false );
}

bool _IKED::policy_dhcp_remove( IDB_TUNNEL * tunnel )
{
	//
	// determine ipsec policy level value
	//

	u_int8_t ipsec_level = IPSEC_LEVEL_DEFAULT;

	switch( tunnel->peer->plcy_level )
	{
		case POLICY_LEVEL_USE:
			ipsec_level = IPSEC_LEVEL_USE;
			break;

		case POLICY_LEVEL_SHARED:
		case POLICY_LEVEL_REQUIRE:
			ipsec_level = IPSEC_LEVEL_REQUIRE;
			break;

		case POLICY_LEVEL_UNIQUE:
			ipsec_level = IPSEC_LEVEL_UNIQUE;
			break;
	}

	//
	// remove our DHCP over IPsec policies
	//

	log.txt( LLOG_DEBUG, "ii : removing IPsec over DHCP policies\n" );

	IKE_PH2ID src;
	memset( &src, 0, sizeof( src ) );
	src.type = ISAKMP_ID_IPV4_ADDR;
	src.prot = PROTO_IP_UDP;
	src.port = htons( UDP_PORT_DHCPS );
	src.addr1 = tunnel->saddr_l.saddr4.sin_addr;

	IKE_PH2ID dst;
	memset( &dst, 0, sizeof( dst ) );
	dst.type = ISAKMP_ID_IPV4_ADDR;
	dst.prot = PROTO_IP_UDP;
	dst.port = htons( UDP_PORT_DHCPS );
	dst.addr1 = tunnel->saddr_r.saddr4.sin_addr;

	return policy_remove( tunnel, IPSEC_POLICY_IPSEC, ipsec_level, src, dst, false );
}

bool _IKED::policy_create( IDB_TUNNEL * tunnel, u_int16_t type, u_int8_t level, IKE_PH2ID & id1, IKE_PH2ID & id2, bool route )
{
	char txtid_src[ LIBIKE_MAX_TEXTP2ID ];
	char txtid_dst[ LIBIKE_MAX_TEXTP2ID ];

	//
	// define inbound policy
	//

	PFKI_SPINFO spinfo;
	memset( &spinfo, 0, sizeof( spinfo ) );

	spinfo.sp.type = type;
	spinfo.sp.dir = IPSEC_DIR_INBOUND;

	ph2id_paddr( id2, spinfo.paddr_src );
	ph2id_paddr( id1, spinfo.paddr_dst );

	if( type == IPSEC_POLICY_IPSEC )
	{
		spinfo.xforms[ 0 ].proto = PROTO_IP_ESP;
		spinfo.xforms[ 0 ].mode = IPSEC_MODE_TUNNEL;
		spinfo.xforms[ 0 ].level = level;

		if( level == IPSEC_LEVEL_UNIQUE )
			spinfo.xforms[ 0 ].reqid = policyid++;

		cpy_sockaddr( tunnel->saddr_r.saddr, spinfo.xforms[ 0 ].saddr_src, false );
		cpy_sockaddr( tunnel->saddr_l.saddr, spinfo.xforms[ 0 ].saddr_dst, false );
	}

	text_ph2id( txtid_src, &id2 );
	text_ph2id( txtid_dst, &id1 );

	log.txt( LLOG_INFO, 
		"ii : creating %s %s policy %s -> %s\n",
		pfki.name( NAME_SPTYPE, spinfo.sp.type ),
		pfki.name( NAME_SPDIR, spinfo.sp.dir ),
		txtid_src,
		txtid_dst );

	//
	// create an inbound policy object
	//

	IDB_POLICY * policy = new IDB_POLICY( &spinfo );
	if( policy == NULL )
	{
		log.txt( LLOG_ERROR, 
			"!! : failed to allocate inbound policy object\n" );

		return false;
	}

	//
	// add the inbbound policy to spd
	//

	policy->add( true );
	policy->dec( true );

	pfkey_send_spadd( &spinfo );

	//
	// define outbound policy
	//

	memset( &spinfo, 0, sizeof( spinfo ) );

	spinfo.sp.type = type;
	spinfo.sp.dir = IPSEC_DIR_OUTBOUND;

	ph2id_paddr( id1, spinfo.paddr_src );
	ph2id_paddr( id2, spinfo.paddr_dst );

	if( type == IPSEC_POLICY_IPSEC )
	{
		spinfo.xforms[ 0 ].proto = PROTO_IP_ESP;
		spinfo.xforms[ 0 ].mode = IPSEC_MODE_TUNNEL;
		spinfo.xforms[ 0 ].level = level;

		if( level == IPSEC_LEVEL_UNIQUE )
			spinfo.xforms[ 0 ].reqid = policyid++;

		cpy_sockaddr( tunnel->saddr_l.saddr, spinfo.xforms[ 0 ].saddr_src, false );
		cpy_sockaddr( tunnel->saddr_r.saddr, spinfo.xforms[ 0 ].saddr_dst, false );
	}

	text_ph2id( txtid_src, &id1 );
	text_ph2id( txtid_dst, &id2 );

	log.txt( LLOG_INFO, 
		"ii : creating %s %s policy %s -> %s\n",
		pfki.name( NAME_SPTYPE, spinfo.sp.type ),
		pfki.name( NAME_SPDIR, spinfo.sp.dir ),
		txtid_src,
		txtid_dst );

	text_addr( txtid_dst, &spinfo.paddr_dst, false, true );

	//
	// create an outbound policy object
	//

	policy = new IDB_POLICY( &spinfo );
	if( policy == NULL )
	{
		log.txt( LLOG_ERROR, 
			"!! : failed to allocate outbound policy object\n" );

		return false;
	}

	//
	// set special flags for outbound policies
	//

	if( tunnel->peer->nailed )
		policy->flags |= PFLAG_NAILED;

	if( ( type == IPSEC_POLICY_IPSEC ) && ( tunnel->tstate & TSTATE_POLICY_INIT ) )
	{
		policy->flags |= PFLAG_INITIAL;
		tunnel->tstate &= ~TSTATE_POLICY_INIT;
	}

	//
	// create client policy route
	//

	if( route && ( tunnel->peer->contact == IPSEC_CONTACT_CLIENT ) )
	{
		IPROUTE_ENTRY & route_entry = policy->route_entry;

		switch( type )
		{
			case IPSEC_POLICY_IPSEC:
			{
				route_entry.local = true;
				route_entry.iface = tunnel->xconf.addr;
				route_entry.addr = id2.addr1;
				route_entry.mask = id2.addr2;
				route_entry.next = tunnel->xconf.addr;

				if( id2.type == ISAKMP_ID_IPV4_ADDR )
					route_entry.mask.s_addr = 0xffffffff;

				iproute.increment(
					route_entry.addr,
					route_entry.mask );

				if( iproute.add( route_entry ) )
					policy->flags |= PFLAG_ROUTED;

				break;
			}

			case IPSEC_POLICY_NONE:
			{
				route_entry.addr = id2.addr1;

				if( iproute.best( route_entry ) )
				{
					route_entry.addr = id2.addr1;
					route_entry.mask = id2.addr2;

					if( id2.type == ISAKMP_ID_IPV4_ADDR )
						route_entry.mask.s_addr = 0xffffffff;

					if( iproute.add( route_entry ) )
						policy->flags |= PFLAG_ROUTED;
				}

				break;
			}
		}

		if( policy->flags & PFLAG_ROUTED )
		{
			log.txt( LLOG_INFO,
				"ii : created %s policy route for %s\n",
				pfki.name( NAME_SPTYPE, type ),
				txtid_dst );
		}
		else
		{
			log.txt( LLOG_ERROR,
				"!! : failed to create %s policy route for %s\n",
				pfki.name( NAME_SPTYPE, type ),
				txtid_dst );
		}
	}

	//
	// add the outbound policy to spd
	//

	policy->add( true );
	policy->dec( true );

	pfkey_send_spadd( &spinfo );

	return true;
}

bool _IKED::policy_remove( IDB_TUNNEL * tunnel, u_int16_t type, u_int8_t level, IKE_PH2ID & id1, IKE_PH2ID & id2, bool route )
{
	char txtid_src[ LIBIKE_MAX_TEXTP2ID ];
	char txtid_dst[ LIBIKE_MAX_TEXTP2ID ];

	IDB_POLICY * policy;

	bool route_deleted = false;
	long flags = 0;
	IPROUTE_ENTRY route_entry;

	IKE_SADDR * src;
	IKE_SADDR * dst;

	//
	// remove inbound policy
	//

	src = NULL;
	dst = NULL;

	if( type == IPSEC_POLICY_IPSEC )
	{
		src = &tunnel->saddr_r;
		dst = &tunnel->saddr_l;
	}

	if( idb_list_policy.find(
			false,
			&policy,
			IPSEC_DIR_INBOUND,
			type,
			NULL,
			NULL,
			src,
			dst,
			&id2,
			&id1 ) )
	{
		text_ph2id( txtid_src, &id2 );
		text_ph2id( txtid_dst, &id1 );

		log.txt( LLOG_INFO, 
			"ii : removing %s %s policy %s -> %s\n",
			pfki.name( NAME_SPTYPE, policy->sp.type ),
			pfki.name( NAME_SPDIR, policy->sp.dir ),
			txtid_src,
			txtid_dst );

		pfkey_send_spdel( policy );

		policy->dec( false );
	}

	//
	// remove outbound policy
	//

	src = NULL;
	dst = NULL;

	if( type == IPSEC_POLICY_IPSEC )
	{
		src = &tunnel->saddr_l;
		dst = &tunnel->saddr_r;
	}

	if( idb_list_policy.find(
			false,
			&policy,
			IPSEC_DIR_OUTBOUND,
			type,
			NULL,
			NULL,
			src,
			dst,
			&id1,
			&id2 ) )
	{
		route_entry = policy->route_entry;
		flags = policy->flags;

		text_ph2id( txtid_src, &id1 );
		text_ph2id( txtid_dst, &id2 );

		log.txt( LLOG_INFO, 
			"ii : removing %s %s policy %s -> %s\n",
			pfki.name( NAME_SPTYPE, policy->sp.type ),
			pfki.name( NAME_SPDIR, policy->sp.dir ),
			txtid_src,
			txtid_dst );

		text_addr( txtid_dst, &policy->paddr_dst, false, true );

		pfkey_send_spdel( policy );

		policy->dec( false );
	}

	//
	// remove client policy route
	//

	if( route && ( flags & PFLAG_ROUTED ) && ( tunnel->peer->contact == IPSEC_CONTACT_CLIENT ) )
	{
		switch( type )
		{
			case IPSEC_POLICY_IPSEC:
			{
				route_deleted = iproute.del( route_entry );

				iproute.decrement(
					route_entry.addr,
					route_entry.mask );

				break;
			}

			case IPSEC_POLICY_NONE:
			{
				route_deleted = iproute.del( route_entry );

				break;
			}
		}

		if( route_deleted )
		{
			text_ph2id( txtid_dst, &id2 );

			log.txt( LLOG_INFO,
				"ii : removed %s policy route for %s\n",
				pfki.name( NAME_SPTYPE, type ),
				txtid_dst );
		}
		else
		{
			text_ph2id( txtid_dst, &id2 );

			log.txt( LLOG_ERROR,
				"!! : failed to remove %s policy route for %s\n",
				pfki.name( NAME_SPTYPE, type ),
				txtid_dst );
		}
	}

	return true;
}
