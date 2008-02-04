
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

		IDB_NETMAP * netmap;

		while( tunnel->peer->netmap_get( &netmap, index++ ) )
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
						netmap->ilist->name.text() );

					continue;
				}

				if( !tunnel->xauth.user.size() ||
					!tunnel->xauth.pass.size() )
				{
					log.txt( LLOG_ERROR,
						"!! : - cannot validate netgroup %s without xauth\n",
						netmap->ilist->name.text() );

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
				netmap->ilist->name.text() );

			long index2 = 0;

			IKE_PH2ID ph2id;

			while( netmap->ilist->get( ph2id, index2++ ) )
			{
				if( netmap->mode == UNITY_SPLIT_INCLUDE )
					tunnel->idlist_incl.add( ph2id );
				else
					tunnel->idlist_excl.add( ph2id );
			}
		}
	}

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
	// if we will be forcing all traffic
	// via this tunnel, add none policies
	// to ensure we will still communicate
	// with our peer
	//

	if( tunnel->force_all )
	{
		memset( &id1, 0, sizeof( id1 ) );
		id1.type = ISAKMP_ID_IPV4_ADDR;
		id1.addr1 = tunnel->saddr_l.saddr4.sin_addr;

		memset( &id2, 0, sizeof( id2 ) );
		id2.type = ISAKMP_ID_IPV4_ADDR;
		id2.addr1 = tunnel->saddr_r.saddr4.sin_addr;

		policy_create( tunnel, IPSEC_POLICY_NONE, id1, id2, true );

		tunnel->force_all = true;
	}

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
			policy_create( tunnel, IPSEC_POLICY_NONE, id1, id2, true );
		else
			policy_create( tunnel, IPSEC_POLICY_DISCARD, id2, id1, true );
	}

	//
	// create an ipsec policy pair for
	// each id in our include list
	//

	index = 0;

	while( tunnel->idlist_incl.get( id2, index++ ) )
	{
		if( initiator )
			policy_create( tunnel, IPSEC_POLICY_IPSEC, id1, id2, true );
		else
			policy_create( tunnel, IPSEC_POLICY_IPSEC, id2, id1, true );
	}

	return true;
}

bool _IKED::policy_list_remove( IDB_TUNNEL * tunnel, bool initiator )
{
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
			policy_remove( tunnel, IPSEC_POLICY_IPSEC, id1, id2, true );
		else
			policy_remove( tunnel, IPSEC_POLICY_IPSEC, id2, id1, true );
	}

	//
	// remove the discard or none policy
	// pair for each id in our exclude list
	//

	index = 0;

	while( tunnel->idlist_excl.get( id2, index++ ) )
	{
		if( initiator )
			policy_remove( tunnel, IPSEC_POLICY_NONE, id1, id2, true );
		else
			policy_remove( tunnel, IPSEC_POLICY_DISCARD, id2, id1, true );
	}

	//
	// if we added none policies, remove
	// them now
	//

	if( tunnel->force_all )
	{
		memset( &id1, 0, sizeof( id1 ) );
		id1.type = ISAKMP_ID_IPV4_ADDR;
		id1.addr1 = tunnel->saddr_l.saddr4.sin_addr;

		memset( &id2, 0, sizeof( id2 ) );
		id2.type = ISAKMP_ID_IPV4_ADDR;
		id2.addr1 = tunnel->saddr_r.saddr4.sin_addr;

		policy_remove( tunnel, IPSEC_POLICY_NONE, id1, id2, true );

		tunnel->force_all = false;
	}

	return true;
}

bool _IKED::policy_dhcp_create( IDB_TUNNEL * tunnel )
{
	//
	// create our DHCP over IPsec policies
	//

	log.txt( LLOG_DEBUG, "ii : creating IPsec over DHCP policies\n" );

	IKE_PH2ID src;
	memset( &src, 0, sizeof( src ) );
	src.type = ISAKMP_ID_IPV4_ADDR;
	src.prot = PROTO_IP_UDP;
	src.port = htons( UDP_PORT_DHCPC );
	src.addr1 = tunnel->saddr_l.saddr4.sin_addr;

	IKE_PH2ID dst;
	memset( &dst, 0, sizeof( dst ) );
	dst.type = ISAKMP_ID_IPV4_ADDR;
	dst.prot = PROTO_IP_UDP;
	dst.port = htons( UDP_PORT_DHCPS );
	dst.addr1 = tunnel->saddr_r.saddr4.sin_addr;

	return policy_create( tunnel, IPSEC_POLICY_IPSEC, src, dst, false );
}

bool _IKED::policy_dhcp_remove( IDB_TUNNEL * tunnel )
{
	//
	// remove our DHCP over IPsec policies
	//

	log.txt( LLOG_DEBUG, "ii : removing IPsec over DHCP policies\n" );

	IKE_PH2ID src;
	memset( &src, 0, sizeof( src ) );
	src.type = ISAKMP_ID_IPV4_ADDR;
	src.prot = PROTO_IP_UDP;
	src.port = htons( UDP_PORT_DHCPC );
	src.addr1 = tunnel->saddr_l.saddr4.sin_addr;

	IKE_PH2ID dst;
	memset( &dst, 0, sizeof( dst ) );
	dst.type = ISAKMP_ID_IPV4_ADDR;
	dst.prot = PROTO_IP_UDP;
	dst.port = htons( UDP_PORT_DHCPS );
	dst.addr1 = tunnel->saddr_r.saddr4.sin_addr;

	return policy_remove( tunnel, IPSEC_POLICY_IPSEC, src, dst, false );
}

bool _IKED::policy_create( IDB_TUNNEL * tunnel, u_int16_t type, IKE_PH2ID & id1, IKE_PH2ID & id2, bool route )
{
	char txtid_src[ LIBIKE_MAX_TEXTP2ID ];
	char txtid_dst[ LIBIKE_MAX_TEXTP2ID ];

	PFKI_SPINFO spinfo;

	//
	// create inbound policy
	//

	memset( &spinfo, 0, sizeof( spinfo ) );

	spinfo.sp.type = type;
	spinfo.sp.dir = IPSEC_DIR_INBOUND;

	ph2id_paddr( id2, spinfo.paddr_src );
	ph2id_paddr( id1, spinfo.paddr_dst );

	if( type == IPSEC_POLICY_IPSEC )
	{
		spinfo.xforms[ 0 ].proto = PROTO_IP_ESP;
		spinfo.xforms[ 0 ].mode = IPSEC_MODE_TUNNEL;
		spinfo.xforms[ 0 ].level = IPSEC_LEVEL_UNIQUE;
		spinfo.xforms[ 0 ].reqid = policyid++;

		cpy_sockaddr( tunnel->saddr_r.saddr, spinfo.xforms[ 0 ].saddr_src, false );
		cpy_sockaddr( tunnel->saddr_l.saddr, spinfo.xforms[ 0 ].saddr_dst, false );
	}

	text_addr( txtid_src, &spinfo.paddr_src, false, true );
	text_addr( txtid_dst, &spinfo.paddr_dst, false, true );

	log.txt( LLOG_INFO, 
		"ii : creating %s %s policy %s -> %s\n",
		pfki.name( NAME_SPTYPE, spinfo.sp.type ),
		pfki.name( NAME_SPDIR, spinfo.sp.dir ),
		txtid_src,
		txtid_dst );

	pfkey_send_spadd( &spinfo );
	
	//
	// create outbound policy
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
		spinfo.xforms[ 0 ].level = IPSEC_LEVEL_UNIQUE;
		spinfo.xforms[ 0 ].reqid = policyid++;

		cpy_sockaddr( tunnel->saddr_l.saddr, spinfo.xforms[ 0 ].saddr_src, false );
		cpy_sockaddr( tunnel->saddr_r.saddr, spinfo.xforms[ 0 ].saddr_dst, false );
	}

	text_addr( txtid_src, &spinfo.paddr_src, false, true );
	text_addr( txtid_dst, &spinfo.paddr_dst, false, true );

	log.txt( LLOG_INFO, 
		"ii : creating %s %s policy %s -> %s\n",
		pfki.name( NAME_SPTYPE, spinfo.sp.type ),
		pfki.name( NAME_SPDIR, spinfo.sp.dir ),
		txtid_src,
		txtid_dst );

	pfkey_send_spadd( &spinfo );

	//
	// create client policy route
	//

	if( route && ( tunnel->peer->contact == IPSEC_CONTACT_CLIENT ) )
	{
		bool	routed = false;

		switch( type )
		{
			case IPSEC_POLICY_IPSEC:
			{
				in_addr addr = id2.addr1;
				in_addr mask = id2.addr2;

				if( id2.type == ISAKMP_ID_IPV4_ADDR )
					mask.s_addr = 0xffffffff;

				iproute.increment(
					addr,
					mask );

				routed = iproute.add(
							tunnel->xconf.addr,
							true,
							addr,
							mask,
							tunnel->xconf.addr );

				break;
			}

			case IPSEC_POLICY_NONE:
			{
				in_addr	cur_iaddr;
				bool	cur_local;
				in_addr	cur_addr = id2.addr1;
				in_addr	cur_mask;
				in_addr	cur_next;

				routed = iproute.best(
							cur_iaddr,
							cur_local,
							cur_addr,
							cur_mask,
							cur_next );

				if( routed )
				{
					in_addr addr = id2.addr1;
					in_addr mask = id2.addr2;

					if( id2.type == ISAKMP_ID_IPV4_ADDR )
						mask.s_addr = 0xffffffff;

					routed = iproute.add(
								cur_iaddr,
								cur_local,
								addr,
								mask,
								cur_next );
				}

				break;
			}
		}

		if( routed )
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

	return true;
}

bool _IKED::policy_remove( IDB_TUNNEL * tunnel, u_int16_t type, IKE_PH2ID & id1, IKE_PH2ID & id2, bool route )
{
	char txtid_src[ LIBIKE_MAX_TEXTP2ID ];
	char txtid_dst[ LIBIKE_MAX_TEXTP2ID ];

	IDB_POLICY * policy;

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

	if( get_policy(
			false,
			&policy,
			IPSEC_DIR_INBOUND,
			type,
			NULL,
			src,
			dst,
			&id2,
			&id1 ) )
	{
		text_addr( txtid_src, &policy->paddr_src, false, true );
		text_addr( txtid_dst, &policy->paddr_dst, false, true );

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

	if( get_policy(
			false,
			&policy,
			IPSEC_DIR_OUTBOUND,
			type,
			NULL,
			src,
			dst,
			&id1,
			&id2 ) )
	{
		text_addr( txtid_src, &policy->paddr_src, false, true );
		text_addr( txtid_dst, &policy->paddr_dst, false, true );

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
	// remove client policy route
	//

	if( route && ( tunnel->peer->contact == IPSEC_CONTACT_CLIENT ) )
	{
		bool	routed = false;

		switch( type )
		{
			case IPSEC_POLICY_IPSEC:
			{
				in_addr addr = id2.addr1;
				in_addr mask = id2.addr2;

				if( id2.type == ISAKMP_ID_IPV4_ADDR )
					mask.s_addr = 0xffffffff;

				routed = iproute.del(
							tunnel->xconf.addr,
							true,
							addr,
							mask,
							tunnel->xconf.addr );

				iproute.decrement(
					addr,
					mask );
			}

			case IPSEC_POLICY_NONE:
			{
				in_addr	cur_iaddr;
				bool	cur_local;
				in_addr	cur_addr = id2.addr1;
				in_addr	cur_mask;
				in_addr	cur_next;

				routed = iproute.best(
							cur_iaddr,
							cur_local,
							cur_addr,
							cur_mask,
							cur_next );

				if( routed )
				{
					in_addr addr = id2.addr1;
					in_addr mask = id2.addr2;

					if( id2.type == ISAKMP_ID_IPV4_ADDR )
						mask.s_addr = 0xffffffff;

					if( ( cur_addr.s_addr == addr.s_addr ) &&
						( cur_mask.s_addr == mask.s_addr ) )
					{
						routed = iproute.del(
									cur_iaddr,
									cur_local,
									addr,
									mask,
									cur_next );
					}
				}
			}
		}

		if( routed )
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

			log.txt( LLOG_INFO,
				"ii : failed to remove %s policy route for %s\n",
				pfki.name( NAME_SPTYPE, type ),
				txtid_dst );
		}
	}

	return true;
}
