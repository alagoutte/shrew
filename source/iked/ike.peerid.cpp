
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

bool _IKED::gen_ph1id_l( IDB_PH1 * ph1, IKE_PH1ID & ph1id )
{
	ph1id.type = ph1->tunnel->peer->idtype_l;

	switch( ph1id.type )
	{
		case ISAKMP_ID_NONE:
			break;

		case ISAKMP_ID_ASN1_DN:
		{
			if( ph1->tunnel->peer->iddata_l.size() )
			{
				if( !text_asn1(
						ph1->tunnel->peer->iddata_l,
						ph1id.varid ) )
				{
					BDATA temp;
					temp = ph1->tunnel->peer->iddata_l;
					temp.add( "", 1 );

					log.txt( LLOG_ERROR,
						"!! : failed to generate local %s id from \'%s\'\n",
							find_name( NAME_IDENT, ph1id.type ),
							temp.text() );

					return false;
				}
			}
			else
			{
				cert_subj(
					ph1->tunnel->peer->cert_l,
					ph1id.varid );
			}

			break;
		}

		case ISAKMP_ID_IPV4_ADDR:
		{
			if( ph1->tunnel->peer->iddata_l.size() )
			{
				BDATA temp;
				temp = ph1->tunnel->peer->iddata_l;
				temp.add( "", 1 );

				ph1id.addr.s_addr = inet_addr( temp.text() );

				if( ph1id.addr.s_addr == INADDR_NONE )
				{
					log.txt( LLOG_ERROR,
						"!! : failed to generate local %s id from \'%s\'\n",
							find_name( NAME_IDENT, ph1id.type ),
							temp.text() );

					return false;
				}
			}
			else
			{
				ph1id.addr.s_addr =
					ph1->tunnel->saddr_l.saddr4.sin_addr.s_addr;
			}

			break;
		}

		case ISAKMP_ID_FQDN:
		case ISAKMP_ID_USER_FQDN:
		case ISAKMP_ID_KEY_ID:
		{
			ph1id.varid.set( ph1->tunnel->peer->iddata_l );

			break;
		}

		default:
		{
			log.txt( LLOG_ERROR,
				"!! : failed to generate local id for unknown type %i\n",
				ph1id.type );

			return false;
		}
	}

	return true;
}

bool _IKED::gen_ph1id_r( IDB_PH1 * ph1, IKE_PH1ID & ph1id )
{
	ph1id.type = ph1->tunnel->peer->idtype_r;

	switch( ph1id.type )
	{
		case ISAKMP_ID_NONE:
			break;

		case ISAKMP_ID_ASN1_DN:
		{
			if( ph1->tunnel->peer->iddata_r.size() )
			{
				if( !text_asn1(
						ph1->tunnel->peer->iddata_r,
						ph1id.varid ) )
				{
					BDATA temp;
					temp = ph1->tunnel->peer->iddata_r;
					temp.add( "", 1 );

					log.txt( LLOG_ERROR,
						"!! : failed to generate remote %s id from \'%s\'\n",
							find_name( NAME_IDENT, ph1id.type ),
							temp.text() );

					return false;
				}
			}

			break;
		}

		case ISAKMP_ID_IPV4_ADDR:
		{
			if( ph1->tunnel->peer->iddata_r.size() )
			{
				BDATA temp;
				temp = ph1->tunnel->peer->iddata_r;
				temp.add( "", 1 );

				ph1id.addr.s_addr = inet_addr( temp.text() );

				if( ph1id.addr.s_addr == INADDR_NONE )
				{
					log.txt( LLOG_ERROR,
						"!! : failed to generate remote %s id from \'%s\'\n",
							find_name( NAME_IDENT, ph1id.type ),
							temp.text() );

					return false;
				}
			}
			else
			{
				ph1id.addr.s_addr =
					ph1->tunnel->saddr_r.saddr4.sin_addr.s_addr;
			}

			break;
		}

		case ISAKMP_ID_FQDN:
		case ISAKMP_ID_USER_FQDN:
		case ISAKMP_ID_KEY_ID:
		{
			ph1id.varid.set( ph1->tunnel->peer->iddata_r );

			break;
		}

		default:
		{
			log.txt( LLOG_ERROR,
				"!! : failed to generate remote id for unknown type %i\n",
				ph1id.type );

			return false;
		}
	}

	return true;
}

bool _IKED::cmp_ph1id( IKE_PH1ID & idt, IKE_PH1ID & ids, bool natt )
{
	static const char * expl_natt = "( natt prevents ip match )";
	static const char * expl_cert = "( cert check only )";
	static const char * expl_none = "";
	const char * expl = expl_none;

	//
	// compare the peer id received
	// with our generated peer id
	//

	if( ( ids.type != idt.type ) &&	( idt.type != ISAKMP_ID_NONE ) )
	{
		log.txt( LLOG_ERROR, 
			"!! : phase1 id type mismatch ( received %s but expected %s )\n",
			find_name( NAME_IDENT, ids.type ),
			find_name( NAME_IDENT, idt.type ) );

		return false;
	}

	//
	// match the id value
	//

	bool match = true;

	switch( idt.type )
	{
		case ISAKMP_ID_NONE:
			log.txt( LLOG_INFO, 
				"ii : phase1 id target is any\n" );
			break;

		case ISAKMP_ID_IPV4_ADDR:
		{
			if( natt )
				expl = expl_natt;
			else
				if( ids.addr.s_addr != idt.addr.s_addr )
					match = false;

			break;
		}

		case ISAKMP_ID_FQDN:
		case ISAKMP_ID_USER_FQDN:
		case ISAKMP_ID_KEY_ID:
		{
			ids.varid.add( 0, 1 );
			idt.varid.add( 0, 1 );

			if( ids.varid != idt.varid )
				match = false;

			break;
		}

		case ISAKMP_ID_ASN1_DN:
		case ISAKMP_ID_ASN1_GN:
		{
			//
			// if we have a specific name
			// to comapre against, check
			// it now. otherwise only use
			// the id to verify the cert
			// subject
			//

			if( idt.varid.size() )
			{
				BDATA idts;
				BDATA idtt;

				asn1_text( ids.varid, idts );
				asn1_text( idt.varid, idtt );

				idts.add( 0, 1 );
				idtt.add( 0, 1 );

				if( idts != idtt )
					match = false;
			}
			else
				expl = expl_cert;

			break;
		}

		default:
		{
			log.txt( LLOG_ERROR, 
				"!! : phase1 id mismatch ( internal error )\n" );

			return false;
		}
	}

	if( match )
	{
		//
		// generate text id for logging
		//

		char txtid[ LIBIKE_MAX_TEXTP1ID ];
		text_ph1id( txtid, &ids );

		log.txt( LLOG_INFO,
			"ii : phase1 id match %s\n"
			"ii : received = %s\n",
			expl,
			txtid );
	}
	else
	{
		//
		// generate text ids for logging
		//

		char txtid_s[ LIBIKE_MAX_TEXTP1ID ];
		text_ph1id( txtid_s, &ids );

		char txtid_t[ LIBIKE_MAX_TEXTP1ID ];
		text_ph1id( txtid_t, &idt );


		log.txt( LLOG_ERROR, 
			"!! : phase1 id mismatch %s\n"
			"!! : received = %s\n"
			"!! : expected = %s\n",
			expl,
			txtid_s,
			txtid_t );
	}

	return match;
}

bool _IKED::cmp_ph2id( IKE_PH2ID & idt, IKE_PH2ID & ids, bool exact )
{
	//
	// exact match option enforces
	// like id value types
	//

	if( exact )
		if( ids.type != idt.type )
			return false;

	//
	// compare protocol value
	//

	if( ids.prot != idt.prot )
		return false;

	//
	// compare port value
	//

	if( ids.port != idt.port )
		return false;

	//
	// inclusive match
	//

	switch( ids.type )
	{
		case ISAKMP_ID_NONE:
		{
			//
			// anything to ...
			//

			return true;
		}

		case ISAKMP_ID_IPV4_ADDR:
		{
			switch( idt.type )
			{
				//
				// ipv4 address to ipv4 address
				//

				case ISAKMP_ID_IPV4_ADDR:
				{
					//
					// is ids's address euqal to
					// idt's address
					//

					if( ids.addr1.s_addr != idt.addr1.s_addr )
						return false;

					break;
				}

				//
				// ipv4 address to ipv4 network
				//

				case ISAKMP_ID_IPV4_ADDR_SUBNET:
				{
					//
					// convert to subnet addresses
					//

					unsigned long subnet1 = idt.addr1.s_addr & idt.addr2.s_addr;
					unsigned long subnet2 = ids.addr1.s_addr & idt.addr2.s_addr;

					//
					// is ids's subnet address equal
					// to idt's subnet address
					//

					if( subnet2 != subnet1 )
						return false;

					break;
				}

				//
				// ipv4 address to ipv4 range
				//

				case ISAKMP_ID_IPV4_ADDR_RANGE:
				{
					//
					// is ids's address within idt's
					// address range
					//

					if( ( ids.addr1.s_addr < idt.addr1.s_addr ) &&
						( ids.addr1.s_addr > idt.addr2.s_addr ) )
						return false;

					break;
				}
			}

			break;
		}

		case ISAKMP_ID_IPV4_ADDR_SUBNET:
		{
			switch( idt.type )
			{
				//
				// ipv4 network to ipv4 address
				//

				case ISAKMP_ID_IPV4_ADDR:
				{
					//
					// is ids's address equal to
					// idt's subnet address with
					// idt's netmask being 32 bits
					//

					if( ( ids.addr1.s_addr != idt.addr1.s_addr ) ||
						( ids.addr2.s_addr != 0xffffffff ) )
						return false;

					break;
				}

				//
				// ipv4 network to ipv4 network
				//

				case ISAKMP_ID_IPV4_ADDR_SUBNET:
				{
					//
					// is ids's subnet address and mask equal
					//

					if( ( ids.addr1.s_addr != idt.addr1.s_addr ) ||
						( ids.addr2.s_addr != idt.addr2.s_addr ) )
						return false;

					break;
				}

				//
				// ipv4 network to ipv4 range
				//

				case ISAKMP_ID_IPV4_ADDR_RANGE:
				{
					return false;
				}
			}

			break;
		}

		case ISAKMP_ID_IPV4_ADDR_RANGE:
		{
			//
			// ipv4 range to ...
			//

			return false;
		}
	}

	return true;
}

