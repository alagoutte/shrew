
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

long _IKED::phase1_gen_prop( IDB_PH1 * ph1 )
{
	//
	// phase1 proposals are described internally
	// as a list of proposal structures. since
	// isakmp only uses one proposal per sa, the
	// ony values that vary are transform values
	//

	unsigned char tnumb = 0;

	// cipher algorithms

	unsigned short clist[] =
	{
		IKE_CIPHER_AES,
		IKE_CIPHER_BLOWFISH,
		IKE_CIPHER_3DES,
		IKE_CIPHER_CAST,
		IKE_CIPHER_DES
	};

	// hash algorithms

	unsigned short hlist[] =
	{
		IKE_HASH_MD5,
		IKE_HASH_SHA1
	};

	// dh groups

	unsigned short glist[] =
	{
		IKE_GRP_GROUP14,
		IKE_GRP_GROUP5,
		IKE_GRP_GROUP2,
		IKE_GRP_GROUP1
	};

	//
	// acquire our peer isakmp proposal
	//

	IKE_PROPOSAL * peerprop;
	if( !ph1->tunnel->peer->proposals.get( &peerprop, 0, ISAKMP_PROTO_ISAKMP ) )
		return LIBIKE_FAILED;

	//
	// step through the cipher list
	//

	long ccount = sizeof( clist ) / sizeof( unsigned short );
	long cindex = 0;

	//
	// restrict to specified cipher
	//

	if( peerprop->ciph_id )
	{
		clist[ 0 ] = peerprop->ciph_id;
		ccount = 1;
	}

	for( ; cindex < ccount; cindex++ )
	{
		//
		// determine valid key sizes
		//

		short klen = 0;
		short kmin = 0;
		short step = 1;

		switch( clist[ cindex ] )
		{
			case IKE_CIPHER_AES:
			case IKE_CIPHER_BLOWFISH:

				klen = 256;
				kmin = 128;
				step = 64;

				break;
		}

		//
		// restrict to specified key size
		//

		if( peerprop->ciph_kl )
		{
			klen = peerprop->ciph_kl;
			kmin = klen;
		}

		//
		// step through key sizes
		//

		for( ; klen >= kmin; klen -= step )
		{
			//
			// step through the hash list
			//

			long hcount = sizeof( hlist ) / sizeof( unsigned short );
			long hindex = 0;

			//
			// restrict to specified hash
			//

			if( peerprop->hash_id )
			{
				hlist[ 0 ] = peerprop->hash_id;
				hcount = 1;
			}

			for( ; hindex < hcount; hindex++ )
			{
				//
				// step through the dh group list
				//

				long gcount = sizeof( glist ) / sizeof( unsigned short );
				long gindex = 0;

				//
				// restrict to specified hash
				//

				if( peerprop->dhgr_id )
				{
					glist[ 0 ] = peerprop->dhgr_id;
					gcount = 1;
				}

				for( ; gindex < gcount; gindex++ )
				{
					//
					// build proposal transform
					//

					IKE_PROPOSAL proposal;
					memset( &proposal, 0, sizeof( proposal ) );

					proposal.pnumb = 1;
					proposal.tnumb = ++tnumb;
					proposal.proto = ISAKMP_PROTO_ISAKMP;
					proposal.xform = IKE_ATTR_TRANSFORM;

					proposal.ciph_id = clist[ cindex ];
					proposal.ciph_kl = klen;
					proposal.hash_id = hlist[ hindex ];
					proposal.dhgr_id = glist[ gindex ];

					proposal.auth_id = peerprop->auth_id;

					proposal.life_sec = peerprop->life_sec;
					proposal.life_kbs = peerprop->life_kbs;

					//
					// add proposal transform
					//

					ph1->plist_l.add( &proposal, ( tnumb == 1 ) );
				}
			}
		}
	}

	return LIBIKE_OK;
}

long _IKED::phase1_sel_prop( IDB_PH1 * ph1 )
{
	//
	// attempt to match a phase1 proposal that
	// was sumitted by the remote peer
	//

	//
	// step through our local proposal list
	//

	IKE_PROPOSAL * lproposal;

	long lpindex = 0;
	long ltcount;
	long ltindex;

	while( ph1->plist_l.nextp( &lproposal, lpindex, ltindex, ltcount ) )
	{
		//
		// step through our remote proposal list
		//

		IKE_PROPOSAL * rproposal;

		long rpindex = 0;
		long rtcount;
		long rtindex;

		while( ph1->plist_r.nextp( &rproposal, rpindex, rtindex, rtcount ) )
		{
			//
			// step through the local tranform list
			//

			while( ph1->plist_l.nextt( &lproposal, ltindex ) )
			{
				//
				// step through the remote transform list
				//

				long ttindex = rtindex;

				while( ph1->plist_r.nextt( &rproposal, ttindex ) )
				{
					//
					// match all other information
					//

					if( !phase1_cmp_prop(
							rproposal,
							lproposal,
							ph1->initiator,
							ph1->tunnel->peer->life_check ) )
						continue;

					//
					// we found a match
					//

					IKE_PROPOSAL ltemp;
					IKE_PROPOSAL rtemp;

					memcpy( &ltemp, lproposal, sizeof( ltemp ) );
					memcpy( &rtemp, rproposal, sizeof( rtemp ) );

					ph1->plist_l.clean();
					ph1->plist_r.clean();

					//
					// check and potentialy modify lifetime
					// values if we are the responder
					//

					if( !ph1->initiator )
					{
						switch( ph1->tunnel->peer->life_check )
						{
							case LTIME_OBEY:
							{
								//
								// always use the initiators
								//

								if( ltemp.life_sec != rtemp.life_sec )
								{
									log.txt( LLOG_INFO,
										"ii : adjusting %s lifetime %i -> %i ( obey )\n",
										find_name( NAME_PROTOCOL, ltemp.proto ),
										ltemp.life_sec,
										rtemp.life_sec );

									ltemp.life_sec = rtemp.life_sec;
								}
							}

							case LTIME_CLAIM:
							{
								//
								// use initiators when shorter
								//

								if( ltemp.life_sec > rtemp.life_sec )
								{
									log.txt( LLOG_INFO,
										"ii : adjusting %s lifetime %i -> %i ( claim )\n",
										find_name( NAME_PROTOCOL, ltemp.proto ),
										ltemp.life_sec,
										rtemp.life_sec );

									ltemp.life_sec = rtemp.life_sec;
								}

								//
								// use responders when shorter and log
								//

								if( ltemp.life_sec < rtemp.life_sec )
								{
									log.txt( LLOG_INFO,
										"ii : using responder %s lifetime %i seconds, initiators is longer ( claim )\n",
										find_name( NAME_PROTOCOL, ltemp.proto ),
										ltemp.life_sec );
								}
							}

							case LTIME_STRICT:
							{
								//
								// use initiators when shorter
								//

								if( ltemp.life_sec > rtemp.life_sec )
								{
									log.txt( LLOG_INFO,
										"ii : adjusting %s lifetime %i -> %i ( strict )\n",
										find_name( NAME_PROTOCOL, ltemp.proto ),
										ltemp.life_sec,
										rtemp.life_sec );

									ltemp.life_sec = rtemp.life_sec;
								}
							}
						}
					}

					//
					// set protocol and transform number
					//

					ltemp.pnumb = rtemp.pnumb;
					ltemp.tnumb = rtemp.tnumb;

					//
					// we found a proposal and transform
					// match, add them to our lists
					//

					ph1->plist_l.add( &ltemp, true );
					ph1->plist_r.add( &rtemp, true );

					return LIBIKE_OK;
				}
			}
		}
	}

	return LIBIKE_FAILED;
}

bool _IKED::phase1_cmp_prop( IKE_PROPOSAL * proposal1, IKE_PROPOSAL * proposal2, bool initiator, long life_check )
{
	//
	// check proposal protocol
	//

	if( proposal1->proto != proposal2->proto )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched phase1 proposal/transform\n"
			"ii : protocol ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( NAME_PROTOCOL, proposal2->proto ) );

		return false;
	}

	//
	// validate phase1 protocol
	//

	long xtype = 0;
	long htype = NAME_MAUTH;

	switch( proposal2->proto )
	{
		case ISAKMP_PROTO_ISAKMP:
			xtype = NAME_XFORM_ISAKMP;
			break;

		default:
		{
			log.txt( LLOG_DEBUG,
				"ii : internal error, phase1 protocol unknown %i\n",
				proposal2->proto );

			return false;
		}
	}

	//
	// check proposal transform type
	//

	if( proposal1->xform != proposal2->xform )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : crypto transform type ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( xtype, proposal1->xform ),
			find_name( xtype, proposal2->xform ) );

		return false;
	}

	//
	// check cipher selection
	//

	if( proposal1->ciph_id != proposal2->ciph_id )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : cipher type ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( NAME_CIPHER, proposal1->ciph_id ),
			find_name( NAME_CIPHER, proposal2->ciph_id ) );

		return false;
	}

	//
	// check cipher key legth
	//

	if( proposal1->ciph_kl != proposal2->ciph_kl )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : key length ( %i != %i )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			proposal1->ciph_kl,
			proposal2->ciph_kl );

		return false;
	}

	//
	// check hash selection
	//

	if( proposal1->hash_id != proposal2->hash_id )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : hash type ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( htype, proposal1->hash_id ),
			find_name( htype, proposal2->hash_id ) );

		return false;
	}

	//
	// check dh group description
	//

	if( proposal1->dhgr_id != proposal2->dhgr_id )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : dh group description ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( NAME_GROUP, proposal1->dhgr_id ),
			find_name( NAME_GROUP, proposal2->dhgr_id ) );

		return false;
	}

	//
	// check authentication method
	//

	if( proposal1->auth_id != proposal2->auth_id )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : hmac type ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( NAME_PAUTH, proposal1->auth_id ),
			find_name( NAME_PAUTH, proposal2->auth_id ) );

		return false;
	}

	//
	// check lifetime values
	//

	if( !initiator )
	{
		switch( life_check )
		{
			case LTIME_OBEY:
			case LTIME_CLAIM:
				break;

			case LTIME_STRICT:
			{
				if( proposal1->life_sec < proposal2->life_sec )
				{
					log.txt( LLOG_DEBUG,
						"ii : unmatched %s proposal/transform\n"
						"ii : lifetime seconds ( %i < %i strict )\n",
						find_name( NAME_PROTOCOL, proposal1->proto ),
						proposal1->life_sec,
						proposal2->life_sec );

					return false;
				}

				break;
			}

			case LTIME_EXACT:
			{
				if( proposal1->life_sec != proposal2->life_sec )
				{
					log.txt( LLOG_DEBUG,
						"ii : unmatched %s proposal/transform\n"
						"ii : lifetime seconds ( %i != %i exact )\n",
						find_name( NAME_PROTOCOL, proposal1->proto ),
						proposal1->life_sec,
						proposal2->life_sec );

					return false;
				}

				break;
			}
		}
	}

	//
	// check peer for RFC compliance
	//

	if( initiator )
		if( proposal1->tnumb != proposal2->tnumb )
			log.txt( LLOG_ERROR,
				"!! : peer violates RFC, transform number mismatch ( %i != %i )\n",
				proposal1->tnumb,
				proposal2->tnumb );

	//
	// proposal and transform matched
	//

	char klentxt[ 32 ];
	if( proposal1->ciph_kl )
		sprintf_s( klentxt, 32, "%i bits", proposal1->ciph_kl );
	else
		sprintf_s( klentxt, 32, "default" );

	log.txt( LLOG_INFO,
		"ii : matched %s proposal #%i transform #%i\n"
		"ii : - transform    = %s\n"
		"ii : - cipher type  = %s\n"
		"ii : - key length   = %s\n"
		"ii : - hash type    = %s\n"
		"ii : - dh group     = %s\n"
		"ii : - auth type    = %s\n"
		"ii : - life seconds = %i\n"
		"ii : - life kbytes  = %i\n",
		find_name( NAME_PROTOCOL, proposal1->proto ),
		proposal1->pnumb,
		proposal1->tnumb,
		find_name( xtype, proposal1->xform ),
		find_name( NAME_CIPHER, proposal1->ciph_id ),
		klentxt,
		find_name( NAME_HASH, proposal1->hash_id ),
		find_name( NAME_GROUP, proposal1->dhgr_id ),
		find_name( NAME_PAUTH, proposal1->auth_id ),
		proposal1->life_sec,
		proposal1->life_kbs );

	return true;
}

long _IKED::phase2_gen_prop( IDB_PH2 * ph2, IDB_POLICY * policy )
{
	//
	// phase2 proposals are described internally
	// as a list of proposal structures. we use
	// the caller supplied policy to generate a
	// list of complimentary proposal bundles
	//

	long xindex	= PFKI_MAX_XFORMS - 1;

	while( xindex >= 0 )
	{
		//
		// determine the protection suite
		//

		unsigned char tnumb = 0;

		switch( policy->xforms[ xindex ].proto )
		{
			//
			// AH
			//

			case PROTO_IP_AH:
			{
				// transform types

				unsigned char tlist[] =
				{
					ISAKMP_AH_MD5,
					ISAKMP_AH_SHA,
					ISAKMP_AH_SHA256,
					ISAKMP_AH_SHA384,
					ISAKMP_AH_SHA512,
				};

				//
				// acquire our peer ah proposal
				//

				IKE_PROPOSAL * peerprop;
				if( !ph2->tunnel->peer->proposals.get( &peerprop, 0, ISAKMP_PROTO_IPSEC_AH ) )
					break;

				//
				// step through the transform list
				//

				long tcount = sizeof( tlist ) / sizeof( unsigned char );
				long tindex = 0;

				//
				// restrict to specified transform
				//

				if( peerprop->xform )
				{
					tlist[ 0 ] = peerprop->xform;
					tcount = 1;
				}

				for( ; tindex < tcount; tindex++ )
				{
					//
					// build proposal transform
					//

					IKE_PROPOSAL proposal;
					memset( &proposal, 0, sizeof( proposal ) );

					proposal.pnumb = 1;
					proposal.tnumb = ++tnumb;
					proposal.proto = peerprop->proto;

					if( policy->xforms[ xindex ].mode == IPSEC_MODE_TUNNEL )
						proposal.encap = ISAKMP_ENCAP_TUNNEL;
					else
						proposal.encap = ISAKMP_ENCAP_TRANSPORT;

					proposal.xform = tlist[ tindex ];

					switch( proposal.xform )
					{
						case ISAKMP_AH_MD5:
							proposal.hash_id = ISAKMP_AUTH_HMAC_MD5;
							break;

						case ISAKMP_AH_SHA:
							proposal.hash_id = ISAKMP_AUTH_HMAC_SHA1;
							break;

						case ISAKMP_AH_SHA256:
							proposal.hash_id = ISAKMP_AUTH_HMAC_SHA2_256;
							break;

						case ISAKMP_AH_SHA384:
							proposal.hash_id = ISAKMP_AUTH_HMAC_SHA2_384;
							break;

						case ISAKMP_AH_SHA512:
							proposal.hash_id = ISAKMP_AUTH_HMAC_SHA2_512;
							break;
					}

					proposal.life_sec = peerprop->life_sec;
					proposal.life_kbs = peerprop->life_kbs;

					//
					// add proposal transform
					//

					ph2->plist_l.add( &proposal, ( tnumb == 1 ) );
				}

				break;
			}

			//
			// ESP
			//

			case PROTO_IP_ESP:
			{
				// transform types

				unsigned char tlist[] =
				{
					ISAKMP_ESP_AES,
					ISAKMP_ESP_BLOWFISH,
					ISAKMP_ESP_3DES,
					ISAKMP_ESP_CAST,
					ISAKMP_ESP_DES
				};

				// authentication algorithms

				unsigned short alist[] =
				{
					ISAKMP_AUTH_HMAC_MD5,
					ISAKMP_AUTH_HMAC_SHA1,
					ISAKMP_AUTH_HMAC_SHA2_256,
					ISAKMP_AUTH_HMAC_SHA2_384,
					ISAKMP_AUTH_HMAC_SHA2_512
				};

				//
				// acquire our peer esp proposal
				//

				IKE_PROPOSAL * peerprop;
				if( !ph2->tunnel->peer->proposals.get( &peerprop, 0, ISAKMP_PROTO_IPSEC_ESP ) )
					break;

				//
				// step through the transform list
				//

				long tcount = sizeof( tlist ) / sizeof( unsigned char );
				long tindex = 0;

				//
				// restrict to specified transform
				//

				if( peerprop->xform )
				{
					tlist[ 0 ] = peerprop->xform;
					tcount = 1;
				}

				for( ; tindex < tcount; tindex++ )
				{
					//
					// determine valid key sizes
					//

					short klen = 0;
					short kmin = 0;
					short step = 1;

					switch( tlist[ tindex ] )
					{
						case ISAKMP_ESP_AES:
						case ISAKMP_ESP_BLOWFISH:

							klen = 256;
							kmin = 128;
							step = 64;

							break;
					}

					//
					// restrict to specified key size
					//

					if( peerprop->ciph_kl )
					{
						klen = peerprop->ciph_kl;
						kmin = klen;
					}

					//
					// step through key sizes
					//

					for( ; klen >= kmin; klen -= step )
					{
						//
						// step through the auth list
						//

						long acount = sizeof( alist ) / sizeof( unsigned short );
						long aindex = 0;

						//
						// restrict to specified msg auth
						//

						if( peerprop->hash_id )
						{
							alist[ 0 ] = peerprop->hash_id;
							acount = 1;
						}

						for( ; aindex < acount; aindex++ )
						{
							//
							// build proposal transform
							//

							IKE_PROPOSAL proposal;
							memset( &proposal, 0, sizeof( proposal ) );

							proposal.pnumb = 1;
							proposal.tnumb = ++tnumb;
							proposal.proto = peerprop->proto;
							proposal.xform = tlist[ tindex ];

							//
							// if natt was negotiated we need to
							// fix-up the encapsulation mode for
							// esp negotiations
							//

							if( policy->xforms[ xindex ].mode == IPSEC_MODE_TUNNEL )
							{
								switch( ph2->tunnel->natt_version )
								{
									case IPSEC_NATT_NONE:
									case IPSEC_NATT_CISCO:
										proposal.encap = ISAKMP_ENCAP_TUNNEL;
										break;

									case IPSEC_NATT_V00:
									case IPSEC_NATT_V01:
									case IPSEC_NATT_V02:
									case IPSEC_NATT_V03:
										proposal.encap = ISAKMP_ENCAP_VXX_UDP_TUNNEL;
										break;

									case IPSEC_NATT_RFC:
										proposal.encap = ISAKMP_ENCAP_RFC_UDP_TUNNEL;
										break;
								}
							}
							else
							{
								switch( ph2->tunnel->natt_version )
								{
									case IPSEC_NATT_NONE:
									case IPSEC_NATT_CISCO:
										proposal.encap = ISAKMP_ENCAP_TRANSPORT;
										break;

									case IPSEC_NATT_V00:
									case IPSEC_NATT_V01:
									case IPSEC_NATT_V02:
									case IPSEC_NATT_V03:
										proposal.encap = ISAKMP_ENCAP_VXX_UDP_TRANSPORT;
										break;

									case IPSEC_NATT_RFC:
										proposal.encap = ISAKMP_ENCAP_RFC_UDP_TRANSPORT;
										break;
								}
							}

							proposal.ciph_kl = klen;
							proposal.hash_id = alist[ aindex ];

							//
							// the config pfs group overrides
							// the proposal setting
							//

							if( ph2->tunnel->xconf.dhgr )
								proposal.dhgr_id = ph2->tunnel->xconf.dhgr;
							else
								proposal.dhgr_id = peerprop->dhgr_id;

							if( proposal.dhgr_id )
								ph2->dhgr_id = proposal.dhgr_id;

							//
							// set proposal lifetime values
							//

							proposal.life_sec = peerprop->life_sec;
							proposal.life_kbs = peerprop->life_kbs;

							//
							// add proposal transform
							//

							ph2->plist_l.add( &proposal, ( tnumb == 1 ) );
						}
					}
				}

				break;
			}

			//
			// IPCOMP
			//

			case PROTO_IP_IPCOMP:
			{
				// transform types

				unsigned char tlist[] =
				{
					ISAKMP_IPCOMP_DEFLATE,
					ISAKMP_IPCOMP_LZS
				};

				//
				// acquire our peer ipcomp proposal
				//

				IKE_PROPOSAL * peerprop;
				if( !ph2->tunnel->peer->proposals.get( &peerprop, 0, ISAKMP_PROTO_IPCOMP ) )
					break;

				//
				// step through the transform list
				//

				long tcount = sizeof( tlist ) / sizeof( unsigned char );
				long tindex = 0;

				//
				// restrict to specified transform
				//

				if( peerprop->xform )
				{
					tlist[ 0 ] = peerprop->xform;
					tcount = 1;
				}

				for( ; tindex < tcount; tindex++ )
				{
					//
					// build proposal transform
					//

					IKE_PROPOSAL proposal;
					memset( &proposal, 0, sizeof( proposal ) );

					proposal.pnumb = 1;
					proposal.tnumb = ++tnumb;
					proposal.proto = peerprop->proto;

					if( policy->xforms[ xindex ].mode == IPSEC_MODE_TUNNEL )
						proposal.encap = ISAKMP_ENCAP_TUNNEL;
					else
						proposal.encap = ISAKMP_ENCAP_TRANSPORT;

					proposal.xform = tlist[ tindex ];

					proposal.life_sec = peerprop->life_sec;
					proposal.life_kbs = peerprop->life_kbs;

					//
					// add proposal transform
					//

					ph2->plist_l.add( &proposal, ( tnumb == 1 ) );
				}

				break;
			}
		}

		xindex--;
	}

	return LIBIKE_OK;
}

long _IKED::phase2_sel_prop( IDB_PH2 * ph2 )
{
	//
	// attempt to match a phase2 proposal
	// bundle to a local proposal bundle
	//

	IDB_LIST_PROPOSAL plist_l;
	IDB_LIST_PROPOSAL plist_r;

	//
	// step through our local bundles
	//

	long lbindex = 0;
	long lpindex;
	long lpcount;

	while( ph2->plist_l.nextb( lbindex, lpindex, lpcount ) )
	{
		//
		// step through our remote bundles
		//

		plist_l.clean();

		long rbindex = 0;
		long rpindex;
		long rpcount;

		while( ph2->plist_r.nextb( rbindex, rpindex, rpcount ) )
		{
			//
			// check that the local and remote
			// bundles have the same proposal
			// count
			//

			plist_r.clean();

			if( rpcount != lpcount )
				continue;

			//
			// step through our local proposals
			//

			IKE_PROPOSAL * lproposal;

			long ltcount;
			long ltindex;

			while( ph2->plist_l.nextp( &lproposal, lpindex, ltindex, ltcount ) )
			{
				//
				// step through our remote proposals
				//

				IKE_PROPOSAL * rproposal;

				long rtcount;
				long rtindex;

				bool ptmatch = false;

				while( !ptmatch && ph2->plist_r.nextp( &rproposal, rpindex, rtindex, rtcount ) )
				{
					//
					// step through the local tranforms
					//

					while( !ptmatch && ph2->plist_l.nextt( &lproposal, ltindex ) )
					{
						//
						// step through the remote transforms
						//

						long ttindex = rtindex;

						while( !ptmatch && ph2->plist_r.nextt( &rproposal, ttindex ) )
						{
							//
							// match the proposal / transform info
							//

							if( !phase2_cmp_prop(
									rproposal,
									lproposal,
									ph2->initiator,
									ph2->tunnel->peer->life_check ) )
								continue;

							//
							// we found a proposal and transform
							// match for this entry of a bundle,
							// add them to our temporary lists
							//

							plist_l.add( lproposal, true );
							plist_r.add( rproposal, true );

							ptmatch = true;
						}
					}
				}
			}
		}

		//
		// if the temporary proposal list
		// contains the same entry count
		// as the local bundle, we found
		// a match
		//

		if( plist_l.count() == lpcount )
		{
			ph2->plist_l.clean();
			ph2->plist_r.clean();

			long lpindex = 0;
			long rpindex = 0;

			long tcount;
			long tindex;

			while( true )
			{
				IKE_PROPOSAL * lproposal;
				IKE_PROPOSAL * rproposal;

				if( ( !plist_l.nextp( &lproposal, lpindex, tindex, tcount ) ) ||
					( !plist_r.nextp( &rproposal, rpindex, tindex, tcount ) ) )
					break;

				//
				// set protocol and transform number
				//

				lproposal->pnumb = rproposal->pnumb;
				lproposal->tnumb = rproposal->tnumb;

				//
				// check and potentialy modify lifetime
				// values if we are the responder
				//

				if( !ph2->initiator )
				{
					switch( ph2->tunnel->peer->life_check )
					{
						case LTIME_OBEY:
						{
							//
							// always use the initiators
							//

							if( lproposal->life_sec != rproposal->life_sec )
							{
								log.txt( LLOG_INFO,
									"ii : adjusting %s lifetime %i -> %i ( obey )\n",
									find_name( NAME_PROTOCOL, lproposal->proto ),
									lproposal->life_sec,
									rproposal->life_sec );

								lproposal->life_sec = rproposal->life_sec;
							}
						}

						case LTIME_CLAIM:
						{
							//
							// use initiators when shorter
							//

							if( lproposal->life_sec > rproposal->life_sec )
							{
								log.txt( LLOG_INFO,
									"ii : adjusting %s lifetime %i -> %i ( claim )\n",
									find_name( NAME_PROTOCOL, lproposal->proto ),
									lproposal->life_sec,
									rproposal->life_sec );

								lproposal->life_sec = rproposal->life_sec;
							}

							//
							// use responders when shorter, log and notify
							//

							if( lproposal->life_sec < rproposal->life_sec )
							{
								log.txt( LLOG_INFO,
									"ii : using responder %s lifetime %i seconds, initiators is longer ( claim )\n",
									find_name( NAME_PROTOCOL, lproposal->proto ),
									lproposal->life_sec );

								ph2->lstate |= LSTATE_CLAIMLT;
							}
						}

						case LTIME_STRICT:
						{
							//
							// use initiators when shorter
							//

							if( lproposal->life_sec > rproposal->life_sec )
							{
								log.txt( LLOG_INFO,
									"ii : adjusting %s lifetime %i -> %i ( strict )\n",
									find_name( NAME_PROTOCOL, lproposal->proto ),
									lproposal->life_sec,
									rproposal->life_sec );

								lproposal->life_sec = rproposal->life_sec;
							}
						}
					}
				}

				//
				// add to our permanent list 
				//

				ph2->plist_l.add( lproposal, true );
				ph2->plist_r.add( rproposal, true );
			}

			return LIBIKE_OK;
		}
	}

	return LIBIKE_FAILED;
}

bool _IKED::phase2_cmp_prop( IKE_PROPOSAL * proposal1, IKE_PROPOSAL * proposal2, bool initiator, long life_check )
{
	//
	// check proposal protocol
	//

	if( proposal1->proto != proposal2->proto )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched proposal protocol\n"
			"ii : protocol ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( NAME_PROTOCOL, proposal2->proto ) );

		return false;
	}

	//
	// validate phase2 protocol
	//

	long xtype = 0;
	long htype = NAME_MAUTH;

	switch( proposal2->proto )
	{
		case ISAKMP_PROTO_IPSEC_AH:
			xtype = NAME_XFORM_AH;
			break;

		case ISAKMP_PROTO_IPSEC_ESP:
			xtype = NAME_XFORM_ESP;
			break;

		case ISAKMP_PROTO_IPCOMP:
			xtype = NAME_XFORM_IPCOMP;
			break;

		default:
		{
			log.txt( LLOG_ERROR,
				"!! : internal error, phase2 protocol unknown %i\n",
				proposal2->proto );

			return false;
		}
	}

	//
	// check proposal transform type
	//

	if( proposal1->xform != proposal2->xform )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : crypto transform type ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( xtype, proposal1->xform ),
			find_name( xtype, proposal2->xform ) );

		return false;
	}

	//
	// check transform key legth
	//

	if( proposal1->ciph_kl != proposal2->ciph_kl )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : key length ( %i != %i )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			proposal1->ciph_kl,
			proposal2->ciph_kl );

		return false;
	}

	//
	// check proposal encap mode
	//

	if( proposal1->encap != proposal2->encap )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : encapsulation mode ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( NAME_ENCAP, proposal1->encap ),
			find_name( NAME_ENCAP, proposal2->encap ) );

		return false;
	}

	//
	// check message auth selection
	//

	if( proposal1->hash_id != proposal2->hash_id )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : msg auth ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( htype, proposal1->hash_id ),
			find_name( htype, proposal2->hash_id ) );

		return false;
	}

	//
	// check pfs dh group description
	//

	if( proposal1->dhgr_id != proposal2->dhgr_id )
	{
		log.txt( LLOG_DEBUG,
			"ii : unmatched %s proposal/transform\n"
			"ii : pfs dh group description ( %s != %s )\n",
			find_name( NAME_PROTOCOL, proposal1->proto ),
			find_name( NAME_GROUP, proposal1->dhgr_id ),
			find_name( NAME_GROUP, proposal2->dhgr_id ) );

		return false;
	}

	//
	// check lifetime values
	//

	if( !initiator )
	{
		switch( life_check )
		{
			case LTIME_OBEY:
			case LTIME_CLAIM:
				break;

			case LTIME_STRICT:
			{
				if( proposal1->life_sec < proposal2->life_sec )
				{
					log.txt( LLOG_DEBUG,
						"ii : unmatched %s proposal/transform\n"
						"ii : lifetime seconds ( %i < %i strict )\n",
						find_name( NAME_PROTOCOL, proposal1->proto ),
						proposal1->life_sec,
						proposal2->life_sec );

					return false;
				}

				break;
			}

			case LTIME_EXACT:
			{
				if( proposal1->life_sec != proposal2->life_sec )
				{
					log.txt( LLOG_DEBUG,
						"ii : unmatched %s proposal/transform\n"
						"ii : lifetime seconds ( %i != %i exact )\n",
						find_name( NAME_PROTOCOL, proposal1->proto ),
						proposal1->life_sec,
						proposal2->life_sec );

					return false;
				}

				break;
			}
		}
	}

	//
	// check peer for RFC compliance
	//

	if( initiator )
	{
		if( proposal1->pnumb != proposal2->pnumb )
			log.txt( LLOG_ERROR,
				"!! : peer violates RFC, proposal number mismatch ( %i != %i )\n",
				proposal1->pnumb,
				proposal2->pnumb );

		if( proposal1->tnumb != proposal2->tnumb )
			log.txt( LLOG_ERROR,
				"!! : peer violates RFC, transform number mismatch ( %i != %i )\n",
				proposal1->tnumb,
				proposal2->tnumb );
	}

	//
	// proposal and transform matched
	//

	char klentxt[ 32 ];
	if( proposal1->ciph_kl )
		sprintf_s( klentxt, 32, "%i bits", proposal1->ciph_kl );
	else
		sprintf_s( klentxt, 32, "default" );

	log.txt( LLOG_INFO,
		"ii : matched %s proposal #%i transform #%i\n"
		"ii : - transform    = %s\n"
		"ii : - key length   = %s\n"
		"ii : - encap mode   = %s\n"
		"ii : - msg auth     = %s\n"
		"ii : - pfs dh group = %s\n"
		"ii : - life seconds = %i\n"
		"ii : - life kbytes  = %i\n",
		find_name( NAME_PROTOCOL, proposal1->proto ),
		proposal2->pnumb,
		proposal2->tnumb,
		find_name( xtype, proposal1->xform ),
		klentxt,
		find_name( NAME_ENCAP, proposal1->encap ),
		find_name( NAME_MAUTH, proposal1->hash_id ),
		find_name( NAME_GROUP, proposal1->dhgr_id ),
		proposal1->life_sec,
		proposal1->life_kbs );

	return true;
}
