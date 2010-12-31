
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

const char * _IKED::find_name( long type, long id )
{
	static const char * unknown1 = "unknown type";
	static const char * unknown2 = "unknown";

	switch( type )
	{
		case NAME_INITIATOR:
		{
			static const char * init0 = "responder";
			static const char * init1 = "initiator";

			switch( id )
			{
				case 0:
					return init0;

				case 1:
					return init1;

				default:
					return unknown2;
			}
		}

		case NAME_EXCHANGE:
		{
			static const char * exchange1 = "base";
			static const char * exchange2 = "identity protect";
			static const char * exchange3 = "authenticateon only";
			static const char * exchange4 = "aggressive";
			static const char * exchange5 = "informational";
			static const char * exchange6 = "isakmp config / xauth";

			switch( id )
			{
				case ISAKMP_EXCH_BASE:
					return exchange1;

				case ISAKMP_EXCH_IDENT_PROTECT:
					return exchange2;

				case ISAKMP_EXCH_AUTHENTICATION:
					return exchange3;

				case ISAKMP_EXCH_AGGRESSIVE:
					return exchange4;

				case ISAKMP_EXCH_INFORMATIONAL:
					return exchange5;

				case ISAKMP_EXCH_CONFIG:
					return exchange6;

				default:
					return unknown2;
			}
		}


		case NAME_PROTOCOL:
		{
			static const char * proto1 = "isakmp";
			static const char * proto2 = "ipsec-ah";
			static const char * proto3 = "ipsec-esp";
			static const char * proto4 = "ipcomp";

			switch( id )
			{
				case ISAKMP_PROTO_ISAKMP:
					return proto1;

				case ISAKMP_PROTO_IPSEC_AH:
					return proto2;

				case ISAKMP_PROTO_IPSEC_ESP:
					return proto3;

				case ISAKMP_PROTO_IPCOMP:
					return proto4;

				default:
					return unknown2;
			}
		}

		case NAME_XFORM_ISAKMP:
		{
			static const char * xform1 = "ike";

			switch( id )
			{
				case ISAKMP_KEY_IKE:
					return xform1;

				default:
					return unknown2;
			}
		}

		case NAME_XFORM_AH:
		{
			static const char * xform1 = "ah-md5";
			static const char * xform2 = "ah-sha";
			static const char * xform3 = "ah-des";
			static const char * xform4 = "ah-sha256";
			static const char * xform5 = "ah-sha384";
			static const char * xform6 = "ah-sha512";

			switch( id )
			{
				case ISAKMP_AH_MD5:
					return xform1;

				case ISAKMP_AH_SHA:
					return xform2;

				case ISAKMP_AH_DES:
					return xform3;

				case ISAKMP_AH_SHA256:
					return xform4;

				case ISAKMP_AH_SHA384:
					return xform5;

				case ISAKMP_AH_SHA512:
					return xform6;

				default:
					return unknown2;
			}
		}

		case NAME_XFORM_ESP:
		{
			static const char * xform1  = "esp-des-iv64";
			static const char * xform2  = "esp-des";
			static const char * xform3  = "esp-3des";
			static const char * xform4  = "esp-rc5";
			static const char * xform5  = "esp-idea";
			static const char * xform6  = "esp-cast";
			static const char * xform7  = "esp-blowfish";
			static const char * xform8  = "esp-3idea";
			static const char * xform9  = "esp-des-iv32";
			static const char * xform10 = "esp-rc4";
			static const char * xform11 = "esp-null";
			static const char * xform12 = "esp-aes";

			switch( id )
			{
				case ISAKMP_ESP_DES_IV64:
					return xform1;

				case ISAKMP_ESP_DES:
					return xform2;

				case ISAKMP_ESP_3DES:
					return xform3;

				case ISAKMP_ESP_RC5:
					return xform4;

				case ISAKMP_ESP_IDEA:
					return xform5;

				case ISAKMP_ESP_CAST:
					return xform6;

				case ISAKMP_ESP_BLOWFISH:
					return xform7;

				case ISAKMP_ESP_3IDEA:
					return xform8;

				case ISAKMP_ESP_DES_IV32:
					return xform9;

				case ISAKMP_ESP_RC4:
					return xform10;

				case ISAKMP_ESP_NULL:
					return xform11;

				case ISAKMP_ESP_AES:
					return xform12;

				default:
					return unknown2;
			}
		}

		case NAME_XFORM_IPCOMP:
		{
			static const char * xform0 = "none";
			static const char * xform1 = "ipcomp-oui";
			static const char * xform2 = "ipcomp-deflate";
			static const char * xform3 = "ipcomp-lzs";

			switch( id )
			{
				case ISAKMP_IPCOMP_NONE:
					return xform0;

				case ISAKMP_IPCOMP_OUI:
					return xform1;

				case ISAKMP_IPCOMP_DEFLATE:
					return xform2;

				case ISAKMP_IPCOMP_LZS:
					return xform3;

				default:
					return unknown2;
			}
		}

		case NAME_PAYLOAD:
		{
			static const char * pload0  = "none";
			static const char * pload1  = "security association";
			static const char * pload2  = "proposal";
			static const char * pload3  = "transform";
			static const char * pload4  = "key exchange";
			static const char * pload5  = "identity";
			static const char * pload6  = "certificate";
			static const char * pload7  = "certificate request";
			static const char * pload8  = "hash";
			static const char * pload9  = "signature";
			static const char * pload10 = "nonce";
			static const char * pload11 = "notify";
			static const char * pload12 = "delete";
			static const char * pload13 = "vendor";
			static const char * pload14 = "attribute";
			static const char * pload15 = "nat discovery draft";
			static const char * pload16 = "nat original adress draft";
			static const char * pload17 = "nat discovery rfc";
			static const char * pload18 = "nat original adress rfc";
			static const char * pload19 = "fragment";

			switch( id )
			{
				case ISAKMP_PAYLOAD_NONE:
					return pload0;

				case ISAKMP_PAYLOAD_SA:
					return pload1;

				case ISAKMP_PAYLOAD_PROPOSAL:
					return pload2;

				case ISAKMP_PAYLOAD_TRANSFORM:
					return pload3;

				case ISAKMP_PAYLOAD_KEX:
					return pload4;

				case ISAKMP_PAYLOAD_IDENT:
					return pload5;

				case ISAKMP_PAYLOAD_CERT:
					return pload6;

				case ISAKMP_PAYLOAD_CERT_REQ:
					return pload7;

				case ISAKMP_PAYLOAD_HASH:
					return pload8;

				case ISAKMP_PAYLOAD_SIGNATURE:
					return pload9;

				case ISAKMP_PAYLOAD_NONCE:
					return pload10;

				case ISAKMP_PAYLOAD_NOTIFY:
					return pload11;

				case ISAKMP_PAYLOAD_DELETE:
					return pload12;

				case ISAKMP_PAYLOAD_VEND:
					return pload13;

				case ISAKMP_PAYLOAD_ATTRIB:
					return pload14;

				case ISAKMP_PAYLOAD_NAT_VXX_DISC:
					return pload15;

				case ISAKMP_PAYLOAD_NAT_VXX_ORIG:
					return pload16;

				case ISAKMP_PAYLOAD_NAT_RFC_DISC:
					return pload17;

				case ISAKMP_PAYLOAD_NAT_RFC_ORIG:
					return pload18;

				case ISAKMP_PAYLOAD_FRAGMENT:
					return pload19;

				default:
					return unknown2;
			}
		}

		case NAME_CIPHER:
		{
			static const char * cipher1 = "des";
			static const char * cipher2 = "idea";
			static const char * cipher3 = "blowfish";
			static const char * cipher4 = "rc5";
			static const char * cipher5 = "3des";
			static const char * cipher6 = "cast";
			static const char * cipher7 = "aes";

			switch( id )
			{
				case IKE_CIPHER_DES:
					return cipher1;

				case IKE_CIPHER_IDEA:
					return cipher2;

				case IKE_CIPHER_BLOWFISH:
					return cipher3;

				case IKE_CIPHER_RC5_R16_B64:
					return cipher4;

				case IKE_CIPHER_3DES:
					return cipher5;

				case IKE_CIPHER_CAST:
					return cipher6;

				case IKE_CIPHER_AES:
					return cipher7;

				default:
					return unknown2;
			}
		}

		case NAME_PAUTH:
		{
			static const char * auth1 = "psk";
			static const char * auth2 = "sig-dsa";
			static const char * auth3 = "sig-rsa";
			static const char * auth4 = "rsa-encrypt";
			static const char * auth5 = "rsa-revised";
			static const char * auth6 = "hybrid-initiator-rsa";
			static const char * auth7 = "hybrid-responder-rsa";
			static const char * auth8 = "hybrid-initiator-dss";
			static const char * auth9 = "hybrid-responder-dss";
			static const char * auth10 = "xauth-initiator-psk";
			static const char * auth11 = "xauth-responder-psk";
			static const char * auth12 = "xauth-initiator-dss";
			static const char * auth13 = "xauth-responder-dss";
			static const char * auth14 = "xauth-initiator-rsa";
			static const char * auth15 = "xauth-responder-rsa";
			static const char * auth16 = "xauth-initiator-rsa-encryption";
			static const char * auth17 = "xauth-responder-rsa-encryption";
			static const char * auth18 = "xauth-initiator-rsa-revised-encryption";
			static const char * auth19 = "xauth-responder-rsa-revised-encryption";

			switch( id )
			{
				case IKE_AUTH_PRESHARED_KEY:
					return auth1;

				case IKE_AUTH_SIG_DSA:
					return auth2;

				case IKE_AUTH_SIG_RSA:
					return auth3;

				case IKE_AUTH_SIG_RSA_ENCRYPT:
					return auth4;

				case IKE_AUTH_SIG_RSA_REVISED:
					return auth5;

				case HYBRID_AUTH_INIT_RSA:
					return auth6;

				case HYBRID_AUTH_RESP_RSA:
					return auth7;

				case HYBRID_AUTH_INIT_DSS:
					return auth8;

				case HYBRID_AUTH_RESP_DSS:
					return auth9;

				case XAUTH_AUTH_INIT_PSK:
					return auth10;

				case XAUTH_AUTH_RESP_PSK:
					return auth11;

				case XAUTH_AUTH_INIT_DSS:
					return auth12;

				case XAUTH_AUTH_RESP_DSS:
					return auth13;

				case XAUTH_AUTH_INIT_RSA:
					return auth14;

				case XAUTH_AUTH_RESP_RSA:
					return auth15;

				case XAUTH_AUTH_INIT_RSA_ENC:
					return auth16;

				case XAUTH_AUTH_RESP_RSA_ENC:
					return auth17;

				case XAUTH_AUTH_INIT_RSA_REV:
					return auth18;

				case XAUTH_AUTH_RESP_RSA_REV:
					return auth19;

				default:
					return unknown2;
			}
		}

		case NAME_MAUTH:
		{
			static const char * hash1 = "hmac-md5";
			static const char * hash2 = "hmac-sha1";
			static const char * hash3 = "des-mac";
			static const char * hash4 = "kpdk";
			static const char * hash5 = "hmac-sha2-256";
			static const char * hash6 = "hmac-sha2-384";
			static const char * hash7 = "hmac-sha2-512";

			switch( id )
			{
				case ISAKMP_AUTH_HMAC_MD5:
					return hash1;

				case ISAKMP_AUTH_HMAC_SHA1:
					return hash2;

				case ISAKMP_AUTH_DES_MAC:
					return hash3;

				case ISAKMP_AUTH_KPDK:
					return hash4;

				case ISAKMP_AUTH_HMAC_SHA2_256:
					return hash5;

				case ISAKMP_AUTH_HMAC_SHA2_384:
					return hash6;

				case ISAKMP_AUTH_HMAC_SHA2_512:
					return hash7;

				default:
					return unknown2;
			}
		}

		case NAME_HASH:
		{
			static const char * hash1 = "md5";
			static const char * hash2 = "sha1";
			static const char * hash3 = "tiger";
			static const char * hash4 = "sha2-256";
			static const char * hash5 = "sha2-384";
			static const char * hash6 = "sha2-512";

			switch( id )
			{
				case IKE_HASH_MD5:
					return hash1;

				case IKE_HASH_SHA1:
					return hash2;

				case IKE_HASH_TIGER:
					return hash3;

				case IKE_HASH_SHA2_256:
					return hash4;

				case IKE_HASH_SHA2_384:
					return hash5;

				case IKE_HASH_SHA2_512:
					return hash6;

				default:
					return unknown2;
			}
		}

		case NAME_CERT:
		{
			static const char * cert0  = "none";
			static const char * cert1  = "pkcs7";
			static const char * cert2  = "pgp";
			static const char * cert3  = "dns signed";
			static const char * cert4  = "x.509 signed";
			static const char * cert5  = "x.509 key exchange";
			static const char * cert6  = "kerberos";
			static const char * cert7  = "certificate revocation list ( CRL )";
			static const char * cert8  = "authority revocation list ( ARL )";
			static const char * cert9  = "spki";
			static const char * cert10 = "x.509 attribute";
			static const char * cert11 = "plain rsa";

			switch( id )
			{
				case ISAKMP_CERT_NONE:
					return cert0;

				case ISAKMP_CERT_PKCS7:
					return cert1;

				case ISAKMP_CERT_PGP:
					return cert2;

				case ISAKMP_CERT_DNS_SIGNED:
					return cert3;

				case ISAKMP_CERT_X509_SIG:
					return cert4;

				case ISAKMP_CERT_X509_KEX:
					return cert5;

				case ISAKMP_CERT_KERBEROS:
					return cert6;

				case ISAKMP_CERT_CRL:
					return cert7;

				case ISAKMP_CERT_ARL:
					return cert8;

				case ISAKMP_CERT_SPKI:
					return cert9;

				case ISAKMP_CERT_X509_ATTR:
					return cert10;

				case ISAKMP_CERT_RSA_PLAIN:
					return cert11;

				default:
					return unknown2;
			}
		}

		case NAME_GROUP:
		{
			static const char * group0 = "none";
			static const char * group1 = "group1 ( modp-768 )";
			static const char * group2 = "group2 ( modp-1024 )";
			static const char * group3 = "group3 ( ecn-155 )";
			static const char * group4 = "group4 ( ecn-185 )";
			static const char * group5 = "group5 ( modp-1536 )";
			static const char * group14 = "group14 ( modp-2048 )";
			static const char * group15 = "group15 ( modp-3072 )";
			static const char * group16 = "group16 ( modp-4096 )";
			static const char * group17 = "group17 ( modp-6144 )";
			static const char * group18 = "group18 ( modp-8192 )";

			switch( id )
			{
				case 0:
					return group0;

				case IKE_GRP_GROUP1:
					return group1;

				case IKE_GRP_GROUP2:
					return group2;

				case IKE_GRP_GROUP3:
					return group3;

				case IKE_GRP_GROUP4:
					return group4;

				case IKE_GRP_GROUP5:
					return group5;

				case IKE_GRP_GROUP14:
					return group14;

				case IKE_GRP_GROUP15:
					return group15;

				case IKE_GRP_GROUP16:
					return group16;

				case IKE_GRP_GROUP17:
					return group17;

				case IKE_GRP_GROUP18:
					return group18;

				default:
					return unknown2;
			}
		}

		case NAME_ENCAP:
		{
			static const char * encap1 = "tunnel";
			static const char * encap2 = "transport";
			static const char * encap3 = "udp-tunnel ( draft )";
			static const char * encap4 = "udp-transport ( draft )";
			static const char * encap5 = "udp-tunnel ( rfc )";
			static const char * encap6 = "udp-transport ( rfc )";

			switch( id )
			{
				case ISAKMP_ENCAP_TUNNEL:
					return encap1;

				case ISAKMP_ENCAP_TRANSPORT:
					return encap2;

				case ISAKMP_ENCAP_VXX_UDP_TUNNEL:
					return encap3;

				case ISAKMP_ENCAP_VXX_UDP_TRANSPORT:
					return encap4;

				case ISAKMP_ENCAP_RFC_UDP_TUNNEL:
					return encap5;

				case ISAKMP_ENCAP_RFC_UDP_TRANSPORT:
					return encap6;

				default:
					return unknown2;
			}
		}

		case NAME_IDENT:
		{
			static const char * ident0  = "none";
			static const char * ident1  = "ipv4-host";
			static const char * ident2  = "fqdn";
			static const char * ident3  = "user-fqdn";
			static const char * ident4  = "ipv4-subnet";
			static const char * ident5  = "ipv6-host";
			static const char * ident6  = "ipv6-subnet";
			static const char * ident7  = "ipv4-range";
			static const char * ident8  = "ipv4-range";
			static const char * ident9  = "asn1-dn";
			static const char * ident10 = "asn1-gn";
			static const char * ident11 = "key-id";

			switch( id )
			{
				case ISAKMP_ID_NONE:
					return ident0;

				case ISAKMP_ID_IPV4_ADDR:
					return ident1;

				case ISAKMP_ID_FQDN:
					return ident2;

				case ISAKMP_ID_USER_FQDN:
					return ident3;

				case ISAKMP_ID_IPV4_ADDR_SUBNET:
					return ident4;

				case ISAKMP_ID_IPV6_ADDR:
					return ident5;

				case ISAKMP_ID_IPV6_ADDR_SUBNET:
					return ident6;

				case ISAKMP_ID_IPV4_ADDR_RANGE:
					return ident7;

				case ISAKMP_ID_IPV6_ADDR_RANGE:
					return ident8;

				case ISAKMP_ID_ASN1_DN:
					return ident9;

				case ISAKMP_ID_ASN1_GN:
					return ident10;

				case ISAKMP_ID_KEY_ID:
					return ident11;
					
				default:
					return unknown2;
			}
		}
		
		case NAME_NOTIFY:
		{
			static const char * notify1  = "INVALID-PAYLOAD-TYPE";
			static const char * notify2  = "DOI-NOT-SUPPORTED";
			static const char * notify3  = "SITUATION-NOT-SUPPORTED";
			static const char * notify4  = "INVALID-COOKIE";
			static const char * notify5  = "INVALID-MAJOR-VERSION";
			static const char * notify6  = "INVALID-MINOR-VERSION";
			static const char * notify7  = "INVALID-EXCHANGE-TYPE";
			static const char * notify8  = "INVALID-FLAGS";
			static const char * notify9  = "INVALID-MESSAGE-ID";
			static const char * notify10 = "INVALID-PROTOCOL-ID";
			static const char * notify11 = "INVALID-SPI";
			static const char * notify12 = "INVALID-TRANSFORM-ID";
			static const char * notify13 = "ATTRIBUTES-NOT-SUPPORTED";
			static const char * notify14 = "NO-PROPOSAL-CHOSEN";
			static const char * notify15 = "BAD-PROPOSAL-SYNTAX";
			static const char * notify16 = "PAYLOAD-MALFORMED";
			static const char * notify17 = "INVALID-KEY-INFORMATION";
			static const char * notify18 = "INVALID-ID-INFORMATION";
			static const char * notify19 = "INVALID-CERT-ENCODING";
			static const char * notify20 = "INVALID-CERTIFICATE";
			static const char * notify21 = "CERT-TYPE-UNSUPPORTED";
			static const char * notify22 = "INVALID-CERT-AUTHORITY";
			static const char * notify23 = "INVALID-HASH-INFORMATION";
			static const char * notify24 = "AUTHENTICATION-FAILED";
			static const char * notify25 = "INVALID-SIGNATURE";
			static const char * notify26 = "ADDRESS-NOTIFICATION";
			static const char * notify27 = "NOTIFY-SA-LIFETIME";
			static const char * notify28 = "CERTIFICATE-UNAVAILABLE";
			static const char * notify29 = "UNSUPPORTED-EXCHANGE-TYPE";
			static const char * notify30 = "UNEQUAL-PAYLOAD-LENGTHS";
			static const char * notify31 = "RESPONDER-LIFETIME";
			static const char * notify32 = "REPLAY-STATUS";
			static const char * notify33 = "INITIAL-CONTACT";
			static const char * notify34 = "UNITY-LOAD-BALANCE";
			static const char * notify35 = "UNITY-GROUP-HASH";
			static const char * notify36 = "DPDV1-R-U-THERE";
			static const char * notify37 = "DPDV1-R-U-THERE-ACK";
			
			switch( id )
			{
				case ISAKMP_N_INVALID_PAYLOAD_TYPE:
					return notify1;
					
				case ISAKMP_N_DOI_NOT_SUPPORTED:
					return notify2;

				case ISAKMP_N_SITUATION_NOT_SUPPORTED:
					return notify3;

				case ISAKMP_N_INVALID_COOKIE:
					return notify4;

				case ISAKMP_N_INVALID_MAJOR_VERSION:
					return notify5;

				case ISAKMP_N_INVALID_MINOR_VERSION:
					return notify6;

				case ISAKMP_N_INVALID_EXCHANGE_TYPE:
					return notify7;

				case ISAKMP_N_INVALID_FLAGS:
					return notify8;

				case ISAKMP_N_INVALID_MESSAGE_ID:
					return notify9;

				case ISAKMP_N_INVALID_PROTOCOL_ID:
					return notify10;

				case ISAKMP_N_INVALID_SPI:
					return notify11;

				case ISAKMP_N_INVALID_TRANSFORM_ID:
					return notify12;

				case ISAKMP_N_ATTRIBUTES_NOT_SUPPORTED:
					return notify13;

				case ISAKMP_N_NO_PROPOSAL_CHOSEN:
					return notify14;

				case ISAKMP_N_BAD_PROPOSAL_SYNTAX:
					return notify15;

				case ISAKMP_N_PAYLOAD_MALFORMED:
					return notify16;

				case ISAKMP_N_INVALID_KEY_INFORMATION:
					return notify17;

				case ISAKMP_N_INVALID_ID_INFORMATION:
					return notify18;

				case ISAKMP_N_INVALID_CERT_ENCODING:
					return notify19;

				case ISAKMP_N_INVALID_CERTIFICATE:
					return notify20;

				case ISAKMP_N_CERT_TYPE_UNSUPPORTED:
					return notify21;

				case ISAKMP_N_INVALID_CERT_AUTHORITY:
					return notify22;

				case ISAKMP_N_INVALID_HASH_INFORMATION:
					return notify23;

				case ISAKMP_N_AUTHENTICATION_FAILED:
					return notify24;

				case ISAKMP_N_INVALID_SIGNATURE:
					return notify25;

				case ISAKMP_N_ADDRESS_NOTIFICATION:
					return notify26;

				case ISAKMP_N_NOTIFY_SA_LIFETIME:
					return notify27;

				case ISAKMP_N_CERTIFICATE_UNAVAILABLE:
					return notify28;

				case ISAKMP_N_UNSUPPORTED_EXCHANGE_TYPE:
					return notify29;

				case ISAKMP_N_UNEQUAL_PAYLOAD_LENGTHS:
					return notify30;
			
				case ISAKMP_N_RESPONDER_LIFETIME:
					return notify31;

				case ISAKMP_N_REPLAY_STATUS:
					return notify32;

				case ISAKMP_N_INITIAL_CONTACT:
					return notify33;

				case ISAKMP_N_UNITY_LOAD_BALANCE:
					return notify34;

				case ISAKMP_N_UNITY_GROUP_HASH:
					return notify35;

				case ISAKMP_N_DPD_R_U_THERE:
					return notify36;

				case ISAKMP_N_DPD_R_U_THERE_ACK:
					return notify37;

				default:
					return unknown2;
			}
		}
					
		default:

			return unknown1;
	}
}
