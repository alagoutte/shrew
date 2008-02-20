
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
// opsenssl version compatibility
//

#if OPENSSL_VERSION_NUMBER < 0x0090800fL
# define X509CONST
#else
# define X509CONST const
#endif

// openssl password callback

int keyfile_cb( char * buf, int size, int rwflag, void * userdata )
{
	BDATA * fpass = ( BDATA * ) userdata;

	memset( buf, 0, size );

	if( size > int( fpass->size() ) )
		size = int( fpass->size() );

	memcpy( buf, fpass->buff(), size );

	return size;
}

bool _IKED::cert_2_bdata( BDATA & cert, X509 * x509 )
{
	int size = i2d_X509( x509, NULL );
	cert.size( size );

	unsigned char * cert_buff = cert.buff();
	if( i2d_X509( x509, &cert_buff ) < size )
		return false;

	return true;
}

bool _IKED::bdata_2_cert( X509 ** x509, BDATA & cert )
{
	X509CONST unsigned char * cert_buff = cert.buff();

	*x509 = d2i_X509( NULL, &cert_buff, ( long ) cert.size() );
	if( *x509 == NULL )
		return false;

	return true;
}

long _IKED::cert_load( BDATA & cert, char * fpath, bool ca, BDATA & pass )
{
#ifdef WIN32

	FILE * fp;
	if( fopen_s( &fp, fpath, "rb" ) )
		return FILE_PATH;

#else

	FILE * fp = fopen( fpath, "rb" );
	if( !fp )
		return FILE_PATH;

#endif

	bool loaded = cert_load_pem( cert, fp, ca, pass );
	if( !loaded )
		loaded = cert_load_p12( cert, fp, ca, pass );

	fclose( fp );

	if( !loaded )
		return FILE_FAIL;

	return FILE_OK;
}

bool _IKED::cert_load_pem( BDATA & cert, FILE * fp, bool ca, BDATA & pass )
{
	fseek( fp, 0, SEEK_SET );

	X509 * x509 = PEM_read_X509( fp, NULL, keyfile_cb, &pass );
	if( x509 == NULL )
		return false;

	cert_2_bdata( cert, x509 );

	X509_free( x509 );

	return true;
}

bool _IKED::cert_load_p12( BDATA & cert, FILE * fp, bool ca, BDATA & pass )
{
	fseek( fp, 0, SEEK_SET );

	PKCS12 * p12 = d2i_PKCS12_fp( fp, NULL );
	if( p12 == NULL )
		return false;

	X509 * x509 = NULL;

	BDATA passnull;
	passnull.set( pass );
	passnull.add( 0, 1 );

	if( ca )
	{
		STACK_OF( X509 ) * stack = NULL;

		if( PKCS12_parse( p12, ( const char * ) passnull.buff(), NULL, NULL, &stack ) )
		{
			if( stack != NULL )
			{
				if( sk_X509_value( stack, 0 ) != NULL )
					x509 = sk_X509_value( stack, 0 );

				sk_X509_free( stack );
			}
		}
	}
	else
		PKCS12_parse( p12, ( const char * ) passnull.buff(), NULL, &x509, NULL );

	PKCS12_free( p12 );

	if( x509 == NULL )
		return false;

	cert_2_bdata( cert, x509 );
	X509_free( x509 );

	return true;
}

long _IKED::cert_save( BDATA & cert, char * fpath )
{
	X509 * x509;
	if( !bdata_2_cert( &x509, cert ) )
		return FILE_FAIL;

#ifdef WIN32

	FILE * fp;
	if( fopen_s( &fp, fpath, "wb" ) )
		return FILE_FAIL;

#else

	FILE * fp = fopen( fpath, "wb" );
	if( !fp )
		return FILE_FAIL;

#endif
	
	PEM_write_X509( fp, x509 );

	fclose( fp );

	X509_free( x509 );

	return FILE_OK;
}

bool _IKED::cert_desc( BDATA & cert, BDATA & desc )
{
	X509 * x509;
	if( !bdata_2_cert( &x509, cert ) )
		return false;

	BIO * bio = BIO_new( BIO_s_mem() );
	if( bio == NULL )
	{
		X509_free( x509 );
		return false;
	}

	if( X509_print( bio, x509 ) != 1 )
	{
		BIO_free( bio );
		X509_free( x509 );
		return false;
	}

	unsigned char * bio_buff = NULL;

	int size = BIO_get_mem_data( bio, &bio_buff );

	desc.size( size + 1 );
	memcpy( desc.buff(), bio_buff, size );

	BIO_free( bio );
	X509_free( x509 );

	return false;
}

bool _IKED::cert_subj( BDATA & cert, BDATA & subj )
{
	X509 * x509;
	if( !bdata_2_cert( &x509, cert ) )
		return false;

	X509_NAME * x509_name = X509_get_subject_name( x509 );
	if( x509_name == NULL )
	{
		X509_free( x509 );
		return false;
	}

	short size = i2d_X509_NAME( x509_name, NULL );

	if( size > LIBIKE_MAX_VARID )
	{
		X509_free( x509 );
		return false;
	}

	subj.size( size );
	unsigned char * temp = subj.buff();
	
	size = i2d_X509_NAME( x509_name, &temp );

	X509_free( x509 );

	log.bin( LLOG_DEBUG, LLOG_DECODE,
		subj.buff(),
		subj.size(),
		"ii : obtained x509 cert subject" );

	return true;
}

bool _IKED::asn1_text( BDATA & data, BDATA & text )
{
	X509_NAME * x509_name = NULL;

	X509CONST unsigned char * buff = data.buff();
	if( buff == NULL )
		return false;

	d2i_X509_NAME( &x509_name, &buff, ( long ) data.size() );

	if( x509_name == NULL )
		return false;

	char name[ 512 ];
	X509_NAME_oneline(
		x509_name,
		name,
		512 );

	text.set( name, strlen( name ) );

	X509_NAME_free( x509_name );

	return true;
}

bool _IKED::text_asn1( BDATA & text, BDATA & asn1 )
{
	BDATA temp;

	//
	// create a copy of our text
	// and reset the output buff
	//

	temp.set( text );
	temp.add( 0, 1 );
	asn1.del( true );
        
	X509_NAME * name = X509_NAME_new();

	unsigned char *	fbuff = NULL;

	char *	tbuff = ( char * ) temp.buff();
	size_t	tsize = 0;
	size_t	tnext = 0;

	char *	field = NULL;
	size_t	fsize = 0;

	char *	value = NULL;
	size_t	vsize = 0;

	bool	pair = false;
	bool	stop = false;

	while( !stop )
	{
		//
		// obtain the length of
		// the current segment
		//

		tsize = strcspn( tbuff, ",/=" );

		//
		// check for null length
		//

		if( !tsize )
		{
			tbuff++;
			continue;
		}

		//
		// check the delimiter type
		//

		switch( tbuff[ tsize ] )
		{
			//
			// are we delimiting between a
			// field and value or between
			// a field value pair
			//

			case '=':
			{
				if( field == NULL )
					field = tbuff;

				fsize += tsize;

				break;
			}

			case ',':
			case '/':
			case '\0':
			{
				if( field == NULL )
					goto text_asn1_failed;

				if( value == NULL )
					value = tbuff;

				vsize += tsize;

				if( !value[ vsize + 1 ] )
				{
					pair = true;
					stop = true;
					break;
				}

				tnext = strcspn( tbuff + tsize + 1, ",/=" );

				switch( value[ vsize + tnext + 1 ] )
				{
					case ',':
					case '/':
					case '\0':
						vsize++;
						break;

					default:
						pair = true;
						break;
				}
			}
		}

		//
		// check for field value pair
		//

		if( pair )
		{
			//
			// trim pair
			//

			while( ( field[ 0 ] == ' ' ) && fsize )
			{
				field++;
				fsize--;
			}

			while( ( field[ fsize - 1 ] == ' ' ) && fsize )
				fsize--;

			while( ( value[ 0 ] == ' ' ) && vsize )
			{
				value++;
				vsize--;
			}

			while( ( value[ vsize - 1 ] == ' ' ) && vsize )
				vsize--;

			//
			// null terminate
			//

			field[ fsize ] = 0;
			value[ vsize ] = 0;

			//
			// add the pair
			//

			X509_NAME_add_entry_by_txt(
				name,
				field,
				MBSTRING_ASC,
				( unsigned char * ) value,
				-1,	-1, 0 );

			log.txt( LLOG_DECODE,
				"ii : asn1_text %s = %s\n",
				field,
				value );

			//
			// cleanup for next pair
			//

			field = NULL;
			fsize = 0;
			value = NULL;
			vsize = 0;

			pair = false;
		}

		tbuff += ( tsize + 1 );
	}

	//
	// copy to buffer
	//

	tsize = i2d_X509_NAME( name, NULL );
	if( !tsize )
		goto text_asn1_failed;

	asn1.size( tsize );
	fbuff = asn1.buff();

    tsize = i2d_X509_NAME( name, &fbuff );
	if( !tsize )
		goto text_asn1_failed;

	//
	// return success
	//

	X509_NAME_free( name );

	return true;

	//
	// return failure
	//

	text_asn1_failed:

	X509_NAME_free( name );

	return false;
}

static int verify_cb( int ok, X509_STORE_CTX * store_ctx )
{
	if( !ok )
	{
		long ll = LLOG_ERROR;
		char name[ 512 ];

		X509_NAME * x509_name = X509_get_subject_name( store_ctx->current_cert );

		X509_NAME_oneline(
			x509_name,
			name,
			512 );

		switch( store_ctx->error )
		{
			case X509_V_ERR_UNABLE_TO_GET_CRL:
				ok = 1;
				ll = LLOG_INFO;
				break;
		}

		iked.log.txt(
			ll,
			"ii : %s(%d) at depth:%d\n"
			"ii : subject :%s\n",
			X509_verify_cert_error_string( store_ctx->error ),
			store_ctx->error,
			store_ctx->error_depth,
			name );
	}

	ERR_clear_error();

	return ok;
}

bool _IKED::cert_verify( IDB_LIST_CERT & certs, BDATA & ca, BDATA & cert )
{
	//
	// create certificate storage
	//

	X509_STORE * store = X509_STORE_new();
	if( store == NULL )
		return false;

	X509_STORE_set_verify_cb_func( store, verify_cb );
	X509_LOOKUP * lookup = X509_STORE_add_lookup( store, X509_LOOKUP_file() );
	if( lookup == NULL )
	{
		X509_STORE_free( store );
		return false;
	}

	//
	// load ca and add to store
	//

	X509 * x509_ca;
	if( !bdata_2_cert( &x509_ca, ca ) )
	{
		X509_STORE_free( store );
		return false;
	}

	X509_STORE_add_cert( store, x509_ca );

#ifdef WIN32

	//
	// add all certificates from a path
	//

	char tmppath[ MAX_PATH ];
	sprintf_s( tmppath, MAX_PATH, "%s\\certificates\\*.*", path_ins );

	WIN32_FIND_DATA ffd;
	memset( &ffd, 0, sizeof( ffd ) );
	ffd.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;

	HANDLE hff = FindFirstFile(
					tmppath,
					&ffd );

	while( hff != NULL )
	{
		sprintf_s( tmppath, MAX_PATH, "%s\\certificates\\%s", path_ins, ffd.cFileName );

		if( X509_LOOKUP_load_file( lookup, tmppath, X509_FILETYPE_PEM ) != NULL )
			log.txt( LLOG_DEBUG, "ii : added %s to x509 store\n", ffd.cFileName );

		if( !FindNextFile( hff, &ffd ) )
			hff = NULL;
	}

#endif

	//
	// create certificate chain
	//

	STACK_OF( X509 ) * chain = sk_X509_new_null();
	X509 * x509_cert;

	long index = 0;
	while( certs.get( cert, index++ ) )
		if( bdata_2_cert( &x509_cert, cert ) )
			sk_X509_push( chain, x509_cert );

	long result = 0;

	if( sk_X509_num( chain ) > 0 )
	{
		//
		// sort the certificate chain if more
		// than one element exists
		//

//		if( sk_X509_num( chain ) > 1 )
//			sk_sort( chain );

		//
		// get the first cert in the chain and
		// store it for our caller
		//

		x509_cert = sk_X509_value( chain, 0 );
		cert_2_bdata( cert, x509_cert );

		//
		// create our store context
		//

		X509_STORE_CTX * store_ctx = X509_STORE_CTX_new();
		if( store_ctx != NULL )
		{
			//
			// iniitialize our store context
			//

			X509_STORE_CTX_init( store_ctx, store, x509_cert, chain );
			X509_STORE_CTX_set_flags( store_ctx, X509_V_FLAG_CRL_CHECK );
			X509_STORE_CTX_set_flags( store_ctx, X509_V_FLAG_CRL_CHECK_ALL );

			//
			// verify our certificate and cleanup
			//

			result = X509_verify_cert( store_ctx );
			X509_STORE_CTX_cleanup( store_ctx );
		}
	}

	//
	// destroy certificate chain
	//

	while( sk_X509_num( chain ) > 0 )
	{
		x509_cert = sk_X509_pop( chain );
		if( x509_cert == NULL )
			break;

		X509_free( x509_cert );
	}

	//
	// cleanup
	//

	X509_free( x509_ca );
	X509_STORE_free( store );

	return ( result > 0 );
}

long _IKED::prvkey_rsa_load( EVP_PKEY ** evp_pkey, char * fpath, BDATA & pass )
{
#ifdef WIN32

	FILE * fp;
	if( fopen_s( &fp, fpath, "rb" ) )
		return FILE_PATH;

#else

	FILE * fp = fopen( fpath, "rb" );
	if( !fp )
		return FILE_PATH;

#endif

	bool loaded = prvkey_rsa_load_pem( evp_pkey, fp, pass );
	if( !loaded )
		loaded = prvkey_rsa_load_p12( evp_pkey, fp, pass );

	fclose( fp );

	if( !loaded )
		return FILE_FAIL;

	return FILE_OK;
}

bool _IKED::prvkey_rsa_load_pem( EVP_PKEY ** evp_pkey, FILE * fp, BDATA & pass )
{
	fseek( fp, 0, SEEK_SET );

	*evp_pkey = PEM_read_PrivateKey( fp, NULL, keyfile_cb, &pass );
	if( *evp_pkey == NULL )
		return false;

	return true;
}

bool _IKED::prvkey_rsa_load_p12( EVP_PKEY ** evp_pkey, FILE * fp, BDATA & pass )
{
	fseek( fp, 0, SEEK_SET );

	PKCS12 * p12 = d2i_PKCS12_fp( fp, NULL );
	if( p12 == NULL )
		return false;

	BDATA passnull;
	passnull.set( pass );
	passnull.add( 0, 1 );

	PKCS12_parse( p12, ( const char * ) passnull.buff(), evp_pkey, NULL, NULL );
	PKCS12_free( p12 );

	if( *evp_pkey == NULL )
		return false;

	return true;
}

bool _IKED::pubkey_rsa_read( BDATA & cert, EVP_PKEY ** evp_pkey )
{
	X509 * x509;
	if( !bdata_2_cert( &x509, cert ) )
		return false;

	*evp_pkey = X509_get_pubkey( x509 );

	X509_free( x509 );

	if( !( *evp_pkey ) )
		return false;

	return true;
}

bool _IKED::prvkey_rsa_encrypt( EVP_PKEY * evp_pkey, BDATA & hash, BDATA & sign )
{
	int size = RSA_size( evp_pkey->pkey.rsa );

	sign.size( size );

	size = RSA_private_encrypt(
				( int ) hash.size(),
				hash.buff(),
				sign.buff(),
				evp_pkey->pkey.rsa,
				RSA_PKCS1_PADDING );

	if( size == -1 )
		return false;

	sign.size( size );

	return true;
}

bool _IKED::pubkey_rsa_decrypt( EVP_PKEY * evp_pkey, BDATA & sign, BDATA & hash )
{
	int size = RSA_size( evp_pkey->pkey.rsa );

	hash.size( size );

	size = RSA_public_decrypt(
				( int ) sign.size(),
				sign.buff(),
				hash.buff(),
				evp_pkey->pkey.rsa,
				RSA_PKCS1_PADDING );

	if( size == -1 )
		return false;

	hash.size( size );

	return true;
}
