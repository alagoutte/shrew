
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
// UNIX socket code
//

long _IKED::socket_init()
{
	socketpair( AF_UNIX, SOCK_STREAM, 0, wake_socket );
	fcntl( wake_socket[ 0 ], F_SETFL, O_NONBLOCK );
	return LIBIKE_OK;
}

void _IKED::socket_done()
{
	while( list_socket.count() )
	{
		SOCK_INFO * sock_info = static_cast<SOCK_INFO*>( list_socket.del_entry( 0 ) );
		close( sock_info->sock );
		delete sock_info;
	}
}

long _IKED::socket_create( IKE_SADDR & saddr, bool natt )
{
	SOCK_INFO * sock_info = new SOCK_INFO;
	if( sock_info == NULL )
		return LIBIKE_SOCKET;

	sock_info->saddr = saddr;
	sock_info->natt = natt;
	sock_info->sock = socket( PF_INET, SOCK_DGRAM, 0 );

	if( sock_info->sock < 0 )
	{
		log.txt( LLOG_ERROR, "!! : socket create failed\n" );
		return LIBIKE_SOCKET;
	}

	struct linger linger = { 0, 0 };
	if( setsockopt( sock_info->sock, SOL_SOCKET, SO_LINGER, &linger, sizeof( linger ) ) < 0 )
	{
		log.txt( LLOG_ERROR, "!! : socket set linger option failed\n" );
		return LIBIKE_SOCKET;
	}

	int optval = 1;
	if( setsockopt( sock_info->sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof( optval ) ) < 0 )
	{
		log.txt( LLOG_ERROR, "!! : socket set linger option failed\n" );
		return LIBIKE_SOCKET;
	}

#ifdef __linux__

	optval = 1;
	if( setsockopt( sock_info->sock, IPPROTO_IP, IP_PKTINFO, &optval, sizeof( optval ) ) < 0)
	{
		log.txt( LLOG_ERROR, "!! : socket set recvdstaddr option failed\n" );
		return LIBIKE_SOCKET;
	}

#else

	optval = 1;
	if( setsockopt( sock_info->sock, IPPROTO_IP, IP_RECVDSTADDR, &optval, sizeof( optval ) ) < 0)
	{
		log.txt( LLOG_ERROR, "!! : socket set recvdstaddr option failed\n" );
		return LIBIKE_SOCKET;
	}

#endif

	if( bind( sock_info->sock, &sock_info->saddr.saddr, sizeof( sock_info->saddr.saddr4 ) ) < 0 )
	{
		log.txt( LLOG_ERROR, "!! : socket bind failed\n" );
		return LIBIKE_SOCKET;
	}

#if defined( OPT_NATT ) && !defined( __APPLE__ )

	if( natt )
	{
		optval = UDP_ENCAP_ESPINUDP;
		if( setsockopt( sock_info->sock, SOL_UDP, UDP_ENCAP, &optval, sizeof( optval ) ) < 0)
		{
			log.txt( LLOG_ERROR, "!! : socket set udp-encap non-esp option failed\n" );
			return LIBIKE_SOCKET;
		}
	}
	else
	{
		optval = UDP_ENCAP_ESPINUDP_NON_IKE;
		if( setsockopt( sock_info->sock, SOL_UDP, UDP_ENCAP, &optval, sizeof( optval ) ) < 0)
		{
			log.txt( LLOG_ERROR, "!! : socket set udp-encap non-ike option failed\n" );
			return LIBIKE_SOCKET;
		}
	}

#endif

	lock_net.lock();

	list_socket.add_entry( sock_info );

	lock_net.unlock();

	char txtaddr[ LIBIKE_MAX_TEXTADDR ];
	iked.text_addr( txtaddr, &saddr, true );

	if( natt )
	{
		log.txt( LLOG_INFO, "ii : created natt socket %s\n", txtaddr );
		sock_natt_open++;
	}
	else
	{
		log.txt( LLOG_INFO, "ii : created ike socket %s\n",	txtaddr );
		sock_ike_open++;
	}

	return LIBIKE_OK;
}

void _IKED::socket_wakeup()
{
	char c = 0;
	send( wake_socket[ 1 ], &c, 1, 0 );
}

long _IKED::socket_lookup_addr( IKE_SADDR & saddr_r, IKE_SADDR & saddr_l )
{
	//
	// determine the best interface and local
	// address to reach a remote host address
	//

	IPROUTE_ENTRY entry;
	entry.addr = saddr_r.saddr4.sin_addr;

	if( !iproute.best( entry ) )
	{
		char txtaddr[ LIBIKE_MAX_TEXTADDR ];
		text_addr( txtaddr, &saddr_r, true );

		log.txt( LLOG_DEBUG,
				"ii : unable to select local address for peer %s\n",
				txtaddr );

		return LIBIKE_SOCKET;
	}

	saddr_l.saddr4.sin_family = AF_INET;
	saddr_l.saddr4.sin_addr = entry.iface;

	char txtaddr[ LIBIKE_MAX_TEXTADDR ];
	text_addr( txtaddr, &saddr_l, false );

	log.txt( LLOG_DEBUG,
		"ii : local address %s selected for peer\n",
		txtaddr );

	return LIBIKE_OK;
}

long _IKED::socket_lookup_port( IKE_SADDR & saddr_l, bool natt )
{
	//
	// locate a locally bound socket port for
	// the specified local address and type
	//

	long count = list_socket.count();
	long index = 0;

	for( ; index < count; index++ )
	{
		SOCK_INFO * sock_info = static_cast<SOCK_INFO*>( list_socket.get_entry( index ) );

		if( has_sockaddr( &sock_info->saddr.saddr  ) )
			if( cmp_sockaddr( sock_info->saddr.saddr, saddr_l.saddr, false ) )
				continue;

		if( sock_info->natt != natt )
			continue;

		u_int16_t port;
		get_sockport( sock_info->saddr.saddr, port );
		set_sockport( saddr_l.saddr, port );

		return LIBIKE_OK;
	}

	return LIBIKE_SOCKET;
}

long _IKED::header( PACKET_IP & packet, ETH_HEADER & header )
{
	//
	// set the header protocol
	//

	header.prot = htons( PROTO_IP );

	return LIBIKE_OK;
}

long _IKED::recv_ip( PACKET_IP & packet, ETH_HEADER * ethhdr )
{
	fd_set fdset;
	FD_ZERO( &fdset );

	lock_net.lock();

	long count = list_socket.count();
	long index = 0;
	int  hival = wake_socket[ 0 ];

	FD_SET( wake_socket[ 0 ], &fdset );

	for( ; index < count; index++ )
	{
		SOCK_INFO * sock_info = static_cast<SOCK_INFO*>( list_socket.get_entry( index ) );

		FD_SET( sock_info->sock, &fdset );

		if( hival < sock_info->sock )
			hival = sock_info->sock;
	}

	long result = select( hival + 1, &fdset, NULL, NULL, NULL );

	lock_net.unlock();

	if( result < 0 )
		return LIBIKE_SOCKET;

	if( FD_ISSET( wake_socket[ 0 ], &fdset ) )
		return LIBIKE_SOCKET;

	//
	// recv packet data
	//

	IKE_SADDR	from;
	IKE_SADDR	dest;

	socklen_t	flen = sizeof( from.saddr4 );

	for( index = 0; index < count; index++ )
	{
		SOCK_INFO * sock_info = static_cast<SOCK_INFO*>( list_socket.get_entry( index ) );

		if( FD_ISSET( sock_info->sock, &fdset ) == 0 )
			continue;

		unsigned char buff[ RAWNET_BUFF_SIZE ];
		unsigned char ctrl[ 256 ];

		iovec iov;
		iov.iov_base = buff;
		iov.iov_len = RAWNET_BUFF_SIZE;

		msghdr msg;
		msg.msg_name = (caddr_t)&from;
		msg.msg_namelen = flen;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = 256;
		msg.msg_flags = 0;

		long result = recvmsg( sock_info->sock, &msg, 0 );
		if( result <= 0 )
			continue;

#ifdef __linux__

		struct cmsghdr *cm;
		cm = (struct cmsghdr *) ctrl;

		struct in_pktinfo * pi;
		pi = ( struct in_pktinfo * )( CMSG_DATA( cm ) );

		memcpy(
			&dest.saddr4.sin_addr,
			&pi->ipi_addr,
			sizeof( dest.saddr4.sin_addr ) );

#else

		memcpy(
			&dest.saddr4.sin_addr,
			CMSG_DATA( msg.msg_control ),
			sizeof( dest.saddr4.sin_addr ) );

#endif

		//
		// add udp and ip headers
		//

		PACKET_UDP packet_udp;

		packet_udp.write(
			from.saddr4.sin_port,
			sock_info->saddr.saddr4.sin_port );

		packet_udp.add( buff, result );

		packet_udp.done(
			from.saddr4.sin_addr,
			dest.saddr4.sin_addr );

		packet.write(
			from.saddr4.sin_addr,
			dest.saddr4.sin_addr,
			0,
			PROTO_IP_UDP );

		packet.add( packet_udp );
		packet.done();

		//
		// optionally return an ethernet
		// header for this packet
		//

		if( ethhdr != NULL )
		{
			result = header( packet, *ethhdr );
			if( result == LIBIKE_SOCKET )
				return LIBIKE_SOCKET;
		}

		return LIBIKE_OK;
	}

	return LIBIKE_NODATA;
}

long _IKED::send_ip( PACKET_IP & packet, ETH_HEADER * ethhdr )
{
	//
	// read ip packet
	//

	IKE_SADDR saddr_src;
	IKE_SADDR saddr_dst;
	unsigned char prot;

	memset( &saddr_src, 0, sizeof( saddr_src ) );
	memset( &saddr_dst, 0, sizeof( saddr_dst ) );

	saddr_src.saddr4.sin_family = AF_INET;
	saddr_dst.saddr4.sin_family = AF_INET;

	packet.read(
		saddr_src.saddr4.sin_addr,
		saddr_dst.saddr4.sin_addr,
		prot );

	//
	// read udp packet
	//

	PACKET_UDP packet_udp;
	packet.get( packet_udp );

	packet_udp.read(
		saddr_src.saddr4.sin_port,
		saddr_dst.saddr4.sin_port );

	long count = list_socket.count();
	long index = 0;

	for( ; index < count; index++ )
	{
		SOCK_INFO * sock_info = static_cast<SOCK_INFO*>( list_socket.get_entry( index ) );

		if( has_sockaddr( &sock_info->saddr.saddr ) )
		{
			if( !cmp_sockaddr( sock_info->saddr.saddr, saddr_src.saddr, true ) )
				continue;
		}
		else
		{
			u_int16_t port1;
			u_int16_t port2;
			get_sockport( sock_info->saddr.saddr, port1 );
			get_sockport( saddr_src.saddr, port2 );

			if( port1 != port2 )
				continue;
		}

		//
		// send packet data
		//

		long result = sendto(
						sock_info->sock,
						packet_udp.buff() + packet_udp.oset(),
						packet_udp.size() - packet_udp.oset(),
						0,
						&saddr_dst.saddr,
						sizeof( saddr_dst.saddr4 ) );


		if( result <= 0 )
		{
			log.txt( LLOG_ERROR, "!! : send error %li\n", result );
			return LIBIKE_SOCKET;
		}

		//
		// optionally return an ethernet
		// header for this packet
		//

		if( ethhdr != NULL )
		{
			result = header( packet, *ethhdr );
			if( result == LIBIKE_SOCKET )
				return LIBIKE_SOCKET;
		}

		return LIBIKE_OK;
	}

	log.txt( LLOG_ERROR, "!! : socket not found\n" );

	return LIBIKE_SOCKET;
}

//
// UNIX virtual adapter code
//

bool _IKED::vnet_init()
{

#ifdef __FreeBSD__

	kldload( "/boot/kernel/if_tap.ko" );
	return true;

#endif

	return false;
}

bool _IKED::vnet_get( VNET_ADAPTER ** adapter )
{
	// create adapter struct

	*adapter = new VNET_ADAPTER;
	if( !*adapter )
		return false;

#if defined( __FreeBSD__ ) || defined( __APPLE__ )

	// find existing device

	int index = 0;

	for( ; index < 16; index++ )
	{
		// check for existing device

		struct stat sb;
		sprintf( (*adapter)->name, "/dev/tap%i" , index );

		// attempt to stat device

		if( stat( (*adapter)->name, &sb ) )
		{
                        log.txt( LLOG_DEBUG, "ii : unable to stat %s\n",
				(*adapter)->name );
			break;
		}

		// attempt to open device

		(*adapter)->fn = open( (*adapter)->name, O_RDWR );
		if( (*adapter)->fn == -1 )
		{
			log.txt( LLOG_DEBUG, "ii : unable to open %s\n",
				(*adapter)->name );
			continue;
		}

		sprintf( (*adapter)->name, "tap%i" , index );

		break;
	}

	if( (*adapter)->fn == -1 )
	{

		// create new device

		(*adapter)->fn = open( "/dev/tap", O_RDWR);
		if( (*adapter)->fn == -1 )
		{
			log.txt( LLOG_ERROR, "!! : failed to open tap device\n" );

			delete *adapter;
			*adapter = NULL;

			return false;
		}

		struct stat buf;
		if( fstat( (*adapter)->fn, &buf ) < 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to read tap interface name\n" );

			close( (*adapter)->fn );
			delete *adapter;
			*adapter = NULL;

			return false;
		}
	
		devname_r( buf.st_rdev, S_IFCHR, (*adapter)->name, IFNAMSIZ );
	}

#endif

#ifdef __NetBSD__

	(*adapter)->fn = open( "/dev/tap", O_RDWR);
	if( (*adapter)->fn == -1 )
	{
		log.txt( LLOG_ERROR, "!! : failed to open tap device\n" );

		delete *adapter;
		*adapter = NULL;

		return false;
	}

	struct ifreq ifr;
	memset( &ifr, 0, sizeof( ifr ) );

	if( ioctl( (*adapter)->fn, TAPGIFNAME, (void*) &ifr ) < 0 )
	{
		log.txt( LLOG_ERROR, "!! : failed to read tap interface name\n" );

		close( (*adapter)->fn );
		delete *adapter;
		*adapter = NULL;

		return false;
	}

	strcpy( (*adapter)->name, ifr.ifr_name );

#endif

#ifdef __linux__

	(*adapter)->fn = open( "/dev/net/tun", O_RDWR);
	if( (*adapter)->fn == -1 )
	{
		log.txt( LLOG_ERROR, "!! : failed to open tap device\n" );

		delete *adapter;
		*adapter = NULL;

		return false;
	}

	struct ifreq ifr;
	memset( &ifr, 0, sizeof( ifr ) );
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if( ioctl( (*adapter)->fn, TUNSETIFF, (void*) &ifr ) < 0 )
	{
		log.txt( LLOG_ERROR, "!! : failed to get tap interface name\n" );

		close( (*adapter)->fn );
		delete *adapter;
		*adapter = NULL;

		return false;
	}

	strcpy( (*adapter)->name, ifr.ifr_name );
#endif

	log.txt( LLOG_INFO, "ii : opened tap device %s\n", (*adapter)->name );

	return true;
}

bool _IKED::vnet_rel( VNET_ADAPTER * adapter )
{
	// close adapter

	if( adapter->fn != -1 )
		close( adapter->fn );

	log.txt( LLOG_INFO, "ii : closed tap device %s\n", adapter->name );

	// free adapter struct

	delete adapter;

	return true;
}

bool _IKED::client_net_config( IDB_TUNNEL * tunnel )
{
	if( tunnel->xconf.opts & IPSEC_OPTS_ADDR )
	{
		//
		// acquire virtual adapter
		//

		if( !vnet_get( &tunnel->adapter ) )
		{
			log.txt( LLOG_ERROR, "ii : unable to create tap adapter ...\n" );

			return false;
		}

		//
		// open socket for configuration
		//

		int sock = socket( PF_INET, SOCK_DGRAM, 0 );
		if( sock == -1 )
		{
			log.txt( LLOG_ERROR, "!! : failed to create adapter socket ( %s )\n",
				strerror( errno ) );

			return false;
		}

		//
		// bring interface down
		//

		struct ifreq ifr;
		memset( &ifr, 0, sizeof( struct ifreq ) );
		strncpy( ifr.ifr_name, tunnel->adapter->name, IFNAMSIZ );

		if( ioctl( sock, SIOCGIFFLAGS, &ifr ) < 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to get interface flags %s for ( %s )\n",
				tunnel->adapter->name, strerror( errno ) );

			close( sock );
			return false;
		}

		ifr.ifr_flags &= IFF_UP;

		if( ioctl( sock, SIOCSIFFLAGS, &ifr ) < 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to set interface flags %s for ( %s )\n",
				tunnel->adapter->name, strerror( errno ) );

			close( sock );
			return false;
		}

#ifdef __linux__

		//
		// configure internet addresses
		//

		struct sockaddr_in * addr = ( struct sockaddr_in * ) &( ifr.ifr_addr );
		addr->sin_family = AF_INET;
		addr->sin_addr = tunnel->xconf.addr;

		if( ioctl( sock, SIOCSIFADDR, &ifr ) != 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to configure address for %s ( %s )\n",
				tunnel->adapter->name, strerror( errno ) );

			close( sock );
			return false;
		}

		//
		// configure netmask addresses
		//

		addr->sin_addr = tunnel->xconf.mask;

		if( ioctl( sock, SIOCSIFNETMASK, &ifr ) != 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to configure netmask for %s ( %s )\n",
				tunnel->adapter->name, strerror( errno ) );

			close( sock );
			return false;
		}

		//
		// configure broadcast addresses
		//

		addr->sin_addr.s_addr = tunnel->xconf.addr.s_addr;
		addr->sin_addr.s_addr &= tunnel->xconf.mask.s_addr;
		addr->sin_addr.s_addr |= ~tunnel->xconf.mask.s_addr;

		if( ioctl( sock, SIOCSIFBRDADDR, &ifr ) != 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to configure broadcast address for %s ( %s )\n",
				tunnel->adapter->name, strerror( errno ) );

			close( sock );
			return false;
		}

#else

		//
		// configure internet, netmask and broadcast addresses
		//

		struct ifaliasreq ifra;
		memset( &ifra, 0, sizeof( struct ifaliasreq ) );
		strncpy( ifra.ifra_name, tunnel->adapter->name, IFNAMSIZ );

		struct sockaddr_in * addr = ( struct sockaddr_in * ) &( ifra.ifra_addr );
		addr->sin_family = AF_INET;
		SET_SALEN( addr, sizeof( struct sockaddr_in ) );
		addr->sin_addr = tunnel->xconf.addr;

		struct sockaddr_in * mask = ( struct sockaddr_in * ) &( ifra.ifra_mask );
		mask->sin_family = AF_INET;
		SET_SALEN( mask, sizeof( struct sockaddr_in ) );
		mask->sin_addr = tunnel->xconf.mask;

		struct sockaddr_in * bcst = ( struct sockaddr_in * ) &( ifra.ifra_broadaddr );
		bcst->sin_family = AF_INET;
		SET_SALEN( bcst, sizeof( struct sockaddr_in ) );
		bcst->sin_addr.s_addr = tunnel->xconf.addr.s_addr;
		bcst->sin_addr.s_addr &= tunnel->xconf.mask.s_addr;
		bcst->sin_addr.s_addr |= ~tunnel->xconf.mask.s_addr;

		if( ioctl( sock, SIOCAIFADDR, &ifra ) < 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to configure address for %s ( %s )\n",
				tunnel->adapter->name, strerror( errno ) );

			close( sock );
			return false;
		}

#endif

		//
		// configure mtu
		//

		ifr.ifr_mtu = tunnel->xconf.vmtu;

		if( ioctl( sock, SIOCSIFMTU, &ifr ) != 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to configure MTU for %s ( %s )\n",
				tunnel->adapter->name, strerror( errno ) );

			close( sock );
			return false;
		}

		//
		// bring interface up
		//

		if( ioctl( sock, SIOCGIFFLAGS, &ifr ) < 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to get interface flags for %s ( %s )\n",
				tunnel->adapter->name, strerror( errno ) );

			close( sock );
			return false;
		}

	        ifr.ifr_flags |= IFF_UP;

	        if( ioctl( sock, SIOCSIFFLAGS, &ifr ) < 0 )
		{
			log.txt( LLOG_ERROR, "!! : failed to set interface flags for %s ( %s )\n",
				tunnel->adapter->name, strerror( errno ) );

			close( sock );
			return false;
		}

		close( sock );

		log.txt( LLOG_INFO, "ii : configured adapter %s\n",
			tunnel->adapter->name );
	}

	return true;
}

bool _IKED::client_net_revert( IDB_TUNNEL * tunnel )
{
	if( tunnel->xconf.opts & IPSEC_OPTS_ADDR )
	{
		if( tunnel->adapter != NULL )
		{
			vnet_rel( tunnel->adapter );
			tunnel->adapter = NULL;
		}
	}

	return true;
}

bool _IKED::client_dns_config( IDB_TUNNEL * tunnel )
{
	if( tunnel->xconf.opts & ( IPSEC_OPTS_DNSS | IPSEC_OPTS_DOMAIN ) )
	{
		// backup the current resolv.conf file

		rename( "/etc/resolv.conf", "/etc/resolv.iked" );

		FILE * fp1 = fopen( "/etc/resolv.iked", "r" );
		FILE * fp2 = fopen( "/etc/resolv.conf", "w+" );

		if( fp2 != NULL )
		{
			// write configuration

			if( tunnel->xconf.opts & IPSEC_OPTS_DOMAIN )
				fprintf( fp2, "domain\t%s\n", tunnel->xconf.nscfg.dnss_suffix );

			if( tunnel->xconf.opts & IPSEC_OPTS_DNSS )
				for( int i = 0; i < tunnel->xconf.nscfg.dnss_count; i++ )
					fprintf( fp2, "nameserver\t%s\n",
						inet_ntoa( tunnel->xconf.nscfg.dnss_list[ i ] ) );

			if( fp1 != NULL )
			{
				// merge additional options

				char line[ 1024 ];

				while( fgets( line, sizeof( line ), fp1 ) != NULL )
				{
					if( !strncmp( line, "domain", 6 ) )
					{
						if( !( tunnel->xconf.opts & IPSEC_OPTS_DOMAIN ) )
							fwrite( line, strlen( line ), 1, fp2 );

						continue;
					}

					if( !strncmp( line, "nameserver", 9 ) )
					{
						if( !( tunnel->xconf.opts & IPSEC_OPTS_DNSS ) )
							fwrite( line, strlen( line ), 1, fp2 );

						continue;
					}

					fwrite( line, strlen( line ), 1, fp2 );
				}

				fclose( fp1 );
			}

			fclose( fp2 );
		}
	}

	return true;
}

bool _IKED::client_dns_revert( IDB_TUNNEL * tunnel )
{
	if( tunnel->xconf.opts & ( IPSEC_OPTS_DNSS | IPSEC_OPTS_DOMAIN ) )
	{
		// restore the previous resolv.conf file

		rename( "/etc/resolv.iked", "/etc/resolv.conf" );
	}

	return true;
}
