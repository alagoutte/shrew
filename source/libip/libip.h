
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

#ifndef _LIBIP_H_
#define _LIBIP_H_

#ifdef WIN32
# define MPR50 1
# include <winsock2.h>
# include <ws2ipdef.h>
# include <iphlpapi.h>
# include <routprot.h>
# include <inttypes.h>
#endif

#ifdef UNIX
# ifdef __linux__
#  include <unistd.h>
#  include <string.h>
#  include <inttypes.h>
#  include <sys/socket.h>
#  include <sys/ioctl.h>
#  include <arpa/inet.h>
#  include <asm/types.h>
#  include <linux/if.h>
#  include <linux/netlink.h>
#  include <linux/rtnetlink.h>
# else
#  include <unistd.h>
#  include <string.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <net/if_dl.h>
#  include <net/route.h>
#  include <arpa/inet.h>
# endif

#endif

#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "export.h"
#include "libidb.h"

#define MEDIA_ETHERNET			0x0001

#define PROTO_IP				0x0800
#define PROTO_ARP				0x0806

#define IP_V4_VERLEN			( 4 << 4 ) | 5

#ifdef PROTO_IP_ICMP			// microsoft punks!
#undef PROTO_IP_ICMP
#endif

#define PROTO_IP_ICMP			0x01
#define PROTO_IP_IPIP			0x04
#define PROTO_IP_TCP			0x06
#define PROTO_IP_UDP			0x11
#define PROTO_IP_ESP			0x32
#define PROTO_IP_AH				0x33
#define PROTO_IP_IPCOMP			0x6C

#define IP_PROTO_UDP_DHCPS		0x0043
#define IP_PROTO_UDP_DHCPC		0x0044

#define IP_FLAG_MORE			0x2000
#define IP_FLAG_DONT_FRAG		0x4000
#define IP_FLAG_RESERVED		0x8000
#define IP_MASK_OFFSET			0x1FFF

#define UDP_PORT_DNS			0x0035

#define UDP_PORT_DHCPS			0x0043
#define UDP_PORT_DHCPC			0x0044

#define DNS_REQUEST				0x00
#define DNS_REPLY				0x01

#define DNS_OP_QUERY			0x00
#define DNS_OP_IQUERY			0x01
#define DNS_OP_STATUS			0x02
#define DNS_OP_NOTIFY			0x04
#define DNS_OP_UPDATE			0x05

#define DNS_AUTHORITY			0x01
#define	DNS_RECURSION			0x01

#define DNS_CODE_OK				0x00
#define DNS_CODE_FORMAT			0x01
#define DNS_CODE_SERVER			0x02
#define DNS_CODE_DOMAIN			0x03
#define DNS_CODE_NOSUPPORT		0x04
#define DNS_CODE_REFUSED		0x05
#define DNS_CODE_XYDOMAIN		0x06
#define DNS_CODE_XYRRSET		0x07
#define DNS_CODE_NXRRSET		0x08
#define DNS_CODE_NOTAUTH		0x09
#define DNS_CODE_NOTZONE		0x0a
#define DNS_CODE_BADVER			0x10
#define DNS_CODE_BADKEY			0x11
#define DNS_CODE_BADTIME		0x12
#define DNS_CODE_BADMODE		0x13
#define DNS_CODE_BADNAME		0x14
#define DNS_CODE_BADALG			0x15

#define DNS_TYPE_A				1
#define DNS_TYPE_NS				2
#define DNS_TYPE_CNAME			5
#define DNS_TYPE_SOA			6
#define DNS_TYPE_MB				7
#define DNS_TYPE_MG				8
#define DNS_TYPE_MR				9
#define DNS_TYPE_NULL			10
#define DNS_TYPE_WKS			11
#define DNS_TYPE_PTR			12
#define DNS_TYPE_HINFO			13
#define DNS_TYPE_MINFO			14
#define DNS_TYPE_MX				15
#define DNS_TYPE_TXT			16
#define DNS_TYPE_RP				17

#define DHCP_MAGIC				0x63538263

#define BOOTP_REQUEST			0x01
#define BOOTP_REPLY				0x02

#define BOOTP_HW_EHTERNET		0x01
#define BOOTP_HW_IPSEC			0x1f

#define DHCP_MSG_DISCOVER		0x01
#define DHCP_MSG_OFFER			0x02
#define DHCP_MSG_REQUEST		0x03
#define DHCP_MSG_ACK			0x05

#define DHCP_OPT_ALIGN16		0x00	// 16bit option alignment
#define DHCP_OPT_SUBMASK		0x01	// subnet mask
#define DHCP_OPT_ROUTER			0x03	// router
#define DHCP_OPT_DNSS			0x06	// dns server
#define DHCP_OPT_DOMAIN			0x0f	// domain name
#define DHCP_OPT_HOSTNAME		0x0c	// host name
#define DHCP_OPT_MTU			0x1a	// adapter mtu
#define DHCP_OPT_RDSCVR			0x1f	// router discover
#define DHCP_OPT_ROUTES			0x21	// static routes
#define DHCP_OPT_VENDOR			0x2b	// vendor specific
#define DHCP_OPT_NBNS			0x2c	// netbios name server
#define DHCP_OPT_NBNT			0x2e	// netbios node type
#define DHCP_OPT_NBOTS			0x2f	// netbios over tcp scope
#define DHCP_OPT_ADDRESS		0x32	// requested address
#define DHCP_OPT_LEASE			0x33	// lease period
#define DHCP_OPT_MSGTYPE		0x35	// message type
#define DHCP_OPT_SERVER			0x36	// server address
#define DHCP_OPT_PARAMS			0x37	// parameters
#define DHCP_OPT_CLASSID		0x3c	// vendor identity
#define DHCP_OPT_CLIENTID		0x3d	// client identity
#define DHCP_OPT_AUTOCONF		0xfb	// auto configure
#define DHCP_OPT_END			0xff	// no more options

#define ARP_REQUEST				0x0001
#define ARP_RESPONSE			0x0002

#define TCPDUMP_MAGIC			0xa1b2c3d4

#define RAWNET_BUFF_SIZE		8192

#define IPFRAG_MAX_LIFETIME		8
#define IPFRAG_MAX_FRAGCOUNT	64

#pragma pack( 1 )

typedef struct _ETH_HEADER
{
	uint8_t		mac_dst[ 6 ];
	uint8_t		mac_src[ 6 ];
	uint16_t	prot;

}ETH_HEADER;

typedef struct _ARP_HEADER
{
	uint16_t	media;
	uint16_t	proto;
	uint8_t		addr_len_media;
	uint8_t		addr_len_proto;
	uint16_t	opcode;

}ARP_HEADER;

typedef struct ARP_PAYLOAD_V4
{
	uint8_t		src_addr_media[ 6 ];
	uint32_t	src_addr_proto;
	uint8_t		dst_addr_media[ 6 ];
	uint32_t	dst_addr_proto;

}ARP_PAYLOAD_V4;

typedef struct _IP_HEADER
{
	uint8_t		verlen;		// <4 bits : ip version
							// >4 bits : header length in 32bit words
	uint8_t		tos;		//  8 bits : type of service ( DSCP )
	uint16_t	size;		// 16 bits : size of ip datagram
	uint16_t	ident;		// 16 bits : identity
	uint16_t	flags;		// 16 bits : flags & fragmentation offset
	uint8_t		ttl;		//  8 bits : time to live
	uint8_t		protocol;	//  8 bits : ip protocol
	uint16_t	checksum;	// 16 bits : header checksum
	uint32_t	ip_src;		// 32 bits : source ip address
	uint32_t	ip_dst;		// 32 bits : destination ip address
//	uint32_t	options;	// 32 bits : ip options

}IP_HEADER;

typedef struct _UDP_HEADER
{
	uint16_t	port_src;	// 16 bits : source port
	uint16_t	port_dst;	// 16 bits : destination port
	uint16_t	size;		// 16 bits : size of udp datagram
	uint16_t	checksum;	// 16 bits : udp checksum

}UDP_HEADER;

typedef struct _ESP_HEADER
{
	uint32_t	spi;		// 32 bits : security parameter index
	uint32_t	seq;		// 32 bits : sequence number

}ESP_HEADER;

typedef struct _AH_HEADER
{
	uint8_t		next;		//  8 bits : next payload
	uint8_t		len;		//  8 bits : payload length
	uint16_t	resrved;	// 16 bits : payload length
	uint32_t	spi;		// 32 bits : security parameter index
	uint32_t	seq;		// 32 bits : sequence number

}AH_HEADER;

typedef struct _IPCOMP_HEADER
{
	uint8_t		next;		//  8 bits : next payload
	uint8_t		flags;		//  8 bits : option flags
	uint16_t	cpi;		// 16 bits : compression parameter index

}IPCOMP_HEADER;

typedef struct _DNS_HEADER
{
	uint16_t	ident;		// 16 bits : identification
	uint16_t	flags;		// 16 bits : dns option flags
	uint16_t	ques;		// 16 bits : total questions
	uint16_t	answ;		// 16 bits : total answer RRs
	uint16_t	ath_rr;		// 16 bits : total authority RRs
	uint16_t	add_rr;		// 16 bits : total additional RRs

}DNS_HEADER;

typedef struct _DHCP_HEADER
{
	uint8_t		op;				//   8 bits  : operation
	uint8_t		htype;			//   8 bits  : hw address type
	uint8_t		hlen;			//   8 bits  : hw address length
	uint8_t		hops;			//   8 bits  : router hop count
	uint32_t	xid;			//  32 bits  : transaction id
	uint16_t	secs;			//  16 bits  : seconds elapsed
	uint16_t	flags;			//  16 bits  : flags
	uint32_t	ciaddr;			//  32 bits  : client ip address
	uint32_t	yiaddr;			//  32 bits  : 'your' ip address
	uint32_t	siaddr;			//  32 bits  : server ip address
	uint32_t	giaddr;			//  32 bits  : relay agent ip address
	uint8_t		chaddr[ 16 ];	//  16 bytes : client hw address
	uint8_t		sname[ 64 ];	//  64 bytes : optional server host name 
	uint8_t		file[ 128 ];	// 128 bytes : boot file name
	uint32_t	magic;			//  32 bits  : magic cookie

	// options

}DHCP_HEADER;

#pragma pack()

//
// adapted from winpcap pcap.h
//

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

struct pcap_file_header {
	uint32_t	magic;
	u_short		version_major;
	u_short		version_minor;
	int32_t		thiszone;	// gmt to local correction
	uint32_t	sigfigs;	// accuracy of timestamps
	uint32_t	snaplen;	// max length saved portion of each pkt
	uint32_t	linktype;	// data link type (LINKTYPE_*)
};

struct pcap_pkthdr {
	uint32_t	ts_sec;		// time stamp seconds
	uint32_t	ts_usec;	// time stamp microseconds
	uint32_t	caplen;		// length of portion present
	uint32_t	len;		// length this packet (off wire)
};

//
// packet classes
//

typedef class DLX _PACKET : public _BDATA, public IDB_ENTRY
{
	public:

	bool	add_byte( uint8_t data );
	bool	add_word( uint16_t data, bool hton = true );
	bool	add_quad( uint32_t data, bool hton = true );
	bool	add_null( size_t size );

	bool	get_byte( uint8_t & data );
	bool	get_word( uint16_t & data, bool ntoh = true );
	bool	get_quad( uint32_t & data, bool ntoh = true );
	bool	get_null( size_t size );

}PACKET;

typedef class DLX _PACKET_IP : public _PACKET
{
	protected:

	uint16_t checksum();

	public:

	bool write( in_addr addr_src, in_addr addr_dst, unsigned short ident, unsigned char prot );
	bool read( in_addr & addr_src, in_addr & addr_dst, unsigned char & prot );
	bool frag( bool more = false, size_t oset = 0 );
	bool done();

}PACKET_IP;

typedef class DLX _PACKET_UDP : public _PACKET
{
	protected:

	uint16_t checksum( in_addr addr_src, in_addr addr_dst );

	public:

	bool write( unsigned short port_src, unsigned short port_dst );
	bool read( unsigned short & port_src, unsigned short & port_dst );
	bool done( in_addr addr_src, in_addr addr_dst );

}PACKET_UDP;

typedef struct DLX _DNS_QUERY : public IDB_ENTRY
{
	char * name;
	unsigned short	type;
	unsigned short	clss;

}DNS_QUERY;

typedef struct DLX _DNS_RECORD : public IDB_ENTRY
{
	char * name;
	unsigned short	type;
	unsigned short	clss;
	unsigned long	rttl;
	unsigned short	rlen;

}DNS_RECORD;

typedef class DLX _PACKET_DNS : public _PACKET
{
	private:

	IDB_LIST	list_ques;
	IDB_LIST	list_answ;
	IDB_LIST	list_ath_rr;
	IDB_LIST	list_add_rr;

	bool	read_name( char * name, long & size );
	bool	read_query( DNS_QUERY ** query );
	bool	read_record( DNS_RECORD ** record );

	public:

	uint16_t	ident;
	uint16_t	flags;
	uint16_t	ques;
	uint16_t	answ;
	uint16_t	ath_rr;
	uint16_t	add_rr;

	_PACKET_DNS();
	~_PACKET_DNS();

	bool write();
	bool read();

	bool get_question( DNS_QUERY ** query, long index );
	bool get_answer( DNS_RECORD ** record, long index );
	bool get_authority( DNS_RECORD ** record, long index );
	bool get_additional( DNS_RECORD ** record, long index );

}PACKET_DNS;

typedef class _IPFRAG_ENTRY : IDB_ENTRY
{
	friend class _IPFRAG;

	time_t		expire;
	PACKET_IP	packet;

}IPFRAG_ENTRY;

typedef class DLX _IPFRAG
{
	private:

	IDB_LIST	used;
	IDB_LIST	free;

	time_t	lastchk;

	public:

	_IPFRAG();

	bool	isfrag( PACKET_IP & packet );
	bool	dnfrag( PACKET_IP & packet );
	bool	dofrag( PACKET_IP & packet, PACKET_IP & fragment, size_t & offset, size_t max_size );

	bool	defrag_add( PACKET_IP & packet, unsigned short & id );
	bool	defrag_chk( unsigned short id );
	bool	defrag_get( unsigned short id, PACKET_IP & packet );

}IPFRAG;

typedef class DLX _IPQUEUE : private IDB_LIST
{
	public:

	_IPQUEUE();
	virtual ~_IPQUEUE();

	bool	add( PACKET_IP & packet );
	bool	get( PACKET_IP & packet, long index );

	long	count();
	void	clean();

}IPQUEUE;

typedef class DLX _IPROUTE_ENTRY : public IDB_ENTRY
{
	public:

	_IPROUTE_ENTRY & operator =( _IPROUTE_ENTRY & source );

	_IPROUTE_ENTRY();

	bool	local;
	in_addr	iface;
	in_addr	addr;
	in_addr	mask;
	in_addr	next;
	
}IPROUTE_ENTRY;

#ifndef WIN32

typedef class DLX _IPROUTE_LIST : private IDB_LIST
{
	public:

	_IPROUTE_LIST();
	virtual ~_IPROUTE_LIST();

	bool	add( IPROUTE_ENTRY & route );
	bool	get( IPROUTE_ENTRY & route );

	long	count();
	void	clean();

}IPROUTE_LIST;

#endif

typedef class DLX _IPROUTE
{
	private:

	int				seq;
	unsigned long	osver_maj;
	unsigned long	osver_min;

#ifndef WIN32
	IPROUTE_LIST	route_list;
#endif

	public:

#ifdef WIN32
	bool	iface_metric( unsigned long & metric, unsigned long index );
	bool	iface_2_addr( in_addr & iface, in_addr & gateway, unsigned long index );
	bool	addr_2_iface( unsigned long & index, in_addr iface );
#endif	

	public:

	_IPROUTE();

	bool add( IPROUTE_ENTRY & route );
	bool del( IPROUTE_ENTRY & route );
	bool get( IPROUTE_ENTRY & route );

	bool best( IPROUTE_ENTRY & route );

	bool increment( in_addr addr, in_addr mask );
	bool decrement( in_addr addr, in_addr mask );

	bool islocal( in_addr & iface );
	bool flusharp( in_addr & iface );

}IPROUTE;

typedef class DLX _PCAP_DUMP
{
	private:

	FILE *	fp;

	public:

	_PCAP_DUMP();
	~_PCAP_DUMP();

	bool	open( char * path );
	void	close();

	bool	dump( unsigned char * buff, size_t size );
	bool	dump( ETH_HEADER & header, PACKET_IP & packet );

	bool	flush();

}PCAP_DUMP;

#endif
