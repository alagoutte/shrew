#
# Shrew Soft VPN / IP Utility Library
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
	${IKE_SOURCE_DIR}/source
	${IKE_SOURCE_DIR}/source/libidb
	${IKE_SOURCE_DIR}/source/liblog
	${IKE_SOURCE_DIR}/source/libith )

add_library(
	ip
	libip.frag.cpp
	libip.packet.cpp
	libip.packet.dns.cpp
	libip.packet.ip.cpp
	libip.packet.udp.cpp
	libip.pcap.cpp
	libip.queue.cpp
	libip.route.cpp )

set_target_properties(
	ip PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )

