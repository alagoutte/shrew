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
	ss_ip SHARED
	libip.frag.cpp
	libip.packet.cpp
	libip.packet.dns.cpp
	libip.packet.ip.cpp
	libip.packet.udp.cpp
	libip.pcap.cpp
	libip.queue.cpp
	libip.route.cpp )

target_link_libraries(
	ss_ip
	ss_idb )

set_target_properties(
	ss_ip
	PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )

if( APPLE )

	set(
		MACOSX_BUNDLE_BUNDLE_NAME
		"ShrewSoftIp" )

	set_property(
		TARGET ss_ip
		PROPERTY FRAMEWORK ON )

	set_property(
		TARGET ss_ip
		PROPERTY OUTPUT_NAME ${MACOSX_BUNDLE_BUNDLE_NAME} )

endif( APPLE )

install(
	TARGETS ss_ip
	LIBRARY DESTINATION ${PATH_LIB}
	FRAMEWORK DESTINATION "/Library/Frameworks" )
