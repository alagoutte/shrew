#
# Shrew Soft VPN / IKE Daemon
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

add_definitions( -D PATH_CONF=\\"${PATH_ETC}\\" )

include_directories(
	${IKE_SOURCE_DIR}/source
	${IKE_SOURCE_DIR}/source/iked
	${IKE_SOURCE_DIR}/source/libike
	${IKE_SOURCE_DIR}/source/libidb
	${IKE_SOURCE_DIR}/source/libith
	${IKE_SOURCE_DIR}/source/libip
	${IKE_SOURCE_DIR}/source/liblog
	${IKE_SOURCE_DIR}/source/libpfk
	${INC_KERNEL_DIR} )

link_directories(
	${IKE_SOURCE_DIR}/source/libike
	${IKE_SOURCE_DIR}/source/libidb
	${IKE_SOURCE_DIR}/source/libith
	${IKE_SOURCE_DIR}/source/libip
	${IKE_SOURCE_DIR}/source/liblog
	${IKE_SOURCE_DIR}/source/libpfk )

add_executable(
	iked
	crypto.cpp
	conf.parse.cpp
	conf.token.cpp
	dhcp.cpp
	ike.cpp
	ike.exch.config.cpp
	ike.exch.inform.cpp
	ike.exch.phase1.cpp
	ike.exch.phase2.cpp
	ike.idb.config.cpp
	ike.idb.inform.cpp
	ike.idb.lists.cpp
	ike.idb.phase1.cpp
	ike.idb.phase2.cpp
	ike.idb.peer.cpp
	ike.idb.policy.cpp
	ike.idb.tunnel.cpp
	ike.idb.exch.cpp
	ike.io.admin.cpp
	ike.io.network.cpp
	ike.io.pfkey.cpp
	ike.keyfile.cpp
	ike.names.cpp
	ike.nethlp.cpp
	ike.packet.cpp
	ike.payload.cpp
	ike.peerid.cpp
	ike.policy.cpp
	ike.proposal.cpp
	ike.socket.cpp
	ike.xauth.cpp
	ike.xconf.cpp
	iked.cpp
	main.cpp )

target_link_libraries(
	iked
	ss_ike
	ss_idb
	ss_ith
	ss_ip
	ss_log
	ss_pfk
	crypto
	pthread )

if( FUNC_LIB_CRYPT )

target_link_libraries(
	iked
	crypt )

endif( FUNC_LIB_CRYPT )

# LDAP support option

if( LDAP )

	include_directories(
		${PATH_INC_LDAP} )

	target_link_libraries(
		iked
		${PATH_LIB_LDAP}
		${PATH_LIB_LBER} )

endif( LDAP )

set_source_files_properties(
	conf.parse.cpp GENERATED,
	conf.token.cpp GENERATED )

# Custom target for parser

add_custom_target( ConfParser echo "Creating Conf Parser" )

# Custom command for flex

add_custom_command(
	SOURCE conf.token.ll
	COMMAND ${PATH_BIN_FLEX}
	ARGS -d -oconf.token.cpp conf.token.ll
	TARGET ConfParser
	OUTPUTS conf.token.cpp )

# Custom command for bison

add_custom_command(
	SOURCE conf.parse.yy
	COMMAND ${PATH_BIN_BISON}
	ARGS -oconf.parse.cpp conf.parse.yy
	TARGET ConfParser
	OUTPUTS conf.parse.cpp conf.parse.hpp location.hh position.hh stack.hh )

# install support

install(
	TARGETS iked
	RUNTIME DESTINATION ${PATH_SBIN} )

install(
	FILES iked.8
	DESTINATION ${PATH_MAN}/man8 )

install(
	FILES iked.conf.5
	DESTINATION ${PATH_MAN}/man5 )

install(
	FILES iked.conf.sample
	DESTINATION ${PATH_ETC} )
