#
# Shrew Soft VPN / Client Connect Application
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
	${IKE_SOURCE_DIR}/source/
	${IKE_SOURCE_DIR}/source/compat
	${IKE_SOURCE_DIR}/source/ikea
	${IKE_SOURCE_DIR}/source/iked
	${IKE_SOURCE_DIR}/source/libike
	${IKE_SOURCE_DIR}/source/libidb
	${IKE_SOURCE_DIR}/source/libith
	${IKE_SOURCE_DIR}/source/liblog
	${IKE_SOURCE_DIR}/source/libip
	${QT_INCLUDES} )

link_directories(
	${IKE_SOURCE_DIR}/source/libip )

add_executable(
	ikec
	config.cpp
	main.cpp
	ikec.cpp
	ikec-cli.cpp )

target_link_libraries(
	ikec
	ss_ike
	ss_idb
	ss_ith
	ss_log
	pthread
	edit )

# install support

install(
	TARGETS ikec
	RUNTIME	DESTINATION bin )

install(
	FILES ikec.1
	DESTINATION ${PATH_MAN}/man1 )
