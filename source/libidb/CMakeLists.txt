#
# Shrew Soft VPN / Internal Object Database
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
	${IKE_SOURCE_DIR}/source
	${IKE_SOURCE_DIR}/source/libip
	${IKE_SOURCE_DIR}/source/liblog
	${IKE_SOURCE_DIR}/source/libith )

add_library(
	idb
	libidb.cpp
	base64.cpp )

set_target_properties(
	idb PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )
