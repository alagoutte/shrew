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
	ss_idb SHARED
	libidb.cpp
	base64.cpp )

target_link_libraries(
	ss_idb
	ss_ith
	ss_log )

set_target_properties(
	ss_idb PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )

if( APPLE )

	set(
		MACOSX_BUNDLE_BUNDLE_NAME
		"ShrewSoftIdb" )

	set_property(
		TARGET ss_idb
		PROPERTY FRAMEWORK ON )

	set_property(
		TARGET ss_idb
		PROPERTY OUTPUT_NAME ${MACOSX_BUNDLE_BUNDLE_NAME} )

endif( APPLE )

install(
	TARGETS ss_idb
	LIBRARY DESTINATION ${PATH_LIB}
	FRAMEWORK DESTINATION "/Library/Frameworks" )
