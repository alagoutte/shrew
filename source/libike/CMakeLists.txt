
#
# Shrew Soft VPN / IKE Daemon Interface Library
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
        ${IKE_SOURCE_DIR}/source
        ${IKE_SOURCE_DIR}/source/iked
        ${IKE_SOURCE_DIR}/source/libike
        ${IKE_SOURCE_DIR}/source/libidb
        ${IKE_SOURCE_DIR}/source/libith
        ${IKE_SOURCE_DIR}/source/liblog
        ${IKE_SOURCE_DIR}/source/libip )

add_library(
	ss_ike SHARED
	client.cpp
	config.cpp
	manager.cpp
	manager.file.cpp
	libike.cpp )

target_link_libraries(
	ss_ike
	ss_idb
	ss_ith
	crypto )

set_target_properties(
	ss_ike PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )

if( APPLE )

	set(
		MACOSX_BUNDLE_BUNDLE_NAME
		"ShrewSoftIke" )

	set_property(
		TARGET ss_ike
		PROPERTY FRAMEWORK ON )

	set_property(
		TARGET ss_ike
		PROPERTY OUTPUT_NAME ${MACOSX_BUNDLE_BUNDLE_NAME} )

endif( APPLE )

install(
	TARGETS ss_ike
	LIBRARY DESTINATION ${PATH_LIB}
	FRAMEWORK DESTINATION "/Library/Frameworks" )

