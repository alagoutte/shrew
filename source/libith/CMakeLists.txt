#
# Shrew Soft VPN / Timer and Thread Library
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
	${IKE_SOURCE_DIR}/source )

add_library(
	ss_ith SHARED
	libith.cpp )

# Linux realtime library

if( PATH_LIB_RT )

	target_link_libraries(
		ss_ith
		rt )

endif( PATH_LIB_RT )

set_target_properties(
	ss_ith PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )

if( APPLE )

	set(
		MACOSX_BUNDLE_BUNDLE_NAME
		"ShrewSoftIth" )

	set_property(
		TARGET ss_ith
		PROPERTY FRAMEWORK ON )

	set_property(
		TARGET ss_ith
		PROPERTY OUTPUT_NAME ${MACOSX_BUNDLE_BUNDLE_NAME} )

endif( APPLE )

install(
	TARGETS ss_ith
	LIBRARY DESTINATION ${PATH_LIB}
	FRAMEWORK DESTINATION "/Library/Frameworks" )
