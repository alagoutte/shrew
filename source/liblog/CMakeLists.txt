#
# Shrew Soft VPN / Log Facility Library
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
        ${IKE_SOURCE_DIR}/source
        ${IKE_SOURCE_DIR}/source/libith )

add_library(
	ss_log SHARED
	liblog.cpp )

target_link_libraries(
	ss_log
	ss_ith )

set_target_properties(
	ss_log PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )

if( APPLE )

	set(
		MACOSX_BUNDLE_BUNDLE_NAME
		"ShrewSoftLog" )

	set_property(
		TARGET ss_log
		PROPERTY FRAMEWORK ON )

	set_property(
		TARGET ss_log
		PROPERTY OUTPUT_NAME ${MACOSX_BUNDLE_BUNDLE_NAME} )

endif( APPLE )

install(
	TARGETS ss_log
	LIBRARY DESTINATION ${PATH_LIB}
	FRAMEWORK DESTINATION "/Library/Frameworks" )

