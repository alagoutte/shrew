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
	ss.log SHARED
	liblog.cpp )

set_target_properties(
	ss.log PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )

# install support

install(
	TARGETS ss.log
	LIBRARY DESTINATION lib )
