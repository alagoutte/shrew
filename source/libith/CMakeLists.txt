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
	ith
	libith.cpp )

set_target_properties(
	ith PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )
