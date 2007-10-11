#
# Shrew Soft VPN / PF KEY Helper Library
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
        ${IKE_SOURCE_DIR}/source )

add_library(
	pfk SHARED
	libpfk.cpp )

set_target_properties(
        pfk PROPERTIES
	VERSION ${RELVER}
	SOVERSION ${RELVER} )

# install support

install(
	TARGETS pfk
	LIBRARY DESTINATION lib )

