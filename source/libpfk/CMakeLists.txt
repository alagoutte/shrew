#
# Shrew Soft VPN / PF KEY Helper Library
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
        ${IKE_SOURCE_DIR}/source
        ${IKE_SOURCE_DIR}/source/libidb
        ${IKE_SOURCE_DIR}/source/libith
        ${IKE_SOURCE_DIR}/source/liblog
	${INC_KERNEL_DIR} )

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

