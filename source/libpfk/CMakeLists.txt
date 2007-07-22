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
	libpfk SHARED
	libpfk.cpp )
