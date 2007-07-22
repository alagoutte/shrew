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
        ${IKE_SOURCE_DIR}/source/libip )

add_library(
	ike SHARED
	libike.cpp )
