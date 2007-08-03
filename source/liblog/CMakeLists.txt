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
        ${IKE_SOURCE_DIR}/source/compat
        ${IKE_SOURCE_DIR}/source/libith )

add_library(
	log
	liblog.cpp )
