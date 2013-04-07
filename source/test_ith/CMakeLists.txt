#
# Shrew Soft VPN / IKE Daemon
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
	${IKE_SOURCE_DIR}/source
	${IKE_SOURCE_DIR}/source/libith )

link_directories(
	${IKE_SOURCE_DIR}/source/libith )

add_executable(
	test_ith_timer
	main.cpp )

target_link_libraries(
	test_ith_timer
	ss_ith
	pthread )
