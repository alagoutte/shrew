#
# Shrew Soft VPN / Client Connect Application
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

add_definitions( -D QT_THREAD_SUPPORT )

include_directories(
	${IKE_SOURCE_DIR}/source/
	${IKE_SOURCE_DIR}/source/ikea
	${IKE_SOURCE_DIR}/source/iked
	${IKE_SOURCE_DIR}/source/libike
	${IKE_SOURCE_DIR}/source/libip
	/usr/X11R6/include )

link_directories(
	/usr/X11R6/lib )

add_executable(
	ikec
	main.cpp
	ikec.cpp
	../ikea/config.cpp
	images.cpp
	banner.cpp
	root.cpp
	moc_banner.cpp
	moc_root.cpp )

target_link_libraries(
	ikec
	ike
        ip
	pthread
	qt-mt )

# Custom target for IMG

add_custom_target( IPSecCIMG echo "Creating VPN Client Connect IMG" )

add_custom_command(
        SOURCE png/ikec.png
        COMMAND uic
        ARGS -embed ikec png/ikec.png -o images.cpp
        TARGET IPSecCIMG
        OUTPUTS images.cpp )

# Custom target for UIC

add_custom_target( IPSecCUIC echo "Creating VPN Client Connect UIC" )

add_custom_command(
        SOURCE banner.ui
        COMMAND uic
        ARGS banner.ui -o banner.h
        TARGET IPSecCUIC
        OUTPUTS banner.h )

add_custom_command(
        SOURCE root.ui
        COMMAND uic
        ARGS root.ui -o root.h
        TARGET IPSecCUIC
        OUTPUTS root.h )

# Custom target for CPP

add_custom_target( IPSecCCPP echo "Creating VPN Client Connect CPP" )

add_custom_command(
        SOURCE banner.h
        COMMAND uic
        ARGS banner.ui -i banner.h -o banner.cpp
        TARGET IPSecCCPP
        OUTPUTS banner.cpp )

add_custom_command(
        SOURCE root.h
        COMMAND uic
        ARGS root.ui -i root.h -o root.cpp
        TARGET IPSecCCPP
        OUTPUTS root.cpp )

add_custom_target( IPSecCMOC echo "Creating VPN Client Connect MOC" )

# Custom command for MOC

add_custom_command(
        SOURCE banner.h
        COMMAND moc
        ARGS banner.h -o moc_banner.cpp
        TARGET IPSecCMOC
        OUTPUTS moc_banner.cpp )

add_custom_command(
        SOURCE root.h
        COMMAND moc
        ARGS root.h -o moc_root.cpp
        TARGET IPSecCMOC
        OUTPUTS moc_root.cpp )

