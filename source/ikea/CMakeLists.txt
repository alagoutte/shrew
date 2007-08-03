#
# Shrew Soft VPN / Access Manager Application
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

add_definitions( -D QT_THREAD_SUPPORT )

include_directories(
	${IKE_SOURCE_DIR}/source/
	${IKE_SOURCE_DIR}/source/libip
	/usr/X11R6/include )

link_directories(
	${IKE_SOURCE_DIR}/source/libip
	/usr/X11R6/lib )

add_executable(
	ikea
	main.cpp
	ikea.cpp
	config.cpp
	images.cpp
	site.cpp
	root.cpp
	topology.cpp
	about.cpp
	moc_site.cpp
	moc_root.cpp
	moc_topology.cpp
	moc_about.cpp )

target_link_libraries(
	ikea
        ip
	pthread
	qt-mt )

# Custom target for IMG

add_custom_target( IPSecAIMG echo "Creating VPN Access Manager IMG" )

add_custom_command(
        SOURCE png/policy_exc.png  png/policy_inc.png  png/site.png  png/site_add.png  png/site_con.png  png/site_del.png  png/site_mod.png  png/ikea.png
        COMMAND uic
        ARGS -embed ikea png/policy_exc.png  png/policy_inc.png  png/site.png  png/site_add.png  png/site_con.png  png/site_del.png  png/site_mod.png  png/ikea.png -o images.cpp
        TARGET IPSecAIMG
        OUTPUTS images.cpp )

# Custom target for UIC

add_custom_target( IPSecAUIC echo "Creating VPN Access Manager UIC" )

add_custom_command(
        SOURCE site.ui
        COMMAND uic
        ARGS site.ui -o site.h
        TARGET IPSecAUIC
        OUTPUTS site.h )

add_custom_command(
        SOURCE root.ui
        COMMAND uic
        ARGS root.ui -o root.h
        TARGET IPSecAUIC
        OUTPUTS root.h )

add_custom_command(
        SOURCE topology.ui
        COMMAND uic
        ARGS topology.ui -o topology.h
        TARGET IPSecAUIC
        OUTPUTS topology.h )

add_custom_command(
        SOURCE about.ui
        COMMAND uic
        ARGS about.ui -o about.h
        TARGET IPSecAUIC
       OUTPUTS about.h )

# Custom target for CPP

add_custom_target( IPSecACPP echo "Creating VPN Access Manager CPP" )

add_custom_command(
        SOURCE site.h
        COMMAND uic
        ARGS site.ui -i site.h -o site.cpp
        TARGET IPSecACPP
        OUTPUTS site.cpp )

add_custom_command(
        SOURCE root.h
        COMMAND uic
        ARGS root.ui -i root.h -o root.cpp
        TARGET IPSecACPP
        OUTPUTS root.cpp )

add_custom_command(
        SOURCE topology.h
        COMMAND uic
        ARGS topology.ui -i topology.h -o topology.cpp
        TARGET IPSecACPP
        OUTPUTS topology.cpp )

add_custom_command(
        SOURCE about.h
        COMMAND uic
        ARGS about.ui -i about.h -o about.cpp
        TARGET IPSecACPP
        OUTPUTS about.cpp )

add_custom_target( IPSecAMOC echo "Creating VPN Access Manager MOC" )

# Custom command for MOC

add_custom_command(
        SOURCE site.h
        COMMAND moc
        ARGS site.h -o moc_site.cpp
        TARGET IPSecAMOC
        OUTPUTS moc_site.cpp )

add_custom_command(
        SOURCE root.h
        COMMAND moc
        ARGS root.h -o moc_root.cpp
        TARGET IPSecAMOC
        OUTPUTS moc_root.cpp )

add_custom_command(
        SOURCE topology.h
        COMMAND moc
        ARGS topology.h -o moc_topology.cpp
        TARGET IPSecAMOC
        OUTPUTS moc_topology.cpp )

add_custom_command(
        SOURCE about.h
        COMMAND moc
        ARGS about.h -o moc_about.cpp
        TARGET IPSecAMOC
        OUTPUTS moc_about.cpp )


