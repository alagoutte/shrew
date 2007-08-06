#
# Shrew Soft VPN / Access Manager Application
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
	${IKE_SOURCE_DIR}/source/
	${IKE_SOURCE_DIR}/source/libip
	${QT_INCLUDE_DIR} )

link_directories(
	${IKE_SOURCE_DIR}/source/libip )

set(
	UIC_FILES
	site.ui
	root.ui
	topology.ui
	about.ui )

set(
	IMG_FILES
	png/policy_exc.png
	png/policy_inc.png
	png/site.png
	png/site_add.png
	png/site_con.png
	png/site_del.png
	png/site_mod.png
	png/ikea.png )

qt_wrap_ui(
	LIB_FILES
	INC_FILES
	CPP_FILES
	${UIC_FILES} )

qt_wrap_cpp(
	LIB_FILES
	MOC_FILES
	${INC_FILES} )

add_executable(
	ikea
	main.cpp
	ikea.cpp
	config.cpp
	images.cpp
	${CPP_FILES} )

target_link_libraries(
	ikea
        ip
	pthread
	${QT_LIBRARIES} )

# qt image support

add_custom_command(  
	SOURCE ${IMG_FILES}
        COMMAND ${QT_UIC_EXECUTABLE}
        ARGS -embed ${IMG_FILES} -o images.cpp
        TARGET ikea
        OUTPUTS images.cpp )

# install support

install(
	TARGETS ikea
	RUNTIME	DESTINATION bin )
