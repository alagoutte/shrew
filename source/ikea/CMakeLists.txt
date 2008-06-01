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
	${IKE_SOURCE_DIR}/source/libidb
	${IKE_SOURCE_DIR}/source/libith
	${IKE_SOURCE_DIR}/source/liblog
	${QT_INCLUDE_DIR} )

link_directories(
	${IKE_SOURCE_DIR}/source/libip )

set(
	UIC_FILES
	site.ui
	root.ui
	conflict.ui
	topology.ui
	about.ui )

set(
	IMG_FILES
	png/logo_ssoft.png
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
	images.cxx
	${CPP_FILES} )

target_link_libraries(
	ikea
        idb
        ith
        log
	pthread
	${QT_LIBRARIES} )

# qt image support

add_custom_command(  
	SOURCE ${IMG_FILES}
        COMMAND ${QT_UIC_EXECUTABLE}
        ARGS -embed ikea ${IMG_FILES} -o images.cxx
        TARGET ikea
        OUTPUTS images.cxx )

# install support

install(
	TARGETS ikea
	RUNTIME	DESTINATION bin )

install(
	FILES ikea.1
	DESTINATION ${PATH_MAN}/man1 )
