#
# Shrew Soft VPN / Client Connect Application
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

include_directories(
	${IKE_SOURCE_DIR}/source/
	${IKE_SOURCE_DIR}/source/ikea
	${IKE_SOURCE_DIR}/source/iked
	${IKE_SOURCE_DIR}/source/libike
	${IKE_SOURCE_DIR}/source/libidb
	${IKE_SOURCE_DIR}/source/libith
	${IKE_SOURCE_DIR}/source/liblog
	${IKE_SOURCE_DIR}/source/libip
	${QT_INCLUDE_DIR} )

link_directories(
	${IKE_SOURCE_DIR}/source/libip )

set(
	UIC_FILES
	banner.ui
	filepass.ui
	root.ui )

set(
	IMG_FILES
	png/ikec.png )

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
	ikec
	main.cpp
	ikec.cpp
	../ikea/config.cpp
	images.cxx
	${CPP_FILES} )

target_link_libraries(
	ikec
	ike
        idb
        ith
        log
	pthread
	${QT_LIBRARIES} )

# qt image support

add_custom_command(  
	SOURCE ${IMG_FILES}
        COMMAND ${QT_UIC_EXECUTABLE}
        ARGS -embed ikec ${IMG_FILES} -o images.cxx
        TARGET ikec
        OUTPUTS images.cxx )

# install support

install(
	TARGETS ikec
	RUNTIME	DESTINATION bin )

install(
	FILES ikec.1
	DESTINATION ${PATH_MAN}/man1 )

