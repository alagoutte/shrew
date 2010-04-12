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
	${IKE_SOURCE_DIR}/source/ikec
	${IKE_SOURCE_DIR}/source/iked
	${IKE_SOURCE_DIR}/source/libike
	${IKE_SOURCE_DIR}/source/libidb
	${IKE_SOURCE_DIR}/source/libith
	${IKE_SOURCE_DIR}/source/liblog
	${IKE_SOURCE_DIR}/source/libip
	${QT_INCLUDES} )

link_directories(
	${IKE_SOURCE_DIR}/source/libip
	${QT_LIBRARY_DIR} )

include( ${QT_USE_FILE} )

qt4_wrap_ui(
	UIH_FILES
	banner.ui
	filepass.ui
	root.ui )

qt4_wrap_cpp(
	CXX_FILES
	ikec.h )

qt4_add_resources(
	QRC_FILES
	ikec.qrc )

add_executable(
	ikec-qt
	main.cpp
	ikec.cpp
	root.cpp
	../ikec/config.cpp
	${UIH_FILES}
	${CXX_FILES}
	${QRC_FILES} )

target_link_libraries(
	ikec-qt
	ss_ike
	ss_idb
	ss_ith
	ss_log
	crypto
	pthread
	${QT_LIBRARIES} )

if( APPLE )

	set_property(
		TARGET ikec-qt
		PROPERTY MACOSX_BUNDLE ON )

	set(
		MACOSX_BUNDLE_BUNDLE_NAME
		"Shrew Soft VPN Connect" )

	set(
		MACOSX_BUNDLE_GUI_IDENTIFIER
		"net.shrew.vpn.ikec" )

	set(
		MACOSX_BUNDLE_ICON_FILE
		"ikec.png" )

	set(
		MACOSX_BUNDLE_LONG_VERSION_STRING
		${RELVER} )

	set(
		MACOSX_BUNDLE_SHORT_VERSION_STRING
		${RELVER} )

	add_custom_target(
		ikec-qt-bundle-resources
		COMMAND mkdir -p
			${CMAKE_CURRENT_BINARY_DIR}/ikec-qt.app/Contents/Resources
		COMMAND cp
			${CMAKE_CURRENT_BINARY_DIR}/png/${MACOSX_BUNDLE_ICON_FILE}
			${CMAKE_CURRENT_BINARY_DIR}/ikec-qt.app/Contents/Resources/${MACOSX_BUNDLE_ICON_FILE} )

	add_dependencies(
		ikec-qt
		ProjectName ikec-qt-bundle-resources )

endif( APPLE )

install(
	TARGETS ikec-qt
	RUNTIME	DESTINATION bin
	BUNDLE DESTINATION "/Applications" )

install(
	FILES ikec-qt.1
	DESTINATION ${PATH_MAN}/man1 )
