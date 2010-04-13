#
# Shrew Soft VPN / Access Manager Application
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

set( APPNAME qikea )

if( APPLE )
	set( APPNAME "Shrew Soft VPN Access Manager" )
endif( APPLE )

include_directories(
	${IKE_SOURCE_DIR}/source/
	${IKE_SOURCE_DIR}/source/ikec
	${IKE_SOURCE_DIR}/source/libidb
	${IKE_SOURCE_DIR}/source/libith
	${IKE_SOURCE_DIR}/source/liblog
	${QT_INCLUDES} )

link_directories(
	${IKE_SOURCE_DIR}/source/libip
	${QT_LIBRARY_DIR} )

include( ${QT_USE_FILE} )

qt4_wrap_ui(
	UIH_FILES
	about.ui
	conflict.ui
	root.ui
	site.ui
	topology.ui )

qt4_wrap_cpp(
	CXX_FILES
	ikea.h )

qt4_add_resources(
	QRC_FILES
	ikea.qrc )

add_executable(
	${APPNAME}
	../ikec/config.cpp
	ikea.cpp
	main.cpp
	root.cpp
	site.cpp
	topology.cpp
	${UIH_FILES}
	${CXX_FILES}
	${QRC_FILES} )

target_link_libraries(
	${APPNAME}
	ss_idb
	ss_ith
	ss_log
	crypto
	pthread
	${QT_LIBRARIES} )

if( APPLE )

	set_property(
		TARGET ${APPNAME}
		PROPERTY MACOSX_BUNDLE ON )

	set(
		MACOSX_BUNDLE_BUNDLE_NAME
		${APPNAME} )

	set(
		MACOSX_BUNDLE_GUI_IDENTIFIER
		"net.shrew.vpn.ikea" )

	set(
		MACOSX_BUNDLE_ICON_FILE
		"qikea.icns" )

	set(
		MACOSX_BUNDLE_LONG_VERSION_STRING
		${RELVER} )

	set(
		MACOSX_BUNDLE_SHORT_VERSION_STRING
		${RELVER} )

	add_custom_target(
		qikea-bundle-resources
		COMMAND mkdir -p
			${CMAKE_CURRENT_SOURCE_DIR}/${APPNAME}.app/Contents/Resources
		COMMAND cp
			${CMAKE_CURRENT_SOURCE_DIR}/png/${MACOSX_BUNDLE_ICON_FILE}
			${CMAKE_CURRENT_SOURCE_DIR}/${APPNAME}.app/Contents/Resources/${MACOSX_BUNDLE_ICON_FILE} )

	add_dependencies(
		${APPNAME}
		ProjectName qikea-bundle-resources )

endif( APPLE )

install(
	TARGETS ${APPNAME}
	RUNTIME	DESTINATION bin
	BUNDLE DESTINATION "/Applications" )

install(
	FILES qikea.1
	DESTINATION ${PATH_MAN}/man1 )
