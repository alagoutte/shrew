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
	${IKE_SOURCE_DIR}/source/ikec
	${IKE_SOURCE_DIR}/source/libike
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
	qikea.h )

qt4_add_resources(
	QRC_FILES
	qikea.qrc )

add_executable(
	qikea
	main.cpp
	qikea.cpp
	root.cpp
	site.cpp
	topology.cpp
	${UIH_FILES}
	${CXX_FILES}
	${QRC_FILES} )

target_link_libraries(
	qikea
	ss_ike
	ss_idb
	ss_ith
	ss_log
	crypto
	pthread
	${QT_LIBRARIES} )

if( APPLE )

	set(
		MACOSX_BUNDLE_BUNDLE_NAME
		"Shrew Soft VPN Access Manager" )

	set(
		MACOSX_BUNDLE_GUI_IDENTIFIER
		"net.shrew.vpn.qikea" )

	set(
		MACOSX_BUNDLE_ICON_FILE
		"qikea.icns" )

	set(
		MACOSX_BUNDLE_LONG_VERSION_STRING
		${RELVER} )

	set(
		MACOSX_BUNDLE_SHORT_VERSION_STRING
		${RELVER} )

	set_property(
		TARGET qikea
		PROPERTY MACOSX_BUNDLE ON )

	set_property(
		TARGET qikea
		PROPERTY OUTPUT_NAME ${MACOSX_BUNDLE_BUNDLE_NAME} )

	add_custom_target(
		qikea-bundle-resources
		COMMAND mkdir -p
			${CMAKE_CURRENT_SOURCE_DIR}/${MACOSX_BUNDLE_BUNDLE_NAME}.app/Contents/Resources
		COMMAND cp
			${CMAKE_CURRENT_SOURCE_DIR}/png/${MACOSX_BUNDLE_ICON_FILE}
			${CMAKE_CURRENT_SOURCE_DIR}/${MACOSX_BUNDLE_BUNDLE_NAME}.app/Contents/Resources/${MACOSX_BUNDLE_ICON_FILE} )

	add_dependencies(
		qikea
		ProjectName qikea-bundle-resources )

endif( APPLE )

install(
	TARGETS qikea
	RUNTIME	DESTINATION bin
	BUNDLE DESTINATION "/Applications" )

install(
	FILES qikea.1
	DESTINATION ${PATH_MAN}/man1 )

if( APPLE )

#	set(
#		MACOSX_BUNDLE_DEST_DIR
#		"/Applications/${MACOSX_BUNDLE_BUNDLE_NAME}.app" )

#	set(
#		MACOSX_QTPLUGINS_DEST_DIR
#		"${MACOSX_BUNDLE_DEST_DIR}/Contents/MacOS/plugins" )

#	install(
#		DIRECTORY "${QT_PLUGINS_DIR}/imageformats"
#		DESTINATION "${MACOSX_QTPLUGINS_DEST_DIR}"
#		COMPONENT Runtime )

#	set(
#		MACOSX_QTCONF_DEST_DIR
#		"${MACOSX_BUNDLE_DEST_DIR}/Contents/Resources" )

#	install(
#		CODE "file( WRITE \"${MACOSX_QTCONF_DEST_DIR}/qt.conf\" \"\" )"
#		COMPONENT Runtime )

	install(
		CODE "execute_process( COMMAND \"install_name_tool\" -change
			${QT_LIBRARY_DIR}/QtCore.framework/Versions/4/QtCore
			ShrewSoftQtCore.framework/Versions/4/ShrewSoftQtCore
			\"/Applications/${MACOSX_BUNDLE_BUNDLE_NAME}.app/Contents/MacOS/${MACOSX_BUNDLE_BUNDLE_NAME}\" )" )

	install(
		CODE "execute_process( COMMAND \"install_name_tool\" -change
			${QT_LIBRARY_DIR}/QtGui.framework/Versions/4/QtGui
			ShrewSoftQtGui.framework/Versions/4/ShrewSoftQtGui
			\"/Applications/${MACOSX_BUNDLE_BUNDLE_NAME}.app/Contents/MacOS/${MACOSX_BUNDLE_BUNDLE_NAME}\" )" )

endif( APPLE )
