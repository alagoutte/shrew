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
	qikea
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
	qikea
	ss_idb
	ss_ith
	ss_log
	crypto
	pthread
	${QT_LIBRARIES} )

if( APPLE )

	set_property(
		TARGET qikea
		PROPERTY MACOSX_BUNDLE ON )

	set(
		MACOSX_BUNDLE_BUNDLE_NAME
		"Shrew Soft VPN Access Manager" )

	set(
		MACOSX_BUNDLE_GUI_IDENTIFIER
		"net.shrew.vpn.ikea" )

	set(
		MACOSX_BUNDLE_ICON_FILE
		"ikea.png" )

	set(
		MACOSX_BUNDLE_LONG_VERSION_STRING
		${RELVER} )

	set(
		MACOSX_BUNDLE_SHORT_VERSION_STRING
		${RELVER} )

	add_custom_target(
		qikea-bundle-resources
		COMMAND mkdir -p
			${CMAKE_CURRENT_BINARY_DIR}/qikea.app/Contents/Resources
		COMMAND cp
			${CMAKE_CURRENT_BINARY_DIR}/png/${MACOSX_BUNDLE_ICON_FILE}
			${CMAKE_CURRENT_BINARY_DIR}/qikea.app/Contents/Resources/${MACOSX_BUNDLE_ICON_FILE} )

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
