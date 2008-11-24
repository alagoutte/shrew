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
	${QT_INCLUDES} )

link_directories(
	${IKE_SOURCE_DIR}/source/libip
	${QT_LIBRARY_DIR} )

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
	ikea-qt
	config.cpp
	ikea.cpp
	main.cpp
	root.cpp
	site.cpp
	${UIH_FILES}
	${CXX_FILES}
	${QRC_FILES} )

target_link_libraries(
	ikea-qt
	ss_idb
	ss_ith
	ss_log
	pthread
	QtCore
	QtGui
	${QT_LIBRARIES} )

# install support

install(
	TARGETS ikea-qt
	RUNTIME	DESTINATION bin )

install(
	FILES ikea.1
	DESTINATION ${PATH_MAN}/man1 )
