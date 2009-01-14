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
	${QT_INCLUDES} )

link_directories(
	${IKE_SOURCE_DIR}/source/libip
	${QT_LIBRARY_DIR} )

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
	../ikea-qt/config.cpp
	${UIH_FILES}
	${CXX_FILES}
	${QRC_FILES} )

target_link_libraries(
	ikec-qt
	ss_ike
	ss_idb
	ss_ith
	ss_log
	pthread
	QtCore
	QtGui
	${QT_LIBRARIES} )

# install support

install(
	TARGETS ikec-qt
	RUNTIME	DESTINATION bin )

install(
	FILES ikec-qt.1
	DESTINATION ${PATH_MAN}/man1 )
