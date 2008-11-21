TEMPLATE = app
LANGUAGE = C++

CONFIG		+= qt warn_on release
QT		+= qtgui
LIBS		+= ../libidb/libidb.a ../libith/libith.a ../liblog/liblog.a
DEFINES		+= OPT_NATT UNIX
INCLUDEPATH 	+= . ./.. ../libidb ../libith ../liblog

HEADERS	= 		\
	config.h	\
	ikea.h

SOURCES	=		\
	config.cpp	\
	ikea.cpp	\
	main.cpp	\
	root.cpp	\
	site.cpp

FORMS	=		\
	site.ui		\
	root.ui		\
	topology.ui	\
	about.ui	\
	conflict.ui

RESOURCES =		\
	ikea.qrc

unix {
	UI_DIR = .ui
	MOC_DIR = .moc
	OBJECTS_DIR = .obj
}

