TEMPLATE = app
LANGUAGE = C++

CONFIG		+= qt warn_on release
QT 		+= qtgui
LIBS 		+= ../ikea/.obj/config.o ../libidb/libidb.a ../libith/libith.a ../liblog/liblog.a ../libike/libike.so
DEFINES		+= OPT_NATT UNIX
INCLUDEPATH	+= ./ ./.. ../libidb/ ../libike/ ../iked/ ../libip/ ../liblog ../libith

HEADERS =		\
	ikec.h

SOURCES	=		\
	ikec.cpp	\
	main.cpp	\
	root.cpp

FORMS	=		\
	banner.ui	\
	filepass.ui	\
	root.ui

RESOUCES =		\
	ikec.qrc
	
unix {
        UI_DIR = .ui
        MOC_DIR = .moc
        OBJECTS_DIR = .obj
}
