TEMPLATE	= app
LANGUAGE	= C++

CONFIG	+= qt warn_on release

LIBS	+= ../ikea/.obj/config.o ../libip/utils.list.o ../libiked/libiked.so

INCLUDEPATH	+= ./.. ../ikea/ ../libip/ ../iked/ ../libiked/

SOURCES	+= main.cpp \
	ikec.cpp

FORMS	= root.ui

IMAGES	= png/ikec.png

unix {
  UI_DIR = .ui
  MOC_DIR = .moc
  OBJECTS_DIR = .obj
}

