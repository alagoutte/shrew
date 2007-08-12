TEMPLATE	= app
LANGUAGE	= C++

CONFIG	+= qt warn_on release

LIBS	+= ../libip/libip.a

DEFINES	+= OPT_NATT

INCLUDEPATH	+= ./.. ../libip

HEADERS	+= config.h

SOURCES	+= main.cpp \
	config.cpp \
	ikea.cpp

FORMS	= site.ui \
	root.ui \
	topology.ui \
	about.ui

IMAGES	= png/policy_exc.png \
	png/policy_inc.png \
	png/site.png \
	png/site_add.png \
	png/site_con.png \
	png/site_del.png \
	png/site_mod.png \
	png/ikea.png

unix {
  UI_DIR = .ui
  MOC_DIR = .moc
  OBJECTS_DIR = .obj
}

