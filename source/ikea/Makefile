#
# IKEA Makefile
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2006, Shrew Soft Inc
#

UC = uic
UM = moc

C_FLAGS += -DUNIX -DQT_THREAD_SUPPORT -DQT_SHARED -Wall
H_FLAGS += -I./ -I../ -I../libiked -I../libip -I/usr/include -I/usr/local/include -I/usr/X11R6/include
L_FLAGS += -L./ -L../ -L../libiked -L../libip -L/usr/lib -L/usr/local/lib -L/usr/X11R6/lib -lstdc++ -lm -lpthread -liked -lqt-mt
D_FLAGS += 

.ifdef DEBUG
  C_FLAGS+=-g
.endif

.ifdef NATT
  C_FLAGS+=-DOPT_NATT
.endif

.SUFFIXES: .ui

IKEA_B = ikea
IKEA_U = site.ui \
	 root.ui \
	 topology.ui \
	 about.ui
IKEA_G = png/policy_exc.png \
	 png/policy_inc.png \
	 png/site.png \
	 png/site_add.png \
	 png/site_con.png \
	 png/site_del.png \
	 png/site_mod.png \
	 png/ikea.png
IKEA_O = main.o\
	 config.o \
	 ikea.o \
	 site.o\
	 root.o\
	 topology.o\
	 about.o\
	 images.o\
	 moc_site.o\
	 moc_root.o\
	 moc_topology.o\
	 moc_about.o

IKEA_P = ../libip/utils.list.o
	 
IKEA_H = ikea.h site.h root.h topology.h about.h

all: $(IKEA_U) $(IKEA_O)
	$(CC) $(L_FLAGS) $(D_FLAGS) -o $(IKEA_B) $(IKEA_O) $(IKEA_P)

moc_site.cpp: $(IKEA_H) site.ui.h
	$(UM) site.h -o moc_site.cpp

moc_root.cpp: $(IKEA_H) root.ui.h
	$(UM) root.h -o moc_root.cpp

moc_topology.cpp: $(IKEA_H) topology.ui.h
	$(UM) topology.h -o moc_topology.cpp

moc_about.cpp: $(IKEA_H)
	$(UM) about.h -o moc_about.cpp

images.cpp: $(IKEA_G)
	$(UC) -embed $(IKEA_B) $(IKEA_G) -o images.cpp

.ui.h: $(IKEA_U)
	$(UC) $< -o $@

.ui.cpp: $(IKEA_U)
	$(UC) $< -i $*.h -o $@

.cpp.o: $(IKEA_H)
	$(CC) -c $(C_FLAGS) $(D_FLAGS) $(H_FLAGS) $<

clean:
	-test -z "$(IKEA_O)" || rm -f $(IKEA_O)
	-test -z "$(IKEA_B)" || rm -f $(IKEA_B)
	-test -z "site.h" || rm -f site.h
	-test -z "root.h" || rm -f root.h
	-test -z "topology.h" || rm -f topology.h
	-test -z "about.h" || rm -f about.h
	-test -z "site.cpp" || rm -f site.cpp
	-test -z "root.cpp" || rm -f root.cpp
	-test -z "topology.cpp" || rm -f topology.cpp
	-test -z "about.cpp" || rm -f about.cpp
	-test -z "images.cpp" || rm -f images.cpp

install:
	-install -c $(IKEA_B) /usr/local/bin/
