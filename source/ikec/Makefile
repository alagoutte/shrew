#
# IKEC Makefile
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2006, Shrew Soft Inc
#

UC = uic
UM = moc

C_FLAGS += -DUNIX -DQT_THREAD_SUPPORT -DQT_SHARED -Wall
H_FLAGS += -I./ -I../ -I../iked -I../ikea -I../libiked -I../libip -I/usr/include -I/usr/local/include -I/usr/X11R6/include
L_FLAGS += -L./ -L../ -L../iked -L../ikea -L../libiked -L../libip -L/usr/lib -L/usr/local/lib -L/usr/X11R6/lib -lstdc++ -lm -lpthread -liked -lqt-mt
D_FLAGS += 

.ifdef DEBUG
  C_FLAGS+=-g
.endif

.SUFFIXES: .ui

IKEC_B = ikec
IKEC_U = root.ui \
	 banner.ui
IKEC_G = png/ikec.png
IKEC_O = main.o\
	 ikec.o \
	 banner.o\
	 root.o\
	 images.o\
	 moc_banner.o\
	 moc_root.o

IKEC_P = ../libip/utils.list.o \
	 ../ikea/config.o
	 
IKEC_H = ikec.h banner.h root.h

all: $(IKEC_U) $(IKEC_O)
	$(CC) $(L_FLAGS) $(D_FLAGS) -o $(IKEC_B) $(IKEC_O) $(IKEC_P)

moc_banner.cpp: $(IKEC_H)
	$(UM) banner.h -o moc_banner.cpp

moc_root.cpp: $(IKEC_H)
	$(UM) root.h -o moc_root.cpp

images.cpp: $(IKEC_G)
	$(UC) -embed $(IKEC_B) $(IKEC_G) -o images.cpp

.ui.h: $(IKEC_U)
	$(UC) $< -o $@

.ui.cpp: $(IKEC_U)
	$(UC) $< -i $*.h -o $@

.cpp.o: $(IKEC_H)
	$(CC) -c $(C_FLAGS) $(D_FLAGS) $(H_FLAGS) $<

clean:
	-test -z "$(IKEC_O)" || rm -f $(IKEC_O)
	-test -z "$(IKEC_B)" || rm -f $(IKEC_B)
	-test -z "banner.h" || rm -f banner.h
	-test -z "root.h" || rm -f root.h
	-test -z "banner.cpp" || rm -f banner.cpp
	-test -z "root.cpp" || rm -f root.cpp
	-test -z "images.cpp" || rm -f images.cpp

install:
	-install -c $(IKEC_B) /usr/X11R6/bin/
