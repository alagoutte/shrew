#
# LIBPFK Makefile
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2006, Shrew Soft Inc
#

C_FLAGS += -DUNIX -Wall -fPIC
H_FLAGS += -I../ -I../libith -I../iked -I/usr/include/netinet6 -I/usr/include -I/usr/local/include
L_FLAGS += -L../ -L/usr/lib -L/usr/local/lib -shared -lpthread

.ifdef DEBUG
  D_FLAGS+=-g
.endif

.ifdef NATT
  C_FLAGS+=-DOPT_NATT
.endif

LIBPFK_B = libpfk.so
LIBPFK_O = libpfk.o

LIBPFK_H = libpfk.h

all: $(LIBPFK_O)
	$(CC) $(L_FLAGS) $(D_FLAGS) -o $(LIBPFK_B) $(LIBPFK_O)

.cpp.o: $(LIBPFK_H)
	$(CC) -c $(C_FLAGS) $(D_FLAGS) $(H_FLAGS) $<
	
clean:
	-test -z "$(LIBPFK_O)" || rm -f $(LIBPFK_O)
	-test -z "$(LIBPFK_B)" || rm -f $(LIBPFK_B)

install:
	-install -c $(LIBPFK_B) /usr/local/lib/
