#
# LIBLOG Makefile
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2006, Shrew Soft Inc
#

C_FLAGS += -DUNIX -Wall -fPIC
H_FLAGS += -I../ -I/usr/include -I/usr/local/include
L_FLAGS += -L../ -L/usr/lib -L/usr/local/lib -shared -lpthread

.ifdef DEBUG
  D_FLAGS+=-g
.endif

LIBITH_B = libith.so
LIBITH_O = libith.o

LIBITH_H = libith.h

all: $(LIBITH_O)
	$(CC) $(L_FLAGS) $(D_FLAGS) -o $(LIBITH_B) $(LIBITH_O)

.cpp.o: $(LIBITH_H)
	$(CC) -c $(C_FLAGS) $(D_FLAGS) $(H_FLAGS) $<
	
clean:
	-test -z "$(LIBITH_O)" || rm -f $(LIBITH_O)
	-test -z "$(LIBITH_B)" || rm -f $(LIBITH_B)

