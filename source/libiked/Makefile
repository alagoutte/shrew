#
# LIBIKED Makefile
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2006, Shrew Soft Inc
#

C_FLAGS += -DUNIX -Wall
H_FLAGS += -I../ -I../iked -I../libip -I/usr/include -I/usr/local/include -I/usr/include/netinet6
L_FLAGS += -L../ -L/usr/lib -L/usr/local/lib -shared
D_FLAGS += 

.ifdef DEBUG
  D_FLAGS+=-g
.endif

LIBIKED_B = libiked.so
LIBIKED_O = libiked.o

LIBIKED_H = libiked.h

all: $(LIBIKED_O) 
	$(CC) $(L_FLAGS) $(D_FLAGS) -o $(LIBIKED_B) $(LIBIKED_O)

.cpp.o: $(LIBIKED_H)
	$(CC) -c $(C_FLAGS) $(D_FLAGS) $(H_FLAGS) $<
	
clean:
	-test -z "$(LIBIKED_O)" || rm -f $(LIBIKED_O)
	-test -z "$(LIBIKED_B)" || rm -f $(LIBIKED_B)

install:
	-install -c $(LIBIKED_B) /usr/local/lib/
