#
# LIBIP Makefile
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2006, Shrew Soft Inc
#

C_FLAGS += -Wall -DUNIX
H_FLAGS += -I../ -I/usr/include -I/usr/local/include
L_FLAGS += -L../ -L/usr/lib -L/usr/local/lib -shared

.ifdef DEBUG
  D_FLAGS+=-g
.endif

LIBIP_B = libip.so
LIBIP_O = libip.bdata.o\
	  libip.frag.o\
	  libip.packet.o\
	  libip.packet.dns.o\
	  libip.packet.ip.o\
	  libip.packet.udp.o\
	  libip.pcap.o\
	  libip.queue.o\
	  libip.route.unix.o\
	  utils.list.o

LIBIP_H = libip.h utils.list.h

all: $(LIBIP_O) 
	$(CC) $(L_FLAGS) $(D_FLAGS) $(LIBIP_O) -o $(LIBIP_B)

.cpp.o: $(LIBIP_H)
	$(CC) -c $(C_FLAGS) $(D_FLAGS) $(H_FLAGS) $<
	
clean:
	-test -z "$(LIBIP_O)" || rm -f $(LIBIP_O)
	-test -z "$(LIBIP_B)" || rm -f $(LIBIP_B)

