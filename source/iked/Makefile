#
# LIBIP Makefile
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2006, Shrew Soft Inc
#

BC = bison
LC = lex

C_FLAGS += -DUNIX -Wall
H_FLAGS += -I./ -I../ -I../libiked -I../libith -I../libip -I../liblog -I../libpfk -I/usr/include -I/usr/local/include -I/usr/include/openssl -I/usr/include/netinet6
L_FLAGS += -L./ -L../ -L../libiked -L../libith -L../libip -L../liblog -L../libpfk -L/usr/lib -L/usr/local/lib -lstdc++ -lm -lpthread -lcrypt -lcrypto -liked -lpfk
D_FLAGS += 

.ifdef DEBUG
  C_FLAGS+=-g
.endif

.ifdef SHADOW
  C_FLAGS+=-DOPT_SHADOW
.endif

.ifdef NATT
  C_FLAGS+=-DOPT_NATT
.endif

.ifdef LDAP
  C_FLAGS+=-DOPT_LDAP
  L_FLAGS+=-lldap -llber
.endif

.SUFFIXES: .yy .ll

IKED_B = iked
IKED_O = crypto.o\
	 conf.parse.o \
	 conf.token.o \
	 ike.o\
	 ike.exch.config.o\
	 ike.exch.inform.o\
	 ike.exch.phase1.o\
	 ike.exch.phase2.o\
	 ike.idb.config.o\
	 ike.idb.inform.o\
	 ike.idb.lists.o\
	 ike.idb.phase1.o\
         ike.idb.phase2.o\
	 ike.idb.peer.o\
	 ike.idb.policy.o\
	 ike.idb.tunnel.o\
	 ike.idb.xch.o\
	 ike.io.admin.o\
	 ike.io.network.o\
	 ike.io.pfkey.o\
	 ike.keyfile.o\
	 ike.names.o\
	 ike.nethlp.o\
	 ike.packet.o\
	 ike.payload.o\
	 ike.peerid.o\
	 ike.policy.o\
	 ike.proposal.o\
	 ike.utility.o\
	 ike.xauth.o\
	 ike.xconf.o\
	 iked.o\
	 main.o

IKED_P = ../libip/libip.bdata.o \
	 ../libip/libip.frag.o \
	 ../libip/libip.packet.o \
	 ../libip/libip.packet.dns.o \
	 ../libip/libip.packet.udp.o \
	 ../libip/libip.packet.ip.o \
         ../libip/libip.pcap.o \
	 ../libip/libip.queue.o \
	 ../libip/libip.route.unix.o \
	 ../libip/utils.list.o \
	 ../libith/libith.o \
	 ../liblog/liblog.o
	 
IKED_H = crypto.h ike.h iked.h idb.h xauth.h xconf.h

debug: $(IKED_O)
	$(CC) $(L_FLAGS) $(D_FLAGS) -o $(IKED_B) $(IKED_O) $(IKED_P)

.yy.cpp: $(IKED_H)
	$(BC) -d -o$@ $<

.ll.cpp: $(IKED_H)
	$(LC) -o$@ $<
	
.cpp.o: $(IKED_H)
	$(CC) -c $(C_FLAGS) $(D_FLAGS) $(H_FLAGS) $<

clean:
	-test -z "stack.hh" || rm -f stack.hh
	-test -z "location.hh" || rm -f location.hh
	-test -z "position.hh" || rm -f position.hh
	-test -z "conf.parse.hpp" || rm -f conf.parse.hpp
	-test -z "conf.parse.cpp" || rm -f conf.parse.cpp
	-test -z "conf.token.cpp" || rm -f conf.token.cpp
	-test -z "$(IKED_O)" || rm -f $(IKED_O)
	-test -z "$(IKED_B)" || rm -f $(IKED_B)
	-test -z /usr/local/man/man8/iked.8.gz || rm -f /usr/local/man/man8/iked.8.gz
	-test -z /usr/local/man/man5/iked.conf.5.gz || rm -f /usr/local/man/man5/iked.conf.5.gz

install:
	-install -c $(IKED_B) /usr/local/sbin/
	cat iked.8 | gzip > /usr/local/man/man8/iked.8.gz
	cat iked.conf.5 | gzip > /usr/local/man/man5/iked.conf.5.gz

