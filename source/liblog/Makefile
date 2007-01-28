#
# LIBLOG Makefile
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2006, Shrew Soft Inc
#

C_FLAGS += -Wall -DUNIX
H_FLAGS += -I../ -I../libith -I/usr/include -I/usr/local/include
L_FLAGS += -L../ -L/usr/lib -L/usr/local/lib -shared -lpthread

.ifdef DEBUG
  D_FLAGS+=-g
.endif

LIBLOG_B = liblog.so
LIBLOG_O = liblog.o

LIBLOG_H = liblog.h

all: $(LIBLOG_O)
	$(CC) $(L_FLAGS) $(D_FLAGS) $(LIBLOG_O) -o $(LIBLOG_B)

.cpp.o: $(LIBLOG_H)
	$(CC) -c $(C_FLAGS) $(D_FLAGS) $(H_FLAGS) $<
	
clean:
	-test -z "$(LIBLOG_O)" || rm -f $(LIBLOG_O)
	-test -z "$(LIBLOG_B)" || rm -f $(LIBLOG_B)

