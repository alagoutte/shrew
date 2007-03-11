#
# IKED Makefile
#
# author : Matthew Grooms
#

all: daemon client

clean: daemon-clean client-clean

install: daemon-install client-install

daemon:
	#
	# building ike deamon
	#
	cd ../source/libip && $(MAKE) $(MFLAGS)
	cd ../source/liblog && $(MAKE) $(MFLAGS)
	cd ../source/libith && $(MAKE) $(MFLAGS)
	cd ../source/libiked && $(MAKE) $(MFLAGS)
	cd ../source/libpfk && $(MAKE) $(MFLAGS)
	cd ../source/iked && $(MAKE) $(MFLAGS)

client:
	#
	# building ike client
	#
	cd ../source/ikea && $(MAKE) $(MFLAGS)
	cd ../source/ikec && $(MAKE) $(MFLAGS)

daemon-clean:
	#
	# cleaning ike deamon
	#
	cd ../source/libip && $(MAKE) clean
	cd ../source/liblog && $(MAKE) clean 
	cd ../source/libith && $(MAKE) clean
	cd ../source/libiked && $(MAKE) clean
	cd ../source/libpfk && $(MAKE) clean
	cd ../source/iked && $(MAKE) clean

client-clean:
	#
	# cleaning ike client
	#
	cd ../source/ikea && $(MAKE) clean
	cd ../source/ikec && $(MAKE) clean 

daemon-install:
	#
	# installing ike deamon
	#
	cd ../source/libiked && $(MAKE) install
	cd ../source/libpfk && $(MAKE) install
	cd ../source/iked && $(MAKE) install

client-install:
	#
	# installing ike client
	#
	cd ../source/ikea && $(MAKE) install
	cd ../source/ikec && $(MAKE) install


