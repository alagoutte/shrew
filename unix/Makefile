#
# IKED Makefile
#
# author : Matthew Grooms
#

all:
	cd ../source/libip && $(MAKE) $(MFLAGS)
	cd ../source/liblog && $(MAKE) $(MFLAGS)
	cd ../source/libith && $(MAKE) $(MFLAGS)
	cd ../source/libiked && $(MAKE) $(MFLAGS)
	cd ../source/libpfk && $(MAKE) $(MFLAGS)
	cd ../source/iked && $(MAKE) $(MFLAGS)

clean:
	cd ../source/libip && $(MAKE) clean
	cd ../source/liblog && $(MAKE) clean 
	cd ../source/libith && $(MAKE) clean
	cd ../source/libiked && $(MAKE) clean
	cd ../source/libpfk && $(MAKE) clean
	cd ../source/iked && $(MAKE) clean

install:
	cd ../source/libiked && $(MAKE) install
	cd ../source/libpfk && $(MAKE) install
	cd ../source/iked && $(MAKE) install

