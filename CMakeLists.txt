#
# Shrew Soft VPN / IKE Tools
# Cross Platform Make File
#
# author : Matthew Grooms
#        : mgrooms@shrew.net
#        : Copyright 2007, Shrew Soft Inc
#

project( IKE )

#
# Unix Target Constants
#

add_definitions( -D UNIX )

include( CheckCSourceCompiles )

subdirs(
	source/iked
	source/libike
	source/libip
	source/libith
	source/liblog
	source/libpfk )

set(
	SEARCH_INC
	/usr/include
	/usr/local/include )

set(
	SEARCH_LIB
	/usr/lib
	/usr/local/lib )

set(
	SEARCH_BIN
	/usr/local/bin
	/usr/pkg/bin
	/usr/bin )

set(
	SEARCH_SYS
	/usr/share
	/usr/local
	/usr )

#
# PreRequisite Checks
#

find_package( OpenSSL )

if( NOT OPENSSL_FOUND )

	message(
		FATAL_ERROR
		"Unable to locate required package : OpenSSL" )

endif( NOT OPENSSL_FOUND )

find_package( Threads )

if( NOT CMAKE_USE_PTHREADS_INIT )

	message(
		FATAL_ERROR
		"Unable to locate required package : pthreads" )

endif( NOT CMAKE_USE_PTHREADS_INIT )

find_program(
	PATH_BIN_FLEX
	NAMES "flex"
	PATHS ${SEARCH_BIN} )

if( NOT PATH_BIN_FLEX )

	message(
		FATAL_ERROR
		"Unable to locate required binary : flex" )

endif( NOT PATH_BIN_FLEX )
		
message(
	STATUS 
	"Using binary ${PATH_BIN_FLEX} ..." )

find_program(
	PATH_BIN_BISON
	NAMES "bison"
	PATHS ${SEARCH_BIN} )

if( NOT PATH_BIN_BISON )

	message(
		FATAL_ERROR
		"Unable to locate required binary : bison" )

endif( NOT PATH_BIN_BISON )
		
message(
	STATUS 
	"Using binary ${PATH_BIN_BISON} ..." )

find_library(
	PATH_LIB_RT
	NAMES "rt"
	PATHS ${SEARCH_LIB} )

#
# Install Path Checks
#

if( NOT EXISTS ${CMAKE_INSTALL_PREFIX} )

	set(
		CMAKE_INSTALL_PREFIX
		"/usr" )

endif( NOT EXISTS ${CMAKE_INSTALL_PREFIX} )

message(
	STATUS 
	"Using install prefix ${CMAKE_INSTALL_PREFIX} ..." )

# etc path

if( ETCDIR )

	set(	PATH_ETC
		${ETCDIR} )

else( ETCDIR )

	if( EXISTS ${CMAKE_INSTALL_PREFIX}/etc )

		set(	PATH_ETC
			"${CMAKE_INSTALL_PREFIX}/etc" )

	else( EXISTS ${CMAKE_INSTALL_PREFIX}/etc )
		
		set(	PATH_ETC
			"/etc" )

	endif( EXISTS ${CMAKE_INSTALL_PREFIX}/etc )

endif( ETCDIR )

message(
	STATUS
	"Using etc path ${PATH_ETC} ..." )

# man path

if( MANDIR )

	set(	PATH_MAN
		${MANDIR} )

else( MANDIR )

	find_path(
		PATH_MAN
		NAMES "man"
		PATHS ${SEARCH_SYS}
		NO_DEFAULT_PATH )

	if( PATH_MAN )

		set(	PATH_MAN
			"${PATH_MAN}/man" )

	else( PATH_MAN )

		set(	PATH_MAN
			"${CMAKE_INSTALL_PREFIX}/man" )

	endif( PATH_MAN )

endif( MANDIR )

message(
	STATUS
	"Using man path ${PATH_MAN} ..." )

#
# Build Options
#

OPTION( DEBUG  "include Debug Symbol support" )
OPTION( NATT   "include NAT Traversal support" )
OPTION( LDAP   "include LDAP Authentication support" )
OPTION( QTGUI  "include Client QT GUI support" )

OPTION( ETCDIR "etc install directory" )
OPTION( MANDIR "man install directory" )


# Debug Symbols Option

if( DEBUG )

	add_definitions( -g )

endif( DEBUG )

# NAT Traversion option

if( NATT )

	check_c_source_compiles(
		"
		#ifdef __linux__
		# include <linux/pfkeyv2.h>
		#else
		# include <sys/types.h>
		# include <net/pfkeyv2.h>
                #endif

		int main()
		{
			struct sadb_x_nat_t_type test;

			return 0;
		}
		"
		NATT_FOUND )

	if( NOT NATT_FOUND )

		message(
			FATAL_ERROR
			"Unable to locate required NAT-T pfkey structures" )

	endif( NOT NATT_FOUND )

	# success

	message(
		STATUS 
		"Enabled NAT Traversal support ..." )

	add_definitions( -D OPT_NATT )

endif( NATT )

# LDAP support option

if( LDAP )

	# ldap include

	find_path(
		PATH_INC_LDAP
		NAMES "ldap.h"
		PATHS ${SEARCH_INC} )

	if( NOT PATH_INC_LDAP )

		message(
			FATAL_ERROR
			"Unable to locate LDAP include file" )

	endif( NOT PATH_INC_LDAP )

	# ldap libraries

	find_library(
		PATH_LIB_LDAP
		NAMES "ldap"
		PATHS ${SEARCH_LIB} )

	find_library(
		PATH_LIB_LBER
		NAMES "lber"
		PATHS ${SEARCH_LIB} )

	if( NOT PATH_LIB_LDAP OR NOT PATH_LIB_LBER )

		message(
			FATAL_ERROR
			"Unable to locate LDAP library file" )

	endif( NOT PATH_LIB_LDAP OR NOT PATH_LIB_LBER )

	# success

	message( 
		STATUS
		"Enabled LDAP Authentication support ..." )

	add_definitions( -D OPT_LDAP )

endif( LDAP )

# Client GUI option

if( QTGUI )

	add_definitions( -D QT_THREAD_SUPPORT )

	set( QT_MT_REQUIRED TRUE )

	find_package( Qt3 )

	if( NOT QT_FOUND )

		message(
			FATAL_ERROR
			"Unable to locate required package : QT" )

	endif( NOT QT_FOUND )
		
	# success

	message(
		STATUS 
		"Enabled Client QT GUI support ..." )

	add_definitions( ${QT_DEFINITIONS} )

	add_subdirectory( source/ikea )
	add_subdirectory( source/ikec )

endif( QTGUI )


