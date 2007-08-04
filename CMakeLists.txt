#
# Shrew Soft IKE daemon and client
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

SET(
	IDIR_PATHS
	/usr/include
	/usr/local/include )

SET(
	LDIR_PATHS
	/usr/lib
	/usr/local/lib )

OPTION( DEBUG "include Debug Symbol support" )
OPTION( QTGUI "include Client QT GUI support" )
OPTION( NATT  "include NAT Traversal support" )
OPTION( LDAP  "include LDAP Authentication support" )

#
# Debug Symbols Option
#

if( DEBUG )

	add_definitions( -g )

endif( DEBUG )

#
# Client GUI option
#

if( QTGUI )

	add_definitions( -D QT_THREAD_SUPPORT )

	set( QT_MT_REQUIRED TRUE )

	FIND_PACKAGE( Qt3 )

	if( NOT QT_FOUND )

		message(
			FATAL_ERROR
			"Unable to locate QT package" )

	endif( NOT QT_FOUND )
		
	# success

	message(
		STATUS 
		"Enabled Client QT GUI support ..." )

	add_subdirectory( source/ikea )
	add_subdirectory( source/ikec )

endif( QTGUI )

#
# NAT Traversion option
#

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

#
# LDAP support option
#

if( LDAP )

	# ldap include

	find_path(
		IDIR_LDAP
		NAMES
		ldap.h
		PATHS
		${IDIR_PATHS} )

	if( NOT IDIR_LDAP )

		message(
			FATAL_ERROR
			"Unable to locate LDAP include file" )

	endif( NOT IDIR_LDAP )

	# ldap libraries

	find_library(
		LDIR_LDAP
		NAMES
		ldap
		PATHS
		${LDIR_PATHS} )

	find_library(
		LDIR_LBER
		NAMES
		lber
		PATHS
		${LDIR_PATHS} )

	if( NOT LDIR_LDAP OR NOT LDIR_LBER )

		message(
			FATAL_ERROR
			"Unable to locate LDAP library file" )

	endif( NOT LDIR_LDAP OR NOT LDIR_LBER )

	# success

	message( 
		STATUS
		"Enabled LDAP Authentication support ..." )

	add_definitions( -D OPT_LDAP )

endif( LDAP )

