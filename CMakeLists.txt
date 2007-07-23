#
# Shrew Soft IKE daemon and client
#

project( IKE )

#
# Compile Options
#

add_definitions( -D UNIX )

if( DEBUG )
	add_definitions( -g )
endif( DEBUG )

if( NATT )
	add_definitions( -D OPT_NATT )
endif( NATT )

if( LDAP )
	add_definitions( -D OPT_LDAP )
endif( LDAP )

#
# subdirectories
#

subdirs(
	source/ikea
	source/ikec
	source/iked
	source/libike
	source/libip
	source/libith
	source/liblog
	source/libpfk )
