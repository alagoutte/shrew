#include "ikea.h"
#include <qiconview.h>

_IKEA::_IKEA()
{
}

_IKEA::~_IKEA()
{
}

char * _IKEA::site_path()
{
	return sites;
}

char * _IKEA::cert_path()
{
	return certs;
}

bool _IKEA::init( root * setr )
{
	char path[ 1024 ];

	// store our root window

	r = setr;

	// locate user home directory

	struct passwd * pwd = getpwuid( getuid() );
	if( pwd == NULL )
	{
		printf( "unable to read pwent for %i\n", getuid() );
		exit( -1 );
	}

	// create ike config directory path

	snprintf( path, 1024, "%s/.ike", pwd->pw_dir );
	endpwent();

	// attempt to open the path

	int fd = open( path, O_RDONLY );
	if( fd == -1 )
	{
		// attempt to create ~/.ike

		if( mkdir( path, S_IRWXU  ) )
		{
			printf( "unable to create dir %s\n", path );
			exit( -1 );
		}
		
		printf( "created %s\n", path );
	}
	else
		close( fd );

	// create ike sites directory path

	snprintf( sites, 1024, "%s/sites", path );

	// attempt to open the path

	fd = open( sites, O_RDONLY );
	if( fd == -1 )
	{
		// attempt to create ~/.ike/sites

		if( mkdir( sites, S_IRWXU ) )
		{
			printf( "unable to create dir %s\n", sites );
			exit( -1 );
		}

		printf( "created %s\n", sites );
	}
	else
		close( fd );

	// validate ike certs directory path

	snprintf( certs, 1024, "%s/certs", path );

	// attempt to open the path

	fd = open( certs, O_RDONLY );
	if( fd == -1 )
	{
		// attempt to create ~/.ike/certs

		if( mkdir( certs, S_IRWXU ) )
		{
			printf( "unable to create dir %s\n", certs );
			exit( -1 );
		}

		printf( "created %s\n", certs );
	}
	else
		close( fd );

	// read all site directory entries

	fd = open( sites, O_RDONLY );
	if( fd == -1 )
	{
		printf( "unable to open dir %s\n", sites );
		exit( -1 );
	}

	printf( "reading site list from \'%s\'\n", sites );

	char dbuff[ 1024 ];
	unsigned int dsize;
	while( ( dsize = getdents( fd, dbuff, 1024 ) ) > 0 )
	{
		unsigned int tsize = 0;
		while( tsize < dsize )
		{
			dirent * dent = ( dirent * )( dbuff + tsize );

			if( dent->d_type == DT_REG )
			{
				snprintf( path, 1024, "%s/%s", sites, dent->d_name );

				CONFIG config;
				config.file_read( path );

				printf( "adding entry for site file \'%s\'\n", path );

				QIconViewItem * i = new QIconViewItem( r->iconViewSites );
				if( i == NULL )
					return false;

				i->setPixmap( QPixmap::fromMimeSource( "site.png" ) );
				i->setText( dent->d_name );
				i->setRenameEnabled ( true );
			}

			tsize += dent->d_reclen;
		}
	}

	close( fd );

	return true;
}
