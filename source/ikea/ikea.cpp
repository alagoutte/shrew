#include "ikea.h"

_IKEA::_IKEA()
{
}

_IKEA::~_IKEA()
{
}

const char * _IKEA::site_path()
{
	return sites.ascii();
}

const char * _IKEA::cert_path()
{
	return certs.ascii();
}

bool _IKEA::init( root * setr )
{
	QDir qdir;

	// store our root window

	r = setr;

	// create config directory

	qdir.mkdir( QDir::homeDirPath() + "/.ike" );

	// create sites directory

	ikea.sites = QDir::homeDirPath() + "/.ike/sites";
	qdir.mkdir( ikea.sites );

	// create certs directory

	ikea.certs = QDir::homeDirPath() + "/.ike/certs";
	qdir.mkdir( ikea.certs );

	// read site list

	qdir.setPath( QDir::homeDirPath() + "/.ike/sites" );
	qdir.setFilter( QDir::Files );

	QStringList entryList = qdir.entryList( "*" );
	QStringList::const_iterator eit = entryList.constBegin();

	for( ; eit != entryList.constEnd(); ++eit)
	{
		QString fileName = *eit;
		QString filePath;

		CONFIG config;
		config.file_read( ( char * ) fileName.ascii() );

		filePath = ikea.sites + "/" + fileName;

		printf( "adding entry for site file \'%s\'\n", fileName.ascii() );

		QIconViewItem * i = new QIconViewItem( r->iconViewSites );
		if( i == NULL )
			return false;

		i->setText( fileName.ascii() );
		i->setPixmap( QPixmap::fromMimeSource( "site.png" ) );
		i->setRenameEnabled ( true );
	}

	return true;
}
