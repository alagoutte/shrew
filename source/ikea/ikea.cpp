
/*
 * Copyright (c) 2007
 *      Shrew Soft Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the software and any
 *    accompanying software that uses the software.  The source code
 *    must either be included in the distribution or be available for no
 *    more than the cost of distribution plus a nominal fee, and must be
 *    freely redistributable under reasonable conditions.  For an
 *    executable file, complete source code means the source code for all
 *    modules it contains.  It does not include source code for modules or
 *    files that typically accompany the major components of the operating
 *    system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY SHREW SOFT INC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED.  IN NO EVENT SHALL SHREW SOFT INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * AUTHOR : Matthew Grooms
 *          mgrooms@shrew.net
 *
 */

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
