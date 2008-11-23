
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

void update_site( CONFIG * config, const char * path, long & version )
{
	switch( version )
	{
		case 0: // version 0 -> 1
		{
			//
			// upgrade the auth-mutual-psk string
			// to a binary value
			//

			char text[ MAX_CONFSTRING ];
			long size = MAX_CONFSTRING;

			if( config->get_string( "auth-mutual-psk", text, size, 0 ) )
			{
				config->del( "auth-mutual-psk" );
				BDATA psk;
				psk.set( text, strlen( text ) );
				config->set_binary( "auth-mutual-psk", psk );
			}

			break;
		}

		case 1:	// version 1 -> 2
		{
			//
			// update client-dns-enable number to
			// client-dns-used
			//

			long numb;

			if( config->get_number( "client-dns-enable", &numb ) )
			{
				config->del( "client-dns-enable" );
				config->set_number( "client-dns-used", numb );
			}
			
			break;
		}
	}

	version++;
	printf( "updated site \'%s\' to version %li\n", config->get_id(), version );
	config->set_number( "version", version );
	config->file_write( path );
}

_IKEA::_IKEA()
{
}

_IKEA::~_IKEA()
{
}

const char * _IKEA::site_path()
{
	return sites.toAscii().constData();
}

const char * _IKEA::cert_path()
{
	return certs.toAscii().constData();
}

bool _IKEA::init( ikeaRoot * setRoot )
{
	QDir qdir;

	// store our root window

	r = setRoot;

	// create config directory

	qdir.mkdir( QDir::homePath() + "/.ike" );

	// create sites directory

	ikea.sites = QDir::homePath() + "/.ike/sites";
	qdir.mkdir( ikea.sites );

	// create certs directory

	ikea.certs = QDir::homePath() + "/.ike/certs";
	qdir.mkdir( ikea.certs );

	// read site list

	qdir.setPath( ikea.sites );
	qdir.setFilter( QDir::Files | QDir::NoSymLinks );

	QFileInfoList infoList = qdir.entryInfoList();

	printf( "reading %i sites\n", infoList.size() );

	for( int i = 0; i < infoList.size(); ++i )
	{
		QFileInfo fileInfo = infoList.at( i );
		QString fileName = fileInfo.fileName();
		QString filePath = ikea.sites + "/" + fileName;

		CONFIG config;
		if( config.file_read( filePath.toAscii().constData() ) )
		{
			config.set_id( fileName.toAscii().constData() );

			long version = 0;
			config.get_number( "version", &version );
			while( version < CLIENT_VER_CFG )
				update_site( &config, filePath.toAscii().constData(), version );

			printf( "adding entry for site file \'%s\'\n", fileName.toAscii().constData() );

			QListWidgetItem * widgetItem = new QListWidgetItem( r->listWidgetSites );
			widgetItem->setIcon( QIcon( ":/png/site.png" ) );
			widgetItem->setText( fileName );
			widgetItem->setData( Qt::UserRole, fileName );
			widgetItem->setFlags( Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsEditable );
//			widgetItem->setRenameEnabled ( true );
		}
		else
		{
			printf( "error loading site file \'%s\'\n", fileName.toAscii().constData() );
		}
	}

	return true;
}
