
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

#include "qikea.h"

_QIKEA::_QIKEA()
{
}

_QIKEA::~_QIKEA()
{
}

bool _QIKEA::init( qikeaRoot * setRoot )
{
	QDir qdir;

	// store our root window

	r = setRoot;

	// enumerate site configurations

	CONFIG config;
	int index = 0;

	while( manager.file_enumerate( config, index ) )
	{
		printf( "adding entry for site file \'%s\'\n", config.get_id() );

		QListWidgetItem * widgetItem = new QListWidgetItem( r->listWidgetSites );
		widgetItem->setIcon( QIcon( ":/png/site.png" ) );
		widgetItem->setText( config.get_id() );
		widgetItem->setData( Qt::UserRole, config.get_id() );
		widgetItem->setFlags( Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsEditable );
//		widgetItem->setRenameEnabled ( true );

		config.del_all();
	}

	return true;

/*
	// create config directory

	qdir.mkdir( QDir::homePath() + "/.ike" );

	// create sites directory

	qikea.sites = QDir::homePath() + "/.ike/sites";
	qdir.mkdir( qikea.sites );

	// create certs directory

	qikea.certs = QDir::homePath() + "/.ike/certs";
	qdir.mkdir( qikea.certs );

	// read site list

	qdir.setPath( qikea.sites );
	qdir.setFilter( QDir::Files | QDir::NoSymLinks );

	QFileInfoList infoList = qdir.entryInfoList();

	printf( "reading %i sites\n", infoList.size() );

	for( int i = 0; i < infoList.size(); ++i )
	{
		QFileInfo fileInfo = infoList.at( i );
		QString fileName = fileInfo.fileName();
		QString filePath = qikea.sites + "/" + fileName;

		CONFIG config;
		CONFIG_MANAGER manager;

		if( manager.file_vpn_load( config, filePath.toAscii().constData() ) )
		{
			config.set_id( fileName.toAscii().constData() );

			long version = 0;
			config.get_number( "version", &version );
			while( version < CLIENT_VER_CFG )
				update_site( &config, filePath.toAscii().constData(), version );

		}
		else
		{
			printf( "error loading site file \'%s\'\n", fileName.toAscii().constData() );
		}
	}
*/
	return true;
}
